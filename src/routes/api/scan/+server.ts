import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { hashUrl, parseRepoUrl } from '$lib/server/scan';
import { supabase } from '$lib/supabase';
import { SCANNER_API_URL } from '$env/static/private';

async function checkRateLimit(identifier: string): Promise<{ allowed: boolean; remaining: number }> {
	const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

	const { count } = await supabase
		.from('scans')
		.select('*', { count: 'exact', head: true })
		.eq('session_id', identifier)
		.gte('created_at', hourAgo);

	const used = count || 0;
	const limit = 20;

	return {
		allowed: used < limit,
		remaining: Math.max(0, limit - used)
	};
}

export const POST: RequestHandler = async ({ request, getClientAddress }) => {
	try {
		const clientIp = getClientAddress();
		const rateLimit = await checkRateLimit(clientIp);

		if (!rateLimit.allowed) {
			return json(
				{
					error: 'rate_limited',
					message: 'Too many scans. Please try again later.',
					remaining: rateLimit.remaining
				},
				{ status: 429 }
			);
		}

		const { url: rawUrl, githubToken } = await request.json();

		console.log('Scan request received, hasGithubToken:', !!githubToken);

		if (!rawUrl) {
			return json({ error: 'url_required', message: 'Repository URL is required' }, { status: 400 });
		}

		let url = rawUrl.trim();
		if (/^[\w-]+\/[\w.-]+$/.test(url)) {
			url = `https://github.com/${url}`;
		} else if (/^github\.com\/[\w-]+\/[\w.-]+/.test(url)) {
			url = `https://${url}`;
		} else if (/^gitlab\.com\/[\w-]+\/[\w.-]+/.test(url)) {
			url = `https://${url}`;
		}
		url = url.replace(/\/+$/, '');

		const githubPattern = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/;
		const gitlabPattern = /^https?:\/\/(www\.)?gitlab\.com\/[\w-]+\/[\w.-]+\/?$/;

		if (!githubPattern.test(url) && !gitlabPattern.test(url)) {
			return json({ error: 'invalid_url', message: 'Please enter a valid GitHub or GitLab URL' }, { status: 400 });
		}

		const parsed = parseRepoUrl(url);
		if (!parsed) {
			return json({ error: 'invalid_url', message: 'Could not parse repository URL' }, { status: 400 });
		}

		const scanId = crypto.randomUUID();
		const urlHash = hashUrl(url);

		const isPrivate = !!githubToken;

		const scanRecord = {
			id: scanId,
			target_type: parsed.type,
			target_url: url,
			target_url_hash: urlHash,
			target_branch: 'main',
			is_private: isPrivate,
			status: 'queued' as const,
			is_public: !isPrivate,
			session_id: clientIp
		};

		const { error: dbError } = await supabase
			.from('scans')
			.insert(scanRecord);

		if (dbError) {
			console.error('Database error:', dbError);
			return json({ error: 'database_error', message: 'Failed to create scan' }, { status: 500 });
		}

		if (SCANNER_API_URL) {
			fetch(`${SCANNER_API_URL}/scan`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					scanId,
					repoUrl: url,
					branch: 'main',
					githubToken: githubToken || undefined
				})
			}).catch(err => console.error('Scanner trigger error:', err));
		}

		return json({
			scanId,
			status: 'queued',
			estimatedTime: 30,
			message: 'Scan queued successfully'
		}, { status: 201 });

	} catch (err) {
		console.error('Scan error:', err);
		return json({ error: 'internal_error', message: 'Something went wrong' }, { status: 500 });
	}
};

export const GET: RequestHandler = async ({ url }) => {
	const scanId = url.searchParams.get('id');

	if (!scanId) {
		return json({ error: 'id_required', message: 'Scan ID is required' }, { status: 400 });
	}

	const { data: scan, error } = await supabase
		.from('scans')
		.select('*')
		.eq('id', scanId)
		.single();

	if (error || !scan) {
		return json({ error: 'not_found', message: 'Scan not found' }, { status: 404 });
	}

	return json(scan);
};
