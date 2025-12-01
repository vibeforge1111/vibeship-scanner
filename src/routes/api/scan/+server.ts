import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { hashUrl, parseRepoUrl } from '$lib/server/scan';
import { supabase } from '$lib/supabase';
import { tasks } from "@trigger.dev/sdk/v3";
import type { scanRepository } from '../../../trigger/scan';
import { checkRateLimit } from '$lib/server/ratelimit';

export const POST: RequestHandler = async ({ request, getClientAddress }) => {
	try {
		const clientIp = getClientAddress();
		const rateLimit = await checkRateLimit(clientIp, 'scan');

		if (!rateLimit.success) {
			return json(
				{
					error: 'rate_limited',
					message: 'Too many scans. Please try again later.',
					retryAfter: Math.ceil((rateLimit.reset - Date.now()) / 1000)
				},
				{
					status: 429,
					headers: {
						'Retry-After': String(Math.ceil((rateLimit.reset - Date.now()) / 1000)),
						'X-RateLimit-Remaining': String(rateLimit.remaining)
					}
				}
			);
		}

		const { url } = await request.json();

		if (!url) {
			return json({ error: 'url_required', message: 'Repository URL is required' }, { status: 400 });
		}

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

		const scanRecord = {
			id: scanId,
			target_type: parsed.type,
			target_url: url,
			target_url_hash: urlHash,
			target_branch: 'main',
			is_private: false,
			status: 'queued' as const,
			is_public: true
		};

		const { error: dbError } = await supabase
			.from('scans')
			.insert(scanRecord);

		if (dbError) {
			console.error('Database error:', dbError);
		}

		try {
			await tasks.trigger<typeof scanRepository>("scan-repository", {
				scanId,
				repoUrl: url,
				branch: 'main'
			});
		} catch (triggerError) {
			console.error('Trigger error:', triggerError);
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
