import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request }) => {
	try {
		const { url } = await request.json();

		if (!url) {
			return json({ error: 'url_required', message: 'Repository URL is required' }, { status: 400 });
		}

		const githubPattern = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/;
		const gitlabPattern = /^https?:\/\/(www\.)?gitlab\.com\/[\w-]+\/[\w.-]+\/?$/;

		if (!githubPattern.test(url) && !gitlabPattern.test(url)) {
			return json({ error: 'invalid_url', message: 'Please enter a valid GitHub or GitLab URL' }, { status: 400 });
		}

		const scanId = crypto.randomUUID();

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
