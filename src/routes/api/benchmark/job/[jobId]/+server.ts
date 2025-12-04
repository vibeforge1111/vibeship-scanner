import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const SCANNER_URL = 'https://scanner-empty-field-5676.fly.dev';

export const GET: RequestHandler = async ({ params }) => {
	try {
		const { jobId } = params;

		const response = await fetch(`${SCANNER_URL}/benchmark/job/${jobId}`);
		const data = await response.json();
		return json(data);
	} catch (error) {
		console.error('Job status error:', error);
		return json({ error: 'Failed to get job status' }, { status: 500 });
	}
};
