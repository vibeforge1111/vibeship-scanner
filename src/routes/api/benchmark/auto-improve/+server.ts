import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const SCANNER_URL = 'https://scanner-empty-field-5676.fly.dev';
const BENCHMARK_SECRET = 'vibeship-benchmark-2024';

export const POST: RequestHandler = async ({ request }) => {
	try {
		const body = await request.json();

		const response = await fetch(`${SCANNER_URL}/benchmark/auto-improve`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Benchmark-Key': BENCHMARK_SECRET
			},
			body: JSON.stringify(body)
		});

		const data = await response.json();
		return json(data);
	} catch (error) {
		console.error('Auto-improve error:', error);
		return json({ error: 'Auto-improve failed' }, { status: 500 });
	}
};
