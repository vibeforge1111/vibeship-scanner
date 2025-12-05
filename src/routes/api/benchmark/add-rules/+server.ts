import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const SCANNER_URL = 'https://vibeship-benchmark.fly.dev';
const BENCHMARK_SECRET = 'vibeship-benchmark-2024';

export const POST: RequestHandler = async ({ request }) => {
	try {
		const body = await request.json();

		const response = await fetch(`${SCANNER_URL}/benchmark/add-rules`, {
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
		console.error('Add rules error:', error);
		return json({ error: 'Failed to add rules' }, { status: 500 });
	}
};
