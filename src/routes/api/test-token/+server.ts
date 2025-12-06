import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { SCANNER_API_URL } from '$env/static/private';

export const POST: RequestHandler = async ({ request }) => {
	try {
		const { token, repo } = await request.json();

		if (!token) {
			return json({ error: 'No token provided' }, { status: 400 });
		}

		if (!SCANNER_API_URL) {
			return json({ error: 'Scanner API not configured' }, { status: 500 });
		}

		// Forward to scanner API
		const response = await fetch(`${SCANNER_API_URL}/test-token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token, repo })
		});

		const data = await response.json();
		return json(data);
	} catch (err) {
		console.error('Test token error:', err);
		return json({ error: 'Failed to test token' }, { status: 500 });
	}
};
