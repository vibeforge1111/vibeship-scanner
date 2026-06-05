import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { SCANNER_API_URL } from '$env/static/private';

const RATE_LIMIT_MAP = new Map<string, { count: number; resetAt: number }>();

function checkTestTokenRateLimit(identifier: string): boolean {
	const now = Date.now();
	const windowMs = 60_000; // 1 minute
	const maxRequests = 10;

	const entry = RATE_LIMIT_MAP.get(identifier);
	if (!entry || now > entry.resetAt) {
		RATE_LIMIT_MAP.set(identifier, { count: 1, resetAt: now + windowMs });
		return true;
	}

	if (entry.count >= maxRequests) {
		return false;
	}

	entry.count++;
	return true;
}

export const POST: RequestHandler = async ({ request, getClientAddress }) => {
	const clientIp = getClientAddress();
	if (!checkTestTokenRateLimit(clientIp)) {
		return json({ error: 'rate_limited', message: 'Too many requests. Please try again later.' }, { status: 429 });
	}

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
