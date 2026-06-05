import type { RequestHandler } from './$types';
import type { RequestEvent } from '@sveltejs/kit';

const FLY_MCP_URL = 'https://scanner-empty-field-5676.fly.dev/mcp';

function requireAuth(event: RequestEvent): void {
	const authHeader = event.request.headers.get('authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		throw new Error('Missing or invalid authorization header');
	}
}

export const GET: RequestHandler = async (event) => {
	requireAuth(event);

	const response = await fetch(FLY_MCP_URL, {
		method: 'GET',
		headers: {
			'Accept': 'application/json',
		}
	});

	const data = await response.text();

	return new Response(data, {
		status: response.status,
		headers: {
			'Content-Type': 'application/json',
		}
	});
};

export const POST: RequestHandler = async (event) => {
	requireAuth(event);

	const body = await event.request.text();

	const response = await fetch(FLY_MCP_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body
	});

	const data = await response.text();

	return new Response(data, {
		status: response.status,
		headers: {
			'Content-Type': 'application/json',
		}
	});
};

export const OPTIONS: RequestHandler = async () => {
	return new Response(null, {
		headers: {
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization'
		}
	});
};
