import type { RequestHandler } from './$types';

const FLY_MCP_URL = 'https://scanner-empty-field-5676.fly.dev/mcp';

export const GET: RequestHandler = async () => {
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
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	});
};

export const POST: RequestHandler = async ({ request }) => {
	const body = await request.text();

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
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	});
};

export const OPTIONS: RequestHandler = async () => {
	return new Response(null, {
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	});
};
