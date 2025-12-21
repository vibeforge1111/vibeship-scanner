import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createServerSupabase } from '$lib/server/supabase';
import { encrypt } from '$lib/server/encryption';

// POST - Complete device authentication
export const POST: RequestHandler = async ({ request }) => {
	const body = await request.json();
	const { token, githubToken } = body;

	if (!token || !githubToken) {
		return json({ error: 'Token and githubToken are required' }, { status: 400 });
	}

	const supabase = createServerSupabase();

	// Check if token exists and is pending
	const { data: auth, error: fetchError } = await supabase
		.from('device_auth')
		.select('*')
		.eq('token', token)
		.single();

	if (fetchError || !auth) {
		return json({ error: 'Invalid token' }, { status: 404 });
	}

	if (auth.status !== 'pending') {
		return json({ error: 'Token already used or expired' }, { status: 400 });
	}

	if (new Date(auth.expires_at) < new Date()) {
		return json({ error: 'Token expired' }, { status: 400 });
	}

	// Encrypt and store the GitHub token
	const encryptedToken = encrypt(githubToken);

	const { error: updateError } = await supabase
		.from('device_auth')
		.update({
			github_token: encryptedToken,
			status: 'authenticated',
			authenticated_at: new Date().toISOString()
		})
		.eq('token', token);

	if (updateError) {
		console.error('Failed to complete auth:', updateError);
		return json({ error: 'Failed to complete authentication' }, { status: 500 });
	}

	return json({ success: true, message: 'Authentication complete' });
};
