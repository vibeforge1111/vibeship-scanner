import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createServerSupabase } from '$lib/server/supabase';
import { decrypt } from '$lib/server/encryption';

// GET - Poll for authentication status
export const GET: RequestHandler = async ({ url }) => {
	const token = url.searchParams.get('token');

	if (!token) {
		return json({ error: 'Token is required' }, { status: 400 });
	}

	const supabase = createServerSupabase();

	const { data: auth, error } = await supabase
		.from('device_auth')
		.select('*')
		.eq('token', token)
		.single();

	if (error || !auth) {
		return json({ error: 'Invalid or expired token' }, { status: 404 });
	}

	// Check if expired
	if (new Date(auth.expires_at) < new Date()) {
		await supabase
			.from('device_auth')
			.update({ status: 'expired' })
			.eq('token', token);

		return json({ status: 'expired', message: 'Authentication link expired' });
	}

	if (auth.status === 'pending') {
		return json({ status: 'pending', message: 'Waiting for user to authenticate...' });
	}

	if (auth.status === 'authenticated') {
		// Mark as used so it can't be polled again
		await supabase
			.from('device_auth')
			.update({ status: 'used' })
			.eq('token', token);

		// Decrypt and return the GitHub token
		let githubToken = null;
		if (auth.github_token) {
			try {
				githubToken = decrypt(auth.github_token);
			} catch (e) {
				console.error('Failed to decrypt token:', e);
			}
		}

		return json({
			status: 'authenticated',
			github_token: githubToken,
			message: 'Authentication successful!'
		});
	}

	return json({ status: auth.status });
};
