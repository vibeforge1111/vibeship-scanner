import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createServerSupabase } from '$lib/server/supabase';
import { randomBytes } from 'crypto';

// POST - Start device auth flow, returns link for user to visit
export const POST: RequestHandler = async () => {
	const supabase = createServerSupabase();

	// Generate unique token
	const token = randomBytes(32).toString('base64url');

	// Expires in 10 minutes
	const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

	const { error } = await supabase
		.from('device_auth')
		.insert({
			token,
			status: 'pending',
			expires_at: expiresAt
		});

	if (error) {
		console.error('Failed to create device auth:', error);
		return json({ error: 'Failed to start authentication' }, { status: 500 });
	}

	const authUrl = `https://scanner.vibeship.co/auth/link/${token}`;

	return json({
		token,
		auth_url: authUrl,
		expires_in: 600, // 10 minutes in seconds
		message: 'Open the auth_url in your browser to authenticate'
	});
};
