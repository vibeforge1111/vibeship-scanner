import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createClient } from '@supabase/supabase-js';
import { env } from '$env/dynamic/private';
import { PUBLIC_SUPABASE_URL, PUBLIC_SUPABASE_ANON_KEY } from '$env/static/public';
import { dev } from '$app/environment';

export const GET: RequestHandler = async ({ url, cookies }) => {
	const supabaseUrl = PUBLIC_SUPABASE_URL || env.VITE_SUPABASE_URL;
	const supabaseKey = PUBLIC_SUPABASE_ANON_KEY || env.VITE_SUPABASE_ANON_KEY;

	if (!supabaseUrl || !supabaseKey) {
		throw redirect(303, '/benchmark?error=config');
	}

	const supabase = createClient(supabaseUrl, supabaseKey);

	const code = url.searchParams.get('code');
	const next = url.searchParams.get('next') || '/benchmark';

	if (code) {
		const { data, error } = await supabase.auth.exchangeCodeForSession(code);

		if (error || !data.session) {
			throw redirect(303, '/benchmark?error=auth');
		}

		// Set cookies
		cookies.set('sb-access-token', data.session.access_token, {
			path: '/',
			httpOnly: true,
			secure: !dev,
			sameSite: 'lax',
			maxAge: 60 * 60 * 24 * 7
		});

		cookies.set('sb-refresh-token', data.session.refresh_token, {
			path: '/',
			httpOnly: true,
			secure: !dev,
			sameSite: 'lax',
			maxAge: 60 * 60 * 24 * 30
		});

		throw redirect(303, next);
	}

	throw redirect(303, '/benchmark?error=no_code');
};
