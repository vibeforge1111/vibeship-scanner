import type { PageServerLoad } from './$types';
import { createClient } from '@supabase/supabase-js';
import { env } from '$env/dynamic/private';
import { PUBLIC_SUPABASE_URL, PUBLIC_SUPABASE_ANON_KEY } from '$env/static/public';

const ALLOWED_GITHUB_USERS = ['vibeforge1111'];

export const load: PageServerLoad = async ({ cookies }) => {
	const supabaseUrl = PUBLIC_SUPABASE_URL || env.VITE_SUPABASE_URL;
	const supabaseKey = PUBLIC_SUPABASE_ANON_KEY || env.VITE_SUPABASE_ANON_KEY;

	if (!supabaseUrl || !supabaseKey) {
		return { authenticated: false, user: null };
	}

	const accessToken = cookies.get('sb-access-token');
	const refreshToken = cookies.get('sb-refresh-token');

	if (!accessToken) {
		return { authenticated: false, user: null };
	}

	const supabase = createClient(supabaseUrl, supabaseKey);

	try {
		const { data: { user }, error } = await supabase.auth.getUser(accessToken);

		if (error || !user) {
			return { authenticated: false, user: null };
		}

		// Get GitHub username from user metadata
		const githubUsername = user.user_metadata?.user_name ||
		                       user.user_metadata?.preferred_username ||
		                       user.identities?.find(i => i.provider === 'github')?.identity_data?.user_name;

		if (!githubUsername || !ALLOWED_GITHUB_USERS.includes(githubUsername)) {
			return { authenticated: false, user: null, denied: true, username: githubUsername };
		}

		return {
			authenticated: true,
			user: {
				username: githubUsername,
				avatar: user.user_metadata?.avatar_url
			}
		};
	} catch (e) {
		console.error('Auth error:', e);
		return { authenticated: false, user: null };
	}
};
