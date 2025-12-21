import { createClient } from '@supabase/supabase-js';
import { SUPABASE_SERVICE_ROLE_KEY } from '$env/static/private';
import type { Database } from '$lib/types/database';

const SUPABASE_URL = 'https://kgxjubeaddrocooklyib.supabase.co';

export function createServerSupabase() {
	return createClient<Database>(
		SUPABASE_URL,
		SUPABASE_SERVICE_ROLE_KEY,
		{
			auth: {
				autoRefreshToken: false,
				persistSession: false
			}
		}
	);
}
