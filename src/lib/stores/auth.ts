import { writable } from 'svelte/store';
import { supabase } from '$lib/supabase';
import type { User, Session } from '@supabase/supabase-js';

interface AuthState {
	user: User | null;
	session: Session | null;
	githubToken: string | null;
	loading: boolean;
}

function createAuthStore() {
	const { subscribe, set, update } = writable<AuthState>({
		user: null,
		session: null,
		githubToken: null,
		loading: true
	});

	return {
		subscribe,

		async initialize() {
			const { data: { session } } = await supabase.auth.getSession();

			if (session) {
				const githubToken = session.provider_token || null;
				set({
					user: session.user,
					session,
					githubToken,
					loading: false
				});
			} else {
				set({
					user: null,
					session: null,
					githubToken: null,
					loading: false
				});
			}

			// Listen for auth changes
			supabase.auth.onAuthStateChange(async (event, session) => {
				if (session) {
					const githubToken = session.provider_token || null;
					set({
						user: session.user,
						session,
						githubToken,
						loading: false
					});
				} else {
					set({
						user: null,
						session: null,
						githubToken: null,
						loading: false
					});
				}
			});
		},

		async signInWithGitHub() {
			const { error } = await supabase.auth.signInWithOAuth({
				provider: 'github',
				options: {
					scopes: 'repo read:user',
					redirectTo: `${window.location.origin}/auth/callback`
				}
			});

			if (error) {
				console.error('GitHub sign in error:', error);
				throw error;
			}
		},

		async signOut() {
			const { error } = await supabase.auth.signOut();
			if (error) {
				console.error('Sign out error:', error);
				throw error;
			}
			set({
				user: null,
				session: null,
				githubToken: null,
				loading: false
			});
		}
	};
}

export const auth = createAuthStore();
