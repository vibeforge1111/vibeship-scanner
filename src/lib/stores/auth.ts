import { writable } from 'svelte/store';
import { supabase } from '$lib/supabase';
import type { User, Session } from '@supabase/supabase-js';

interface AuthState {
	user: User | null;
	session: Session | null;
	githubToken: string | null;
	loading: boolean;
}

const GITHUB_TOKEN_KEY = 'vibeship_github_token';

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
			console.log('[Auth] Initializing...');
			const { data: { session } } = await supabase.auth.getSession();
			console.log('[Auth] Session:', session ? 'exists' : 'null', 'provider_token:', session?.provider_token ? 'exists' : 'null');

			if (session) {
				// Try to get token from session first, then fall back to localStorage
				let githubToken = session.provider_token || null;
				const storedToken = localStorage.getItem(GITHUB_TOKEN_KEY);
				console.log('[Auth] Token from session:', !!githubToken, 'Token from localStorage:', !!storedToken);

				if (githubToken) {
					// New token from OAuth - store it
					localStorage.setItem(GITHUB_TOKEN_KEY, githubToken);
					console.log('[Auth] Stored new token to localStorage');
				} else {
					// Try to retrieve stored token
					githubToken = storedToken;
					console.log('[Auth] Using stored token from localStorage');
				}

				console.log('[Auth] Final githubToken:', !!githubToken);
				set({
					user: session.user,
					session,
					githubToken,
					loading: false
				});
			} else {
				// No session - clear stored token
				console.log('[Auth] No session, clearing token');
				localStorage.removeItem(GITHUB_TOKEN_KEY);
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
					let githubToken = session.provider_token || null;

					if (githubToken) {
						// New token from OAuth - store it
						localStorage.setItem(GITHUB_TOKEN_KEY, githubToken);
					} else {
						// Try to retrieve stored token
						githubToken = localStorage.getItem(GITHUB_TOKEN_KEY);
					}

					set({
						user: session.user,
						session,
						githubToken,
						loading: false
					});
				} else {
					// Signed out - clear stored token
					localStorage.removeItem(GITHUB_TOKEN_KEY);
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
			// Clear stored GitHub token
			localStorage.removeItem(GITHUB_TOKEN_KEY);
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
