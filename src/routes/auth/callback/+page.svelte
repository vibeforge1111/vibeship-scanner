<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { supabase } from '$lib/supabase';
	import { auth } from '$lib/stores/auth';

	let message = $state('Completing sign in...');

	onMount(async () => {
		// Handle the OAuth callback
		const { data, error } = await supabase.auth.getSession();

		if (error) {
			message = 'Sign in failed. Redirecting...';
			console.error('Auth callback error:', error);
			setTimeout(() => goto('/'), 2000);
			return;
		}

		if (data.session) {
			message = 'Sign in successful! Redirecting...';
			// Store the GitHub token for private repo cloning
			if (data.session.provider_token) {
				localStorage.setItem('vibeship_github_token', data.session.provider_token);
				console.log('GitHub token stored');
			}
			// Initialize auth store to pick up the new session
			await auth.initialize();
			setTimeout(() => goto('/'), 500);
		} else {
			message = 'No session found. Redirecting...';
			setTimeout(() => goto('/'), 1000);
		}
	});
</script>

<div class="callback-container">
	<div class="callback-card">
		<div class="spinner"></div>
		<p>{message}</p>
	</div>
</div>

<style>
	.callback-container {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-primary, #0a0a0a);
	}

	.callback-card {
		text-align: center;
		padding: 2rem;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--bg-secondary, #1a1a1a);
		border-top-color: var(--green, #00c49a);
		border-radius: 50%;
		animation: spin 1s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	p {
		color: var(--text-secondary, #888);
	}
</style>
