<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';

	let status = $state<'loading' | 'need_auth' | 'authenticating' | 'success' | 'error' | 'expired'>('loading');
	let error = $state('');

	const token = $page.params.token;

	onMount(async () => {
		await auth.initialize();

		// Check if token is valid first
		const checkRes = await fetch(`/api/auth/device/poll?token=${token}`);
		const checkData = await checkRes.json();

		if (checkData.status === 'expired' || checkData.error) {
			status = 'expired';
			return;
		}

		if (checkData.status === 'authenticated' || checkData.status === 'used') {
			status = 'success';
			return;
		}

		// Token is pending - check if user is logged in
		auth.subscribe(async (state) => {
			if (state.loading) return;

			if (!state.user) {
				status = 'need_auth';
			} else if (state.githubToken) {
				// User is logged in with GitHub token - complete the auth
				status = 'authenticating';
				await completeAuth(state.githubToken);
			} else {
				// Logged in but no GitHub token - need to re-auth
				status = 'need_auth';
			}
		});
	});

	async function completeAuth(githubToken: string) {
		try {
			const res = await fetch(`/api/auth/device/complete`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ token, githubToken })
			});

			if (res.ok) {
				status = 'success';
			} else {
				const data = await res.json();
				error = data.error || 'Failed to complete authentication';
				status = 'error';
			}
		} catch (e) {
			error = 'Failed to complete authentication';
			status = 'error';
		}
	}

	async function handleLogin() {
		try {
			// Store the device token so callback can complete the auth
			localStorage.setItem('pending_device_auth', token);
			await auth.signInWithGitHub();
		} catch (e) {
			error = 'Failed to sign in with GitHub';
			status = 'error';
		}
	}
</script>

<svelte:head>
	<title>Authenticate - Vibeship Scanner</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<img src="/assets/images/logo.png" alt="vibeship" class="auth-logo" />

		{#if status === 'loading'}
			<h1>Loading...</h1>
		{:else if status === 'expired'}
			<h1>Link Expired</h1>
			<p>This authentication link has expired. Please try again from your IDE.</p>
		{:else if status === 'need_auth'}
			<h1>Authenticate Scanner</h1>
			<p>Sign in with GitHub to enable private repo scanning in your IDE.</p>
			<button class="github-btn" onclick={handleLogin}>
				<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
					<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
				</svg>
				Sign in with GitHub
			</button>
		{:else if status === 'authenticating'}
			<h1>Authenticating...</h1>
			<div class="spinner"></div>
			<p>Completing authentication...</p>
		{:else if status === 'success'}
			<div class="success-icon">
				<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
					<polyline points="22 4 12 14.01 9 11.01"/>
				</svg>
			</div>
			<h1>Authenticated!</h1>
			<p>You can close this tab and return to your IDE.</p>
			<p class="hint">Private repo scanning is now enabled.</p>
		{:else if status === 'error'}
			<h1>Error</h1>
			<p class="error-text">{error}</p>
			<button class="retry-btn" onclick={() => location.reload()}>Try Again</button>
		{/if}
	</div>
</div>

<style>
	.auth-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}

	.auth-container {
		text-align: center;
		max-width: 400px;
	}

	.auth-logo {
		width: 64px;
		height: 64px;
		margin-bottom: 2rem;
	}

	h1 {
		font-family: 'Instrument Serif', serif;
		font-size: 2rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	p {
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
	}

	.github-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem 2rem;
		background: var(--text-primary);
		color: var(--bg-primary);
		border: none;
		font-size: 1rem;
		font-weight: 500;
		cursor: pointer;
		transition: opacity 0.15s;
	}

	.github-btn:hover {
		opacity: 0.9;
	}

	.success-icon {
		color: var(--green);
		margin-bottom: 1rem;
	}

	.hint {
		font-size: 0.85rem;
		color: var(--text-tertiary);
	}

	.error-text {
		color: var(--red);
	}

	.retry-btn {
		padding: 0.75rem 1.5rem;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.retry-btn:hover {
		border-color: var(--text-primary);
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--border);
		border-top-color: var(--green);
		border-radius: 50%;
		margin: 1rem auto;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}
</style>
