<script lang="ts">
	import { onMount } from 'svelte';
	import { initAnalytics } from '$lib/analytics';
	import { auth } from '$lib/stores/auth';

	let { children } = $props();
	let authLoading = $state(false);
	let isDark = $state(true);

	onMount(() => {
		initAnalytics();
		auth.initialize();

		// Check for saved theme or system preference
		const savedTheme = localStorage.getItem('theme');
		if (savedTheme) {
			isDark = savedTheme === 'dark';
		} else {
			isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
		}
		document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
	});

	function toggleTheme() {
		isDark = !isDark;
		const theme = isDark ? 'dark' : 'light';
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
	}

	async function handleGitHubLogin() {
		authLoading = true;
		try {
			await auth.signInWithGitHub();
		} catch (err) {
			console.error('GitHub login error:', err);
		} finally {
			authLoading = false;
		}
	}

	async function handleSignOut() {
		try {
			await auth.signOut();
		} catch (err) {
			console.error('Sign out error:', err);
		}
	}
</script>

<nav class="navbar">
	<div class="navbar-content">
		<a href="/" class="navbar-logo-link">
			<img src="/assets/images/logo.png" alt="vibeship" class="navbar-logo-img">
			<span class="navbar-logo-text">vibeship</span>
			<span class="navbar-logo-product">scanner</span>
		</a>
		<div class="navbar-right">
			<button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle theme">
				{#if isDark}
					<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<circle cx="12" cy="12" r="5"/>
						<line x1="12" y1="1" x2="12" y2="3"/>
						<line x1="12" y1="21" x2="12" y2="23"/>
						<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
						<line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
						<line x1="1" y1="12" x2="3" y2="12"/>
						<line x1="21" y1="12" x2="23" y2="12"/>
						<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
						<line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
					</svg>
				{:else}
					<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
					</svg>
				{/if}
			</button>
			{#if $auth.loading}
				<span class="navbar-auth-loading">...</span>
			{:else if $auth.user}
				<div class="navbar-auth-status">
					<span class="navbar-auth-badge">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
						</svg>
						Private repos
					</span>
					<button class="navbar-signout" onclick={handleSignOut}>Sign out</button>
				</div>
			{:else}
				<button class="navbar-github-btn" onclick={handleGitHubLogin} disabled={authLoading}>
					<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
						<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
					</svg>
					{authLoading ? 'Connecting...' : 'Sign in for private repos'}
				</button>
			{/if}
		</div>
	</div>
</nav>

<main>
	{@render children()}
</main>

<footer class="footer">
	<p class="footer-left">© 2025 vibeship</p>
	<div class="footer-right">
		<a href="/terms" class="footer-link">Terms</a>
		<a href="/privacy" class="footer-link">Privacy</a>
		<a href="https://x.com/vibeshipco" target="_blank" rel="noopener noreferrer" class="footer-x-btn" aria-label="Follow us on X">
			<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
				<path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
			</svg>
		</a>
	</div>
</footer>

<style>
	main {
		min-height: calc(100vh - 104px);
	}
</style>
