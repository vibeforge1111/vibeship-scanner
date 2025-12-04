<script lang="ts">
	import { onMount } from 'svelte';
	import { initAnalytics } from '$lib/analytics';

	let { children } = $props();

	onMount(() => {
		initAnalytics();
	});
</script>

<nav class="navbar">
	<a href="/" class="navbar-logo-link">
		<img src="/assets/images/logo.png" alt="vibeship" class="navbar-logo-img">
		<span class="navbar-logo-text">vibeship</span>
		<span class="navbar-logo-text" style="color: var(--green-dim); margin-left: 0.25rem;">scanner</span>
	</a>
	<a href="https://x.com/vibeshipco" target="_blank" rel="noopener noreferrer" class="navbar-x-btn" aria-label="Follow us on X">
		<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
			<path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
		</svg>
	</a>
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
		min-height: calc(100vh - 160px);
	}
</style>
