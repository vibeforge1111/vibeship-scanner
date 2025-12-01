<script lang="ts">
	let { children } = $props();
</script>

<nav class="navbar">
	<a href="/" class="navbar-logo-link">
		<img src="/assets/images/logo.png" alt="vibeship" class="navbar-logo-img">
		<span class="navbar-logo-text">vibeship</span>
		<span style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--green-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-left: 0.5rem;">scanner</span>
	</a>
	<div class="nav-links">
		<a href="https://vibeship.com">Back to Vibeship</a>
		<a href="/" class="btn btn-green">Scan Now</a>
	</div>
</nav>

<main>
	{@render children()}
</main>

<footer class="footer">
	<p class="footer-left">© 2025 vibeship</p>
	<div class="footer-links">
		<a href="https://twitter.com/vibeship">Twitter</a>
		<a href="https://vibeship.com">Vibeship</a>
	</div>
</footer>

<style>
	main {
		min-height: calc(100vh - 160px);
	}
</style>
