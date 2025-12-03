<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { supabase } from '$lib/supabase';

	let repoUrl = $state('');
	let loading = $state(false);
	let error = $state('');
	let recentScans = $state<Array<{
		id: string;
		target_url: string;
		score: number | null;
		grade: string | null;
		status: string;
		created_at: string;
	}>>([]);

	const tools = ['Claude Code', 'Cursor', 'Windsurf', 'Replit', 'GPT', 'Gemini'];
	let currentToolIndex = $state(0);

	$effect(() => {
		const interval = setInterval(() => {
			currentToolIndex = (currentToolIndex + 1) % tools.length;
		}, 2000);
		return () => clearInterval(interval);
	});

	onMount(async () => {
		const storedIds = localStorage.getItem('vibeship-recent-scans');
		if (storedIds) {
			const ids = JSON.parse(storedIds) as string[];
			if (ids.length > 0) {
				const { data } = await supabase
					.from('scans')
					.select('id, target_url, score, grade, status, created_at')
					.in('id', ids)
					.order('created_at', { ascending: false })
					.limit(5);
				if (data) {
					recentScans = data;
				}
			}
		}
	});

	function saveToRecent(scanId: string) {
		const stored = localStorage.getItem('vibeship-recent-scans');
		let ids: string[] = stored ? JSON.parse(stored) : [];
		ids = [scanId, ...ids.filter(id => id !== scanId)].slice(0, 10);
		localStorage.setItem('vibeship-recent-scans', JSON.stringify(ids));
	}

	function getRepoName(url: string): string {
		const match = url.match(/github\.com\/([\/\w.-]+)/);
		return match ? match[1] : url;
	}

	function getGradeClass(grade: string | null): string {
		if (!grade) return '';
		return `grade-${grade.toLowerCase()}`;
	}

	function formatDate(dateStr: string): string {
		const date = new Date(dateStr);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffMins = Math.floor(diffMs / 60000);
		const diffHours = Math.floor(diffMs / 3600000);
		const diffDays = Math.floor(diffMs / 86400000);

		if (diffMins < 1) return 'Just now';
		if (diffMins < 60) return `${diffMins}m ago`;
		if (diffHours < 24) return `${diffHours}h ago`;
		if (diffDays < 7) return `${diffDays}d ago`;
		return date.toLocaleDateString();
	}

	function normalizeUrl(url: string): string {
		let normalized = url.trim();
		if (/^[\w-]+\/[\w.-]+$/.test(normalized)) {
			normalized = `https://github.com/${normalized}`;
		}
		else if (/^github\.com\/[\w-]+\/[\w.-]+/.test(normalized)) {
			normalized = `https://${normalized}`;
		}
		else if (/^gitlab\.com\/[\w-]+\/[\w.-]+/.test(normalized)) {
			normalized = `https://${normalized}`;
		}
		return normalized.replace(/\/+$/, '');
	}

	function validateUrl(url: string): boolean {
		const githubPattern = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/;
		const gitlabPattern = /^https?:\/\/(www\.)?gitlab\.com\/[\w-]+\/[\w.-]+\/?$/;
		return githubPattern.test(url) || gitlabPattern.test(url);
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		error = '';

		if (!repoUrl.trim()) {
			error = 'Please enter a repository URL';
			return;
		}

		const normalizedUrl = normalizeUrl(repoUrl);

		if (!validateUrl(normalizedUrl)) {
			error = 'Please enter a valid GitHub or GitLab URL';
			return;
		}

		repoUrl = normalizedUrl;

		loading = true;

		try {
			const res = await fetch('/api/scan', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ url: repoUrl })
			});

			const data = await res.json();

			if (!res.ok) {
				throw new Error(data.message || 'Failed to start scan');
			}

			saveToRecent(data.scanId);
			goto(`/scan/${data.scanId}`);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Something went wrong';
			loading = false;
		}
	}
</script>

<div class="hero-wrapper">
	<section class="hero">
		<p class="hero-label">Free security scanner for vibe coders</p>
		<h1>
			{#key currentToolIndex}
				<span class="ai-rotate">You built it with <span class="ai-tool">{tools[currentToolIndex]}</span></span>
			{/key}<br>
			Let's make sure it's <em>secure</em>.
		</h1>
		<p class="hero-sub">
			Instant security scan for your AI-generated code. Find vulnerabilities, exposed secrets, and dependency issues before you ship.
		</p>

		<form class="scan-form" onsubmit={handleSubmit}>
			<div class="scan-input-wrapper">
				<svg class="scan-input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
				</svg>
				<input
					type="text"
					class="scan-input"
					placeholder="username/repo or https://github.com/username/repo"
					bind:value={repoUrl}
					disabled={loading}
				/>
				<button type="submit" class="btn btn-glow scan-btn" disabled={loading}>
					{#if loading}
						<span class="typing">
							<span></span>
							<span></span>
							<span></span>
						</span>
						Scanning...
					{:else}
						Scan Free
					{/if}
				</button>
			</div>
			{#if error}
				<p class="scan-error">{error}</p>
			{/if}
		</form>

		<p class="hero-note">Public repos only • No signup required • Results in ~30 seconds</p>

		{#if recentScans.length > 0}
			<div class="recent-scans">
				<p class="recent-label">Recent scans</p>
				<div class="recent-list">
					{#each recentScans as scan}
						<a href="/scan/{scan.id}" class="recent-item">
							<div class="recent-repo">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
								</svg>
								<span class="recent-name">{getRepoName(scan.target_url)}</span>
							</div>
							<div class="recent-meta">
								{#if scan.status === 'complete' && scan.grade}
									<span class="recent-grade {getGradeClass(scan.grade)}">{scan.grade}</span>
									<span class="recent-score">{scan.score}</span>
								{:else if scan.status === 'scanning' || scan.status === 'queued'}
									<span class="recent-status">Scanning...</span>
								{:else}
									<span class="recent-status">{scan.status}</span>
								{/if}
								<span class="recent-time">{formatDate(scan.created_at)}</span>
							</div>
						</a>
					{/each}
				</div>
			</div>
		{/if}
	</section>
</div>

<section class="features" id="features">
	<div class="features-inner">
		<p class="section-label">Security Analysis</p>
		<h2 class="section-title">What we scan</h2>
		<div class="features-grid">
			<div class="feature-card">
				<div class="feature-icon">🔐</div>
				<h3>Code Security</h3>
				<p>SQL injection, XSS, insecure auth patterns, and 500+ vulnerability checks using Semgrep.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">🔑</div>
				<h3>Exposed Secrets</h3>
				<p>API keys, database URLs, JWT secrets, and credentials that shouldn't be in your code.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">📦</div>
				<h3>Dependencies</h3>
				<p>Known CVEs in your npm, pip, or cargo packages with upgrade recommendations.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">🛡️</div>
				<h3>Authentication</h3>
				<p>Weak password policies, missing rate limiting, insecure session handling, and auth bypasses.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">🗄️</div>
				<h3>Database Security</h3>
				<p>NoSQL injection, ORM misuse, unparameterized queries, and data exposure risks.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">🌐</div>
				<h3>API Security</h3>
				<p>CORS misconfigurations, missing auth on endpoints, and insecure data serialization.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">📁</div>
				<h3>File Handling</h3>
				<p>Path traversal, unrestricted uploads, insecure file permissions, and directory exposure.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">⚡</div>
				<h3>Injection Attacks</h3>
				<p>Command injection, LDAP injection, template injection, and code execution vulnerabilities.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">🔒</div>
				<h3>Cryptography</h3>
				<p>Weak algorithms, hardcoded keys, improper random generation, and insecure hashing.</p>
			</div>
		</div>
	</div>
</section>

<section class="how" id="how">
	<div class="how-inner">
		<p class="section-label">Simple Process</p>
		<h2 class="section-title">How it works</h2>
		<div class="how-grid">
			<div class="how-step">
				<p class="how-step-number">01</p>
				<h4>Paste your repo URL</h4>
				<p>Public GitHub or GitLab repos. No signup, no OAuth, just paste and scan.</p>
			</div>
			<div class="how-step">
				<p class="how-step-number">02</p>
				<h4>We scan everything</h4>
				<p>Industry-standard security tools and vulnerability databases.</p>
			</div>
			<div class="how-step">
				<p class="how-step-number">03</p>
				<h4>Get actionable fixes</h4>
				<p>Every issue comes with copy-paste fixes tailored to your stack.</p>
			</div>
			<div class="how-step">
				<p class="how-step-number">04</p>
				<h4>Need help?</h4>
				<p>Our experts at Vibeship can fix everything for you.</p>
				<span class="how-coming-soon">Coming soon</span>
			</div>
		</div>
	</div>
</section>

<div class="cta-wrapper">
	<section class="cta">
		<div class="cta-inner">
			<h2>Ship secure, ship fast</h2>
			<p>Free security scans now. Expert help when you need it <span class="cta-coming-soon">(coming soon)</span>.</p>
			<button class="btn btn-glow btn-lg" onclick={() => document.querySelector<HTMLInputElement>('.scan-input')?.focus()}>
				Scan Your Repo Now
			</button>
		</div>
	</section>
</div>

<style>
	.hero-wrapper {
		position: relative;
		background: url('/assets/images/hero-bg.png') center center / cover no-repeat;
		background-color: var(--bg-primary);
	}

	.hero-wrapper::before {
		content: '';
		position: absolute;
		inset: 0;
		background: radial-gradient(ellipse at center, transparent 0%, var(--bg-primary) 70%);
		pointer-events: none;
	}

	.hero {
		position: relative;
		min-height: 80vh;
		display: flex;
		flex-direction: column;
		justify-content: center;
		padding: 8rem 3rem 4rem;
		max-width: 1000px;
		margin: 0 auto;
		text-align: center;
	}

	.hero-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.12em;
		color: var(--text-tertiary);
		margin-bottom: 2rem;
		font-weight: 500;
	}

	.hero h1 {
		font-family: 'Instrument Serif', serif;
		font-size: clamp(2.5rem, 6vw, 4rem);
		font-weight: 400;
		line-height: 1.1;
		letter-spacing: -0.03em;
	}

	.hero h1 em {
		font-style: italic;
	}

	.ai-rotate {
		display: inline-block;
		animation: fadeSwap 0.4s ease;
	}

	.ai-tool {
		color: var(--green-dim);
	}

	@keyframes fadeSwap {
		0% { opacity: 0; transform: translateY(10px); }
		100% { opacity: 1; transform: translateY(0); }
	}

	.hero-sub {
		margin-top: 2rem;
		font-size: 1rem;
		color: var(--text-secondary);
		max-width: 550px;
		margin-left: auto;
		margin-right: auto;
		line-height: 1.8;
	}

	.scan-form {
		margin-top: 3rem;
	}

	.scan-input-wrapper {
		display: flex;
		max-width: 600px;
		margin: 0 auto;
		border: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.scan-input-icon {
		width: 20px;
		height: 20px;
		margin: auto 1rem;
		color: var(--text-tertiary);
		flex-shrink: 0;
	}

	.scan-input {
		flex: 1;
		padding: 1rem 0;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.85rem;
		border: none;
		background: transparent;
		color: var(--text-primary);
		outline: none;
	}

	.scan-input::placeholder {
		color: var(--text-tertiary);
	}

	.scan-btn {
		border: none;
		border-left: 1px solid var(--border);
		padding: 1rem 2rem;
	}

	.scan-error {
		margin-top: 1rem;
		color: var(--red);
		font-size: 0.85rem;
	}

	.hero-note {
		margin-top: 2rem;
		font-size: 0.8rem;
		color: var(--text-tertiary);
	}

	.features {
		padding: 6rem 3rem;
		border-top: 1px solid var(--border);
	}

	.features-inner {
		max-width: 1200px;
		margin: 0 auto;
	}

	.features-inner .section-title {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		margin-bottom: 2.5rem;
		letter-spacing: -0.02em;
	}

	.features-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1px;
		background: var(--border);
		border: 1px solid var(--border);
	}

	.feature-card {
		background: var(--bg-primary);
		padding: 2.5rem;
		transition: all 0.3s;
	}

	.feature-card:hover {
		background: var(--bg-secondary);
	}

	.feature-icon {
		font-size: 2rem;
		margin-bottom: 1.5rem;
	}

	.feature-card h3 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 1rem;
	}

	.feature-card p {
		font-size: 0.85rem;
		color: var(--text-secondary);
		line-height: 1.7;
	}

	.how {
		padding: 6rem 3rem;
		background: var(--bg-inverse);
		color: var(--text-inverse);
	}

	.how-inner {
		max-width: 1200px;
		margin: 0 auto;
	}

	.how .section-label {
		color: var(--text-inverse-secondary);
	}

	.how .section-title {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		margin-bottom: 2.5rem;
		letter-spacing: -0.02em;
	}

	.how-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 2rem;
	}

	.how-step {
		border-left: 1px solid var(--text-inverse-secondary);
		padding-left: 1.5rem;
	}

	.how-step-number {
		font-size: 0.7rem;
		color: var(--text-inverse-secondary);
		margin-bottom: 1.5rem;
	}

	.how-step h4 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.25rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	.how-step p {
		font-size: 0.8rem;
		color: var(--text-inverse-secondary);
		line-height: 1.7;
	}

	.how-coming-soon {
		display: inline-block;
		margin-top: 0.75rem;
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--green-dim);
		border: 1px solid var(--green-dim);
		padding: 0.25rem 0.5rem;
	}

	.cta-wrapper {
		position: relative;
		background: url('/assets/images/hero-bg.png') center center / cover no-repeat;
		background-color: var(--bg-primary);
		border-top: 1px solid var(--border);
	}

	.cta-wrapper::before {
		content: '';
		position: absolute;
		inset: 0;
		background: radial-gradient(ellipse at center, transparent 0%, var(--bg-primary) 70%);
		pointer-events: none;
	}

	.cta {
		position: relative;
		padding: 8rem 3rem;
		text-align: center;
	}

	.cta-inner {
		max-width: 600px;
		margin: 0 auto;
	}

	.cta h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		margin-bottom: 1rem;
	}

	.cta p {
		font-size: 1rem;
		color: var(--text-secondary);
		margin-bottom: 2.5rem;
	}

	.cta-coming-soon {
		color: var(--text-tertiary);
		font-size: 0.85rem;
	}

	.btn-lg {
		padding: 1rem 2.5rem;
		font-size: 0.9rem;
	}

	.recent-scans {
		margin-top: 3rem;
	}

	.recent-label {
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--text-tertiary);
		margin-bottom: 1rem;
		text-align: center;
	}

	.recent-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-width: 500px;
		margin: 0 auto;
	}

	.recent-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem 1rem;
		border: 1px solid var(--border);
		background: var(--bg-primary);
		text-decoration: none;
		color: var(--text-primary);
		transition: all 0.15s;
	}

	.recent-item:hover {
		border-color: var(--green-dim);
		background: var(--bg-secondary);
	}

	.recent-repo {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.recent-repo svg {
		color: var(--text-tertiary);
	}

	.recent-name {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
	}

	.recent-meta {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.recent-grade {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 24px;
		height: 24px;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.recent-grade.grade-a { background: var(--green); color: white; }
	.recent-grade.grade-b { background: #84cc16; color: white; }
	.recent-grade.grade-c { background: var(--orange); color: var(--bg-inverse); }
	.recent-grade.grade-d { background: #f97316; color: white; }
	.recent-grade.grade-f { background: var(--red); color: white; }

	.recent-score {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.recent-status {
		font-size: 0.75rem;
		color: var(--text-tertiary);
	}

	.recent-time {
		font-size: 0.7rem;
		color: var(--text-tertiary);
	}

	@media (max-width: 1024px) {
		.features-grid {
			grid-template-columns: 1fr;
		}

		.how-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}

	@media (max-width: 768px) {
		.hero {
			padding: 6rem 1.5rem 3rem;
		}

		.scan-input-wrapper {
			flex-direction: column;
		}

		.scan-input-icon {
			display: none;
		}

		.scan-input {
			padding: 1rem;
			border-bottom: 1px solid var(--border);
		}

		.scan-btn {
			border-left: none;
		}

		.how-grid {
			grid-template-columns: 1fr;
		}

		.features,
		.how,
		.cta {
			padding: 4rem 1.5rem;
		}
	}
</style>
