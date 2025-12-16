<script lang="ts">
	import { goto, afterNavigate } from '$app/navigation';
	import { onMount } from 'svelte';
	import { supabase } from '$lib/supabase';
	import { auth } from '$lib/stores/auth';
	import { trackPageView, trackScanStarted, trackScanFailed, trackButtonClick, trackRecentScanClicked } from '$lib/analytics';

	let repoUrl = $state('');
	let loading = $state(false);
	let error = $state('');
	let authLoading = $state(false);
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

	const placeholders = [
		'your-startup/next-big-thing',
		'awesome-dev/side-project',
		'vibe-coder/ship-it-fast-and-secure',
		'founder/mvp-v1',
		'builder/always-be-building',
		'dev/agentic-saas'
	];
	let currentPlaceholderIndex = $state(0);

	$effect(() => {
		const interval = setInterval(() => {
			currentToolIndex = (currentToolIndex + 1) % tools.length;
		}, 2000);
		return () => clearInterval(interval);
	});

	$effect(() => {
		const interval = setInterval(() => {
			currentPlaceholderIndex = (currentPlaceholderIndex + 1) % placeholders.length;
		}, 15000);
		return () => clearInterval(interval);
	});

	async function loadRecentScans() {
		const storedIds = localStorage.getItem('vibeship-recent-scans');
		if (storedIds) {
			const ids = JSON.parse(storedIds) as string[];
			if (ids.length > 0) {
				const { data } = await supabase
					.from('scans')
					.select('id, target_url, score, grade, status, created_at')
					.in('id', ids)
					.order('created_at', { ascending: false })
					.limit(10);
				if (data) {
					// Sort by the order in localStorage (most recent first)
					const sortedData = ids
						.map(id => data.find(scan => scan.id === id))
						.filter((scan): scan is typeof data[0] => scan !== undefined)
						.slice(0, 10);
					recentScans = sortedData;
				}
			}
		}
	}

	// Refresh scans when navigating back to this page (e.g., after completing a scan)
	afterNavigate(() => {
		loadRecentScans();
	});

	onMount(async () => {
		trackPageView('Home');
		auth.initialize();
		await loadRecentScans();

		// Refresh scans when user returns to the tab
		const handleVisibilityChange = () => {
			if (document.visibilityState === 'visible') {
				loadRecentScans();
			}
		};

		document.addEventListener('visibilitychange', handleVisibilityChange);

		return () => {
			document.removeEventListener('visibilitychange', handleVisibilityChange);
		};
	});

	async function handleGitHubLogin() {
		authLoading = true;
		try {
			await auth.signInWithGitHub();
		} catch (err) {
			console.error('GitHub login error:', err);
			error = 'Failed to sign in with GitHub';
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
		trackScanStarted(repoUrl);

		try {
			// Get GitHub token if user is authenticated
			const githubToken = $auth.githubToken;
			console.log('Scan starting, hasGithubToken:', !!githubToken, 'user:', $auth.user?.email);

			const res = await fetch('/api/scan', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					url: repoUrl,
					githubToken: githubToken || undefined
				})
			});

			const data = await res.json();

			if (!res.ok) {
				throw new Error(data.message || 'Failed to start scan');
			}

			saveToRecent(data.scanId);
			goto(`/scan/${data.scanId}`);
		} catch (err) {
			const errorMessage = err instanceof Error ? err.message : 'Something went wrong';
			error = errorMessage;
			trackScanFailed(repoUrl, errorMessage);
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
					placeholder={placeholders[currentPlaceholderIndex]}
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

		<div class="hero-auth">
			{#if $auth.loading}
				<p class="hero-note">Loading...</p>
			{:else if $auth.user}
				<div class="auth-status">
					<span class="auth-badge">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
						</svg>
						Private repos enabled
					</span>
					<button class="auth-signout" onclick={handleSignOut}>Sign out</button>
				</div>
			{:else}
				<p class="hero-note">Public repos • No signup required</p>
				<button class="github-login-btn" onclick={handleGitHubLogin} disabled={authLoading}>
					<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
						<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
					</svg>
					{authLoading ? 'Connecting...' : 'Sign in with GitHub for private repos'}
				</button>
			{/if}
		</div>

		{#if recentScans.length > 0}
			<div class="recent-scans">
				<p class="recent-label">Recent scans</p>
				<div class="recent-list">
					{#each recentScans as scan}
						<a href="/scan/{scan.id}" class="recent-item" onclick={() => trackRecentScanClicked(scan.target_url)}>
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
									<span class="recent-scanning">
										<span class="scan-pulse"></span>
										Scanning
									</span>
								{:else if scan.status === 'failed'}
									<span class="recent-failed">Failed</span>
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

<section class="ai-fix" id="ai-fix">
	<div class="ai-fix-inner">
		<p class="section-label">Built for Vibe Coders</p>
		<h2 class="section-title">AI-Ready Fix Prompts</h2>
		<p class="ai-fix-subtitle">You built it with AI. Fix it with AI.</p>

		<div class="ai-fix-flow-wrapper">
			<div class="ai-fix-flow">
				<div class="ai-fix-step">
					<div class="ai-fix-step-icon">
						<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
							<circle cx="11" cy="11" r="8"/>
							<path d="m21 21-4.35-4.35"/>
						</svg>
					</div>
					<div class="ai-fix-step-content">
						<h4>Scan finds issues</h4>
						<p>SQL injection, XSS, exposed secrets — we catch it all</p>
					</div>
				</div>
				<div class="ai-fix-arrow">
					<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M5 12h14M12 5l7 7-7 7"/>
					</svg>
				</div>
				<div class="ai-fix-step">
					<div class="ai-fix-step-icon">
						<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
							<rect x="8" y="2" width="8" height="4" rx="1"/>
							<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
							<path d="M12 11h4M12 16h4M8 11h.01M8 16h.01"/>
						</svg>
					</div>
					<div class="ai-fix-step-content">
						<h4>Get the fix prompt</h4>
						<p>One-click copy with file, line, and exact fix instructions</p>
					</div>
				</div>
				<div class="ai-fix-arrow">
					<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M5 12h14M12 5l7 7-7 7"/>
					</svg>
				</div>
				<div class="ai-fix-step">
					<div class="ai-fix-step-icon">
						<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
							<path d="M12 8V4H8"/>
							<rect x="2" y="2" width="20" height="20" rx="5"/>
							<path d="M8 4l4 4-4 4"/>
							<path d="m16 12-4 4 4 4"/>
						</svg>
					</div>
					<div class="ai-fix-step-content">
						<h4>Paste to your AI</h4>
						<p>Claude, Cursor, ChatGPT, Gemini — they all understand it</p>
					</div>
				</div>
			</div>
		</div>

		<div class="ai-fix-demo">
			<div class="ai-fix-demo-header">
				<span class="ai-fix-demo-label">Example AI Fix Prompt</span>
				<span class="ai-fix-demo-badge">Copy & Paste Ready</span>
			</div>
			<div class="ai-fix-demo-content">
				<pre><code><span class="prompt-title"># Security Fix Guide</span>

<span class="prompt-meta">I need help fixing <span class="prompt-highlight">12 security vulnerabilities</span> in my codebase.</span>

<span class="prompt-stats">Severity: 2 Critical | 5 High | 4 Medium | 1 Low</span>
<span class="prompt-stats">Quick Wins: 4 issues can be fixed with simple changes</span>

<span class="prompt-section">## SQL Injection</span>

<span class="prompt-location">- `src/db/users.js:45` [HIGH] SQL query uses string concatenation</span>
<span class="prompt-location">- `src/api/search.js:23` [HIGH] Unparameterized query</span>

<span class="prompt-fix">**How to Fix:**
Replace string concatenation with parameterized queries:

```javascript
// Vulnerable
db.query("SELECT * FROM users WHERE id = " + userId)

// Fixed
db.query("SELECT * FROM users WHERE id = $1", [userId])
```</span></code></pre>
			</div>
		</div>

		<div class="ai-fix-features">
			<div class="ai-fix-feature">
				<svg class="ai-fix-feature-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
					<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
				</svg>
				<span>Quick wins marked for easy fixes</span>
			</div>
			<div class="ai-fix-feature">
				<svg class="ai-fix-feature-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
					<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/>
					<circle cx="12" cy="10" r="3"/>
				</svg>
				<span>Exact file and line numbers</span>
			</div>
			<div class="ai-fix-feature">
				<svg class="ai-fix-feature-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
					<polyline points="16 18 22 12 16 6"/>
					<polyline points="8 6 2 12 8 18"/>
				</svg>
				<span>Before/after code examples</span>
			</div>
			<div class="ai-fix-feature">
				<svg class="ai-fix-feature-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
					<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
					<polyline points="22 4 12 14.01 9 11.01"/>
				</svg>
				<span>Severity-ordered for priority</span>
			</div>
		</div>
	</div>
</section>

<section class="features" id="features">
	<div class="features-inner">
		<p class="section-label">Security Analysis</p>
		<h2 class="section-title">What we scan</h2>
		<div class="features-grid">
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<rect x="3" y="11" width="18" height="11" rx="2"/>
						<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
					</svg>
				</div>
				<h3>Code Security</h3>
				<p>SQL injection, XSS, insecure auth patterns, and 2000+ vulnerability checks using Semgrep.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>
					</svg>
				</div>
				<h3>Exposed Secrets</h3>
				<p>API keys, database URLs, JWT secrets, and credentials that shouldn't be in your code.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
						<polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
						<line x1="12" y1="22.08" x2="12" y2="12"/>
					</svg>
				</div>
				<h3>Dependencies</h3>
				<p>Known CVEs in your npm, pip, or cargo packages with upgrade recommendations.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
					</svg>
				</div>
				<h3>Authentication</h3>
				<p>Weak password policies, missing rate limiting, insecure session handling, and auth bypasses.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<ellipse cx="12" cy="5" rx="9" ry="3"/>
						<path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
						<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
					</svg>
				</div>
				<h3>Database Security</h3>
				<p>NoSQL injection, ORM misuse, unparameterized queries, and data exposure risks.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<circle cx="12" cy="12" r="10"/>
						<line x1="2" y1="12" x2="22" y2="12"/>
						<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
					</svg>
				</div>
				<h3>API Security</h3>
				<p>CORS misconfigurations, missing auth on endpoints, and insecure data serialization.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
						<polyline points="14 2 14 8 20 8"/>
					</svg>
				</div>
				<h3>File Handling</h3>
				<p>Path traversal, unrestricted uploads, insecure file permissions, and directory exposure.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
					</svg>
				</div>
				<h3>Injection Attacks</h3>
				<p>Command injection, LDAP injection, template injection, and code execution vulnerabilities.</p>
			</div>
			<div class="feature-card">
				<div class="feature-icon">
					<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
						<rect x="3" y="11" width="18" height="11" rx="2"/>
						<path d="M7 11V7a5 5 0 0 1 9.9-1"/>
						<circle cx="12" cy="16" r="1"/>
					</svg>
				</div>
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
				<h4>Ship the fix</h4>
				<p>Get clear recommendations for each issue, or just point your AI to it and let it cook.</p>
			</div>
		</div>
	</div>
</section>

<div class="cta-wrapper">
	<section class="cta">
		<div class="cta-inner">
			<h2>Ready to ship with confidence?</h2>
			<p>Free. No signup required.</p>
			<button class="btn btn-glow btn-lg" onclick={() => { trackButtonClick('CTA Scan Now'); document.querySelector<HTMLInputElement>('.scan-input')?.focus(); }}>
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
		font-size: 1rem;
		border: none;
		background: transparent;
		color: var(--text-primary);
		outline: none;
		-webkit-appearance: none;
		border-radius: 0;
	}

	.scan-input::placeholder {
		color: var(--text-tertiary);
		transition: opacity 0.3s ease;
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

	.hero-auth {
		margin-top: 1.5rem;
	}

	.github-login-link {
		background: none;
		border: none;
		color: var(--green);
		cursor: pointer;
		font-size: 0.8rem;
		text-decoration: underline;
		margin-left: 0.5rem;
		padding: 0;
	}

	.github-login-link:hover {
		opacity: 0.8;
	}

	.github-login-link:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.github-login-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		margin-top: 0.75rem;
		padding: 0.6rem 1.25rem;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		font-size: 0.9rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.github-login-btn:hover {
		border-color: var(--green-dim);
		color: var(--text-primary);
	}

	.github-login-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.github-login-btn svg {
		fill: currentColor;
	}

	.auth-status {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		font-size: 0.85rem;
	}

	.auth-badge {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		background: rgba(0, 196, 154, 0.1);
		color: var(--green);
		padding: 0.5rem 1rem;
		border-radius: 20px;
		font-weight: 500;
	}

	.auth-badge svg {
		fill: currentColor;
	}

	.auth-signout {
		background: none;
		border: 1px solid var(--border-primary);
		color: var(--text-secondary);
		padding: 0.5rem 1rem;
		border-radius: 20px;
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.auth-signout:hover {
		border-color: var(--text-tertiary);
		color: var(--text-primary);
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
		margin-bottom: 1.5rem;
		color: var(--text-primary);
	}

	.feature-icon svg {
		display: block;
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
		grid-template-columns: repeat(3, 1fr);
		gap: 2rem;
	}

	.how-step {
		border-left: 1px solid var(--text-inverse-secondary);
		padding-left: 2rem;
	}

	.how-step-number {
		font-size: 1rem;
		font-weight: 600;
		color: var(--text-inverse-secondary);
		margin-bottom: 1.5rem;
		font-family: 'JetBrains Mono', monospace;
	}

	.how-step h4 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	.how-step p {
		font-size: 0.9rem;
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
		min-width: 140px;
		justify-content: flex-end;
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
		min-width: 24px;
		text-align: right;
	}

	.recent-status {
		font-size: 0.75rem;
		color: var(--text-tertiary);
	}

	.recent-scanning {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.75rem;
		color: var(--green-dim);
		font-family: 'JetBrains Mono', monospace;
	}

	.scan-pulse {
		width: 8px;
		height: 8px;
		background: var(--green-dim);
		border-radius: 50%;
		animation: pulse 1.5s ease-in-out infinite;
	}

	@keyframes pulse {
		0%, 100% {
			opacity: 1;
			transform: scale(1);
		}
		50% {
			opacity: 0.4;
			transform: scale(0.8);
		}
	}

	.recent-failed {
		font-size: 0.75rem;
		color: var(--red);
		font-family: 'JetBrains Mono', monospace;
	}

	.recent-time {
		font-size: 0.7rem;
		color: var(--text-tertiary);
		min-width: 50px;
		text-align: right;
	}

	/* AI Fix Section */
	.ai-fix {
		padding: 6rem 3rem;
		border-top: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.ai-fix-inner {
		max-width: 1000px;
		margin: 0 auto;
	}

	.ai-fix .section-title {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		margin-bottom: 0.5rem;
		letter-spacing: -0.02em;
	}

	.ai-fix-subtitle {
		font-size: 1.1rem;
		color: var(--text-secondary);
		margin-bottom: 3rem;
	}

	.ai-fix-flow-wrapper {
		background: var(--bg-inverse);
		padding: 2.5rem 2rem;
		margin-bottom: 3rem;
	}

	.ai-fix-flow {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1.5rem;
	}

	.ai-fix-step {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		flex: 1;
		max-width: 250px;
	}

	.ai-fix-step-icon {
		flex-shrink: 0;
		color: var(--text-inverse);
	}

	.ai-fix-step-icon svg {
		display: block;
	}

	.ai-fix-step-content h4 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.25rem;
		font-weight: 400;
		margin-bottom: 0.5rem;
		color: var(--text-inverse);
	}

	.ai-fix-step-content p {
		font-size: 0.85rem;
		color: var(--text-inverse-secondary);
		line-height: 1.6;
	}

	.ai-fix-arrow {
		color: var(--text-inverse-secondary);
		flex-shrink: 0;
	}

	.ai-fix-arrow svg {
		display: block;
	}

	.ai-fix-demo {
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		margin-bottom: 2.5rem;
		overflow: hidden;
	}

	.ai-fix-demo-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem 1.25rem;
		border-bottom: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.ai-fix-demo-label {
		font-size: 0.8rem;
		font-weight: 500;
		color: var(--text-secondary);
	}

	.ai-fix-demo-badge {
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--green);
		background: rgba(0, 196, 154, 0.1);
		padding: 0.25rem 0.75rem;
		border-radius: 20px;
	}

	.ai-fix-demo-content {
		padding: 1.5rem;
		overflow-x: auto;
	}

	.ai-fix-demo-content pre {
		margin: 0;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		line-height: 1.7;
		white-space: pre-wrap;
		word-break: break-word;
	}

	.ai-fix-demo-content code {
		color: var(--text-secondary);
	}

	.prompt-title {
		color: var(--text-primary);
		font-weight: 600;
		font-size: 0.9rem;
	}

	.prompt-meta {
		color: var(--text-secondary);
	}

	.prompt-highlight {
		color: var(--green);
		font-weight: 500;
	}

	.prompt-stats {
		color: var(--text-tertiary);
		font-size: 0.75rem;
	}

	.prompt-section {
		color: var(--red);
		font-weight: 600;
		margin-top: 0.5rem;
	}

	.prompt-location {
		color: var(--text-secondary);
		font-size: 0.75rem;
	}

	.prompt-fix {
		color: var(--text-tertiary);
		font-size: 0.75rem;
	}

	.ai-fix-features {
		display: flex;
		justify-content: center;
		flex-wrap: wrap;
		gap: 1.5rem 2.5rem;
	}

	.ai-fix-feature {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.9rem;
		color: var(--text-secondary);
	}

	.ai-fix-feature-icon {
		color: var(--text-primary);
	}

	@media (max-width: 1024px) {
		.features-grid {
			grid-template-columns: 1fr;
		}

		.how-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.ai-fix-flow {
			flex-wrap: wrap;
			gap: 2rem;
		}

		.ai-fix-arrow {
			display: none;
		}

		.ai-fix-step {
			max-width: 100%;
			flex-basis: calc(50% - 1rem);
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
			padding: 1rem;
			font-size: 1rem;
		}

		.how-grid {
			grid-template-columns: 1fr;
		}

		.features,
		.how,
		.cta,
		.ai-fix {
			padding: 4rem 1.5rem;
		}

		.ai-fix .section-title {
			font-size: 2rem;
		}

		.ai-fix-subtitle {
			font-size: 1rem;
			margin-bottom: 2rem;
		}

		.ai-fix-flow-wrapper {
			padding: 2rem 1.5rem;
			margin-left: -1.5rem;
			margin-right: -1.5rem;
			margin-bottom: 2rem;
		}

		.ai-fix-flow {
			flex-direction: column;
			align-items: stretch;
			gap: 1.5rem;
		}

		.ai-fix-step {
			flex-basis: 100%;
			max-width: 100%;
		}

		.ai-fix-step-icon svg {
			width: 24px;
			height: 24px;
		}

		.ai-fix-step-content h4 {
			font-size: 1.1rem;
		}

		.ai-fix-demo-content {
			padding: 1rem;
		}

		.ai-fix-demo-content pre {
			font-size: 0.7rem;
			line-height: 1.6;
		}

		.ai-fix-features {
			flex-direction: column;
			align-items: flex-start;
			gap: 1rem;
		}

		.ai-fix-feature {
			font-size: 0.85rem;
		}

		.recent-list {
			max-width: 100%;
		}

		.recent-item {
			padding: 0.75rem;
		}

		.recent-name {
			font-size: 0.75rem;
			max-width: 150px;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}

		.recent-meta {
			min-width: auto;
			gap: 0.5rem;
		}

		.recent-time {
			display: none;
		}
	}
</style>
