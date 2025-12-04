<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	const SCANNER_URL = 'https://scanner-empty-field-5676.fly.dev';
	const BENCHMARK_SECRET = 'vibeship-benchmark-2024';
	const ACCESS_PASSWORD = 'vibeship-admin-2024';

	let isAuthenticated = $state(false);
	let password = $state('');
	let loginError = $state('');

	onMount(() => {
		// Check if already authenticated via localStorage
		const stored = localStorage.getItem('benchmark_auth');
		if (stored === ACCESS_PASSWORD) {
			isAuthenticated = true;
		}
	});

	function login() {
		if (password === ACCESS_PASSWORD) {
			localStorage.setItem('benchmark_auth', password);
			isAuthenticated = true;
			loginError = '';
		} else {
			loginError = 'Invalid password';
		}
	}

	function logout() {
		localStorage.removeItem('benchmark_auth');
		isAuthenticated = false;
	}

	type BenchmarkRepo = {
		repo: string;
		name: string;
		language: string;
		vuln_count: number;
	};

	type RepoResult = {
		repo: string;
		name: string;
		language: string;
		status: 'pending' | 'scanning' | 'complete' | 'error';
		coverage: number;
		detected: number;
		total: number;
		findings: number;
		detected_vulns: string[];
		missed_vulns: string[];
		error?: string;
		improved_from?: number;
	};

	type BenchmarkHistory = {
		timestamp: string;
		overall_coverage: number;
		total_detected: number;
		total_known: number;
		rules_added: number;
	};

	let repos = $state<BenchmarkRepo[]>([]);
	let results = $state<Map<string, RepoResult>>(new Map());
	let overallCoverage = $state(0);
	let targetCoverage = $state(95);
	let isRunning = $state(false);
	let currentRepo = $state<string | null>(null);
	let iteration = $state(0);
	let history = $state<BenchmarkHistory[]>([]);
	let autoRefresh = $state(true);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;
	let error = $state<string | null>(null);
	let jobId = $state<string | null>(null);
	let rulesAdded = $state(0);
	let totalDetected = $state(0);
	let totalKnown = $state(0);

	async function loadRepos() {
		try {
			const res = await fetch(`${SCANNER_URL}/benchmark/repos`);
			const data = await res.json();
			repos = data.repos || [];

			// Initialize results map
			repos.forEach(repo => {
				if (!results.has(repo.repo)) {
					results.set(repo.repo, {
						repo: repo.repo,
						name: repo.name,
						language: repo.language,
						status: 'pending',
						coverage: 0,
						detected: 0,
						total: repo.vuln_count,
						findings: 0,
						detected_vulns: [],
						missed_vulns: []
					});
				}
			});
			results = new Map(results);
		} catch (e) {
			console.error('Failed to load repos:', e);
			error = 'Failed to load benchmark repos';
		}
	}

	async function scanSingleRepo(repoName: string) {
		const result = results.get(repoName);
		if (!result) return;

		result.status = 'scanning';
		results = new Map(results);
		currentRepo = repoName;

		try {
			const res = await fetch(`${SCANNER_URL}/benchmark/scan-single`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-Benchmark-Key': BENCHMARK_SECRET
				},
				body: JSON.stringify({ repo: repoName })
			});

			const data = await res.json();

			if (data.error) {
				result.status = 'error';
				result.error = data.error;
			} else if (data.result) {
				const r = data.result;
				const previousCoverage = result.coverage;
				result.status = 'complete';
				result.coverage = (r.coverage || 0) * 100;
				result.detected = r.detected_count || 0;
				result.total = (r.detected_count || 0) + (r.missed_count || 0);
				result.findings = r.total_findings || 0;
				result.detected_vulns = (r.detected || []).map((v: any) => v.id);
				result.missed_vulns = (r.missed || []).map((v: any) => v.id);

				if (previousCoverage > 0 && result.coverage > previousCoverage) {
					result.improved_from = previousCoverage;
				}
			}
		} catch (e) {
			result.status = 'error';
			result.error = String(e);
		}

		results = new Map(results);
		currentRepo = null;
		updateOverallCoverage();
	}

	async function runFullBenchmark() {
		isRunning = true;
		iteration++;
		error = null;

		for (const repo of repos) {
			if (!isRunning) break;
			await scanSingleRepo(repo.repo);
		}

		// Save to history
		history = [...history, {
			timestamp: new Date().toISOString(),
			overall_coverage: overallCoverage,
			total_detected: totalDetected,
			total_known: totalKnown,
			rules_added: rulesAdded
		}];

		isRunning = false;
	}

	async function startAutoImprove() {
		isRunning = true;
		error = null;

		try {
			const res = await fetch(`${SCANNER_URL}/benchmark/auto-improve`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-Benchmark-Key': BENCHMARK_SECRET
				},
				body: JSON.stringify({
					target_coverage: targetCoverage / 100,
					max_iterations: 10
				})
			});

			const data = await res.json();
			if (data.job_id) {
				jobId = data.job_id;
				pollJobStatus();
			} else if (data.error) {
				error = data.error;
				isRunning = false;
			}
		} catch (e) {
			error = String(e);
			isRunning = false;
		}
	}

	async function pollJobStatus() {
		if (!jobId) return;

		try {
			const res = await fetch(`${SCANNER_URL}/benchmark/job/${jobId}`);
			const data = await res.json();

			if (data.status === 'complete') {
				isRunning = false;
				if (data.result) {
					processAutoImproveResult(data.result);
				}
			} else if (data.status === 'failed') {
				isRunning = false;
				error = data.error || 'Job failed';
			} else if (data.status === 'running') {
				// Keep polling
				setTimeout(pollJobStatus, 5000);
			}
		} catch (e) {
			// Job might not exist yet, keep trying
			setTimeout(pollJobStatus, 5000);
		}
	}

	function processAutoImproveResult(result: any) {
		if (result.final_coverage) {
			overallCoverage = result.final_coverage * 100;
		}
		if (result.per_repo) {
			for (const [repoName, repoData] of Object.entries(result.per_repo as Record<string, any>)) {
				const existing = results.get(repoName);
				if (existing) {
					existing.coverage = (repoData.coverage || 0) * 100;
					existing.detected = repoData.detected || 0;
					existing.findings = repoData.findings || 0;
					existing.status = 'complete';
				}
			}
			results = new Map(results);
		}
		if (result.history) {
			history = result.history.map((h: any) => ({
				timestamp: h.timestamp,
				overall_coverage: (h.overall_coverage || 0) * 100,
				total_detected: h.total_detected || 0,
				total_known: h.total_known || 0,
				rules_added: h.rules_added || 0
			}));
		}
	}

	function updateOverallCoverage() {
		let detected = 0;
		let total = 0;
		let added = 0;

		results.forEach(r => {
			if (r.status === 'complete') {
				detected += r.detected;
				total += r.total;
			}
		});

		totalDetected = detected;
		totalKnown = total;
		overallCoverage = total > 0 ? (detected / total) * 100 : 0;
	}

	function stopBenchmark() {
		isRunning = false;
		currentRepo = null;
	}

	function getCoverageClass(coverage: number): string {
		if (coverage >= 90) return 'coverage-excellent';
		if (coverage >= 70) return 'coverage-good';
		if (coverage >= 50) return 'coverage-fair';
		return 'coverage-poor';
	}

	function getStatusIcon(status: string): string {
		switch (status) {
			case 'complete': return '✓';
			case 'scanning': return '⟳';
			case 'error': return '✗';
			default: return '○';
		}
	}

	function formatTimestamp(ts: string): string {
		return new Date(ts).toLocaleString();
	}

	onMount(() => {
		loadRepos();
	});

	onDestroy(() => {
		if (refreshInterval) {
			clearInterval(refreshInterval);
		}
	});
</script>

<svelte:head>
	<title>Benchmark Dashboard | Vibeship Scanner</title>
</svelte:head>

{#if !isAuthenticated}
	<div class="login-gate">
		<div class="login-card">
			<div class="login-icon">
				<svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
					<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
				</svg>
			</div>
			<h2>Admin Access Required</h2>
			<p class="login-description">Enter password to access the benchmark dashboard.</p>
			{#if loginError}
				<div class="denied-msg">
					<span class="denied-icon">!</span>
					{loginError}
				</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); login(); }}>
				<input
					type="password"
					bind:value={password}
					placeholder="Enter password"
					class="password-input"
				/>
				<button type="submit" class="btn btn-primary btn-full">
					Access Dashboard
				</button>
			</form>
		</div>
	</div>
{:else}
	<div class="benchmark-page">
		<div class="benchmark-header">
			<div class="header-content">
				<h1>Benchmark Dashboard</h1>
				<p class="header-subtitle">Testing scanner accuracy against known vulnerable repositories</p>
			</div>
			<div class="header-right">
				<button class="btn btn-small btn-ghost" onclick={logout}>Logout</button>
			</div>
			<div class="header-actions">
			{#if isRunning}
				<button class="btn btn-stop" onclick={stopBenchmark}>
					<span class="btn-icon">⏹</span>
					Stop
				</button>
			{:else}
				<button class="btn btn-primary" onclick={runFullBenchmark}>
					<span class="btn-icon">▶</span>
					Run Benchmark
				</button>
				<button class="btn btn-glow" onclick={startAutoImprove}>
					<span class="btn-icon">🔄</span>
					Auto-Improve
				</button>
			{/if}
		</div>
	</div>

	{#if error}
		<div class="error-banner">
			<span class="error-icon">⚠️</span>
			<span>{error}</span>
			<button class="error-dismiss" onclick={() => error = null}>×</button>
		</div>
	{/if}

	<div class="stats-grid">
		<div class="stat-card stat-coverage">
			<div class="stat-label">Overall Coverage</div>
			<div class="stat-value {getCoverageClass(overallCoverage)}">
				{overallCoverage.toFixed(1)}%
			</div>
			<div class="stat-target">Target: {targetCoverage}%</div>
			<div class="coverage-bar">
				<div class="coverage-fill" style="width: {overallCoverage}%"></div>
				<div class="coverage-target" style="left: {targetCoverage}%"></div>
			</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Vulns Detected</div>
			<div class="stat-value">{totalDetected}/{totalKnown}</div>
			<div class="stat-detail">{totalKnown - totalDetected} gaps remaining</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Iteration</div>
			<div class="stat-value">{iteration}</div>
			<div class="stat-detail">{history.length} runs recorded</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Rules Added</div>
			<div class="stat-value">{rulesAdded}</div>
			<div class="stat-detail">Auto-generated</div>
		</div>
	</div>

	{#if history.length > 1}
		<div class="progress-section">
			<h2>Progress Over Time</h2>
			<div class="progress-chart">
				{#each history as h, i}
					<div class="progress-bar-container">
						<div class="progress-bar {getCoverageClass(h.overall_coverage)}" style="height: {h.overall_coverage}%">
							<span class="progress-label">{h.overall_coverage.toFixed(0)}%</span>
						</div>
						<span class="progress-iteration">#{i + 1}</span>
					</div>
				{/each}
			</div>
		</div>
	{/if}

	<div class="repos-section">
		<h2>Benchmark Repositories</h2>
		<div class="repos-grid">
			{#each repos as repo}
				{@const result = results.get(repo.repo)}
				<div class="repo-card {result?.status || 'pending'}" class:scanning={currentRepo === repo.repo}>
					<div class="repo-header">
						<div class="repo-status">
							<span class="status-icon {result?.status || 'pending'}">
								{getStatusIcon(result?.status || 'pending')}
							</span>
							<span class="repo-name">{repo.name}</span>
						</div>
						<span class="repo-language">{repo.language}</span>
					</div>

					<div class="repo-coverage">
						<div class="coverage-ring {getCoverageClass(result?.coverage || 0)}">
							<svg viewBox="0 0 36 36">
								<path class="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
								<path class="ring-fill" stroke-dasharray="{result?.coverage || 0}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
							</svg>
							<span class="coverage-text">{(result?.coverage || 0).toFixed(0)}%</span>
						</div>
					</div>

					<div class="repo-stats">
						<div class="repo-stat">
							<span class="stat-num">{result?.detected || 0}/{result?.total || repo.vuln_count}</span>
							<span class="stat-label">Detected</span>
						</div>
						<div class="repo-stat">
							<span class="stat-num">{result?.findings || 0}</span>
							<span class="stat-label">Findings</span>
						</div>
					</div>

					{#if result?.improved_from}
						<div class="improvement-badge">
							<span class="improvement-icon">📈</span>
							+{(result.coverage - result.improved_from).toFixed(1)}% from last run
						</div>
					{/if}

					{#if result?.status === 'complete' && result.missed_vulns.length > 0}
						<div class="missed-vulns">
							<span class="missed-label">Gaps ({result.missed_vulns.length}):</span>
							<div class="missed-list">
								{#each result.missed_vulns.slice(0, 3) as vuln}
									<span class="missed-tag">{vuln}</span>
								{/each}
								{#if result.missed_vulns.length > 3}
									<span class="missed-more">+{result.missed_vulns.length - 3} more</span>
								{/if}
							</div>
						</div>
					{/if}

					{#if result?.error}
						<div class="repo-error">{result.error}</div>
					{/if}

					<div class="repo-actions">
						<button
							class="btn btn-sm"
							onclick={() => scanSingleRepo(repo.repo)}
							disabled={isRunning}
						>
							{currentRepo === repo.repo ? 'Scanning...' : 'Scan'}
						</button>
					</div>
				</div>
			{/each}
		</div>
	</div>

	{#if history.length > 0}
		<div class="history-section">
			<h2>Run History</h2>
			<div class="history-table">
				<div class="history-header">
					<span>Run</span>
					<span>Time</span>
					<span>Coverage</span>
					<span>Detected</span>
					<span>Rules Added</span>
				</div>
				{#each [...history].reverse() as h, i}
					<div class="history-row">
						<span class="run-number">#{history.length - i}</span>
						<span class="run-time">{formatTimestamp(h.timestamp)}</span>
						<span class="run-coverage {getCoverageClass(h.overall_coverage)}">{h.overall_coverage.toFixed(1)}%</span>
						<span class="run-detected">{h.total_detected}/{h.total_known}</span>
						<span class="run-rules">{h.rules_added > 0 ? `+${h.rules_added}` : '-'}</span>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</div>
{/if}

<style>
	.login-gate {
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: calc(100vh - 200px);
		padding: 2rem;
	}

	.login-card {
		background: var(--card-bg, #1a1a2e);
		border: 1px solid var(--border-dim, #2a2a4a);
		border-radius: 16px;
		padding: 3rem;
		text-align: center;
		max-width: 400px;
		width: 100%;
	}

	.login-icon {
		color: var(--green, #00ff88);
		margin-bottom: 1.5rem;
	}

	.login-card h2 {
		color: var(--text, #fff);
		font-size: 1.5rem;
		margin-bottom: 0.75rem;
	}

	.login-description {
		color: var(--text-dim, #888);
		margin-bottom: 2rem;
		line-height: 1.5;
	}

	.denied-msg {
		background: rgba(255, 100, 100, 0.1);
		border: 1px solid rgba(255, 100, 100, 0.3);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		color: #ff6b6b;
		margin-bottom: 1.5rem;
		font-size: 0.9rem;
	}

	.denied-icon {
		margin-right: 0.5rem;
	}

	.btn-github {
		display: inline-flex;
		align-items: center;
		gap: 0.75rem;
		background: #24292e;
		color: #fff;
		border: 1px solid #444;
		padding: 0.875rem 1.5rem;
		border-radius: 8px;
		font-size: 1rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		width: 100%;
		justify-content: center;
	}

	.btn-github:hover:not(:disabled) {
		background: #2f363d;
		border-color: #666;
	}

	.btn-github:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}

	.spinner {
		width: 18px;
		height: 18px;
		border: 2px solid transparent;
		border-top-color: #fff;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.user-info {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		background: var(--card-bg, #1a1a2e);
		border: 1px solid var(--border-dim, #2a2a4a);
		border-radius: 8px;
		padding: 0.5rem 1rem;
	}

	.user-avatar {
		width: 28px;
		height: 28px;
		border-radius: 50%;
	}

	.user-name {
		color: var(--text, #fff);
		font-size: 0.9rem;
	}

	.btn-small {
		padding: 0.375rem 0.75rem;
		font-size: 0.8rem;
	}

	.btn-ghost {
		background: transparent;
		border: 1px solid var(--border-dim, #2a2a4a);
		color: var(--text-dim, #888);
	}

	.btn-ghost:hover {
		border-color: var(--text-dim, #888);
		color: var(--text, #fff);
	}

	.password-input {
		width: 100%;
		padding: 0.875rem 1rem;
		background: var(--bg, #0a0a1a);
		border: 1px solid var(--border-dim, #2a2a4a);
		border-radius: 8px;
		color: var(--text, #fff);
		font-size: 1rem;
		margin-bottom: 1rem;
	}

	.password-input:focus {
		outline: none;
		border-color: var(--green, #00ff88);
	}

	.btn-full {
		width: 100%;
	}

	.header-right {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.benchmark-page {
		padding: 8rem 2rem 4rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: calc(100vh - 80px);
	}

	.benchmark-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
		gap: 2rem;
	}

	.header-content h1 {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		margin-bottom: 0.5rem;
	}

	.header-subtitle {
		color: var(--text-secondary);
		font-size: 1rem;
	}

	.header-actions {
		display: flex;
		gap: 0.75rem;
	}

	.btn {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.25rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		color: var(--text-primary);
		cursor: pointer;
		font-size: 0.9rem;
		font-weight: 500;
		transition: all 0.15s;
	}

	.btn:hover:not(:disabled) {
		border-color: var(--text-primary);
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: var(--purple);
		border-color: var(--purple);
		color: white;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--purple-light);
		border-color: var(--purple-light);
	}

	.btn-glow {
		background: var(--green);
		border-color: var(--green);
		color: var(--bg-primary);
		box-shadow: 0 0 20px rgba(0, 196, 154, 0.3);
	}

	.btn-glow:hover:not(:disabled) {
		box-shadow: 0 0 30px rgba(0, 196, 154, 0.5);
	}

	.btn-stop {
		background: var(--red);
		border-color: var(--red);
		color: white;
	}

	.btn-sm {
		padding: 0.5rem 1rem;
		font-size: 0.8rem;
	}

	.btn-icon {
		font-size: 1rem;
	}

	.error-banner {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(255, 107, 107, 0.1);
		border: 1px solid var(--red);
		margin-bottom: 2rem;
		color: var(--red);
	}

	.error-dismiss {
		margin-left: auto;
		background: none;
		border: none;
		color: var(--red);
		cursor: pointer;
		font-size: 1.25rem;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
		margin-bottom: 2rem;
	}

	.stat-card {
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		padding: 1.5rem;
	}

	.stat-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary);
		margin-bottom: 0.5rem;
	}

	.stat-value {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		line-height: 1;
		margin-bottom: 0.5rem;
	}

	.stat-detail, .stat-target {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.coverage-bar {
		position: relative;
		height: 4px;
		background: var(--bg-tertiary);
		margin-top: 1rem;
		overflow: visible;
	}

	.coverage-fill {
		height: 100%;
		background: var(--green);
		transition: width 0.5s ease;
	}

	.coverage-target {
		position: absolute;
		top: -4px;
		width: 2px;
		height: 12px;
		background: var(--text-primary);
	}

	.coverage-excellent { color: var(--green); }
	.coverage-good { color: var(--blue); }
	.coverage-fair { color: var(--orange); }
	.coverage-poor { color: var(--red); }

	.progress-section {
		margin-bottom: 2rem;
		padding: 1.5rem;
		background: var(--bg-secondary);
		border: 1px solid var(--border);
	}

	.progress-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.25rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	.progress-chart {
		display: flex;
		align-items: flex-end;
		gap: 0.5rem;
		height: 120px;
	}

	.progress-bar-container {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		height: 100%;
	}

	.progress-bar {
		width: 100%;
		min-height: 10px;
		display: flex;
		align-items: flex-end;
		justify-content: center;
		transition: height 0.3s ease;
	}

	.progress-bar.coverage-excellent { background: var(--green); }
	.progress-bar.coverage-good { background: var(--blue); }
	.progress-bar.coverage-fair { background: var(--orange); }
	.progress-bar.coverage-poor { background: var(--red); }

	.progress-label {
		font-size: 0.7rem;
		color: var(--bg-primary);
		font-weight: 600;
		padding: 0.25rem;
	}

	.progress-iteration {
		font-size: 0.7rem;
		color: var(--text-tertiary);
		margin-top: 0.5rem;
	}

	.repos-section h2, .history-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	.repos-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
		gap: 1rem;
		margin-bottom: 2rem;
	}

	.repo-card {
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		padding: 1.25rem;
		transition: all 0.2s;
	}

	.repo-card.scanning {
		border-color: var(--purple);
		box-shadow: 0 0 20px rgba(157, 140, 255, 0.2);
	}

	.repo-card.complete {
		border-color: var(--green-dim);
	}

	.repo-card.error {
		border-color: var(--red);
	}

	.repo-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.repo-status {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.status-icon {
		width: 20px;
		height: 20px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 50%;
		font-size: 0.75rem;
	}

	.status-icon.pending { background: var(--bg-tertiary); color: var(--text-tertiary); }
	.status-icon.scanning { background: var(--purple); color: white; animation: pulse 1s infinite; }
	.status-icon.complete { background: var(--green); color: var(--bg-primary); }
	.status-icon.error { background: var(--red); color: white; }

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.5; }
	}

	.repo-name {
		font-weight: 500;
	}

	.repo-language {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		background: var(--bg-tertiary);
		padding: 0.25rem 0.5rem;
	}

	.repo-coverage {
		display: flex;
		justify-content: center;
		margin-bottom: 1rem;
	}

	.coverage-ring {
		position: relative;
		width: 80px;
		height: 80px;
	}

	.coverage-ring svg {
		width: 100%;
		height: 100%;
		transform: rotate(-90deg);
	}

	.ring-bg {
		fill: none;
		stroke: var(--bg-tertiary);
		stroke-width: 3;
	}

	.ring-fill {
		fill: none;
		stroke: currentColor;
		stroke-width: 3;
		stroke-linecap: round;
		transition: stroke-dasharray 0.5s ease;
	}

	.coverage-text {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		font-size: 1.25rem;
		font-weight: 600;
	}

	.repo-stats {
		display: flex;
		justify-content: space-around;
		margin-bottom: 1rem;
		padding: 0.75rem 0;
		border-top: 1px solid var(--border);
		border-bottom: 1px solid var(--border);
	}

	.repo-stat {
		text-align: center;
	}

	.repo-stat .stat-num {
		display: block;
		font-size: 1.1rem;
		font-weight: 600;
	}

	.repo-stat .stat-label {
		font-size: 0.7rem;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.improvement-badge {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 0.5rem;
		background: rgba(0, 196, 154, 0.1);
		border: 1px solid var(--green-dim);
		color: var(--green);
		font-size: 0.8rem;
		margin-bottom: 1rem;
	}

	.missed-vulns {
		margin-bottom: 1rem;
	}

	.missed-label {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		display: block;
		margin-bottom: 0.5rem;
	}

	.missed-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
	}

	.missed-tag {
		font-size: 0.7rem;
		padding: 0.2rem 0.5rem;
		background: rgba(255, 107, 107, 0.1);
		border: 1px solid var(--red);
		color: var(--red);
	}

	.missed-more {
		font-size: 0.7rem;
		color: var(--text-tertiary);
		padding: 0.2rem 0.5rem;
	}

	.repo-error {
		font-size: 0.8rem;
		color: var(--red);
		margin-bottom: 1rem;
		padding: 0.5rem;
		background: rgba(255, 107, 107, 0.1);
	}

	.repo-actions {
		display: flex;
		justify-content: center;
	}

	.history-section {
		margin-bottom: 2rem;
	}

	.history-table {
		background: var(--bg-secondary);
		border: 1px solid var(--border);
	}

	.history-header, .history-row {
		display: grid;
		grid-template-columns: 60px 1fr 100px 100px 100px;
		padding: 0.75rem 1rem;
		gap: 1rem;
	}

	.history-header {
		background: var(--bg-tertiary);
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary);
		font-weight: 500;
	}

	.history-row {
		border-top: 1px solid var(--border);
	}

	.run-number {
		font-weight: 500;
	}

	.run-time {
		font-size: 0.85rem;
		color: var(--text-secondary);
	}

	.run-coverage {
		font-weight: 600;
	}

	.run-rules {
		color: var(--green);
	}

	@media (max-width: 768px) {
		.benchmark-header {
			flex-direction: column;
		}

		.header-actions {
			width: 100%;
		}

		.header-actions .btn {
			flex: 1;
		}

		.stats-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.repos-grid {
			grid-template-columns: 1fr;
		}

		.history-header, .history-row {
			grid-template-columns: 40px 1fr 60px;
		}

		.history-header span:nth-child(4),
		.history-header span:nth-child(5),
		.history-row span:nth-child(4),
		.history-row span:nth-child(5) {
			display: none;
		}
	}
</style>
