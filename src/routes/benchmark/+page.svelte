<script lang="ts">
	import { onMount } from 'svelte';

	const SCANNER_URL = 'https://vibeship-benchmark.fly.dev';

	// Types
	type BenchmarkRepo = {
		repo: string;
		name: string;
		language: string;
		vuln_count: number;
	};

	type ScanResult = {
		status: 'pending' | 'scanning' | 'complete' | 'error';
		coverage: number;
		detected: number;
		total: number;
		detected_vulns: string[];
		missed_vulns: string[];
		findingsCount: number;
		error?: string;
	};

	// State
	let repos = $state<BenchmarkRepo[]>([]);
	let results = $state<Map<string, ScanResult>>(new Map());
	let scanning = $state<string | null>(null);
	let scanQueue = $state<string[]>([]);
	let error = $state<string | null>(null);
	let loading = $state(true);

	// Computed
	let overallStats = $derived(() => {
		let detected = 0;
		let total = 0;
		for (const repo of repos) {
			const result = results.get(repo.repo);
			if (result?.status === 'complete') {
				detected += result.detected;
				total += result.total;
			}
		}
		const coverage = total > 0 ? (detected / total) * 100 : 0;
		return { detected, total, coverage };
	});

	// Load repos on mount
	onMount(async () => {
		await loadRepos();
	});

	async function loadRepos() {
		loading = true;
		error = null;
		try {
			const res = await fetch(`${SCANNER_URL}/benchmark/repos`);
			if (!res.ok) throw new Error('Failed to load repos');
			const data = await res.json();
			repos = data.repos || [];

			// Initialize results for each repo
			for (const repo of repos) {
				if (!results.has(repo.repo)) {
					results.set(repo.repo, {
						status: 'pending',
						coverage: 0,
						detected: 0,
						total: repo.vuln_count,
						detected_vulns: [],
						missed_vulns: [],
						findingsCount: 0
					});
				}
			}
			results = new Map(results);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load repos';
		} finally {
			loading = false;
		}
	}

	async function scanRepo(repoId: string) {
		const repo = repos.find(r => r.repo === repoId);
		if (!repo) return;

		// Update status to scanning
		results.set(repoId, {
			...results.get(repoId)!,
			status: 'scanning'
		});
		results = new Map(results);
		scanning = repoId;

		try {
			const res = await fetch('/api/benchmark/scan', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ repo: repoId })
			});

			const data = await res.json();

			if (data.error) {
				results.set(repoId, {
					...results.get(repoId)!,
					status: 'error',
					error: data.error
				});
			} else {
				results.set(repoId, {
					status: 'complete',
					coverage: data.coverage || 0,
					detected: data.detected_vulns?.length || 0,
					total: data.known_vulns?.length || repo.vuln_count,
					detected_vulns: data.detected_vulns || [],
					missed_vulns: data.missed_vulns || [],
					findingsCount: data.findings?.length || 0
				});
			}
		} catch (e) {
			results.set(repoId, {
				...results.get(repoId)!,
				status: 'error',
				error: e instanceof Error ? e.message : 'Scan failed'
			});
		} finally {
			results = new Map(results);
			scanning = null;
			processQueue();
		}
	}

	function processQueue() {
		if (scanning || scanQueue.length === 0) return;
		const next = scanQueue.shift();
		scanQueue = [...scanQueue];
		if (next) scanRepo(next);
	}

	function scanSingle(repoId: string) {
		if (scanning) {
			// Queue it
			if (!scanQueue.includes(repoId)) {
				scanQueue = [...scanQueue, repoId];
			}
		} else {
			scanRepo(repoId);
		}
	}

	function scanAll() {
		// Queue all repos that aren't already complete or scanning
		const toScan = repos
			.filter(r => {
				const result = results.get(r.repo);
				return result?.status !== 'scanning' && result?.status !== 'complete';
			})
			.map(r => r.repo);

		if (toScan.length === 0) {
			// Re-scan all
			scanQueue = repos.map(r => r.repo);
		} else {
			scanQueue = toScan;
		}
		processQueue();
	}

	function stopScanning() {
		scanQueue = [];
	}

	function getCoverageClass(coverage: number): string {
		if (coverage >= 80) return 'coverage-high';
		if (coverage >= 50) return 'coverage-medium';
		return 'coverage-low';
	}

	function getLanguageColor(lang: string): string {
		const colors: Record<string, string> = {
			javascript: '#f7df1e',
			python: '#3776ab',
			php: '#777bb4',
			java: '#007396'
		};
		return colors[lang.toLowerCase()] || '#888';
	}
</script>

<div class="benchmark-page">
	<header class="header">
		<div class="header-content">
			<h1>Benchmark Dashboard</h1>
			<p class="subtitle">Testing scanner accuracy against known vulnerable repositories</p>
		</div>
		<div class="header-actions">
			{#if scanning || scanQueue.length > 0}
				<button class="btn btn-stop" onclick={stopScanning}>
					Stop ({scanQueue.length} queued)
				</button>
			{:else}
				<button class="btn btn-primary" onclick={scanAll}>
					Scan All Repos
				</button>
			{/if}
		</div>
	</header>

	{#if error}
		<div class="error-banner">
			<span>{error}</span>
			<button onclick={() => error = null}>×</button>
		</div>
	{/if}

	<!-- Overall Stats -->
	<div class="stats-bar">
		<div class="stat">
			<span class="stat-label">Overall Coverage</span>
			<span class="stat-value {getCoverageClass(overallStats().coverage)}">
				{overallStats().coverage.toFixed(1)}%
			</span>
		</div>
		<div class="stat">
			<span class="stat-label">Vulnerabilities Detected</span>
			<span class="stat-value">
				{overallStats().detected} / {overallStats().total}
			</span>
		</div>
		<div class="stat">
			<span class="stat-label">Repos</span>
			<span class="stat-value">{repos.length}</span>
		</div>
	</div>

	<!-- Repo Grid -->
	{#if loading}
		<div class="loading">Loading repos...</div>
	{:else}
		<div class="repo-grid">
			{#each repos as repo}
				{@const result = results.get(repo.repo)}
				<div class="repo-card" class:scanning={result?.status === 'scanning'} class:complete={result?.status === 'complete'}>
					<div class="repo-header">
						<h3 class="repo-name">{repo.name}</h3>
						<span class="lang-badge" style="background: {getLanguageColor(repo.language)}">
							{repo.language}
						</span>
					</div>

					<div class="repo-info">
						<span class="vuln-count">{repo.vuln_count} known vulnerabilities</span>
					</div>

					{#if result?.status === 'complete'}
						<div class="result-section">
							<div class="coverage-display {getCoverageClass(result.coverage)}">
								<span class="coverage-value">{result.coverage.toFixed(0)}%</span>
								<span class="coverage-label">coverage</span>
							</div>
							<div class="detection-stats">
								<div class="stat-row">
									<span class="stat-icon good">✓</span>
									<span>{result.detected} detected</span>
								</div>
								<div class="stat-row">
									<span class="stat-icon bad">✗</span>
									<span>{result.missed_vulns.length} missed</span>
								</div>
								<div class="stat-row">
									<span class="stat-icon neutral">📋</span>
									<span>{result.findingsCount} findings</span>
								</div>
							</div>
							{#if result.missed_vulns.length > 0}
								<div class="missed-vulns">
									<span class="missed-label">Missed:</span>
									{#each result.missed_vulns.slice(0, 3) as vuln}
										<span class="missed-tag">{vuln}</span>
									{/each}
									{#if result.missed_vulns.length > 3}
										<span class="missed-more">+{result.missed_vulns.length - 3} more</span>
									{/if}
								</div>
							{/if}
						</div>
					{:else if result?.status === 'error'}
						<div class="error-section">
							<span class="error-icon">⚠️</span>
							<span>{result.error || 'Scan failed'}</span>
						</div>
					{:else if result?.status === 'scanning'}
						<div class="scanning-section">
							<div class="spinner"></div>
							<span>Scanning...</span>
						</div>
					{/if}

					<div class="repo-actions">
						<button
							class="btn btn-scan"
							onclick={() => scanSingle(repo.repo)}
							disabled={result?.status === 'scanning'}
						>
							{#if result?.status === 'scanning'}
								Scanning...
							{:else if result?.status === 'complete'}
								Re-scan
							{:else if scanQueue.includes(repo.repo)}
								Queued
							{:else}
								Scan
							{/if}
						</button>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.benchmark-page {
		padding: 2rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}

	.header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.header-content h1 {
		font-size: 2rem;
		margin: 0 0 0.5rem 0;
		color: #fff;
	}

	.subtitle {
		color: #888;
		margin: 0;
	}

	.header-actions {
		display: flex;
		gap: 0.75rem;
	}

	.btn {
		padding: 0.75rem 1.5rem;
		border-radius: 8px;
		font-weight: 600;
		cursor: pointer;
		border: none;
		font-size: 0.95rem;
		transition: all 0.2s;
	}

	.btn-primary {
		background: linear-gradient(135deg, #00ff88, #00cc6a);
		color: #000;
	}

	.btn-primary:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 20px rgba(0, 255, 136, 0.3);
	}

	.btn-stop {
		background: #ff4757;
		color: #fff;
	}

	.btn-scan {
		background: #2a2a4a;
		color: #fff;
		width: 100%;
		padding: 0.6rem 1rem;
	}

	.btn-scan:hover:not(:disabled) {
		background: #3a3a5a;
	}

	.btn-scan:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.error-banner {
		background: rgba(255, 71, 87, 0.1);
		border: 1px solid rgba(255, 71, 87, 0.3);
		border-radius: 8px;
		padding: 1rem;
		margin-bottom: 1.5rem;
		display: flex;
		justify-content: space-between;
		align-items: center;
		color: #ff4757;
	}

	.error-banner button {
		background: none;
		border: none;
		color: #ff4757;
		cursor: pointer;
		font-size: 1.2rem;
	}

	.stats-bar {
		display: flex;
		gap: 2rem;
		background: #1a1a2e;
		border: 1px solid #2a2a4a;
		border-radius: 12px;
		padding: 1.5rem 2rem;
		margin-bottom: 2rem;
		flex-wrap: wrap;
	}

	.stat {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.stat-label {
		color: #888;
		font-size: 0.85rem;
	}

	.stat-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #fff;
	}

	.stat-value.coverage-high { color: #00ff88; }
	.stat-value.coverage-medium { color: #ffc107; }
	.stat-value.coverage-low { color: #ff4757; }

	.loading {
		text-align: center;
		padding: 4rem;
		color: #888;
	}

	.repo-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
		gap: 1.5rem;
	}

	.repo-card {
		background: #1a1a2e;
		border: 1px solid #2a2a4a;
		border-radius: 12px;
		padding: 1.5rem;
		transition: all 0.2s;
	}

	.repo-card:hover {
		border-color: #3a3a5a;
	}

	.repo-card.scanning {
		border-color: #ffc107;
		box-shadow: 0 0 20px rgba(255, 193, 7, 0.1);
	}

	.repo-card.complete {
		border-color: #2a2a4a;
	}

	.repo-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 0.75rem;
	}

	.repo-name {
		font-size: 1.1rem;
		font-weight: 600;
		color: #fff;
		margin: 0;
	}

	.lang-badge {
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
		color: #000;
	}

	.repo-info {
		margin-bottom: 1rem;
	}

	.vuln-count {
		color: #888;
		font-size: 0.9rem;
	}

	.result-section {
		background: #12121f;
		border-radius: 8px;
		padding: 1rem;
		margin-bottom: 1rem;
	}

	.coverage-display {
		display: flex;
		align-items: baseline;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.coverage-value {
		font-size: 2rem;
		font-weight: 700;
	}

	.coverage-label {
		color: #888;
		font-size: 0.9rem;
	}

	.coverage-display.coverage-high .coverage-value { color: #00ff88; }
	.coverage-display.coverage-medium .coverage-value { color: #ffc107; }
	.coverage-display.coverage-low .coverage-value { color: #ff4757; }

	.detection-stats {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.stat-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.9rem;
		color: #ccc;
	}

	.stat-icon {
		font-size: 0.85rem;
	}

	.stat-icon.good { color: #00ff88; }
	.stat-icon.bad { color: #ff4757; }
	.stat-icon.neutral { color: #888; }

	.missed-vulns {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid #2a2a4a;
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		align-items: center;
	}

	.missed-label {
		color: #ff4757;
		font-size: 0.85rem;
		font-weight: 500;
	}

	.missed-tag {
		background: rgba(255, 71, 87, 0.1);
		border: 1px solid rgba(255, 71, 87, 0.3);
		color: #ff6b7a;
		padding: 0.2rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
	}

	.missed-more {
		color: #888;
		font-size: 0.8rem;
	}

	.error-section {
		background: rgba(255, 71, 87, 0.1);
		border-radius: 8px;
		padding: 1rem;
		margin-bottom: 1rem;
		color: #ff4757;
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.scanning-section {
		background: rgba(255, 193, 7, 0.1);
		border-radius: 8px;
		padding: 1rem;
		margin-bottom: 1rem;
		color: #ffc107;
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.spinner {
		width: 20px;
		height: 20px;
		border: 2px solid #ffc107;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.repo-actions {
		margin-top: auto;
	}
</style>
