<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	const SCANNER_URL = 'https://scanner-empty-field-5676.fly.dev';
	const BENCHMARK_SECRET = 'vibeship-benchmark-2024';
	const PASSWORD_HASH = '69b86692b84806ffc45e9d9b5fa44320';
	const MAX_PARALLEL_SCANS = 2; // Reduced to prevent overwhelming the server

	let isAuthenticated = $state(false);
	let password = $state('');
	let loginError = $state('');

	async function hashPassword(pwd: string): Promise<string> {
		const encoder = new TextEncoder();
		const data = encoder.encode(pwd);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
	}

	// Auth check moved to main onMount below

	async function login() {
		const hash = await hashPassword(password);
		if (hash === PASSWORD_HASH) {
			localStorage.setItem('benchmark_auth', hash);
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

	function clearData() {
		if (confirm('Clear all benchmark data? This will reset all scan results and history.')) {
			localStorage.removeItem(STORAGE_KEY);
			results = new Map();
			history = [];
			iteration = 0;
			rulesAdded = 0;
			overallCoverage = 0;
			totalDetected = 0;
			totalKnown = 0;
			loadRepos();
		}
	}

	type BenchmarkRepo = {
		repo: string;
		name: string;
		language: string;
		vuln_count: number;
	};

	type Finding = {
		id: string;
		ruleId: string;
		severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
		category: string;
		title: string;
		description?: string;
		location: {
			file: string;
			line: number;
			column?: number;
		};
		snippet?: {
			code: string;
			highlightLines?: number[];
		};
		fix?: {
			available: boolean;
			template?: string;
		};
		references?: string[];
	};

	type RepoResult = {
		repo: string;
		name: string;
		language: string;
		status: 'pending' | 'scanning' | 'complete' | 'error';
		coverage: number;
		detected: number;
		total: number;
		findingsCount: number;
		detected_vulns: string[];
		missed_vulns: string[];
		error?: string;
		improved_from?: number;
		scanProgress: number;
		scanStartTime?: number;
		// Full findings data like the main scan page
		findings?: Finding[];
		score?: number;
		finding_counts?: { critical: number; high: number; medium: number; low: number; info: number };
		stack?: { languages: string[]; frameworks: string[] };
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
	let activeScans = $state<Set<string>>(new Set());
	let iteration = $state(0);
	let history = $state<BenchmarkHistory[]>([]);
	let error = $state<string | null>(null);
	let jobId = $state<string | null>(null);
	let rulesAdded = $state(0);
	let totalDetected = $state(0);
	let totalKnown = $state(0);
	let autoImproveStatus = $state<string | null>(null);
	let autoImproveProgress = $state(0);
	let scanQueue = $state<string[]>([]);
	let progressIntervals = new Map<string, ReturnType<typeof setInterval>>();
	let selectedRepo = $state<string | null>(null);
	let expandedFindings = $state<Set<string>>(new Set());
	let clickedScans = $state<Set<string>>(new Set()); // Track buttons that were just clicked

	const STORAGE_KEY = 'benchmark_data';

	function getSeverityClass(severity: string): string {
		const classes: Record<string, string> = {
			critical: 'severity-critical',
			high: 'severity-high',
			medium: 'severity-medium',
			low: 'severity-low',
			info: 'severity-info'
		};
		return classes[severity] || '';
	}

	function getGradeFromScore(score: number): string {
		if (score >= 90) return 'A';
		if (score >= 80) return 'B';
		if (score >= 70) return 'C';
		if (score >= 60) return 'D';
		return 'F';
	}

	function getGradeClass(grade: string): string {
		const classes: Record<string, string> = {
			A: 'grade-a',
			B: 'grade-b',
			C: 'grade-c',
			D: 'grade-d',
			F: 'grade-f'
		};
		return classes[grade] || '';
	}

	function toggleFinding(id: string) {
		if (expandedFindings.has(id)) {
			expandedFindings.delete(id);
			expandedFindings = new Set(expandedFindings);
		} else {
			expandedFindings.add(id);
			expandedFindings = new Set(expandedFindings);
		}
	}

	function closeModal() {
		selectedRepo = null;
		expandedFindings = new Set();
	}

	function saveToStorage() {
		const data = {
			results: Array.from(results.entries()).map(([key, val]) => ({
				...val,
				status: val.status === 'scanning' ? 'pending' : val.status, // Reset scanning to pending
				scanProgress: 0
			})),
			repos: repos, // Also save repos list
			history,
			iteration,
			rulesAdded,
			overallCoverage,
			totalDetected,
			totalKnown,
			savedAt: new Date().toISOString()
		};
		localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
		console.log('[Benchmark] Saved to storage:', results.size, 'results,', repos.length, 'repos');
	}

	function loadFromStorage(): boolean {
		try {
			const stored = localStorage.getItem(STORAGE_KEY);
			if (!stored) {
				console.log('[Benchmark] No stored data found');
				return false;
			}

			const data = JSON.parse(stored);
			console.log('[Benchmark] Loading from storage:', data.savedAt);

			// Restore repos list first (needed for display)
			if (data.repos && Array.isArray(data.repos)) {
				repos = data.repos;
				console.log('[Benchmark] Restored', repos.length, 'repos');
			}

			// Restore results
			if (data.results && Array.isArray(data.results)) {
				const restoredResults = new Map<string, RepoResult>();
				data.results.forEach((r: RepoResult) => {
					restoredResults.set(r.repo, r);
				});
				results = restoredResults;
				console.log('[Benchmark] Restored', results.size, 'repo results');
			}

			// Restore other state
			if (data.history) history = data.history;
			if (typeof data.iteration === 'number') iteration = data.iteration;
			if (typeof data.rulesAdded === 'number') rulesAdded = data.rulesAdded;
			if (typeof data.overallCoverage === 'number') overallCoverage = data.overallCoverage;
			if (typeof data.totalDetected === 'number') totalDetected = data.totalDetected;
			if (typeof data.totalKnown === 'number') totalKnown = data.totalKnown;

			return true;
		} catch (e) {
			console.error('[Benchmark] Failed to load from storage:', e);
			return false;
		}
	}

	// Fallback repos in case API fails (CORS issues during local dev)
	const FALLBACK_REPOS: BenchmarkRepo[] = [
		{ repo: 'juice-shop/juice-shop', name: 'OWASP Juice Shop', language: 'javascript', vuln_count: 10 },
		{ repo: 'OWASP/NodeGoat', name: 'OWASP NodeGoat', language: 'javascript', vuln_count: 9 },
		{ repo: 'appsecco/dvna', name: 'Damn Vulnerable NodeJS Application', language: 'javascript', vuln_count: 7 },
		{ repo: 'erev0s/VAmPI', name: 'Vulnerable API (VAmPI)', language: 'python', vuln_count: 7 },
		{ repo: 'samoylenko/vulnerable-app-nodejs-express', name: 'Vulnerable Express App', language: 'javascript', vuln_count: 4 },
		{ repo: 'digininja/DVWA', name: 'Damn Vulnerable Web Application', language: 'php', vuln_count: 7 },
		{ repo: 'OWASP/crAPI', name: 'OWASP crAPI', language: 'python', vuln_count: 6 }
	];

	async function loadRepos() {
		try {
			console.log('[Benchmark] Fetching repos from API...');
			const res = await fetch(`${SCANNER_URL}/benchmark/repos`);
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const data = await res.json();
			repos = data.repos || FALLBACK_REPOS;
			console.log('[Benchmark] Got', repos.length, 'repos from API');

			// Track how many we're preserving vs adding new
			let preserved = 0;
			let added = 0;

			// Only add repos that don't exist yet (preserve stored results)
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
						findingsCount: 0,
						detected_vulns: [],
						missed_vulns: [],
						scanProgress: 0
					});
					added++;
				} else {
					// Update name/language from API but keep scan results
					const existing = results.get(repo.repo)!;
					existing.name = repo.name;
					existing.language = repo.language;
					existing.total = repo.vuln_count; // Update total from API
					preserved++;
				}
			});

			console.log('[Benchmark] Preserved', preserved, 'existing results, added', added, 'new repos');
			results = new Map(results);
			updateOverallCoverage();
		} catch (e) {
			console.error('[Benchmark] Failed to load repos from API, using fallback:', e);
			repos = FALLBACK_REPOS;

			// Initialize results for fallback repos
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
						findingsCount: 0,
						detected_vulns: [],
						missed_vulns: [],
						scanProgress: 0
					});
				}
			});
			results = new Map(results);
			error = null; // Clear error since we have fallback
		}
	}

	function startProgressAnimation(repoName: string) {
		const result = results.get(repoName);
		if (!result) return;

		result.scanStartTime = Date.now();
		result.scanProgress = 0;

		// Animate progress from 0 to 90 over ~60 seconds
		const interval = setInterval(() => {
			const r = results.get(repoName);
			if (!r || r.status !== 'scanning') {
				clearInterval(interval);
				progressIntervals.delete(repoName);
				return;
			}

			// Logarithmic progress - fast at start, slows down
			const elapsed = Date.now() - (r.scanStartTime || Date.now());
			const targetProgress = Math.min(90, 90 * (1 - Math.exp(-elapsed / 30000)));
			r.scanProgress = targetProgress;
			results = new Map(results);
		}, 100);

		progressIntervals.set(repoName, interval);
	}

	function stopProgressAnimation(repoName: string) {
		const interval = progressIntervals.get(repoName);
		if (interval) {
			clearInterval(interval);
			progressIntervals.delete(repoName);
		}
	}

	async function scanSingleRepo(repoName: string, retryCount = 0): Promise<void> {
		const result = results.get(repoName);
		if (!result || result.status === 'scanning') return;

		// Immediately mark as clicked for visual feedback
		clickedScans.add(repoName);
		clickedScans = new Set(clickedScans);

		result.status = 'scanning';
		result.scanProgress = 0;
		result.error = undefined;
		activeScans.add(repoName);
		activeScans = new Set(activeScans);
		results = new Map(results);

		startProgressAnimation(repoName);

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minute timeout

			// Use local proxy to avoid CORS issues
			const res = await fetch('/api/benchmark/scan', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ repo: repoName }),
				signal: controller.signal
			});

			clearTimeout(timeoutId);

			if (!res.ok) {
				throw new Error(`HTTP ${res.status}: ${res.statusText}`);
			}

			const data = await res.json();

			stopProgressAnimation(repoName);

			if (data.error) {
				result.status = 'error';
				result.error = data.error;
				result.scanProgress = 0;
			} else if (data.result) {
				const r = data.result;
				const previousCoverage = result.coverage;
				result.status = 'complete';
				result.coverage = (r.coverage || 0) * 100;
				result.detected = r.detected_count || 0;
				result.total = (r.detected_count || 0) + (r.missed_count || 0);
				result.findingsCount = r.total_findings || 0;
				result.detected_vulns = (r.detected || []).map((v: any) => v.id);
				result.missed_vulns = (r.missed || []).map((v: any) => v.id);
				result.scanProgress = 100;
				// Store full findings data for detailed view
				result.findings = r.findings || [];
				result.score = r.score;
				result.finding_counts = r.finding_counts;
				result.stack = r.stack;

				if (previousCoverage > 0 && result.coverage > previousCoverage) {
					result.improved_from = previousCoverage;
				}
			}
		} catch (e: any) {
			stopProgressAnimation(repoName);

			// Retry on network errors (up to 2 retries)
			if (retryCount < 2 && (e.name === 'TypeError' || e.name === 'AbortError')) {
				console.log(`Retrying ${repoName} (attempt ${retryCount + 2}/3)...`);
				activeScans.delete(repoName);
				activeScans = new Set(activeScans);
				result.status = 'pending';
				results = new Map(results);

				// Wait before retry with exponential backoff
				await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
				return scanSingleRepo(repoName, retryCount + 1);
			}

			result.status = 'error';
			result.error = e.name === 'AbortError' ? 'Request timed out' : (e.message || String(e));
			result.scanProgress = 0;
		}

		activeScans.delete(repoName);
		activeScans = new Set(activeScans);
		clickedScans.delete(repoName);
		clickedScans = new Set(clickedScans);
		results = new Map(results);
		updateOverallCoverage();
		saveToStorage();

		// Process next in queue if exists
		processQueue();
	}

	async function processQueue() {
		while (scanQueue.length > 0 && activeScans.size < MAX_PARALLEL_SCANS) {
			const nextRepo = scanQueue.shift();
			if (nextRepo) {
				// Add small delay between starting scans to prevent overwhelming the server
				await new Promise(resolve => setTimeout(resolve, 500));
				scanSingleRepo(nextRepo);
			}
		}
		scanQueue = [...scanQueue];
	}

	async function runFullBenchmark() {
		isRunning = true;
		iteration++;
		error = null;

		// Reset all results to pending
		repos.forEach(repo => {
			const result = results.get(repo.repo);
			if (result) {
				result.status = 'pending';
				result.scanProgress = 0;
			}
		});
		results = new Map(results);

		// Queue all repos
		scanQueue = repos.map(r => r.repo);

		// Start initial batch
		processQueue();

		// Wait for all scans to complete
		await new Promise<void>((resolve) => {
			const checkInterval = setInterval(() => {
				if (activeScans.size === 0 && scanQueue.length === 0) {
					clearInterval(checkInterval);
					resolve();
				}
			}, 500);
		});

		// Save to history
		history = [...history, {
			timestamp: new Date().toISOString(),
			overall_coverage: overallCoverage,
			total_detected: totalDetected,
			total_known: totalKnown,
			rules_added: rulesAdded
		}];
		saveToStorage();

		isRunning = false;
	}

	async function scanAllParallel() {
		isRunning = true;
		error = null;

		// Start all scans simultaneously (up to MAX_PARALLEL_SCANS)
		const reposToScan = repos.filter(r => {
			const result = results.get(r.repo);
			return result?.status !== 'scanning';
		});

		// Queue them all
		scanQueue = reposToScan.map(r => r.repo);
		processQueue();
	}

	async function startAutoImprove() {
		isRunning = true;
		error = null;
		autoImproveStatus = 'Starting auto-improve...';
		autoImproveProgress = 5;

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
				autoImproveStatus = 'Job started, analyzing gaps...';
				autoImproveProgress = 15;
				pollJobStatus();
			} else if (data.error) {
				error = data.error;
				autoImproveStatus = null;
				isRunning = false;
			}
		} catch (e) {
			error = String(e);
			autoImproveStatus = null;
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
				autoImproveStatus = 'Complete!';
				autoImproveProgress = 100;
				if (data.result) {
					processAutoImproveResult(data.result);
				}
				setTimeout(() => {
					autoImproveStatus = null;
					autoImproveProgress = 0;
				}, 3000);
			} else if (data.status === 'failed') {
				isRunning = false;
				error = data.error || 'Job failed';
				autoImproveStatus = null;
				autoImproveProgress = 0;
			} else if (data.status === 'running') {
				// Update progress message
				if (data.progress) {
					autoImproveStatus = data.progress;
				}
				autoImproveProgress = Math.min(90, autoImproveProgress + 5);
				setTimeout(pollJobStatus, 3000);
			}
		} catch (e) {
			setTimeout(pollJobStatus, 3000);
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
					existing.findingsCount = repoData.findings || 0;
					existing.status = 'complete';
					existing.scanProgress = 100;
				}
			}
			results = new Map(results);
		}
		if (result.rules_added) {
			rulesAdded += result.rules_added;
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
		saveToStorage();
	}

	function updateOverallCoverage() {
		let detected = 0;
		let total = 0;

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
		scanQueue = [];
		// Note: active scans will complete but no new ones will start
	}

	function getCoverageClass(coverage: number): string {
		if (coverage >= 90) return 'coverage-excellent';
		if (coverage >= 70) return 'coverage-good';
		if (coverage >= 50) return 'coverage-fair';
		return 'coverage-poor';
	}

	function getRulesetStatus(coverage: number): { text: string; class: string; icon: string } {
		if (coverage >= 100) return { text: 'All Covered', class: 'ruleset-complete', icon: '✓' };
		if (coverage >= 90) return { text: 'Nearly Complete', class: 'ruleset-good', icon: '◐' };
		if (coverage >= 50) return { text: 'Needs Work', class: 'ruleset-partial', icon: '◔' };
		return { text: 'Needs Rules', class: 'ruleset-missing', icon: '○' };
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

	function getLanguageIcon(lang: string): string {
		const icons: Record<string, string> = {
			javascript: '🟨',
			typescript: '🔷',
			python: '🐍',
			php: '🐘',
			java: '☕',
			ruby: '💎',
			go: '🔵',
			rust: '🦀'
		};
		return icons[lang.toLowerCase()] || '📄';
	}

	onMount(async () => {
		// Check authentication first
		const authStored = localStorage.getItem('benchmark_auth');
		if (authStored === PASSWORD_HASH) {
			isAuthenticated = true;
		}

		// Load saved data first, then fetch repos
		const hadStoredData = loadFromStorage();
		console.log('[Benchmark] onMount - had stored data:', hadStoredData, 'results size:', results.size);
		await loadRepos();
		console.log('[Benchmark] onMount complete - final results size:', results.size);
	});

	onDestroy(() => {
		progressIntervals.forEach(interval => clearInterval(interval));
		progressIntervals.clear();
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
				<button class="btn btn-small btn-ghost" onclick={clearData}>Clear Data</button>
				<button class="btn btn-small btn-ghost" onclick={logout}>Logout</button>
			</div>
			<div class="header-actions">
				{#if isRunning}
					<button class="btn btn-stop" onclick={stopBenchmark}>
						<span class="btn-icon">⏹</span>
						Stop
					</button>
					<span class="running-indicator">
						<span class="pulse-dot"></span>
						{activeScans.size} scanning, {scanQueue.length} queued
					</span>
				{:else}
					<button class="btn btn-primary" onclick={runFullBenchmark}>
						<span class="btn-icon">▶</span>
						Run All Sequential
					</button>
					<button class="btn btn-secondary" onclick={scanAllParallel}>
						<span class="btn-icon">⚡</span>
						Run All Parallel
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

		{#if autoImproveStatus}
			<div class="auto-improve-banner">
				<div class="auto-improve-header">
					<span class="auto-improve-icon">🤖</span>
					<span class="auto-improve-title">Auto-Improve Running</span>
				</div>
				<p class="auto-improve-status">{autoImproveStatus}</p>
				<div class="auto-improve-progress">
					<div class="auto-improve-fill" style="width: {autoImproveProgress}%"></div>
				</div>
			</div>
		{/if}

		<div class="stats-grid">
			<div class="stat-card stat-ruleset">
				<div class="stat-label">Ruleset Status</div>
				<div class="stat-value {getRulesetStatus(overallCoverage).class}">
					<span class="ruleset-icon">{getRulesetStatus(overallCoverage).icon}</span> {getRulesetStatus(overallCoverage).text}
				</div>
				<div class="stat-detail">{totalDetected}/{totalKnown} vuln types covered</div>
				<div class="coverage-bar">
					<div class="coverage-fill {getCoverageClass(overallCoverage)}" style="width: {overallCoverage}%"></div>
				</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Detection Gaps</div>
				<div class="stat-value">{totalKnown - totalDetected}</div>
				<div class="stat-detail">vuln types need new rules</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Active Scans</div>
				<div class="stat-value">{activeScans.size}</div>
				<div class="stat-detail">{scanQueue.length} in queue</div>
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
			<div class="repos-table">
				<div class="repos-header">
					<span class="col-status">Status</span>
					<span class="col-name">Repository</span>
					<span class="col-lang">Language</span>
					<span class="col-ruleset">Ruleset</span>
					<span class="col-detected">Detected</span>
					<span class="col-findings">Findings</span>
					<span class="col-gaps">Gaps</span>
					<span class="col-actions">Actions</span>
				</div>
				{#each repos as repo}
					{@const result = results.get(repo.repo)}
					<div class="repo-row {result?.status || 'pending'}" class:scanning={result?.status === 'scanning'}>
						<div class="col-status">
							<span class="status-icon {result?.status || 'pending'}">
								{getStatusIcon(result?.status || 'pending')}
							</span>
						</div>
						<div class="col-name">
							<span class="repo-name">{repo.name}</span>
							{#if result?.status === 'scanning'}
								<div class="row-progress">
									<div class="row-progress-bar">
										<div class="row-progress-fill" style="width: {result.scanProgress}%"></div>
									</div>
									<span class="row-progress-text">{result.scanProgress.toFixed(0)}%</span>
								</div>
							{/if}
							{#if result?.error}
								<span class="row-error">{result.error}</span>
							{/if}
						</div>
						<div class="col-lang">
							<span class="lang-badge">{getLanguageIcon(repo.language)} {repo.language}</span>
						</div>
						<div class="col-ruleset">
							{#if result?.status === 'scanning'}
								<span class="scanning-dots">
									<span class="dot"></span><span class="dot"></span><span class="dot"></span>
								</span>
							{:else if result?.status === 'complete'}
								{@const status = getRulesetStatus(result?.coverage || 0)}
								<span class="ruleset-badge {status.class}" title="{(result?.coverage || 0).toFixed(0)}% of known vulns detected">
									{status.icon} {status.text}
								</span>
							{:else}
								<span class="ruleset-badge ruleset-pending">—</span>
							{/if}
						</div>
						<div class="col-detected">
							{#if result?.status !== 'scanning'}
								<span class="detected-value">{result?.detected || 0}/{result?.total || repo.vuln_count}</span>
							{:else}
								<span class="placeholder">-</span>
							{/if}
						</div>
						<div class="col-findings">
							{#if result?.status !== 'scanning'}
								<span class="findings-value">{result?.findingsCount || 0}</span>
							{:else}
								<span class="placeholder">-</span>
							{/if}
						</div>
						<div class="col-gaps">
							{#if result?.status === 'complete' && result.missed_vulns.length > 0}
								<span class="gaps-count">{result.missed_vulns.length}</span>
							{:else if result?.status === 'complete'}
								<span class="gaps-none">0</span>
							{:else}
								<span class="placeholder">-</span>
							{/if}
						</div>
						<div class="col-actions">
							<button
								class="btn btn-sm {clickedScans.has(repo.repo) || result?.status === 'scanning' ? 'btn-scanning' : ''}"
								onclick={() => scanSingleRepo(repo.repo)}
								disabled={clickedScans.has(repo.repo) || result?.status === 'scanning'}
							>
								{#if result?.status === 'scanning'}
									<span class="btn-spinner"></span>
									Scanning...
								{:else if clickedScans.has(repo.repo)}
									<span class="btn-spinner"></span>
									Starting...
								{:else}
									Scan
								{/if}
							</button>
							{#if result?.status === 'complete' && (result.findingsCount > 0 || (result.findings && result.findings.length > 0))}
								<a
									class="btn btn-sm btn-view"
									href="/benchmark/report/{encodeURIComponent(repo.repo)}"
								>
									Report
								</a>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</div>

		<!-- Completed Reports Section -->
		{#if repos.filter(r => {
			const res = results.get(r.repo);
			return res?.status === 'complete' && res.findingsCount > 0;
		}).length > 0}
			{@const completedRepos = repos.filter(r => {
				const res = results.get(r.repo);
				return res?.status === 'complete' && res.findingsCount > 0;
			})}
			<div class="reports-section">
				<h2>Completed Reports</h2>
				<p class="reports-subtitle">Click any report to view detailed findings</p>
				<div class="reports-grid">
					{#each completedRepos as repo}
						{@const result = results.get(repo.repo)}
						{#if result}
							<a class="report-card" href="/benchmark/report/{encodeURIComponent(repo.repo)}">
								<div class="report-header">
									<span class="report-icon">{getLanguageIcon(repo.language)}</span>
									<span class="report-name">{result.name}</span>
								</div>
								<div class="report-stats">
									<div class="report-score {getGradeClass(getGradeFromScore(result.score || 0))}">
										<span class="score-val">{result.score || 0}</span>
										<span class="score-max">/100</span>
									</div>
									<div class="report-counts">
										{#if result.finding_counts?.critical}
											<span class="count-badge critical">{result.finding_counts.critical}C</span>
										{/if}
										{#if result.finding_counts?.high}
											<span class="count-badge high">{result.finding_counts.high}H</span>
										{/if}
										{#if result.finding_counts?.medium}
											<span class="count-badge medium">{result.finding_counts.medium}M</span>
										{/if}
										{#if result.finding_counts?.low}
											<span class="count-badge low">{result.finding_counts.low}L</span>
										{/if}
									</div>
								</div>
								<div class="report-footer">
									<span class="report-findings">{result.findingsCount} findings</span>
									<span class="report-coverage {getCoverageClass(result.coverage)}">{result.coverage.toFixed(0)}% coverage</span>
								</div>
							</a>
						{/if}
					{/each}
				</div>
			</div>
		{/if}

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

		<!-- Findings Modal -->
		{#if selectedRepo}
			{@const selectedResult = results.get(selectedRepo)}
			{#if selectedResult}
				<div class="modal-overlay" onclick={closeModal}>
					<div class="modal-content" onclick={(e) => e.stopPropagation()}>
						<div class="modal-header">
							<div class="modal-title-section">
								<h2>{selectedResult.name}</h2>
								<a href="https://github.com/{selectedRepo}" target="_blank" rel="noopener noreferrer" class="repo-link-modal">
									github.com/{selectedRepo}
								</a>
							</div>
							<button class="modal-close" onclick={closeModal}>×</button>
						</div>

						<div class="modal-score-section">
							<div class="score-circle-modal {getGradeClass(getGradeFromScore(selectedResult.score || 0))}">
								<span class="score-number">{selectedResult.score || 0}</span>
								<span class="score-label">/ 100</span>
							</div>
							<div class="score-details">
								<div class="summary-counts">
									{#if selectedResult.finding_counts?.critical}
										<span class="count severity-critical">{selectedResult.finding_counts.critical} Critical</span>
									{/if}
									{#if selectedResult.finding_counts?.high}
										<span class="count severity-high">{selectedResult.finding_counts.high} High</span>
									{/if}
									{#if selectedResult.finding_counts?.medium}
										<span class="count severity-medium">{selectedResult.finding_counts.medium} Medium</span>
									{/if}
									{#if selectedResult.finding_counts?.low}
										<span class="count severity-low">{selectedResult.finding_counts.low} Low</span>
									{/if}
									{#if selectedResult.finding_counts?.info}
										<span class="count severity-info">{selectedResult.finding_counts.info} Info</span>
									{/if}
								</div>
								{#if selectedResult.stack?.languages?.length}
									<div class="stack-info-modal">
										<span class="stack-label">Languages:</span>
										<span class="stack-value">{selectedResult.stack.languages.join(', ')}</span>
									</div>
								{/if}
								{#if selectedResult.stack?.frameworks?.length}
									<div class="stack-info-modal">
										<span class="stack-label">Frameworks:</span>
										<span class="stack-value">{selectedResult.stack.frameworks.join(', ')}</span>
									</div>
								{/if}
							</div>
						</div>

						<div class="modal-coverage-section">
							<div class="coverage-stat">
								<span class="coverage-label">Benchmark Coverage</span>
								<span class="coverage-value {getCoverageClass(selectedResult.coverage)}">{selectedResult.coverage.toFixed(1)}%</span>
							</div>
							<div class="coverage-stat">
								<span class="coverage-label">Known Vulns Detected</span>
								<span class="coverage-value">{selectedResult.detected}/{selectedResult.total}</span>
							</div>
						</div>

						{#if selectedResult.missed_vulns.length > 0}
							<div class="gaps-section">
								<h3>Detection Gaps ({selectedResult.missed_vulns.length})</h3>
								<div class="gaps-list">
									{#each selectedResult.missed_vulns as gap}
										<span class="gap-tag">{gap}</span>
									{/each}
								</div>
							</div>
						{/if}

						<div class="findings-section-modal">
							<h3>All Findings ({selectedResult.findings?.length || 0})</h3>
							<div class="findings-list">
								{#each selectedResult.findings || [] as finding, i}
									{@const findingId = finding.id || `finding-${i}`}
									{@const isExpanded = expandedFindings.has(findingId)}
									<div class="finding-card" class:expanded={isExpanded}>
										<button class="finding-toggle" onclick={() => toggleFinding(findingId)}>
											<div class="finding-header">
												<span class="severity-badge {getSeverityClass(finding.severity)}">
													{finding.severity.toUpperCase()}
												</span>
												<span class="finding-category">{finding.category}</span>
												<span class="finding-chevron" class:rotated={isExpanded}>▼</span>
											</div>
											<h4 class="finding-title">{finding.title}</h4>
										</button>

										{#if isExpanded}
											<div class="finding-details">
												{#if finding.location?.file}
													<div class="finding-location">
														<span class="location-label">Location:</span>
														<code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
													</div>
												{/if}

												{#if finding.snippet?.code}
													<div class="finding-snippet">
														<pre><code>{finding.snippet.code}</code></pre>
													</div>
												{/if}

												{#if finding.description}
													<p class="finding-description">{finding.description}</p>
												{/if}

												{#if finding.fix?.available && finding.fix?.template}
													<div class="finding-fix">
														<span class="fix-label">Suggested Fix:</span>
														<pre><code>{finding.fix.template}</code></pre>
													</div>
												{/if}
											</div>
										{/if}
									</div>
								{/each}
							</div>
						</div>
					</div>
				</div>
			{/if}
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

	.benchmark-page {
		padding: 8rem 2rem 4rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: calc(100vh - 80px);
	}

	.benchmark-header {
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
		gap: 1rem;
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
		align-items: center;
		flex-wrap: wrap;
	}

	.running-indicator {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.85rem;
		color: var(--text-secondary);
	}

	.pulse-dot {
		width: 8px;
		height: 8px;
		background: var(--green);
		border-radius: 50%;
		animation: pulse-dot 1.5s infinite;
	}

	@keyframes pulse-dot {
		0%, 100% { opacity: 1; transform: scale(1); }
		50% { opacity: 0.5; transform: scale(1.2); }
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
		border-radius: 4px;
	}

	.btn:hover:not(:disabled) {
		border-color: var(--text-primary);
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: var(--purple, #9d8cff);
		border-color: var(--purple, #9d8cff);
		color: white;
	}

	.btn-primary:hover:not(:disabled) {
		filter: brightness(1.1);
	}

	.btn-secondary {
		background: var(--blue, #3b82f6);
		border-color: var(--blue, #3b82f6);
		color: white;
	}

	.btn-glow {
		background: var(--green, #00c49a);
		border-color: var(--green, #00c49a);
		color: var(--bg-primary, #0a0a1a);
		box-shadow: 0 0 20px rgba(0, 196, 154, 0.3);
	}

	.btn-glow:hover:not(:disabled) {
		box-shadow: 0 0 30px rgba(0, 196, 154, 0.5);
	}

	.btn-stop {
		background: var(--red, #ff6b6b);
		border-color: var(--red, #ff6b6b);
		color: white;
	}

	.btn-sm {
		padding: 0.5rem 1rem;
		font-size: 0.8rem;
	}

	.btn-scanning {
		background: var(--purple, #9d8cff);
		border-color: var(--purple, #9d8cff);
		color: white;
	}

	.btn-spinner {
		display: inline-block;
		width: 12px;
		height: 12px;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin-right: 0.5rem;
		vertical-align: middle;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
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
		border: 1px solid var(--red, #ff6b6b);
		margin-bottom: 2rem;
		color: var(--red, #ff6b6b);
		border-radius: 4px;
	}

	.error-dismiss {
		margin-left: auto;
		background: none;
		border: none;
		color: var(--red, #ff6b6b);
		cursor: pointer;
		font-size: 1.25rem;
	}

	.auto-improve-banner {
		background: linear-gradient(135deg, rgba(0, 196, 154, 0.1), rgba(59, 130, 246, 0.1));
		border: 1px solid var(--green, #00c49a);
		border-radius: 8px;
		padding: 1.5rem;
		margin-bottom: 2rem;
	}

	.auto-improve-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}

	.auto-improve-icon {
		font-size: 1.5rem;
	}

	.auto-improve-title {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--green, #00c49a);
	}

	.auto-improve-status {
		color: var(--text-secondary);
		margin-bottom: 1rem;
	}

	.auto-improve-progress {
		height: 6px;
		background: var(--bg-tertiary, #1a1a2e);
		border-radius: 3px;
		overflow: hidden;
	}

	.auto-improve-fill {
		height: 100%;
		background: linear-gradient(90deg, var(--green, #00c49a), var(--blue, #3b82f6));
		transition: width 0.5s ease;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
		margin-bottom: 2rem;
	}

	.stat-card {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		padding: 1.5rem;
		border-radius: 4px;
	}

	.stat-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary, #666);
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
		color: var(--text-secondary, #888);
	}

	.coverage-bar {
		position: relative;
		height: 4px;
		background: var(--bg-tertiary, #1a1a2e);
		margin-top: 1rem;
		overflow: visible;
		border-radius: 2px;
	}

	.coverage-fill {
		height: 100%;
		transition: width 0.5s ease;
		border-radius: 2px;
	}

	.coverage-fill.coverage-excellent { background: var(--green, #00c49a); }
	.coverage-fill.coverage-good { background: var(--blue, #3b82f6); }
	.coverage-fill.coverage-fair { background: var(--orange, #f59e0b); }
	.coverage-fill.coverage-poor { background: var(--red, #ff6b6b); }

	.coverage-target {
		position: absolute;
		top: -4px;
		width: 2px;
		height: 12px;
		background: var(--text-primary, #fff);
	}

	.coverage-excellent { color: var(--green, #00c49a); }
	.coverage-good { color: var(--blue, #3b82f6); }
	.coverage-fair { color: var(--orange, #f59e0b); }
	.coverage-poor { color: var(--red, #ff6b6b); }

	/* Ruleset Status Styles */
	.ruleset-complete { color: var(--green, #00c49a); }
	.ruleset-good { color: var(--blue, #3b82f6); }
	.ruleset-partial { color: var(--orange, #f59e0b); }
	.ruleset-missing { color: var(--red, #ff6b6b); }
	.ruleset-pending { color: var(--text-secondary, #888); }

	.ruleset-icon {
		font-size: 1.2em;
		margin-right: 0.25rem;
	}

	.ruleset-badge {
		font-size: 0.75rem;
		font-weight: 500;
		padding: 0.2rem 0.5rem;
		border-radius: 4px;
		background: rgba(255, 255, 255, 0.05);
		white-space: nowrap;
	}

	.ruleset-badge.ruleset-complete { background: rgba(0, 196, 154, 0.15); }
	.ruleset-badge.ruleset-good { background: rgba(59, 130, 246, 0.15); }
	.ruleset-badge.ruleset-partial { background: rgba(245, 158, 11, 0.15); }
	.ruleset-badge.ruleset-missing { background: rgba(255, 107, 107, 0.15); }

	.col-ruleset {
		min-width: 100px;
	}

	/* Reports Section */
	.reports-section {
		margin-bottom: 2rem;
	}

	.reports-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		font-weight: 400;
		margin-bottom: 0.25rem;
	}

	.reports-subtitle {
		color: var(--text-secondary, #888);
		font-size: 0.9rem;
		margin-bottom: 1rem;
	}

	.reports-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
		gap: 1rem;
	}

	.report-card {
		display: block;
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 8px;
		padding: 1.25rem;
		cursor: pointer;
		transition: all 0.2s;
		text-align: left;
		text-decoration: none;
		color: inherit;
	}

	.report-card:hover {
		border-color: var(--purple, #9d8cff);
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
	}

	.report-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.report-icon {
		font-size: 1.25rem;
	}

	.report-name {
		font-weight: 500;
		font-size: 1rem;
		color: var(--text-primary, #fff);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.report-stats {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.report-score {
		display: flex;
		align-items: baseline;
		gap: 0.125rem;
	}

	.report-score .score-val {
		font-family: 'Instrument Serif', serif;
		font-size: 2rem;
		line-height: 1;
	}

	.report-score .score-max {
		font-size: 0.8rem;
		color: var(--text-tertiary, #666);
	}

	.report-counts {
		display: flex;
		gap: 0.375rem;
	}

	.count-badge {
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.count-badge.critical {
		background: rgba(255, 77, 77, 0.2);
		color: #ff4d4d;
	}

	.count-badge.high {
		background: rgba(255, 107, 107, 0.2);
		color: #ff6b6b;
	}

	.count-badge.medium {
		background: rgba(255, 176, 32, 0.2);
		color: #ffb020;
	}

	.count-badge.low {
		background: rgba(59, 130, 246, 0.2);
		color: #3b82f6;
	}

	.report-footer {
		display: flex;
		justify-content: space-between;
		font-size: 0.8rem;
		color: var(--text-secondary, #888);
		padding-top: 0.75rem;
		border-top: 1px solid var(--border, #333);
	}

	.progress-section {
		margin-bottom: 2rem;
		padding: 1.5rem;
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
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
		border-radius: 2px 2px 0 0;
	}

	.progress-bar.coverage-excellent { background: var(--green, #00c49a); }
	.progress-bar.coverage-good { background: var(--blue, #3b82f6); }
	.progress-bar.coverage-fair { background: var(--orange, #f59e0b); }
	.progress-bar.coverage-poor { background: var(--red, #ff6b6b); }

	.progress-label {
		font-size: 0.7rem;
		color: var(--bg-primary, #0a0a1a);
		font-weight: 600;
		padding: 0.25rem;
	}

	.progress-iteration {
		font-size: 0.7rem;
		color: var(--text-tertiary, #666);
		margin-top: 0.5rem;
	}

	.repos-section h2, .history-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		font-weight: 400;
		margin-bottom: 1rem;
	}

	/* Table-based repo list */
	.repos-table {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
		overflow: hidden;
		margin-bottom: 2rem;
	}

	.repos-header {
		display: grid;
		grid-template-columns: 60px 1fr 100px 90px 90px 80px 60px 140px;
		padding: 0.75rem 1rem;
		background: var(--bg-tertiary, #1a1a2e);
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary, #666);
		font-weight: 600;
		gap: 0.5rem;
	}

	.repo-row {
		display: grid;
		grid-template-columns: 60px 1fr 100px 90px 90px 80px 60px 140px;
		padding: 0.875rem 1rem;
		border-top: 1px solid var(--border, #333);
		align-items: center;
		gap: 0.5rem;
		transition: background 0.15s;
	}

	.repo-row:hover {
		background: var(--bg-tertiary, #1a1a2e);
	}

	.repo-row.scanning {
		background: rgba(157, 140, 255, 0.05);
	}

	.repo-row.complete {
		background: rgba(0, 196, 154, 0.03);
	}

	.repo-row.error {
		background: rgba(255, 107, 107, 0.05);
	}

	.col-status {
		display: flex;
		justify-content: center;
	}

	.col-name {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		min-width: 0;
	}

	.col-lang, .col-ruleset, .col-detected, .col-findings, .col-gaps {
		text-align: center;
	}

	.col-actions {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
	}

	.status-icon {
		width: 24px;
		height: 24px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 50%;
		font-size: 0.8rem;
	}

	.status-icon.pending { background: var(--bg-tertiary, #1a1a2e); color: var(--text-tertiary, #666); }
	.status-icon.scanning { background: var(--purple, #9d8cff); color: white; animation: pulse 1s infinite; }
	.status-icon.complete { background: var(--green, #00c49a); color: var(--bg-primary, #0a0a1a); }
	.status-icon.error { background: var(--red, #ff6b6b); color: white; }

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.5; }
	}

	.repo-name {
		font-weight: 500;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.lang-badge {
		font-size: 0.75rem;
		color: var(--text-secondary, #888);
	}

	.coverage-value {
		font-weight: 600;
		font-size: 0.95rem;
	}

	.detected-value, .findings-value {
		font-size: 0.9rem;
		color: var(--text-secondary, #888);
	}

	.gaps-count {
		background: rgba(255, 107, 107, 0.15);
		color: #ff6b6b;
		padding: 0.2rem 0.5rem;
		border-radius: 10px;
		font-size: 0.8rem;
		font-weight: 600;
	}

	.gaps-none {
		color: var(--green, #00c49a);
		font-weight: 500;
	}

	.placeholder {
		color: var(--text-tertiary, #666);
	}

	.row-progress {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.row-progress-bar {
		flex: 1;
		height: 4px;
		background: var(--bg-tertiary, #1a1a2e);
		border-radius: 2px;
		overflow: hidden;
		max-width: 120px;
	}

	.row-progress-fill {
		height: 100%;
		background: linear-gradient(90deg, var(--purple, #9d8cff), var(--blue, #3b82f6));
		transition: width 0.1s ease;
	}

	.row-progress-text {
		font-size: 0.7rem;
		color: var(--purple, #9d8cff);
		min-width: 30px;
	}

	.row-error {
		font-size: 0.75rem;
		color: var(--red, #ff6b6b);
	}

	.scanning-dots {
		display: flex;
		gap: 3px;
		justify-content: center;
	}

	.scanning-dots .dot {
		width: 5px;
		height: 5px;
		background: var(--purple, #9d8cff);
		border-radius: 50%;
		animation: scan-bounce 1.4s infinite ease-in-out both;
	}

	.scanning-dots .dot:nth-child(1) { animation-delay: -0.32s; }
	.scanning-dots .dot:nth-child(2) { animation-delay: -0.16s; }

	@keyframes scan-bounce {
		0%, 80%, 100% { transform: scale(0); }
		40% { transform: scale(1); }
	}

	/* Keep old ring styles for potential future use but unused now */
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
		stroke: var(--bg-tertiary, #1a1a2e);
		stroke-width: 3;
	}

	.ring-fill {
		fill: none;
		stroke: currentColor;
		stroke-width: 3;
		stroke-linecap: round;
		transition: stroke-dasharray 0.5s ease;
	}

	.coverage-text-ring {
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
		border-top: 1px solid var(--border, #333);
		border-bottom: 1px solid var(--border, #333);
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
		color: var(--text-tertiary, #666);
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
		border: 1px solid rgba(0, 196, 154, 0.3);
		color: var(--green, #00c49a);
		font-size: 0.8rem;
		margin-bottom: 1rem;
		border-radius: 4px;
	}

	.missed-vulns {
		margin-bottom: 1rem;
	}

	.missed-label {
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
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
		border: 1px solid var(--red, #ff6b6b);
		color: var(--red, #ff6b6b);
		border-radius: 2px;
	}

	.missed-more {
		font-size: 0.7rem;
		color: var(--text-tertiary, #666);
		padding: 0.2rem 0.5rem;
	}

	.repo-error {
		font-size: 0.8rem;
		color: var(--red, #ff6b6b);
		margin-bottom: 1rem;
		padding: 0.5rem;
		background: rgba(255, 107, 107, 0.1);
		border-radius: 4px;
	}

	.repo-actions {
		display: flex;
		justify-content: center;
	}

	.history-section {
		margin-bottom: 2rem;
	}

	.history-table {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
		overflow: hidden;
	}

	.history-header, .history-row {
		display: grid;
		grid-template-columns: 60px 1fr 100px 100px 100px;
		padding: 0.75rem 1rem;
		gap: 1rem;
	}

	.history-header {
		background: var(--bg-tertiary, #1a1a2e);
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary, #666);
		font-weight: 500;
	}

	.history-row {
		border-top: 1px solid var(--border, #333);
	}

	.run-number {
		font-weight: 500;
	}

	.run-time {
		font-size: 0.85rem;
		color: var(--text-secondary, #888);
	}

	.run-coverage {
		font-weight: 600;
	}

	.run-rules {
		color: var(--green, #00c49a);
	}

	@media (max-width: 1024px) {
		.repos-header, .repo-row {
			grid-template-columns: 50px 1fr 80px 70px 60px 100px;
		}

		.col-detected, .col-gaps {
			display: none;
		}

		.repos-header .col-detected,
		.repos-header .col-gaps {
			display: none;
		}
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

		.repos-header, .repo-row {
			grid-template-columns: 40px 1fr 70px 80px;
		}

		.col-lang, .col-detected, .col-findings, .col-gaps {
			display: none;
		}

		.repos-header .col-lang,
		.repos-header .col-detected,
		.repos-header .col-findings,
		.repos-header .col-gaps {
			display: none;
		}

		.col-actions {
			flex-direction: column;
			gap: 0.25rem;
		}

		.col-actions .btn {
			font-size: 0.7rem;
			padding: 0.4rem 0.6rem;
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

	/* View Report Button */
	.btn-view {
		background: transparent;
		border-color: var(--purple, #9d8cff);
		color: var(--purple, #9d8cff);
	}

	.btn-view:hover:not(:disabled) {
		background: rgba(157, 140, 255, 0.1);
	}

	/* Modal Styles */
	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.8);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: 2rem;
		overflow-y: auto;
	}

	.modal-content {
		background: var(--bg-primary, #0a0a1a);
		border: 1px solid var(--border, #333);
		border-radius: 8px;
		max-width: 900px;
		width: 100%;
		max-height: 90vh;
		overflow-y: auto;
		position: relative;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 1.5rem;
		border-bottom: 1px solid var(--border, #333);
		position: sticky;
		top: 0;
		background: var(--bg-primary, #0a0a1a);
		z-index: 10;
	}

	.modal-title-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 0.25rem;
	}

	.repo-link-modal {
		font-size: 0.85rem;
		color: var(--text-secondary, #888);
		text-decoration: none;
	}

	.repo-link-modal:hover {
		color: var(--purple, #9d8cff);
	}

	.modal-close {
		background: none;
		border: none;
		color: var(--text-secondary, #888);
		font-size: 2rem;
		cursor: pointer;
		line-height: 1;
		padding: 0;
	}

	.modal-close:hover {
		color: var(--text-primary, #fff);
	}

	.modal-score-section {
		display: flex;
		gap: 2rem;
		padding: 1.5rem;
		border-bottom: 1px solid var(--border, #333);
		align-items: center;
	}

	.score-circle-modal {
		width: 100px;
		height: 100px;
		border-radius: 50%;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		border: 3px solid currentColor;
		flex-shrink: 0;
	}

	.score-circle-modal .score-number {
		font-family: 'Instrument Serif', serif;
		font-size: 2rem;
		line-height: 1;
	}

	.score-circle-modal .score-label {
		font-size: 0.7rem;
		color: var(--text-secondary, #888);
	}

	.grade-a { color: var(--green, #00c49a); border-color: var(--green, #00c49a); }
	.grade-b { color: #84cc16; border-color: #84cc16; }
	.grade-c { color: var(--orange, #f59e0b); border-color: var(--orange, #f59e0b); }
	.grade-d { color: #f97316; border-color: #f97316; }
	.grade-f { color: var(--red, #ff6b6b); border-color: var(--red, #ff6b6b); }

	.score-details {
		flex: 1;
	}

	.summary-counts {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.count {
		padding: 0.375rem 0.75rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 500;
	}

	.severity-critical { background: rgba(255, 77, 77, 0.15); color: #ff4d4d; }
	.severity-high { background: rgba(255, 107, 107, 0.15); color: #ff6b6b; }
	.severity-medium { background: rgba(255, 176, 32, 0.15); color: #ffb020; }
	.severity-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
	.severity-info { background: rgba(136, 136, 136, 0.15); color: #888; }

	.stack-info-modal {
		font-size: 0.85rem;
		color: var(--text-secondary, #888);
		margin-bottom: 0.25rem;
	}

	.stack-label {
		color: var(--text-tertiary, #666);
	}

	.modal-coverage-section {
		display: flex;
		gap: 2rem;
		padding: 1rem 1.5rem;
		background: var(--bg-secondary, #111);
	}

	.coverage-stat {
		display: flex;
		flex-direction: column;
	}

	.coverage-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary, #666);
	}

	.coverage-value {
		font-size: 1.5rem;
		font-weight: 600;
	}

	.gaps-section {
		padding: 1.5rem;
		border-bottom: 1px solid var(--border, #333);
	}

	.gaps-section h3 {
		font-size: 1rem;
		margin-bottom: 0.75rem;
		color: var(--red, #ff6b6b);
	}

	.gaps-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.gap-tag {
		background: rgba(255, 107, 107, 0.15);
		color: #ff6b6b;
		padding: 0.375rem 0.75rem;
		border-radius: 4px;
		font-size: 0.8rem;
		font-family: monospace;
	}

	.findings-section-modal {
		padding: 1.5rem;
	}

	.findings-section-modal h3 {
		font-size: 1rem;
		margin-bottom: 1rem;
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.finding-card {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 4px;
		overflow: hidden;
	}

	.finding-card.expanded {
		border-color: var(--purple, #9d8cff);
	}

	.finding-toggle {
		width: 100%;
		padding: 1rem;
		background: none;
		border: none;
		color: var(--text-primary, #fff);
		text-align: left;
		cursor: pointer;
	}

	.finding-toggle:hover {
		background: var(--bg-tertiary, #1a1a2e);
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.severity-badge {
		padding: 0.25rem 0.5rem;
		border-radius: 3px;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.finding-category {
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
		text-transform: uppercase;
	}

	.finding-chevron {
		margin-left: auto;
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
		transition: transform 0.2s;
	}

	.finding-chevron.rotated {
		transform: rotate(180deg);
	}

	.finding-title {
		font-size: 0.95rem;
		font-weight: 500;
		margin: 0;
	}

	.finding-details {
		padding: 0 1rem 1rem;
		border-top: 1px solid var(--border, #333);
	}

	.finding-location {
		margin-top: 1rem;
		font-size: 0.85rem;
	}

	.location-label {
		color: var(--text-tertiary, #666);
		margin-right: 0.5rem;
	}

	.finding-location code {
		background: var(--bg-tertiary, #1a1a2e);
		padding: 0.25rem 0.5rem;
		border-radius: 3px;
		font-size: 0.8rem;
	}

	.finding-snippet {
		margin-top: 1rem;
		background: var(--bg-tertiary, #1a1a2e);
		border-radius: 4px;
		overflow-x: auto;
	}

	.finding-snippet pre {
		margin: 0;
		padding: 1rem;
	}

	.finding-snippet code {
		font-size: 0.8rem;
		white-space: pre-wrap;
		word-break: break-all;
	}

	.finding-description {
		margin-top: 1rem;
		font-size: 0.9rem;
		color: var(--text-secondary, #888);
		line-height: 1.5;
	}

	.finding-fix {
		margin-top: 1rem;
		padding: 1rem;
		background: rgba(0, 196, 154, 0.1);
		border: 1px solid rgba(0, 196, 154, 0.3);
		border-radius: 4px;
	}

	.fix-label {
		display: block;
		font-size: 0.75rem;
		text-transform: uppercase;
		color: var(--green, #00c49a);
		margin-bottom: 0.5rem;
	}

	.finding-fix pre {
		margin: 0;
	}

	.finding-fix code {
		font-size: 0.8rem;
		color: var(--text-primary, #fff);
	}
</style>
