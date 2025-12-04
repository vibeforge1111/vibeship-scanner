<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	const SCANNER_URL = 'https://scanner-empty-field-5676.fly.dev';
	const BENCHMARK_SECRET = 'vibeship-benchmark-2024';
	const PASSWORD_HASH = '69b86692b84806ffc45e9d9b5fa44320';

	let isAuthenticated = $state(false);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let report = $state<any>(null);
	let expandedFindings = $state<Set<string>>(new Set());

	// Get repo from URL params (e.g., OWASP/NodeGoat becomes OWASP%2FNodeGoat)
	$effect(() => {
		const repoParam = $page.params.repo;
		if (repoParam && isAuthenticated) {
			loadReport(decodeURIComponent(repoParam));
		}
	});

	onMount(() => {
		const stored = localStorage.getItem('benchmark_auth');
		if (stored === PASSWORD_HASH) {
			isAuthenticated = true;
		} else {
			goto('/benchmark');
		}
	});

	async function loadReport(repoName: string) {
		loading = true;
		error = null;

		// First try to load from localStorage cache
		const cached = loadFromCache(repoName);
		if (cached) {
			report = cached;
			loading = false;
			return;
		}

		// If not cached, scan the repo
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
				error = data.error;
			} else if (data.result) {
				report = data.result;
				saveToCache(repoName, report);
			}
		} catch (e) {
			error = String(e);
		}

		loading = false;
	}

	function loadFromCache(repoName: string): any {
		try {
			const stored = localStorage.getItem('benchmark_data');
			if (!stored) return null;
			const data = JSON.parse(stored);
			const results = data.results || [];
			const found = results.find((r: any) => r.repo === repoName && r.status === 'complete');
			return found || null;
		} catch {
			return null;
		}
	}

	function saveToCache(repoName: string, result: any) {
		try {
			const stored = localStorage.getItem('benchmark_data');
			const data = stored ? JSON.parse(stored) : { results: [], repos: [] };

			// Update or add result
			const idx = data.results.findIndex((r: any) => r.repo === repoName);
			const entry = {
				repo: repoName,
				name: result.name,
				language: result.stack?.languages?.[0] || 'unknown',
				status: 'complete',
				coverage: (result.coverage || 0) * 100,
				detected: result.detected_count || 0,
				total: (result.detected_count || 0) + (result.missed_count || 0),
				findingsCount: result.total_findings || 0,
				detected_vulns: (result.detected || []).map((v: any) => v.id),
				missed_vulns: (result.missed || []).map((v: any) => v.id),
				findings: result.findings || [],
				score: result.score,
				finding_counts: result.finding_counts,
				stack: result.stack
			};

			if (idx >= 0) {
				data.results[idx] = entry;
			} else {
				data.results.push(entry);
			}

			data.savedAt = new Date().toISOString();
			localStorage.setItem('benchmark_data', JSON.stringify(data));
		} catch (e) {
			console.error('Failed to save to cache:', e);
		}
	}

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

	function getCoverageClass(coverage: number): string {
		if (coverage >= 90) return 'coverage-excellent';
		if (coverage >= 70) return 'coverage-good';
		if (coverage >= 50) return 'coverage-fair';
		return 'coverage-poor';
	}

	function toggleFinding(id: string) {
		if (expandedFindings.has(id)) {
			expandedFindings.delete(id);
		} else {
			expandedFindings.add(id);
		}
		expandedFindings = new Set(expandedFindings);
	}

	function downloadReport() {
		if (!report) return;

		const reportData = {
			generated: new Date().toISOString(),
			repository: report.repo || report.name,
			score: report.score,
			grade: getGradeFromScore(report.score || 0),
			coverage: {
				percentage: ((report.coverage || 0) * 100).toFixed(1) + '%',
				detected: report.detected_count || 0,
				total: (report.detected_count || 0) + (report.missed_count || 0)
			},
			finding_summary: report.finding_counts,
			total_findings: report.total_findings || report.findings?.length || 0,
			detected_vulnerabilities: report.detected || [],
			missed_vulnerabilities: report.missed || [],
			findings: report.findings || [],
			stack: report.stack
		};

		const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `benchmark-report-${(report.repo || report.name || 'unknown').replace(/\//g, '-')}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function goBack() {
		goto('/benchmark');
	}
</script>

<svelte:head>
	<title>Benchmark Report | Vibeship Scanner</title>
</svelte:head>

<div class="report-page">
	<div class="report-nav">
		<button class="btn btn-back" onclick={goBack}>
			<span class="back-arrow">←</span>
			Back to Dashboard
		</button>
		{#if report}
			<button class="btn btn-download" onclick={downloadReport}>
				<span class="download-icon">↓</span>
				Download Report
			</button>
		{/if}
	</div>

	{#if loading}
		<div class="loading-state">
			<div class="spinner"></div>
			<p>Loading report...</p>
		</div>
	{:else if error}
		<div class="error-state">
			<h2>Error</h2>
			<p>{error}</p>
			<button class="btn btn-primary" onclick={goBack}>Go Back</button>
		</div>
	{:else if report}
		<div class="report-content">
			<!-- Header -->
			<div class="report-header">
				<div class="header-left">
					<h1>{report.name || report.repo}</h1>
					<a href="https://github.com/{report.repo || $page.params.repo}" target="_blank" rel="noopener noreferrer" class="repo-link">
						github.com/{report.repo || decodeURIComponent($page.params.repo)}
					</a>
				</div>
				<div class="header-right">
					<div class="score-circle {getGradeClass(getGradeFromScore(report.score || 0))}">
						<span class="score-value">{report.score || 0}</span>
						<span class="score-max">/100</span>
					</div>
				</div>
			</div>

			<!-- Summary Cards -->
			<div class="summary-grid">
				<div class="summary-card">
					<h3>Findings</h3>
					<div class="summary-value">{report.total_findings || report.findings?.length || 0}</div>
					<div class="severity-breakdown">
						{#if report.finding_counts?.critical}
							<span class="severity-badge critical">{report.finding_counts.critical} Critical</span>
						{/if}
						{#if report.finding_counts?.high}
							<span class="severity-badge high">{report.finding_counts.high} High</span>
						{/if}
						{#if report.finding_counts?.medium}
							<span class="severity-badge medium">{report.finding_counts.medium} Medium</span>
						{/if}
						{#if report.finding_counts?.low}
							<span class="severity-badge low">{report.finding_counts.low} Low</span>
						{/if}
					</div>
				</div>

				<div class="summary-card coverage-card">
					<h3>Known Vuln Coverage</h3>
					<div class="summary-value {getCoverageClass((report.coverage || 0) * 100)}">
						{((report.coverage || 0) * 100).toFixed(0)}%
					</div>
					<div class="coverage-detail">
						{report.detected_count || 0} of {(report.detected_count || 0) + (report.missed_count || 0)} detected
					</div>
					<div class="coverage-bar">
						<div class="coverage-fill {getCoverageClass((report.coverage || 0) * 100)}"
							 style="width: {(report.coverage || 0) * 100}%"></div>
					</div>
				</div>

				<div class="summary-card">
					<h3>Stack</h3>
					<div class="stack-info">
						{#if report.stack?.languages?.length}
							<div class="stack-row">
								<span class="stack-label">Languages:</span>
								<span class="stack-value">{report.stack.languages.join(', ')}</span>
							</div>
						{/if}
						{#if report.stack?.frameworks?.length}
							<div class="stack-row">
								<span class="stack-label">Frameworks:</span>
								<span class="stack-value">{report.stack.frameworks.join(', ')}</span>
							</div>
						{/if}
					</div>
				</div>
			</div>

			<!-- Coverage Analysis -->
			{#if (report.detected?.length > 0 || report.missed?.length > 0)}
				<div class="coverage-section">
					<h2>Coverage Analysis</h2>
					<p class="section-subtitle">Comparison against known vulnerabilities in this repository</p>

					<div class="coverage-grid">
						{#if report.detected?.length > 0}
							<div class="coverage-column detected">
								<h3>Detected ({report.detected.length})</h3>
								<div class="vuln-list">
									{#each report.detected as vuln}
										<div class="vuln-item detected">
											<span class="vuln-icon">✓</span>
											<div class="vuln-content">
												<span class="vuln-id">{vuln.id}</span>
												<span class="vuln-desc">{vuln.description}</span>
												<span class="vuln-type">{vuln.type}</span>
											</div>
										</div>
									{/each}
								</div>
							</div>
						{/if}

						{#if report.missed?.length > 0}
							<div class="coverage-column missed">
								<h3>Gaps ({report.missed.length})</h3>
								<div class="vuln-list">
									{#each report.missed as vuln}
										<div class="vuln-item missed">
											<span class="vuln-icon">✗</span>
											<div class="vuln-content">
												<span class="vuln-id">{vuln.id}</span>
												<span class="vuln-desc">{vuln.description}</span>
												<span class="vuln-type">{vuln.type}</span>
												{#if vuln.file}
													<span class="vuln-file">{vuln.file}</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							</div>
						{/if}
					</div>
				</div>
			{/if}

			<!-- All Findings -->
			<div class="findings-section">
				<h2>All Findings ({report.findings?.length || 0})</h2>
				<p class="section-subtitle">Complete list of security issues detected</p>

				<div class="findings-list">
					{#each report.findings || [] as finding, i}
						{@const findingId = finding.id || `finding-${i}`}
						{@const isExpanded = expandedFindings.has(findingId)}
						<div class="finding-card" class:expanded={isExpanded}>
							<button class="finding-header" onclick={() => toggleFinding(findingId)}>
								<div class="finding-meta">
									<span class="severity-tag {getSeverityClass(finding.severity)}">
										{finding.severity?.toUpperCase()}
									</span>
									<span class="finding-category">{finding.category}</span>
								</div>
								<h4 class="finding-title">{finding.title}</h4>
								<span class="finding-chevron" class:rotated={isExpanded}>▼</span>
							</button>

							{#if isExpanded}
								<div class="finding-body">
									{#if finding.location?.file}
										<div class="finding-location">
											<span class="label">Location:</span>
											<code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
										</div>
									{/if}

									{#if finding.snippet?.code}
										<div class="finding-snippet">
											<span class="label">Code:</span>
											<pre><code>{finding.snippet.code}</code></pre>
										</div>
									{/if}

									{#if finding.description}
										<div class="finding-description">
											<span class="label">Description:</span>
											<p>{finding.description}</p>
										</div>
									{/if}

									{#if finding.fix?.available && finding.fix?.template}
										<div class="finding-fix">
											<span class="label">Suggested Fix:</span>
											<pre><code>{finding.fix.template}</code></pre>
										</div>
									{/if}

									{#if finding.references?.length}
										<div class="finding-refs">
											<span class="label">References:</span>
											<ul>
												{#each finding.references as ref}
													<li><a href={ref} target="_blank" rel="noopener">{ref}</a></li>
												{/each}
											</ul>
										</div>
									{/if}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.report-page {
		padding: 6rem 2rem 4rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}

	.report-nav {
		display: flex;
		justify-content: space-between;
		margin-bottom: 2rem;
	}

	.btn {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.25rem;
		border: 1px solid var(--border, #333);
		background: var(--bg-secondary, #111);
		color: var(--text-primary, #fff);
		cursor: pointer;
		font-size: 0.9rem;
		border-radius: 4px;
		transition: all 0.15s;
	}

	.btn:hover {
		border-color: var(--text-primary, #fff);
	}

	.btn-back {
		background: transparent;
	}

	.btn-download {
		background: var(--purple, #9d8cff);
		border-color: var(--purple, #9d8cff);
	}

	.btn-download:hover {
		filter: brightness(1.1);
	}

	.btn-primary {
		background: var(--purple, #9d8cff);
		border-color: var(--purple, #9d8cff);
	}

	.loading-state, .error-state {
		text-align: center;
		padding: 4rem 2rem;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--border, #333);
		border-top-color: var(--purple, #9d8cff);
		border-radius: 50%;
		animation: spin 1s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.error-state h2 {
		color: var(--red, #ff6b6b);
		margin-bottom: 1rem;
	}

	.report-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 2rem;
		padding-bottom: 2rem;
		border-bottom: 1px solid var(--border, #333);
	}

	.report-header h1 {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		font-weight: 400;
		margin-bottom: 0.5rem;
	}

	.repo-link {
		color: var(--text-secondary, #888);
		text-decoration: none;
		font-size: 0.95rem;
	}

	.repo-link:hover {
		color: var(--purple, #9d8cff);
	}

	.score-circle {
		width: 100px;
		height: 100px;
		border-radius: 50%;
		border: 3px solid currentColor;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
	}

	.score-value {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		line-height: 1;
	}

	.score-max {
		font-size: 0.8rem;
		color: var(--text-secondary, #888);
	}

	.grade-a { color: var(--green, #00c49a); }
	.grade-b { color: #84cc16; }
	.grade-c { color: var(--orange, #f59e0b); }
	.grade-d { color: #f97316; }
	.grade-f { color: var(--red, #ff6b6b); }

	.summary-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 1.5rem;
		margin-bottom: 3rem;
	}

	.summary-card {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 8px;
		padding: 1.5rem;
	}

	.summary-card h3 {
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary, #666);
		margin-bottom: 0.75rem;
	}

	.summary-value {
		font-family: 'Instrument Serif', serif;
		font-size: 3rem;
		line-height: 1;
		margin-bottom: 0.75rem;
	}

	.severity-breakdown {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.severity-badge {
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 500;
	}

	.severity-badge.critical, .severity-critical { background: rgba(255, 77, 77, 0.15); color: #ff4d4d; }
	.severity-badge.high, .severity-high { background: rgba(255, 107, 107, 0.15); color: #ff6b6b; }
	.severity-badge.medium, .severity-medium { background: rgba(255, 176, 32, 0.15); color: #ffb020; }
	.severity-badge.low, .severity-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
	.severity-badge.info, .severity-info { background: rgba(136, 136, 136, 0.15); color: #888; }

	.coverage-excellent { color: var(--green, #00c49a); }
	.coverage-good { color: var(--blue, #3b82f6); }
	.coverage-fair { color: var(--orange, #f59e0b); }
	.coverage-poor { color: var(--red, #ff6b6b); }

	.coverage-detail {
		font-size: 0.9rem;
		color: var(--text-secondary, #888);
		margin-bottom: 0.75rem;
	}

	.coverage-bar {
		height: 6px;
		background: var(--bg-tertiary, #1a1a2e);
		border-radius: 3px;
		overflow: hidden;
	}

	.coverage-fill {
		height: 100%;
		border-radius: 3px;
		transition: width 0.3s;
	}

	.coverage-fill.coverage-excellent { background: var(--green, #00c49a); }
	.coverage-fill.coverage-good { background: var(--blue, #3b82f6); }
	.coverage-fill.coverage-fair { background: var(--orange, #f59e0b); }
	.coverage-fill.coverage-poor { background: var(--red, #ff6b6b); }

	.stack-info {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.stack-row {
		display: flex;
		gap: 0.5rem;
	}

	.stack-label {
		color: var(--text-tertiary, #666);
		font-size: 0.85rem;
	}

	.stack-value {
		color: var(--text-primary, #fff);
		font-size: 0.85rem;
	}

	.coverage-section, .findings-section {
		margin-bottom: 3rem;
	}

	.coverage-section h2, .findings-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.75rem;
		font-weight: 400;
		margin-bottom: 0.25rem;
	}

	.section-subtitle {
		color: var(--text-secondary, #888);
		margin-bottom: 1.5rem;
	}

	.coverage-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
		gap: 1.5rem;
	}

	.coverage-column {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 8px;
		padding: 1.5rem;
	}

	.coverage-column.detected {
		border-color: rgba(0, 196, 154, 0.3);
	}

	.coverage-column.missed {
		border-color: rgba(255, 107, 107, 0.3);
	}

	.coverage-column h3 {
		font-size: 1rem;
		margin-bottom: 1rem;
	}

	.coverage-column.detected h3 {
		color: var(--green, #00c49a);
	}

	.coverage-column.missed h3 {
		color: var(--red, #ff6b6b);
	}

	.vuln-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.vuln-item {
		display: flex;
		gap: 0.75rem;
		padding: 0.75rem;
		background: var(--bg-tertiary, #1a1a2e);
		border-radius: 6px;
	}

	.vuln-icon {
		font-size: 1rem;
		flex-shrink: 0;
	}

	.vuln-item.detected .vuln-icon {
		color: var(--green, #00c49a);
	}

	.vuln-item.missed .vuln-icon {
		color: var(--red, #ff6b6b);
	}

	.vuln-content {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		min-width: 0;
	}

	.vuln-id {
		font-family: monospace;
		font-size: 0.85rem;
		color: var(--text-primary, #fff);
	}

	.vuln-desc {
		font-size: 0.85rem;
		color: var(--text-secondary, #888);
	}

	.vuln-type {
		font-size: 0.75rem;
		color: var(--purple, #9d8cff);
		text-transform: uppercase;
	}

	.vuln-file {
		font-family: monospace;
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.finding-card {
		background: var(--bg-secondary, #111);
		border: 1px solid var(--border, #333);
		border-radius: 6px;
		overflow: hidden;
	}

	.finding-card.expanded {
		border-color: var(--purple, #9d8cff);
	}

	.finding-header {
		width: 100%;
		padding: 1rem 1.25rem;
		background: transparent;
		border: none;
		color: var(--text-primary, #fff);
		cursor: pointer;
		text-align: left;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.finding-header:hover {
		background: var(--bg-tertiary, #1a1a2e);
	}

	.finding-meta {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.severity-tag {
		padding: 0.2rem 0.5rem;
		border-radius: 3px;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.finding-category {
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
		text-transform: uppercase;
	}

	.finding-title {
		font-size: 0.95rem;
		font-weight: 500;
		margin: 0;
		padding-right: 2rem;
	}

	.finding-chevron {
		position: absolute;
		right: 1.25rem;
		top: 1rem;
		font-size: 0.75rem;
		color: var(--text-tertiary, #666);
		transition: transform 0.2s;
	}

	.finding-chevron.rotated {
		transform: rotate(180deg);
	}

	.finding-header {
		position: relative;
	}

	.finding-body {
		padding: 0 1.25rem 1.25rem;
		border-top: 1px solid var(--border, #333);
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.finding-body .label {
		display: block;
		font-size: 0.75rem;
		text-transform: uppercase;
		color: var(--text-tertiary, #666);
		margin-bottom: 0.375rem;
	}

	.finding-location code {
		background: var(--bg-tertiary, #1a1a2e);
		padding: 0.25rem 0.5rem;
		border-radius: 3px;
		font-size: 0.85rem;
	}

	.finding-snippet {
		margin-top: 0.5rem;
	}

	.finding-snippet pre {
		background: var(--bg-tertiary, #1a1a2e);
		padding: 1rem;
		border-radius: 4px;
		overflow-x: auto;
		margin: 0;
	}

	.finding-snippet code {
		font-size: 0.8rem;
		white-space: pre-wrap;
		word-break: break-word;
	}

	.finding-description p {
		margin: 0;
		font-size: 0.9rem;
		color: var(--text-secondary, #888);
		line-height: 1.5;
	}

	.finding-fix {
		background: rgba(0, 196, 154, 0.1);
		border: 1px solid rgba(0, 196, 154, 0.3);
		border-radius: 6px;
		padding: 1rem;
	}

	.finding-fix .label {
		color: var(--green, #00c49a);
	}

	.finding-fix pre {
		margin: 0;
		background: transparent;
	}

	.finding-fix code {
		font-size: 0.85rem;
	}

	.finding-refs ul {
		margin: 0;
		padding-left: 1.25rem;
	}

	.finding-refs li {
		margin-bottom: 0.25rem;
	}

	.finding-refs a {
		color: var(--purple, #9d8cff);
		text-decoration: none;
		font-size: 0.85rem;
		word-break: break-all;
	}

	.finding-refs a:hover {
		text-decoration: underline;
	}

	@media (max-width: 768px) {
		.report-page {
			padding: 5rem 1rem 2rem;
		}

		.report-header {
			flex-direction: column;
			gap: 1.5rem;
		}

		.report-header h1 {
			font-size: 1.75rem;
		}

		.coverage-grid {
			grid-template-columns: 1fr;
		}

		.summary-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
