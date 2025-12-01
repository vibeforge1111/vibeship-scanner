<script lang="ts">
	import { page } from '$app/stores';
	import { onMount, onDestroy } from 'svelte';
	import { supabase } from '$lib/supabase';
	import type { RealtimeChannel } from '@supabase/supabase-js';

	let scanId = $derived($page.params.id);
	let status = $state<'queued' | 'scanning' | 'complete' | 'failed'>('queued');
	let progress = $state({
		step: 'init',
		stepNumber: 0,
		totalSteps: 5,
		message: 'Starting scan...',
		percent: 0
	});
	let results = $state<any>(null);
	let error = $state<string | null>(null);
	let channel: RealtimeChannel | null = null;

	const steps = [
		{ id: 'init', label: 'Initializing', icon: '⚡' },
		{ id: 'clone', label: 'Cloning repository', icon: '📥' },
		{ id: 'sast', label: 'Scanning code', icon: '🛡️' },
		{ id: 'deps', label: 'Checking dependencies', icon: '📦' },
		{ id: 'secrets', label: 'Scanning for secrets', icon: '🔐' },
		{ id: 'score', label: 'Calculating score', icon: '📊' }
	];

	function getStepIndex(stepId: string): number {
		const index = steps.findIndex(s => s.id === stepId);
		return index >= 0 ? index : 0;
	}

	async function fetchScan() {
		const { data, error: fetchError } = await supabase
			.from('scans')
			.select('*')
			.eq('id', scanId)
			.single();

		if (fetchError) {
			error = 'Scan not found';
			return;
		}

		if (data) {
			status = data.status;
			if (data.status === 'complete') {
				results = {
					score: data.score,
					grade: data.grade,
					shipStatus: data.ship_status,
					summary: data.summary,
					stack: data.stack,
					findings: data.findings || []
				};
			} else if (data.status === 'failed') {
				error = data.error || 'Scan failed';
			}
		}
	}

	async function fetchProgress() {
		const { data } = await supabase
			.from('scan_progress')
			.select('*')
			.eq('scan_id', scanId)
			.order('created_at', { ascending: false })
			.limit(1)
			.single();

		if (data) {
			progress = {
				step: data.step,
				stepNumber: getStepIndex(data.step),
				totalSteps: steps.length,
				message: data.message,
				percent: data.percent || 0
			};
		}
	}

	onMount(async () => {
		await fetchScan();
		await fetchProgress();

		channel = supabase
			.channel(`scan-${scanId}`)
			.on(
				'postgres_changes',
				{
					event: 'UPDATE',
					schema: 'public',
					table: 'scans',
					filter: `id=eq.${scanId}`
				},
				(payload) => {
					const data = payload.new;
					status = data.status;

					if (data.status === 'complete') {
						results = {
							score: data.score,
							grade: data.grade,
							shipStatus: data.ship_status,
							summary: data.summary,
							stack: data.stack,
							findings: data.findings || []
						};
					} else if (data.status === 'failed') {
						error = data.error || 'Scan failed';
					}
				}
			)
			.on(
				'postgres_changes',
				{
					event: '*',
					schema: 'public',
					table: 'scan_progress',
					filter: `scan_id=eq.${scanId}`
				},
				(payload) => {
					const data = payload.new as any;
					if (data) {
						progress = {
							step: data.step,
							stepNumber: getStepIndex(data.step),
							totalSteps: steps.length,
							message: data.message,
							percent: data.percent || 0
						};
					}
				}
			)
			.subscribe();
	});

	onDestroy(() => {
		if (channel) {
			supabase.removeChannel(channel);
		}
	});

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

	function getShipMessage(status: string): string {
		const messages: Record<string, string> = {
			ship: '🚀 Ship It!',
			review: '⚠️ Needs Review',
			fix: '🔧 Fix Required',
			danger: '🛑 Do Not Ship'
		};
		return messages[status] || '';
	}

	function copyFix(template: string) {
		navigator.clipboard.writeText(template);
	}
</script>

<div class="scan-page">
	{#if error}
		<div class="error-container">
			<h1>Scan Error</h1>
			<p>{error}</p>
			<a href="/" class="btn">Try Again</a>
		</div>

	{:else if status === 'queued' || status === 'scanning'}
		<div class="progress-container">
			<h1>Scanning your repository...</h1>
			<p class="progress-subtitle">This usually takes about 30 seconds</p>

			<div class="progress-steps">
				{#each steps as step, i}
					<div class="step" class:active={i === progress.stepNumber} class:complete={i < progress.stepNumber}>
						<span class="step-icon">{step.icon}</span>
						<span class="step-label">{step.label}</span>
						{#if i < progress.stepNumber}
							<span class="step-check">✓</span>
						{:else if i === progress.stepNumber}
							<span class="step-spinner"></span>
						{/if}
					</div>
				{/each}
			</div>

			<div class="progress-bar">
				<div class="progress-fill" style="width: {progress.percent}%"></div>
			</div>

			<p class="progress-message">{progress.message}</p>
		</div>

	{:else if status === 'complete' && results}
		<div class="results-container">
			<div class="results-header">
				<div class="score-section">
					<div class="score-circle {getGradeClass(results.grade)}">
						<span class="score-number">{results.score}</span>
						<span class="score-label">out of 100</span>
					</div>
					<div class="grade-badge {getGradeClass(results.grade)}">
						<span class="grade-letter">{results.grade}</span>
					</div>
					<p class="ship-status">{getShipMessage(results.shipStatus)}</p>
				</div>

				<div class="summary-section">
					<h2>Security Summary</h2>
					<div class="summary-counts">
						{#if results.summary?.critical > 0}
							<span class="count severity-critical">{results.summary.critical} Critical</span>
						{/if}
						{#if results.summary?.high > 0}
							<span class="count severity-high">{results.summary.high} High</span>
						{/if}
						{#if results.summary?.medium > 0}
							<span class="count severity-medium">{results.summary.medium} Medium</span>
						{/if}
						{#if results.summary?.low > 0}
							<span class="count severity-low">{results.summary.low} Low</span>
						{/if}
						{#if !results.summary?.critical && !results.summary?.high && !results.summary?.medium && !results.summary?.low}
							<span class="count severity-info">No issues found</span>
						{/if}
					</div>
					{#if results.stack?.frameworks?.length > 0}
						<div class="stack-info">
							<span class="stack-label">Stack detected:</span>
							<span class="stack-value">{results.stack.frameworks.join(', ')}</span>
						</div>
					{/if}
					{#if results.stack?.languages?.length > 0}
						<div class="stack-info">
							<span class="stack-label">Languages:</span>
							<span class="stack-value">{results.stack.languages.join(', ')}</span>
						</div>
					{/if}
				</div>
			</div>

			{#if results.findings?.length > 0}
				<div class="findings-section">
					<h2>Findings ({results.findings.length})</h2>
					<div class="findings-list">
						{#each results.findings as finding}
							<div class="finding-card">
								<div class="finding-header">
									<span class="severity-badge {getSeverityClass(finding.severity)}">
										{finding.severity.toUpperCase()}
									</span>
									<span class="finding-category">{finding.category}</span>
								</div>
								<h3 class="finding-title">{finding.title}</h3>
								<p class="finding-desc">{finding.description}</p>
								{#if finding.location?.file}
									<p class="finding-location">
										<code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
									</p>
								{/if}
								{#if finding.fix?.available && finding.fix?.template}
									<div class="finding-fix">
										<span class="fix-label">Fix:</span>
										<code class="fix-code">{finding.fix.template}</code>
										<button class="btn-copy" onclick={() => copyFix(finding.fix.template)}>
											Copy
										</button>
									</div>
								{/if}
								<div class="finding-actions">
									<a href="https://vibeship.com" class="btn btn-green btn-sm">
										Get Vibeship to fix this →
									</a>
								</div>
							</div>
						{/each}
					</div>
				</div>
			{:else}
				<div class="no-findings">
					<h2>No Security Issues Found</h2>
					<p>Your code looks clean! Consider running deeper analysis with Vibeship Pro.</p>
				</div>
			{/if}

			<div class="results-footer">
				<a href="/" class="btn">Scan Another Repo</a>
				<a href="https://vibeship.com" class="btn btn-glow">Get Expert Help</a>
			</div>
		</div>

	{:else if status === 'failed'}
		<div class="error-container">
			<h1>Scan Failed</h1>
			<p>{error || 'Something went wrong during the scan.'}</p>
			<a href="/" class="btn">Try Again</a>
		</div>
	{/if}
</div>

<style>
	.scan-page {
		padding: 6rem 2rem 4rem;
		max-width: 1000px;
		margin: 0 auto;
	}

	.error-container {
		text-align: center;
		padding: 4rem 0;
	}

	.error-container h1 {
		font-family: 'Instrument Serif', serif;
		font-size: 2rem;
		margin-bottom: 1rem;
		color: var(--red);
	}

	.error-container p {
		color: var(--text-secondary);
		margin-bottom: 2rem;
	}

	.progress-container {
		text-align: center;
		padding: 4rem 0;
	}

	.progress-container h1 {
		font-family: 'Instrument Serif', serif;
		font-size: 2.5rem;
		margin-bottom: 0.5rem;
	}

	.progress-subtitle {
		color: var(--text-secondary);
		margin-bottom: 4rem;
	}

	.progress-steps {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 400px;
		margin: 0 auto 3rem;
		text-align: left;
	}

	.step {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 1rem;
		border: 1px solid var(--border);
		background: var(--bg-primary);
		opacity: 0.5;
		transition: all 0.3s;
	}

	.step.active {
		opacity: 1;
		border-color: var(--green-dim);
		background: var(--bg-secondary);
	}

	.step.complete {
		opacity: 1;
	}

	.step-icon {
		font-size: 1.25rem;
	}

	.step-label {
		flex: 1;
		font-size: 0.9rem;
	}

	.step-check {
		color: var(--green);
	}

	.step-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid var(--border);
		border-top-color: var(--green-dim);
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.progress-bar {
		max-width: 400px;
		margin: 0 auto 1rem;
		height: 4px;
		background: var(--border);
	}

	.progress-fill {
		height: 100%;
		background: var(--green-dim);
		transition: width 0.5s ease;
	}

	.progress-message {
		font-size: 0.9rem;
		color: var(--text-secondary);
	}

	.results-container {
		animation: fadeUp 0.5s ease;
	}

	.results-header {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 4rem;
		margin-bottom: 4rem;
		padding-bottom: 2rem;
		border-bottom: 1px solid var(--border);
	}

	.score-section {
		text-align: center;
	}

	.score-circle {
		width: 150px;
		height: 150px;
		border-radius: 50%;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		margin-bottom: 1rem;
		border: 3px solid;
	}

	.score-circle.grade-a { border-color: var(--green); }
	.score-circle.grade-b { border-color: #84cc16; }
	.score-circle.grade-c { border-color: var(--orange); }
	.score-circle.grade-d { border-color: #f97316; }
	.score-circle.grade-f { border-color: var(--red); }

	.score-number {
		font-size: 3rem;
		font-weight: 600;
		line-height: 1;
	}

	.score-label {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.grade-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 48px;
		height: 48px;
		font-size: 1.5rem;
		font-weight: 600;
		margin-bottom: 0.5rem;
	}

	.grade-badge.grade-a { background: var(--green); color: white; }
	.grade-badge.grade-b { background: #84cc16; color: white; }
	.grade-badge.grade-c { background: var(--orange); color: var(--bg-inverse); }
	.grade-badge.grade-d { background: #f97316; color: white; }
	.grade-badge.grade-f { background: var(--red); color: white; }

	.ship-status {
		font-size: 1rem;
		font-weight: 500;
	}

	.summary-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.summary-counts {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
		margin-bottom: 1.5rem;
	}

	.count {
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
		font-weight: 500;
		border: 1px solid;
	}

	.severity-critical { border-color: var(--red); color: var(--red); }
	.severity-high { border-color: #f97316; color: #f97316; }
	.severity-medium { border-color: var(--orange); color: var(--orange); }
	.severity-low { border-color: var(--blue); color: var(--blue); }
	.severity-info { border-color: var(--text-tertiary); color: var(--text-tertiary); }

	.stack-info {
		font-size: 0.85rem;
		margin-bottom: 0.5rem;
	}

	.stack-label {
		color: var(--text-secondary);
	}

	.stack-value {
		color: var(--text-primary);
	}

	.findings-section h2,
	.no-findings h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.no-findings {
		text-align: center;
		padding: 3rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
	}

	.no-findings p {
		color: var(--text-secondary);
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.finding-card {
		border: 1px solid var(--border);
		padding: 1.5rem;
		background: var(--bg-primary);
	}

	.finding-header {
		display: flex;
		gap: 1rem;
		margin-bottom: 0.75rem;
	}

	.severity-badge {
		padding: 0.25rem 0.5rem;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.severity-badge.severity-critical { background: var(--red); color: white; }
	.severity-badge.severity-high { background: #f97316; color: white; }
	.severity-badge.severity-medium { background: var(--orange); color: var(--bg-inverse); }
	.severity-badge.severity-low { background: var(--blue); color: white; }

	.finding-category {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.finding-title {
		font-family: 'Inter', sans-serif;
		font-size: 1.1rem;
		font-weight: 600;
		margin-bottom: 0.5rem;
	}

	.finding-desc {
		font-size: 0.9rem;
		color: var(--text-secondary);
		margin-bottom: 0.75rem;
	}

	.finding-location code {
		font-size: 0.8rem;
		background: var(--bg-tertiary);
		padding: 0.25rem 0.5rem;
	}

	.finding-fix {
		margin-top: 1rem;
		padding: 1rem;
		background: var(--bg-secondary);
		display: flex;
		align-items: center;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.fix-label {
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		color: var(--green-dim);
	}

	.fix-code {
		flex: 1;
		font-size: 0.8rem;
		background: transparent;
		padding: 0;
	}

	.btn-copy {
		padding: 0.5rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		text-transform: uppercase;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-copy:hover {
		border-color: var(--text-primary);
	}

	.finding-actions {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid var(--border);
	}

	.btn-sm {
		padding: 0.5rem 1rem;
		font-size: 0.75rem;
	}

	.results-footer {
		margin-top: 4rem;
		padding-top: 2rem;
		border-top: 1px solid var(--border);
		display: flex;
		gap: 1rem;
		justify-content: center;
	}

	@keyframes fadeUp {
		from {
			opacity: 0;
			transform: translateY(20px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	@media (max-width: 768px) {
		.results-header {
			grid-template-columns: 1fr;
			gap: 2rem;
		}

		.score-section {
			display: flex;
			flex-direction: column;
			align-items: center;
		}
	}
</style>
