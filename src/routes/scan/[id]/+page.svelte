<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';

	let scanId = $derived($page.params.id);
	let status = $state<'scanning' | 'complete' | 'error'>('scanning');
	let progress = $state({
		step: 'Initializing',
		stepNumber: 0,
		totalSteps: 5,
		message: 'Starting scan...'
	});
	let results = $state<any>(null);

	const steps = [
		{ id: 'clone', label: 'Cloning repository', icon: '📥' },
		{ id: 'detect', label: 'Detecting stack', icon: '🔍' },
		{ id: 'sast', label: 'Scanning code', icon: '🛡️' },
		{ id: 'deps', label: 'Checking dependencies', icon: '📦' },
		{ id: 'score', label: 'Calculating score', icon: '📊' }
	];

	onMount(() => {
		let step = 0;
		const interval = setInterval(() => {
			if (step < steps.length) {
				progress = {
					step: steps[step].id,
					stepNumber: step,
					totalSteps: steps.length,
					message: steps[step].label
				};
				step++;
			} else {
				clearInterval(interval);
				status = 'complete';
				results = {
					score: 73,
					grade: 'C',
					shipStatus: 'review',
					summary: { critical: 1, high: 2, medium: 4, low: 3, info: 2 },
					stack: { languages: ['TypeScript', 'JavaScript'], frameworks: ['Next.js', 'React'] },
					findings: [
						{
							id: '1',
							severity: 'critical',
							category: 'secrets',
							title: 'Hardcoded API Key Detected',
							description: 'OpenAI API key found in source code',
							location: { file: 'src/lib/ai.ts', line: 12 },
							fix: { available: true, template: 'Move to environment variable: process.env.OPENAI_API_KEY' }
						},
						{
							id: '2',
							severity: 'high',
							category: 'code',
							title: 'SQL Injection Vulnerability',
							description: 'User input directly concatenated into SQL query',
							location: { file: 'src/api/users.ts', line: 45 },
							fix: { available: true, template: 'Use parameterized query: db.query("SELECT * FROM users WHERE id = $1", [userId])' }
						},
						{
							id: '3',
							severity: 'high',
							category: 'dependencies',
							title: 'CVE-2024-1234 in lodash',
							description: 'Prototype pollution vulnerability in lodash < 4.17.21',
							location: { file: 'package.json', line: 15 },
							fix: { available: true, template: 'npm update lodash@^4.17.21' }
						},
						{
							id: '4',
							severity: 'medium',
							category: 'code',
							title: 'Missing Authentication Check',
							description: 'API route lacks authentication middleware',
							location: { file: 'src/api/admin.ts', line: 8 },
							fix: { available: true, template: 'Add authentication middleware before route handler' }
						}
					]
				};
			}
		}, 1500);

		return () => clearInterval(interval);
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
</script>

<div class="scan-page">
	{#if status === 'scanning'}
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
						{/if}
					</div>
				{/each}
			</div>

			<div class="progress-bar">
				<div class="progress-fill" style="width: {((progress.stepNumber + 1) / progress.totalSteps) * 100}%"></div>
			</div>
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
						{#if results.summary.critical > 0}
							<span class="count severity-critical">{results.summary.critical} Critical</span>
						{/if}
						{#if results.summary.high > 0}
							<span class="count severity-high">{results.summary.high} High</span>
						{/if}
						{#if results.summary.medium > 0}
							<span class="count severity-medium">{results.summary.medium} Medium</span>
						{/if}
						{#if results.summary.low > 0}
							<span class="count severity-low">{results.summary.low} Low</span>
						{/if}
					</div>
					<div class="stack-info">
						<span class="stack-label">Stack detected:</span>
						<span class="stack-value">{results.stack.frameworks.join(', ')}</span>
					</div>
				</div>
			</div>

			<div class="findings-section">
				<h2>Findings</h2>
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
							<p class="finding-location">
								<code>{finding.location.file}:{finding.location.line}</code>
							</p>
							{#if finding.fix?.available}
								<div class="finding-fix">
									<span class="fix-label">Fix:</span>
									<code class="fix-code">{finding.fix.template}</code>
									<button class="btn-copy" onclick={() => navigator.clipboard.writeText(finding.fix.template)}>
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

			<div class="results-footer">
				<a href="/" class="btn">Scan Another Repo</a>
				<a href="https://vibeship.com" class="btn btn-glow">Get Expert Help</a>
			</div>
		</div>
	{/if}
</div>

<style>
	.scan-page {
		padding: 6rem 2rem 4rem;
		max-width: 1000px;
		margin: 0 auto;
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

	.progress-bar {
		max-width: 400px;
		margin: 0 auto;
		height: 4px;
		background: var(--border);
	}

	.progress-fill {
		height: 100%;
		background: var(--green-dim);
		transition: width 0.5s ease;
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
	}

	.stack-label {
		color: var(--text-secondary);
	}

	.stack-value {
		color: var(--text-primary);
	}

	.findings-section h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 1.5rem;
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
