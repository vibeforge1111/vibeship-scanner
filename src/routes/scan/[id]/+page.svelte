<script lang="ts">
	import { page } from '$app/stores';
	import { onMount, onDestroy } from 'svelte';
	import { supabase } from '$lib/supabase';
	import { explanationMode, type ExplanationMode } from '$lib/stores/preferences';
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

	let displayScore = $state(0);
	let showResults = $state(false);
	let showConfetti = $state(false);
	let revealStage = $state(0);
	let confettiParticles = $state<Array<{id: number, x: number, delay: number, color: string, size: number}>>([]);
	let mode = $state<ExplanationMode>('founder');
	let expandedFindings = $state<Set<string>>(new Set());
	let copied = $state<string | null>(null);
	let showBadgeEmbed = $state(false);

	explanationMode.subscribe(value => {
		mode = value;
	});

	function getScanUrl(): string {
		if (typeof window !== 'undefined') {
			return window.location.href;
		}
		return '';
	}

	function copyToClipboard(text: string, type: string) {
		navigator.clipboard.writeText(text);
		copied = type;
		setTimeout(() => copied = null, 2000);
	}

	function shareTwitter() {
		const score = results?.score || 0;
		const grade = results?.grade || '?';
		const text = `My code just scored ${score}/100 (Grade ${grade}) on Vibeship Scanner! Check your repo's security:`;
		const url = getScanUrl();
		window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, '_blank');
	}

	function getBadgeMarkdown(): string {
		const grade = results?.grade || 'F';
		return `[![Vibeship Security Score](https://img.shields.io/badge/vibeship-${grade}-${getGradeColor(grade)})](${getScanUrl()})`;
	}

	function getBadgeHtml(): string {
		const grade = results?.grade || 'F';
		return `<a href="${getScanUrl()}"><img src="https://img.shields.io/badge/vibeship-${grade}-${getGradeColor(grade)}" alt="Vibeship Security Score"></a>`;
	}

	function getGradeColor(grade: string): string {
		const colors: Record<string, string> = {
			A: '2ECC71',
			B: '84cc16',
			C: 'FFB020',
			D: 'f97316',
			F: 'FF4D4D'
		};
		return colors[grade] || 'gray';
	}

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

	function toggleFinding(id: string) {
		if (expandedFindings.has(id)) {
			expandedFindings.delete(id);
			expandedFindings = new Set(expandedFindings);
		} else {
			expandedFindings.add(id);
			expandedFindings = new Set(expandedFindings);
		}
	}

	function getFounderExplanation(finding: any): string {
		const explanations: Record<string, string> = {
			'sql-injection': `Think of this like leaving your store's back door unlocked. Anyone can type special commands that let them see, change, or delete ALL your customer data. This could mean stolen data, legal liability, and reputation damage.`,
			'xss': `This is like letting strangers put up their own signs in your store. Attackers can inject malicious scripts that steal user sessions, redirect to phishing sites, or deface your app.`,
			'hardcoded-secret': `You've left a key under the doormat where anyone can find it. If this code is public (or gets leaked), attackers have direct access to your services and data.`,
			'insecure-dependency': `One of your building blocks has known weaknesses. Attackers actively scan for apps using vulnerable packages - it's like having a published list of houses with broken locks.`,
			'missing-auth': `Some doors in your app don't check if visitors should be allowed in. Anyone who finds these paths can access data or features they shouldn't.`,
			default: `This security issue could expose your app or users to risk. Even if it seems minor, attackers chain small vulnerabilities together for bigger attacks.`
		};
		const key = finding.ruleId?.toLowerCase() || finding.category?.toLowerCase() || 'default';
		for (const [k, v] of Object.entries(explanations)) {
			if (key.includes(k)) return v;
		}
		return explanations.default;
	}

	function getDeveloperExplanation(finding: any): string {
		const explanations: Record<string, string> = {
			'sql-injection': `CWE-89: User input concatenated directly into SQL query without parameterization. Use prepared statements or ORM methods with bound parameters.`,
			'xss': `CWE-79: Unsanitized user input rendered in DOM. Implement output encoding, use framework auto-escaping, or sanitize with DOMPurify.`,
			'hardcoded-secret': `CWE-798: Credentials embedded in source code. Move to environment variables, secrets manager (Vault, AWS Secrets Manager), or .env files excluded from VCS.`,
			'insecure-dependency': `Known CVE in dependency. Check npm audit / pip-audit for details. Update to patched version or apply workaround if update not available.`,
			'missing-auth': `CWE-306: Missing authentication on sensitive endpoint. Implement middleware/guard to verify session/JWT before processing request.`,
			default: `Security vulnerability detected. Review the code context, understand the attack vector, and apply the recommended fix pattern.`
		};
		const key = finding.ruleId?.toLowerCase() || finding.category?.toLowerCase() || 'default';
		for (const [k, v] of Object.entries(explanations)) {
			if (key.includes(k)) return v;
		}
		return explanations.default;
	}

	function animateScore(targetScore: number) {
		const duration = 1500;
		const startTime = performance.now();
		const easeOutQuart = (t: number) => 1 - Math.pow(1 - t, 4);

		function update() {
			const elapsed = performance.now() - startTime;
			const progress = Math.min(elapsed / duration, 1);
			const easedProgress = easeOutQuart(progress);
			displayScore = Math.round(easedProgress * targetScore);

			if (progress < 1) {
				requestAnimationFrame(update);
			} else {
				displayScore = targetScore;
				if (targetScore >= 80) {
					triggerConfetti();
				}
				startCascadeReveal();
			}
		}
		requestAnimationFrame(update);
	}

	function triggerConfetti() {
		showConfetti = true;
		const colors = ['#00C49A', '#2ECC71', '#FFB020', '#3399FF', '#9D8CFF'];
		const particles: typeof confettiParticles = [];

		for (let i = 0; i < 50; i++) {
			particles.push({
				id: i,
				x: Math.random() * 100,
				delay: Math.random() * 0.5,
				color: colors[Math.floor(Math.random() * colors.length)],
				size: Math.random() * 8 + 4
			});
		}
		confettiParticles = particles;

		setTimeout(() => {
			showConfetti = false;
		}, 3000);
	}

	function startCascadeReveal() {
		const stages = [1, 2, 3, 4];
		stages.forEach((stage, i) => {
			setTimeout(() => {
				revealStage = stage;
			}, i * 200);
		});
	}

	$effect(() => {
		if (status === 'complete' && results && !showResults) {
			showResults = true;
			setTimeout(() => {
				animateScore(results.score || 0);
			}, 300);
		}
	});
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
			{#if showConfetti}
				<div class="confetti-container">
					{#each confettiParticles as particle (particle.id)}
						<div
							class="confetti-particle"
							style="
								left: {particle.x}%;
								animation-delay: {particle.delay}s;
								background: {particle.color};
								width: {particle.size}px;
								height: {particle.size}px;
							"
						></div>
					{/each}
				</div>
			{/if}

			<div class="results-header">
				<div class="score-section" class:revealed={showResults}>
					<div class="score-circle {getGradeClass(results.grade)}">
						<span class="score-number">{displayScore}</span>
						<span class="score-label">out of 100</span>
					</div>
					<div class="grade-badge {getGradeClass(results.grade)}" class:pop={revealStage >= 1}>
						<span class="grade-letter">{results.grade}</span>
					</div>
					<p class="ship-status" class:fade-in={revealStage >= 2}>{getShipMessage(results.shipStatus)}</p>
				</div>

				<div class="summary-section" class:revealed={revealStage >= 3}>
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

			<div class="share-section" class:revealed={revealStage >= 3}>
				<div class="share-actions">
					<button class="share-btn" onclick={() => copyToClipboard(getScanUrl(), 'link')}>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
							<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
						</svg>
						{copied === 'link' ? 'Copied!' : 'Copy Link'}
					</button>
					<button class="share-btn" onclick={shareTwitter}>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
							<path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
						</svg>
						Share on X
					</button>
					<button class="share-btn" onclick={() => showBadgeEmbed = !showBadgeEmbed}>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
							<line x1="9" y1="9" x2="15" y2="9"/>
							<line x1="9" y1="15" x2="15" y2="15"/>
						</svg>
						Get Badge
					</button>
				</div>

				{#if showBadgeEmbed}
					<div class="badge-embed">
						<div class="badge-preview">
							<img src="https://img.shields.io/badge/vibeship-{results.grade}-{getGradeColor(results.grade)}" alt="Vibeship Badge">
						</div>
						<div class="badge-codes">
							<div class="badge-code-block">
								<div class="badge-code-header">
									<span>Markdown</span>
									<button class="btn-copy-sm" onclick={() => copyToClipboard(getBadgeMarkdown(), 'md')}>
										{copied === 'md' ? 'Copied!' : 'Copy'}
									</button>
								</div>
								<code>{getBadgeMarkdown()}</code>
							</div>
							<div class="badge-code-block">
								<div class="badge-code-header">
									<span>HTML</span>
									<button class="btn-copy-sm" onclick={() => copyToClipboard(getBadgeHtml(), 'html')}>
										{copied === 'html' ? 'Copied!' : 'Copy'}
									</button>
								</div>
								<code>{getBadgeHtml()}</code>
							</div>
						</div>
					</div>
				{/if}
			</div>

			{#if results.findings?.length > 0}
				<div class="findings-section" class:revealed={revealStage >= 4}>
					<div class="findings-header">
						<h2>Findings ({results.findings.length})</h2>
						<div class="mode-toggle">
							<button
								class="mode-btn"
								class:active={mode === 'founder'}
								onclick={() => explanationMode.setMode('founder')}
							>
								<span class="mode-icon">🎯</span>
								Founder
							</button>
							<button
								class="mode-btn"
								class:active={mode === 'developer'}
								onclick={() => explanationMode.setMode('developer')}
							>
								<span class="mode-icon">💻</span>
								Developer
							</button>
						</div>
					</div>
					<div class="findings-list">
						{#each results.findings as finding, i}
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
									<h3 class="finding-title">{finding.title}</h3>
								</button>

								{#if isExpanded}
									<div class="finding-details">
										<div class="explanation-box" class:founder={mode === 'founder'} class:developer={mode === 'developer'}>
											<div class="explanation-header">
												{#if mode === 'founder'}
													<span class="explanation-icon">💡</span>
													<span class="explanation-label">Why this matters</span>
												{:else}
													<span class="explanation-icon">🔧</span>
													<span class="explanation-label">Technical details</span>
												{/if}
											</div>
											<p class="explanation-text">
												{#if mode === 'founder'}
													{getFounderExplanation(finding)}
												{:else}
													{getDeveloperExplanation(finding)}
												{/if}
											</p>
										</div>

										{#if finding.location?.file}
											<div class="finding-location">
												<span class="location-label">Location:</span>
												<code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
											</div>
										{/if}

										{#if finding.snippet}
											<div class="code-snippet">
												<div class="snippet-header">
													<span>Vulnerable Code</span>
												</div>
												<pre><code>{finding.snippet}</code></pre>
											</div>
										{/if}

										{#if finding.fix?.available && finding.fix?.template}
											<div class="finding-fix">
												<div class="fix-header">
													<span class="fix-label">Suggested Fix</span>
													<button class="btn-copy" onclick={() => copyFix(finding.fix.template)}>
														Copy
													</button>
												</div>
												<pre class="fix-code"><code>{finding.fix.template}</code></pre>
											</div>
										{/if}

										<div class="finding-actions">
											<a href="https://vibeship.com" class="btn btn-glow btn-sm">
												Get Vibeship to fix this →
											</a>
										</div>
									</div>
								{/if}
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

	.findings-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1.5rem;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.findings-section h2,
	.no-findings h2 {
		font-family: 'Instrument Serif', serif;
		font-size: 1.5rem;
		margin-bottom: 0;
	}

	.mode-toggle {
		display: flex;
		border: 1px solid var(--border);
	}

	.mode-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: transparent;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.mode-btn:first-child {
		border-right: 1px solid var(--border);
	}

	.mode-btn:hover {
		color: var(--text-primary);
		background: var(--bg-secondary);
	}

	.mode-btn.active {
		color: var(--green-dim);
		background: var(--bg-secondary);
	}

	.mode-icon {
		font-size: 0.9rem;
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
		background: var(--bg-primary);
		transition: border-color 0.15s;
	}

	.finding-card:hover {
		border-color: var(--border-strong);
	}

	.finding-card.expanded {
		border-color: var(--green-dim);
	}

	.finding-toggle {
		width: 100%;
		padding: 1.5rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
	}

	.finding-header {
		display: flex;
		gap: 1rem;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.finding-chevron {
		margin-left: auto;
		font-size: 0.7rem;
		color: var(--text-tertiary);
		transition: transform 0.2s;
	}

	.finding-chevron.rotated {
		transform: rotate(180deg);
	}

	.finding-details {
		padding: 0 1.5rem 1.5rem;
		border-top: 1px solid var(--border);
		margin-top: 0;
		animation: slideDown 0.2s ease;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			transform: translateY(-10px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.explanation-box {
		margin: 1.5rem 0;
		padding: 1rem;
		border-left: 3px solid var(--border);
		background: var(--bg-secondary);
	}

	.explanation-box.founder {
		border-left-color: var(--orange);
	}

	.explanation-box.developer {
		border-left-color: var(--blue);
	}

	.explanation-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.75rem;
	}

	.explanation-icon {
		font-size: 1rem;
	}

	.explanation-label {
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.explanation-text {
		font-size: 0.9rem;
		line-height: 1.7;
		color: var(--text-primary);
	}

	.code-snippet {
		margin: 1rem 0;
		border: 1px solid var(--border);
		overflow: hidden;
	}

	.snippet-header {
		padding: 0.5rem 1rem;
		background: var(--bg-tertiary);
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.code-snippet pre {
		padding: 1rem;
		margin: 0;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		overflow-x: auto;
		font-size: 0.8rem;
		line-height: 1.5;
	}

	.code-snippet code {
		background: transparent;
		padding: 0;
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
		color: var(--text-primary);
		margin: 0;
	}

	.finding-location {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin: 1rem 0;
	}

	.location-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.finding-location code {
		font-size: 0.8rem;
		background: var(--bg-tertiary);
		padding: 0.25rem 0.5rem;
	}

	.finding-fix {
		margin-top: 1rem;
		border: 1px solid var(--border);
		overflow: hidden;
	}

	.fix-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 1rem;
		background: var(--bg-tertiary);
	}

	.fix-label {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--green-dim);
	}

	pre.fix-code {
		padding: 1rem;
		margin: 0;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		overflow-x: auto;
		font-size: 0.8rem;
		line-height: 1.5;
	}

	pre.fix-code code {
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
		margin-top: 1.5rem;
		padding-top: 1.5rem;
		border-top: 1px solid var(--border);
		display: flex;
		gap: 1rem;
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

	.confetti-container {
		position: fixed;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		pointer-events: none;
		z-index: 1000;
		overflow: hidden;
	}

	.confetti-particle {
		position: absolute;
		top: -20px;
		animation: confetti-fall 3s ease-out forwards;
	}

	@keyframes confetti-fall {
		0% {
			transform: translateY(0) rotate(0deg);
			opacity: 1;
		}
		100% {
			transform: translateY(100vh) rotate(720deg);
			opacity: 0;
		}
	}

	.score-section {
		opacity: 0;
		transform: scale(0.8);
		transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
	}

	.score-section.revealed {
		opacity: 1;
		transform: scale(1);
	}

	.grade-badge {
		opacity: 0;
		transform: scale(0);
		transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
	}

	.grade-badge.pop {
		opacity: 1;
		transform: scale(1);
	}

	.ship-status {
		opacity: 0;
		transition: opacity 0.4s ease;
	}

	.ship-status.fade-in {
		opacity: 1;
	}

	.summary-section {
		opacity: 0;
		transform: translateX(20px);
		transition: all 0.5s ease;
	}

	.summary-section.revealed {
		opacity: 1;
		transform: translateX(0);
	}

	.findings-section {
		opacity: 0;
		transform: translateY(20px);
		transition: all 0.5s ease;
	}

	.findings-section.revealed {
		opacity: 1;
		transform: translateY(0);
	}

	.share-section {
		margin-bottom: 3rem;
		padding: 1.5rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		opacity: 0;
		transform: translateY(10px);
		transition: all 0.4s ease;
	}

	.share-section.revealed {
		opacity: 1;
		transform: translateY(0);
	}

	.share-actions {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.share-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.6rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.share-btn:hover {
		border-color: var(--text-primary);
		background: var(--bg-primary);
	}

	.share-btn svg {
		width: 14px;
		height: 14px;
	}

	.badge-embed {
		margin-top: 1.5rem;
		padding-top: 1.5rem;
		border-top: 1px solid var(--border);
		animation: slideDown 0.2s ease;
	}

	.badge-preview {
		margin-bottom: 1rem;
	}

	.badge-preview img {
		height: 24px;
	}

	.badge-codes {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.badge-code-block {
		border: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.badge-code-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0.75rem;
		border-bottom: 1px solid var(--border);
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.badge-code-block code {
		display: block;
		padding: 0.75rem;
		font-size: 0.75rem;
		word-break: break-all;
		background: transparent;
	}

	.btn-copy-sm {
		padding: 0.25rem 0.5rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.65rem;
		text-transform: uppercase;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-copy-sm:hover {
		border-color: var(--text-primary);
		color: var(--text-primary);
	}

	.score-number {
		font-family: 'JetBrains Mono', monospace;
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
