<script lang="ts">
	import type { VibeOutput } from '$lib/vibeTransformer';

	interface Props {
		finding: VibeOutput;
		index: number;
		onCopyPrompt?: (prompt: string) => void;
	}

	let { finding, index, onCopyPrompt }: Props = $props();

	let isExpanded = $state(false);
	let showTechnical = $state(false);
	let copied = $state<string | null>(null);

	function toggleExpand() {
		isExpanded = !isExpanded;
	}

	function copyToClipboard(text: string, type: string) {
		navigator.clipboard.writeText(text);
		copied = type;
		setTimeout(() => (copied = null), 2000);
		if (type === 'prompt' && onCopyPrompt) {
			onCopyPrompt(text);
		}
	}
</script>

<div class="finding-card" class:expanded={isExpanded}>
	<!-- Card Header - Always Visible -->
	<button class="card-header" onclick={toggleExpand}>
		<div class="header-top">
			<span
				class="urgency-badge {finding.urgency}"
			>
				{#if finding.urgency === 'ship-blocker'}Critical
				{:else if finding.urgency === 'fix-this-week'}High
				{:else if finding.urgency === 'good-to-fix'}Medium
				{:else if finding.urgency === 'consider'}Low
				{:else}Info{/if}
			</span>
			<span class="finding-number">#{index + 1}</span>
		</div>

		<h3 class="headline">{finding.headline}</h3>

		<div class="location">
			<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
				<polyline points="13 2 13 9 20 9" />
			</svg>
			<code>{finding.where.displayPath}</code>
		</div>

		<span class="chevron" class:rotated={isExpanded}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<polyline points="6 9 12 15 18 9" />
			</svg>
		</span>
	</button>

	<!-- Expanded Content -->
	{#if isExpanded}
		<div class="card-content">
			<!-- What's Wrong -->
			<div class="section">
				<h4 class="section-title">What's wrong</h4>
				<p class="whats-wrong">{finding.whatsWrong}</p>
			</div>

			<!-- What Could Happen -->
			<div class="section">
				<h4 class="section-title">What could happen</h4>
				<ul class="consequences">
					{#each finding.consequences.slice(0, 3) as consequence}
						<li>{consequence}</li>
					{/each}
				</ul>
			</div>

			<!-- Vulnerable Code -->
			{#if finding.vulnerableCode}
				<div class="section">
					<h4 class="section-title">The vulnerable code</h4>
					<pre class="code-block"><code>{finding.vulnerableCode.code}</code></pre>
				</div>
			{/if}

			<!-- AI Fix Prompt - The Star of the Show -->
			<div class="section ai-prompt-section">
				<div class="prompt-header">
					<h4 class="section-title">AI Fix Prompt</h4>
					<span class="prompt-hint">Copy and paste into Claude, Cursor, or ChatGPT</span>
				</div>
				<div class="prompt-box">
					<pre class="prompt-text">{finding.aiFixPrompt}</pre>
					<button
						class="copy-btn"
						class:copied={copied === 'prompt'}
						onclick={() => copyToClipboard(finding.aiFixPrompt, 'prompt')}
					>
						{#if copied === 'prompt'}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polyline points="20 6 9 17 4 12" />
							</svg>
							Copied!
						{:else}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
								<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
							</svg>
							Copy Prompt
						{/if}
					</button>
				</div>
			</div>

			<!-- Technical Details (Collapsed) -->
			<details class="technical-details" bind:open={showTechnical}>
				<summary class="technical-summary">
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<circle cx="12" cy="12" r="10" />
						<line x1="12" y1="16" x2="12" y2="12" />
						<line x1="12" y1="8" x2="12.01" y2="8" />
					</svg>
					Technical Details
					<span class="toggle-icon">{showTechnical ? '−' : '+'}</span>
				</summary>
				<div class="technical-content">
					<div class="tech-grid">
						{#if finding.technicalDetails.cweId}
							<div class="tech-item">
								<span class="tech-label">CWE</span>
								<span class="tech-value">{finding.technicalDetails.cweId}</span>
							</div>
						{/if}
						{#if finding.technicalDetails.cweName}
							<div class="tech-item">
								<span class="tech-label">Name</span>
								<span class="tech-value">{finding.technicalDetails.cweName}</span>
							</div>
						{/if}
						{#if finding.technicalDetails.cvssScore}
							<div class="tech-item">
								<span class="tech-label">CVSS</span>
								<span class="tech-value cvss" style="color: {getUrgencyColor(finding.urgency)}">
									{finding.technicalDetails.cvssScore} ({finding.technicalDetails.cvssLabel})
								</span>
							</div>
						{/if}
						{#if finding.technicalDetails.owaspCategory}
							<div class="tech-item">
								<span class="tech-label">OWASP</span>
								<span class="tech-value">{finding.technicalDetails.owaspCategory}</span>
							</div>
						{/if}
						<div class="tech-item">
							<span class="tech-label">Rule ID</span>
							<span class="tech-value mono">{finding.technicalDetails.ruleId}</span>
						</div>
						<div class="tech-item">
							<span class="tech-label">Severity</span>
							<span class="tech-value">{finding.technicalDetails.severity.toUpperCase()}</span>
						</div>
					</div>
				</div>
			</details>
		</div>
	{/if}
</div>

<style>
	.finding-card {
		background: var(--bg-primary);
		border: 1px solid var(--border);
		margin-bottom: 1rem;
		transition: all 0.15s ease;
	}

	.finding-card:hover {
		border-color: var(--text-tertiary);
	}

	.finding-card.expanded {
		border-color: var(--text-secondary);
	}

	/* Card Header */
	.card-header {
		width: 100%;
		padding: 1rem;
		background: transparent;
		border: none;
		text-align: left;
		cursor: pointer;
		position: relative;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.header-top {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.urgency-badge {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.65rem;
		font-weight: 500;
		padding: 0.2rem 0.5rem;
		text-transform: uppercase;
		letter-spacing: 0.02em;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		color: var(--text-tertiary);
	}

	.urgency-badge.ship-blocker {
		color: #ef4444;
		border-color: rgba(239, 68, 68, 0.3);
	}

	.urgency-badge.fix-this-week {
		color: #f97316;
		border-color: rgba(249, 115, 22, 0.3);
	}

	.urgency-badge.good-to-fix {
		color: #eab308;
		border-color: rgba(234, 179, 8, 0.3);
	}

	.urgency-badge.consider {
		color: #3b82f6;
		border-color: rgba(59, 130, 246, 0.3);
	}

	.urgency-badge.fyi {
		color: var(--text-tertiary);
		border-color: var(--border);
	}

	.finding-number {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		font-family: 'JetBrains Mono', monospace;
	}

	.headline {
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		font-size: 1.05rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
		padding-right: 2rem;
		line-height: 1.5;
		letter-spacing: -0.01em;
	}

	.location {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--text-tertiary);
	}

	.location svg {
		flex-shrink: 0;
	}

	.location code {
		font-size: 0.8rem;
		background: var(--bg-secondary);
		padding: 0.15rem 0.4rem;
		color: var(--text-secondary);
		word-break: break-all;
	}

	.chevron {
		position: absolute;
		right: 1rem;
		top: 50%;
		transform: translateY(-50%);
		color: var(--text-tertiary);
		transition: transform 0.2s ease;
	}

	.chevron.rotated {
		transform: translateY(-50%) rotate(180deg);
	}

	/* Card Content */
	.card-content {
		padding: 0 1rem 1rem;
		border-top: 1px solid var(--border);
		animation: slideIn 0.15s ease;
	}

	@keyframes slideIn {
		from {
			opacity: 0;
			transform: translateY(-8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	/* Sections */
	.section {
		margin-top: 1rem;
	}

	.section-title {
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		font-size: 0.75rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-tertiary);
		margin: 0 0 0.5rem 0;
	}

	.whats-wrong {
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		font-size: 0.95rem;
		line-height: 1.6;
		color: var(--text-secondary);
		margin: 0;
	}

	/* Consequences */
	.consequences {
		margin: 0;
		padding: 0;
		list-style: none;
	}

	.consequences li {
		position: relative;
		padding-left: 1.25rem;
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		font-size: 0.9rem;
		color: var(--text-secondary);
		margin-bottom: 0.4rem;
		line-height: 1.5;
	}

	.consequences li::before {
		content: '→';
		position: absolute;
		left: 0;
		color: var(--red);
	}

	/* Code Block */
	.code-block {
		margin: 0;
		padding: 0.75rem 1rem;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		font-size: 0.8rem;
		line-height: 1.5;
		overflow-x: auto;
		border-left: 3px solid var(--red);
	}

	.code-block code {
		background: transparent;
		padding: 0;
		font-family: 'JetBrains Mono', 'Fira Code', monospace;
	}

	/* AI Prompt Section - The Main Feature */
	.ai-prompt-section {
		background: var(--bg-secondary);
		margin-left: -1rem;
		margin-right: -1rem;
		padding: 1rem;
		border-top: 1px solid var(--border);
		border-bottom: 1px solid var(--border);
	}

	.prompt-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-bottom: 0.75rem;
	}

	.prompt-header .section-title {
		margin: 0;
		color: var(--green);
	}

	.prompt-hint {
		font-size: 0.75rem;
		color: var(--text-tertiary);
	}

	.prompt-box {
		position: relative;
		background: var(--bg-inverse);
		border: 1px solid var(--border);
	}

	.prompt-text {
		margin: 0;
		padding: 1rem;
		padding-bottom: 3rem;
		color: var(--text-inverse);
		font-size: 0.8rem;
		line-height: 1.6;
		white-space: pre-wrap;
		word-break: break-word;
		max-height: 300px;
		overflow-y: auto;
		font-family: 'JetBrains Mono', 'Fira Code', monospace;
	}

	.copy-btn {
		position: absolute;
		bottom: 0.75rem;
		right: 0.75rem;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		background: var(--green);
		color: white;
		border: none;
		font-size: 0.8rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.copy-btn:hover {
		background: var(--green-dim);
	}

	.copy-btn.copied {
		background: var(--green-dim);
	}

	/* Technical Details */
	.technical-details {
		margin-top: 1rem;
		border: 1px solid var(--border);
	}

	.technical-summary {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: var(--bg-tertiary);
		cursor: pointer;
		font-size: 0.8rem;
		color: var(--text-secondary);
		list-style: none;
	}

	.technical-summary::-webkit-details-marker {
		display: none;
	}

	.toggle-icon {
		margin-left: auto;
		font-family: monospace;
		font-size: 1rem;
	}

	.technical-summary:hover {
		background: var(--bg-secondary);
	}

	.technical-content {
		padding: 1rem;
		background: var(--bg-secondary);
	}

	.tech-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 0.75rem;
	}

	.tech-item {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}

	.tech-label {
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary);
	}

	.tech-value {
		font-size: 0.85rem;
		color: var(--text-primary);
	}

	.tech-value.mono {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
	}

	.tech-value.cvss {
		font-weight: 600;
	}

	/* Mobile Responsive */
	@media (max-width: 600px) {
		.card-header {
			padding: 0.875rem;
		}

		.headline {
			font-size: 0.95rem;
		}

		.location code {
			font-size: 0.75rem;
		}

		.prompt-text {
			font-size: 0.75rem;
			max-height: 250px;
		}

		.tech-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
