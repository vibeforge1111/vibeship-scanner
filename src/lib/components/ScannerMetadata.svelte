<script lang="ts">
	interface ScannerInfo {
		name: string;
		category: string;
		targets: string;
		findings: number;
		duration_ms: number;
	}

	interface StackInfo {
		languages?: string[];
		frameworks?: string[];
		scanners_run?: ScannerInfo[];
		scanners_skipped?: { name: string; reason: string }[];
		raw_findings_count?: number;
		deduplicated_count?: number;
	}

	let { stack, duration }: { stack: StackInfo; duration?: number } = $props();
	let expanded = $state(false);

	// Separate universal and stack-specific scanners
	const universalScanners = $derived(
		(stack?.scanners_run || []).filter(s => s.category === 'universal')
	);
	const stackScanners = $derived(
		(stack?.scanners_run || []).filter(s => s.category === 'stack')
	);
	const activeScanners = $derived(stackScanners.filter(s => s.findings > 0));
	const inactiveScanners = $derived(stackScanners.filter(s => s.findings === 0));

	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		const seconds = (ms / 1000).toFixed(1);
		return `${seconds}s`;
	}
</script>

{#if stack?.scanners_run?.length}
	<div class="scanner-metadata">
		<button class="metadata-header" onclick={() => expanded = !expanded}>
			<div class="header-left">
				<span class="header-icon">🔬</span>
				<span class="header-title">Scanner Details</span>
				<span class="scanner-count">
					{stack.scanners_run.length} scanner{stack.scanners_run.length !== 1 ? 's' : ''} ran
				</span>
			</div>
			<div class="header-right">
				{#if stack.raw_findings_count && stack.deduplicated_count && stack.raw_findings_count !== stack.deduplicated_count}
					<span class="dedup-badge">
						{stack.raw_findings_count - stack.deduplicated_count} duplicates removed
					</span>
				{/if}
				<span class="expand-icon">{expanded ? '−' : '+'}</span>
			</div>
		</button>

		{#if expanded}
			<div class="metadata-content">
				<!-- Detected Stack -->
				{#if stack.languages?.length || stack.frameworks?.length}
					<div class="stack-section">
						<h4>Detected Stack</h4>
						<div class="stack-tags">
							{#each stack.languages || [] as lang}
								<span class="stack-tag lang">{lang}</span>
							{/each}
							{#each stack.frameworks || [] as fw}
								<span class="stack-tag framework">{fw}</span>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Universal Scanners -->
				{#if universalScanners.length}
					<div class="scanner-section">
						<h4>Universal Scanners <span class="section-note">(always run)</span></h4>
						<div class="scanner-list">
							{#each universalScanners as scanner}
								<div class="scanner-item">
									<span class="scanner-name">{scanner.name}</span>
									<span class="scanner-targets">{scanner.targets}</span>
									<span class="scanner-stats">
										<span class="findings-count" class:has-findings={scanner.findings > 0}>
											{scanner.findings}
										</span>
										<span class="duration">{formatDuration(scanner.duration_ms)}</span>
									</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Active Stack Scanners -->
				{#if activeScanners.length}
					<div class="scanner-section">
						<h4>Stack-Specific <span class="section-note">(found issues)</span></h4>
						<div class="scanner-list">
							{#each activeScanners as scanner}
								<div class="scanner-item active">
									<span class="scanner-name">{scanner.name}</span>
									<span class="scanner-targets">{scanner.targets}</span>
									<span class="scanner-stats">
										<span class="findings-count has-findings">{scanner.findings}</span>
										<span class="duration">{formatDuration(scanner.duration_ms)}</span>
									</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Inactive Stack Scanners -->
				{#if inactiveScanners.length}
					<div class="scanner-section skipped">
						<h4>Stack-Specific <span class="section-note">(no relevant files)</span></h4>
						<div class="scanner-chips">
							{#each inactiveScanners as scanner}
								<span class="scanner-chip">{scanner.name}</span>
							{/each}
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</div>
{/if}

<style>
	.scanner-metadata {
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		margin-bottom: 1rem;
	}

	.metadata-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 0.75rem 1rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
		transition: background 0.15s;
	}

	.metadata-header:hover {
		background: var(--bg-tertiary);
	}

	.header-left {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.header-icon {
		font-size: 1rem;
	}

	.header-title {
		font-family: 'Inter', -apple-system, sans-serif;
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--text-primary);
	}

	.scanner-count {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		color: var(--text-tertiary);
		padding: 0.2rem 0.5rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
	}

	.header-right {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.dedup-badge {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.65rem;
		color: var(--green);
		padding: 0.2rem 0.5rem;
		background: rgba(46, 204, 113, 0.1);
		border: 1px solid rgba(46, 204, 113, 0.3);
	}

	.expand-icon {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1rem;
		color: var(--text-tertiary);
		width: 1.5rem;
		text-align: center;
	}

	.metadata-content {
		padding: 1rem;
		border-top: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.stack-section,
	.scanner-section {
		margin-bottom: 1.25rem;
	}

	.stack-section:last-child,
	.scanner-section:last-child {
		margin-bottom: 0;
	}

	h4 {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
		margin: 0 0 0.5rem 0;
	}

	.section-note {
		font-weight: 400;
		color: var(--text-tertiary);
	}

	.stack-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}

	.stack-tag {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		padding: 0.25rem 0.5rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		color: var(--text-secondary);
	}

	.stack-tag.lang {
		border-color: rgba(59, 130, 246, 0.3);
		background: rgba(59, 130, 246, 0.08);
		color: #3b82f6;
	}

	.stack-tag.framework {
		border-color: rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.08);
		color: #a855f7;
	}

	.scanner-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.scanner-item {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.5rem 0.75rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		font-size: 0.8rem;
	}

	.scanner-item.active {
		border-left: 3px solid var(--orange);
	}

	.scanner-name {
		font-family: 'JetBrains Mono', monospace;
		font-weight: 600;
		color: var(--text-primary);
		min-width: 80px;
	}

	.scanner-targets {
		flex: 1;
		color: var(--text-tertiary);
		font-size: 0.75rem;
	}

	.scanner-stats {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
	}

	.findings-count {
		color: var(--text-tertiary);
		min-width: 30px;
		text-align: right;
	}

	.findings-count.has-findings {
		color: var(--orange);
		font-weight: 600;
	}

	.duration {
		color: var(--text-tertiary);
		min-width: 50px;
		text-align: right;
	}

	.scanner-section.skipped h4 {
		color: var(--text-tertiary);
	}

	.scanner-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}

	.scanner-chip {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.65rem;
		padding: 0.2rem 0.5rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		color: var(--text-tertiary);
	}
</style>
