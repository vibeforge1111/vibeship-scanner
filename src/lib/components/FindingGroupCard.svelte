<script lang="ts">
	import type { FindingGroup, VibeOutput, VibeUrgency } from '$lib/vibeTransformer';
	import { getUrgencyColor, getUrgencyBgColor } from '$lib/vibeTransformer';
	import FindingCard from './FindingCard.svelte';

	let { group }: { group: FindingGroup } = $props();
	let expanded = $state(false);

	const severityColors: Record<VibeUrgency, string> = {
		'ship-blocker': '#ef4444',
		'fix-this-week': '#f97316',
		'good-to-fix': '#eab308',
		'consider': '#3b82f6',
		'fyi': '#6b7280'
	};

	const severityLabels: Record<VibeUrgency, string> = {
		'ship-blocker': 'Critical',
		'fix-this-week': 'High',
		'good-to-fix': 'Medium',
		'consider': 'Low',
		'fyi': 'Info'
	};

	function toggleExpanded() {
		expanded = !expanded;
	}
</script>

<div class="group-card" style="--severity-color: {severityColors[group.highestSeverity]}">
	<button class="group-header" onclick={toggleExpanded}>
		<div class="group-left">
			<span class="group-emoji">{group.categoryEmoji}</span>
			<div class="group-info">
				<span class="group-label">{group.categoryLabel}</span>
				<span class="group-count">{group.locationCount} location{group.locationCount !== 1 ? 's' : ''}</span>
			</div>
		</div>
		<div class="group-right">
			<span class="severity-badge" style="background: {getUrgencyBgColor(group.highestSeverity)}; color: {severityColors[group.highestSeverity]}">
				{severityLabels[group.highestSeverity]}
			</span>
			<span class="expand-icon" class:expanded>{expanded ? '−' : '+'}</span>
		</div>
	</button>

	{#if expanded}
		<div class="group-findings">
			{#each group.findings as finding, i}
				<FindingCard {finding} index={i} />
			{/each}
		</div>
	{/if}
</div>

<style>
	.group-card {
		border: 1px solid var(--border);
		border-left: 3px solid var(--severity-color);
		background: var(--bg-secondary);
		margin-bottom: 0.5rem;
	}

	.group-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 1rem 1.25rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
		transition: background 0.15s;
	}

	.group-header:hover {
		background: var(--bg-tertiary);
	}

	.group-left {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.group-emoji {
		font-size: 1.25rem;
	}

	.group-info {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}

	.group-label {
		font-family: 'Inter', -apple-system, sans-serif;
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-primary);
	}

	.group-count {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		color: var(--text-tertiary);
	}

	.group-right {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.severity-badge {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		font-weight: 600;
		padding: 0.25rem 0.5rem;
		text-transform: uppercase;
		letter-spacing: 0.03em;
	}

	.expand-icon {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1.25rem;
		font-weight: 300;
		color: var(--text-tertiary);
		width: 1.5rem;
		text-align: center;
		transition: transform 0.2s;
	}

	.expand-icon.expanded {
		color: var(--text-primary);
	}

	.group-findings {
		border-top: 1px solid var(--border);
		padding: 0.5rem;
		background: var(--bg-primary);
	}

	.group-findings :global(.finding-card) {
		margin-bottom: 0.5rem;
	}

	.group-findings :global(.finding-card:last-child) {
		margin-bottom: 0;
	}
</style>
