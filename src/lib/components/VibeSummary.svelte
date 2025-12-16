<script lang="ts">
	import type { TransformedResults } from '$lib/vibeTransformer';
	import { getUrgencyColor } from '$lib/vibeTransformer';

	interface Props {
		results: TransformedResults;
	}

	let { results }: Props = $props();

	let showMasterPrompt = $state(false);
	let copied = $state(false);

	function copyMasterPrompt() {
		navigator.clipboard.writeText(results.masterPrompt);
		copied = true;
		setTimeout(() => (copied = false), 2000);
	}
</script>

<!-- Master Fix Prompt Section - Displays only the AI prompt, counts are in parent -->
<div class="vibe-summary">
	{#if results.masterPrompt && (results.summary.shipBlockers > 0 || results.summary.fixThisWeek > 0)}
		<div class="master-prompt-section">
			<button class="master-prompt-toggle" onclick={() => (showMasterPrompt = !showMasterPrompt)}>
				<div class="toggle-content">
					<span class="toggle-icon">🤖</span>
					<div class="toggle-text">
						<span class="toggle-title">Fix All Critical Issues with AI</span>
						<span class="toggle-subtitle">
							One prompt to fix {results.summary.shipBlockers + results.summary.fixThisWeek} issues
						</span>
					</div>
				</div>
				<span class="toggle-chevron" class:open={showMasterPrompt}>
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<polyline points="6 9 12 15 18 9" />
					</svg>
				</span>
			</button>

			{#if showMasterPrompt}
				<div class="master-prompt-content">
					<div class="prompt-instructions">
						<p><strong>How to use:</strong></p>
						<ol>
							<li>Copy the prompt below</li>
							<li>Paste into Claude Code, Cursor, or ChatGPT</li>
							<li>The AI will fix each issue one by one</li>
							<li>Review and approve each fix</li>
						</ol>
					</div>

					<div class="prompt-box">
						<pre class="prompt-text">{results.masterPrompt}</pre>
						<button class="copy-master-btn" class:copied onclick={copyMasterPrompt}>
							{#if copied}
								<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<polyline points="20 6 9 17 4 12" />
								</svg>
								Copied!
							{:else}
								<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
									<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
								</svg>
								Copy Master Prompt
							{/if}
						</button>
					</div>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.vibe-summary {
		margin-bottom: 1.5rem;
	}

	/* Master Prompt Section */
	.master-prompt-section {
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		padding: 1rem 1.5rem;
	}

	.master-prompt-toggle {
		width: 100%;
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem;
		background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(59, 130, 246, 0.1));
		border: 1px solid var(--green);
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.master-prompt-toggle:hover {
		background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(59, 130, 246, 0.15));
	}

	.toggle-content {
		display: flex;
		align-items: center;
		gap: 1rem;
	}

	.toggle-icon {
		font-size: 1.5rem;
	}

	.toggle-text {
		display: flex;
		flex-direction: column;
		text-align: left;
	}

	.toggle-title {
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-primary);
	}

	.toggle-subtitle {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.toggle-chevron {
		color: var(--text-secondary);
		transition: transform 0.2s ease;
	}

	.toggle-chevron.open {
		transform: rotate(180deg);
	}

	/* Master Prompt Content */
	.master-prompt-content {
		padding: 1rem;
		background: var(--bg-primary);
		border: 1px solid var(--border);
		border-top: none;
		animation: slideDown 0.15s ease;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			transform: translateY(-8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.prompt-instructions {
		margin-bottom: 1rem;
	}

	.prompt-instructions p {
		margin: 0 0 0.5rem 0;
		font-size: 0.85rem;
		color: var(--text-primary);
	}

	.prompt-instructions ol {
		margin: 0;
		padding-left: 1.25rem;
	}

	.prompt-instructions li {
		font-size: 0.85rem;
		color: var(--text-secondary);
		margin-bottom: 0.25rem;
	}

	.prompt-box {
		position: relative;
		background: var(--bg-inverse);
		border: 1px solid var(--border);
	}

	.prompt-text {
		margin: 0;
		padding: 1rem;
		padding-bottom: 4rem;
		color: var(--text-inverse);
		font-size: 0.8rem;
		line-height: 1.6;
		white-space: pre-wrap;
		word-break: break-word;
		max-height: 400px;
		overflow-y: auto;
		font-family: 'JetBrains Mono', 'Fira Code', monospace;
	}

	.copy-master-btn {
		position: absolute;
		bottom: 1rem;
		right: 1rem;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		background: var(--green);
		color: white;
		border: none;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.copy-master-btn:hover {
		background: var(--green-dim);
	}

	.copy-master-btn.copied {
		background: var(--green-dim);
	}

	/* Mobile */
	@media (max-width: 600px) {
		.master-prompt-section {
			padding: 0.75rem 1rem;
		}

		.toggle-content {
			gap: 0.75rem;
		}

		.toggle-title {
			font-size: 0.85rem;
		}

		.toggle-subtitle {
			font-size: 0.75rem;
		}

		.prompt-text {
			font-size: 0.75rem;
			max-height: 300px;
		}

		.copy-master-btn {
			padding: 0.6rem 1rem;
			font-size: 0.8rem;
		}
	}
</style>
