# Vibeship Scanner - Component Specification

## Component Architecture

```
src/lib/components/
├── ui/                    # Base UI primitives
│   ├── Button.svelte
│   ├── Input.svelte
│   ├── Card.svelte
│   ├── Badge.svelte
│   ├── Modal.svelte
│   ├── Tooltip.svelte
│   ├── Skeleton.svelte
│   └── Toggle.svelte
├── scan/                  # Scan flow components
│   ├── ScanInput.svelte
│   ├── ScanProgress.svelte
│   ├── ScanError.svelte
│   └── ScanHistory.svelte
├── results/               # Results display
│   ├── ScoreReveal.svelte
│   ├── GradeBadge.svelte
│   ├── FindingCard.svelte
│   ├── FindingList.svelte
│   ├── CategoryBreakdown.svelte
│   ├── StackDisplay.svelte
│   └── BenchmarkComparison.svelte
├── charts/                # Visualization
│   ├── RadarChart.svelte
│   ├── DonutChart.svelte
│   ├── TrendChart.svelte
│   └── ChartLoader.svelte
├── actions/               # Action components
│   ├── CopyButton.svelte
│   ├── ShareMenu.svelte
│   ├── BadgeEmbed.svelte
│   └── VibeshipCTA.svelte
├── layout/                # Layout components
│   ├── Header.svelte
│   ├── Footer.svelte
│   ├── Nav.svelte
│   └── Container.svelte
└── feedback/              # User feedback
    ├── FeedbackButtons.svelte
    └── EmailCapture.svelte
```

---

## Base UI Components

### Button

```svelte
<!-- ui/Button.svelte -->
<script lang="ts">
  export let variant: 'primary' | 'secondary' | 'ghost' | 'danger' = 'primary';
  export let size: 'sm' | 'md' | 'lg' = 'md';
  export let loading: boolean = false;
  export let disabled: boolean = false;
  export let href: string | undefined = undefined;
</script>

<!-- Usage -->
<Button variant="primary" size="lg" on:click={handleClick}>
  Start Scan
</Button>

<Button variant="secondary" href="/pro">
  Upgrade to Pro
</Button>

<Button loading={true}>
  Scanning...
</Button>
```

**Variants:**
| Variant | Background | Text | Border |
|---------|------------|------|--------|
| primary | vibeship-purple | white | none |
| secondary | transparent | vibeship-purple | vibeship-purple |
| ghost | transparent | gray-700 | none |
| danger | red-600 | white | none |

**Sizes:**
| Size | Padding | Font Size |
|------|---------|-----------|
| sm | px-3 py-1.5 | text-sm |
| md | px-4 py-2 | text-base |
| lg | px-6 py-3 | text-lg |

---

### Input

```svelte
<!-- ui/Input.svelte -->
<script lang="ts">
  export let type: 'text' | 'url' | 'email' = 'text';
  export let placeholder: string = '';
  export let value: string = '';
  export let error: string | undefined = undefined;
  export let icon: 'github' | 'gitlab' | 'link' | undefined = undefined;
</script>

<!-- Usage -->
<Input
  type="url"
  placeholder="https://github.com/user/repo"
  bind:value={repoUrl}
  error={urlError}
  icon="github"
/>
```

---

### Card

```svelte
<!-- ui/Card.svelte -->
<script lang="ts">
  export let variant: 'default' | 'elevated' | 'outlined' = 'default';
  export let padding: 'none' | 'sm' | 'md' | 'lg' = 'md';
  export let hoverable: boolean = false;
</script>

<!-- Usage -->
<Card variant="elevated" hoverable>
  <h3>Finding Title</h3>
  <p>Description...</p>
</Card>
```

---

### Badge

```svelte
<!-- ui/Badge.svelte -->
<script lang="ts">
  export let variant: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
  export let size: 'sm' | 'md' = 'md';
</script>

<!-- Usage -->
<Badge variant="critical">CRITICAL</Badge>
<Badge variant="high" size="sm">HIGH</Badge>
```

**Colors:**
| Variant | Background | Text |
|---------|------------|------|
| critical | red-100 | red-800 |
| high | orange-100 | orange-800 |
| medium | yellow-100 | yellow-800 |
| low | blue-100 | blue-800 |
| info | gray-100 | gray-800 |

---

### Modal

```svelte
<!-- ui/Modal.svelte -->
<script lang="ts">
  export let open: boolean = false;
  export let title: string = '';
  export let size: 'sm' | 'md' | 'lg' = 'md';
</script>

<!-- Usage -->
<Modal bind:open title="Share Your Score">
  <ShareContent />
</Modal>
```

---

## Scan Components

### ScanInput

Main input component on landing page.

```svelte
<!-- scan/ScanInput.svelte -->
<script lang="ts">
  import { goto } from '$app/navigation';
  import { startScan } from '$lib/api/scan';

  let url = '';
  let loading = false;
  let error = '';

  async function handleSubmit() {
    loading = true;
    error = '';

    try {
      const { scanId } = await startScan({ url });
      goto(`/scan/${scanId}`);
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }
</script>

<form on:submit|preventDefault={handleSubmit}>
  <div class="scan-input-container">
    <Input
      type="url"
      placeholder="Paste your GitHub repo URL"
      bind:value={url}
      {error}
      icon="github"
    />
    <Button type="submit" {loading}>
      {loading ? 'Scanning...' : 'Scan Free'}
    </Button>
  </div>
</form>
```

**Features:**
- URL validation (GitHub, GitLab patterns)
- Loading state with spinner
- Error display
- Keyboard submit (Enter)
- Auto-focus on mount

---

### ScanProgress

Real-time progress display during scanning.

```svelte
<!-- scan/ScanProgress.svelte -->
<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { supabase } from '$lib/supabase';

  export let scanId: string;

  let progress = {
    step: 'Initializing',
    stepNumber: 0,
    totalSteps: 5,
    message: 'Starting scan...'
  };

  const steps = [
    { id: 'clone', label: 'Cloning repository', icon: '📥' },
    { id: 'detect', label: 'Detecting stack', icon: '🔍' },
    { id: 'sast', label: 'Running security analysis', icon: '🛡️' },
    { id: 'deps', label: 'Checking dependencies', icon: '📦' },
    { id: 'score', label: 'Calculating score', icon: '📊' }
  ];

  let channel;

  onMount(() => {
    channel = supabase
      .channel(`scan:${scanId}`)
      .on('broadcast', { event: 'progress' }, ({ payload }) => {
        progress = payload;
      })
      .subscribe();
  });

  onDestroy(() => {
    channel?.unsubscribe();
  });
</script>

<div class="progress-container">
  <div class="progress-steps">
    {#each steps as step, i}
      <div class="step" class:active={i === progress.stepNumber} class:complete={i < progress.stepNumber}>
        <span class="step-icon">{step.icon}</span>
        <span class="step-label">{step.label}</span>
      </div>
    {/each}
  </div>

  <div class="progress-bar">
    <div
      class="progress-fill"
      style="width: {(progress.stepNumber / progress.totalSteps) * 100}%"
    ></div>
  </div>

  <p class="progress-message">{progress.message}</p>
</div>
```

**Features:**
- Real-time Supabase subscription
- Animated progress bar
- Step indicators with icons
- Current step highlight
- Estimated time remaining

---

## Results Components

### ScoreReveal

Animated score counter with confetti.

```svelte
<!-- results/ScoreReveal.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { spring } from 'svelte/motion';
  import confetti from 'canvas-confetti';

  export let score: number;
  export let grade: string;

  const displayScore = spring(0, { stiffness: 0.05, damping: 0.5 });

  $: color = getColorForScore(score);

  function getColorForScore(s: number) {
    if (s >= 90) return 'text-green-500';
    if (s >= 80) return 'text-lime-500';
    if (s >= 70) return 'text-yellow-500';
    if (s >= 60) return 'text-orange-500';
    return 'text-red-500';
  }

  onMount(() => {
    displayScore.set(score);

    if (score >= 80) {
      confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 }
      });
    }
  });
</script>

<div class="score-reveal">
  <div class="score-circle {color}">
    <span class="score-number">{Math.round($displayScore)}</span>
    <span class="score-label">out of 100</span>
  </div>

  <GradeBadge {grade} />
</div>
```

**Features:**
- Spring animation for smooth count-up
- Color transition based on score
- Confetti on high scores (80+)
- Grade badge display
- Responsive sizing

---

### GradeBadge

Large grade display with status.

```svelte
<!-- results/GradeBadge.svelte -->
<script lang="ts">
  export let grade: 'A' | 'B' | 'C' | 'D' | 'F';

  const gradeInfo = {
    A: { color: 'bg-green-500', status: 'Ship It!', emoji: '🚀' },
    B: { color: 'bg-lime-500', status: 'Almost There', emoji: '👍' },
    C: { color: 'bg-yellow-500', status: 'Needs Work', emoji: '⚠️' },
    D: { color: 'bg-orange-500', status: 'Risky', emoji: '😬' },
    F: { color: 'bg-red-500', status: 'Do Not Ship', emoji: '🛑' }
  };

  $: info = gradeInfo[grade];
</script>

<div class="grade-badge {info.color}">
  <span class="grade-letter">{grade}</span>
  <span class="grade-status">{info.emoji} {info.status}</span>
</div>
```

---

### FindingCard

Individual finding display with fix.

```svelte
<!-- results/FindingCard.svelte -->
<script lang="ts">
  import type { Finding } from '$lib/types';
  import { userPreferences } from '$lib/stores/preferences';

  export let finding: Finding;

  let expanded = false;

  $: mode = $userPreferences.explanationMode;
</script>

<Card variant="outlined" class="finding-card">
  <header class="finding-header" on:click={() => expanded = !expanded}>
    <Badge variant={finding.severity}>{finding.severity.toUpperCase()}</Badge>
    <h3 class="finding-title">{finding.title}</h3>
    <button class="expand-button">
      {expanded ? '▼' : '▶'}
    </button>
  </header>

  {#if expanded}
    <div class="finding-body" transition:slide>
      <!-- Location -->
      <div class="finding-location">
        <code>{finding.location.file}:{finding.location.line}</code>
      </div>

      <!-- Code Snippet -->
      <div class="finding-snippet">
        <pre><code>{finding.snippet.code}</code></pre>
      </div>

      <!-- Mode Toggle -->
      <div class="mode-toggle">
        <Toggle
          options={['Founder Mode', 'Developer Mode']}
          bind:selected={$userPreferences.explanationMode}
        />
      </div>

      <!-- Explanation -->
      <div class="finding-explanation">
        {#if mode === 'founder'}
          <FounderExplanation {finding} />
        {:else}
          <DeveloperExplanation {finding} />
        {/if}
      </div>

      <!-- Fix Section -->
      {#if finding.fix.available}
        <div class="finding-fix">
          <h4>Suggested Fix</h4>
          <pre><code>{finding.fix.template}</code></pre>
          <div class="fix-actions">
            <CopyButton text={finding.fix.template} />
            <Button variant="secondary" size="sm">
              View Full Fix
            </Button>
          </div>
        </div>
      {/if}

      <!-- CTA -->
      <VibeshipCTA findingId={finding.id} />
    </div>
  {/if}

  <!-- Feedback -->
  <footer class="finding-footer">
    <FeedbackButtons findingId={finding.id} />
  </footer>
</Card>
```

**Features:**
- Collapsible details
- Severity badge with color
- File location link
- Syntax-highlighted code
- Founder/Developer mode toggle
- Copy fix button
- Vibeship CTA
- Feedback buttons

---

### FindingList

Filterable list of findings.

```svelte
<!-- results/FindingList.svelte -->
<script lang="ts">
  import type { Finding } from '$lib/types';

  export let findings: Finding[];

  let filter = 'all';
  let sort = 'severity';

  $: filteredFindings = findings
    .filter(f => filter === 'all' || f.severity === filter)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
</script>

<div class="finding-list">
  <!-- Filters -->
  <div class="finding-filters">
    <select bind:value={filter}>
      <option value="all">All Severities</option>
      <option value="critical">Critical Only</option>
      <option value="high">High Only</option>
      <option value="medium">Medium Only</option>
      <option value="low">Low Only</option>
    </select>

    <select bind:value={sort}>
      <option value="severity">By Severity</option>
      <option value="file">By File</option>
      <option value="category">By Category</option>
    </select>
  </div>

  <!-- List -->
  {#each filteredFindings as finding (finding.id)}
    <FindingCard {finding} />
  {/each}

  {#if filteredFindings.length === 0}
    <div class="empty-state">
      <p>No findings match your filter.</p>
    </div>
  {/if}
</div>
```

---

### CategoryBreakdown

Summary cards for each category.

```svelte
<!-- results/CategoryBreakdown.svelte -->
<script lang="ts">
  export let summary: {
    code: { critical: number; high: number; medium: number; low: number };
    dependencies: { critical: number; high: number; medium: number; low: number };
    secrets: { critical: number; high: number; medium: number; low: number };
  };

  const categories = [
    { id: 'code', label: 'Code Security', icon: '🔐' },
    { id: 'dependencies', label: 'Dependencies', icon: '📦' },
    { id: 'secrets', label: 'Secrets', icon: '🔑' }
  ];
</script>

<div class="category-breakdown">
  {#each categories as cat}
    <Card>
      <div class="category-header">
        <span class="category-icon">{cat.icon}</span>
        <h4>{cat.label}</h4>
      </div>

      <div class="category-counts">
        {#if summary[cat.id].critical > 0}
          <Badge variant="critical">{summary[cat.id].critical}</Badge>
        {/if}
        {#if summary[cat.id].high > 0}
          <Badge variant="high">{summary[cat.id].high}</Badge>
        {/if}
        {#if summary[cat.id].medium > 0}
          <Badge variant="medium">{summary[cat.id].medium}</Badge>
        {/if}
        {#if summary[cat.id].low > 0}
          <Badge variant="low">{summary[cat.id].low}</Badge>
        {/if}
      </div>
    </Card>
  {/each}
</div>
```

---

## Chart Components

### RadarChart

Security category radar visualization.

```svelte
<!-- charts/RadarChart.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import * as echarts from 'echarts/core';

  export let data: {
    labels: string[];
    userScores: number[];
    communityScores: number[];
  };

  let chartEl: HTMLElement;
  let chart: echarts.ECharts;

  onMount(async () => {
    const { RadarChart } = await import('echarts/charts');
    const { CanvasRenderer } = await import('echarts/renderers');

    echarts.use([RadarChart, CanvasRenderer]);

    chart = echarts.init(chartEl);
    chart.setOption({
      radar: {
        indicator: data.labels.map(l => ({ name: l, max: 100 }))
      },
      series: [
        {
          type: 'radar',
          data: [
            {
              value: data.userScores,
              name: 'Your Score',
              areaStyle: { color: 'rgba(147, 51, 234, 0.3)' }
            },
            {
              value: data.communityScores,
              name: 'Community Average',
              lineStyle: { type: 'dashed' }
            }
          ]
        }
      ]
    });

    return () => chart.dispose();
  });
</script>

<div bind:this={chartEl} class="radar-chart"></div>
```

---

### DonutChart

Severity distribution visualization.

```svelte
<!-- charts/DonutChart.svelte -->
<script lang="ts">
  export let data: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
</script>
```

---

## Action Components

### CopyButton

Click-to-copy with feedback.

```svelte
<!-- actions/CopyButton.svelte -->
<script lang="ts">
  export let text: string;
  export let label: string = 'Copy';

  let copied = false;

  async function copy() {
    await navigator.clipboard.writeText(text);
    copied = true;
    setTimeout(() => copied = false, 2000);
  }
</script>

<Button variant="ghost" size="sm" on:click={copy}>
  {copied ? '✓ Copied!' : `📋 ${label}`}
</Button>
```

---

### ShareMenu

Social sharing dropdown.

```svelte
<!-- actions/ShareMenu.svelte -->
<script lang="ts">
  export let scanId: string;
  export let score: number;
  export let grade: string;

  const shareUrl = `https://scan.vibeship.com/scan/${scanId}`;

  function shareTwitter() {
    const text = `I just scored ${score}/100 (${grade}) on my security scan! 🛡️`;
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(shareUrl)}`);
  }

  function shareLinkedIn() {
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`);
  }
</script>

<div class="share-menu">
  <Button variant="ghost" on:click={shareTwitter}>
    Share on Twitter
  </Button>
  <Button variant="ghost" on:click={shareLinkedIn}>
    Share on LinkedIn
  </Button>
  <CopyButton text={shareUrl} label="Copy Link" />
</div>
```

---

### BadgeEmbed

Embeddable badge code generator.

```svelte
<!-- actions/BadgeEmbed.svelte -->
<script lang="ts">
  export let scanId: string;

  let style: 'flat' | 'flat-square' | 'plastic' | 'for-the-badge' = 'flat';

  $: badgeUrl = `https://scan.vibeship.com/api/badge/${scanId}?style=${style}`;
  $: markdown = `[![Vibeship Security](${badgeUrl})](https://scan.vibeship.com/scan/${scanId})`;
  $: html = `<a href="https://scan.vibeship.com/scan/${scanId}"><img src="${badgeUrl}" alt="Vibeship Security" /></a>`;
</script>

<div class="badge-embed">
  <div class="badge-preview">
    <img src={badgeUrl} alt="Security Badge Preview" />
  </div>

  <div class="style-selector">
    <label>Style:</label>
    <select bind:value={style}>
      <option value="flat">Flat</option>
      <option value="flat-square">Flat Square</option>
      <option value="plastic">Plastic</option>
      <option value="for-the-badge">For the Badge</option>
    </select>
  </div>

  <div class="embed-codes">
    <div class="embed-code">
      <label>Markdown</label>
      <code>{markdown}</code>
      <CopyButton text={markdown} />
    </div>

    <div class="embed-code">
      <label>HTML</label>
      <code>{html}</code>
      <CopyButton text={html} />
    </div>
  </div>
</div>
```

---

### VibeshipCTA

Conversion call-to-action.

```svelte
<!-- actions/VibeshipCTA.svelte -->
<script lang="ts">
  export let findingId: string | undefined = undefined;
  export let variant: 'inline' | 'card' | 'banner' = 'inline';
</script>

{#if variant === 'inline'}
  <a
    href="https://vibeship.com/help?finding={findingId}"
    class="vibeship-cta-inline"
  >
    Get Vibeship to fix this →
  </a>

{:else if variant === 'card'}
  <Card class="vibeship-cta-card">
    <h4>Need help fixing this?</h4>
    <p>Our security experts can fix this for you in hours, not days.</p>
    <Button variant="primary" href="https://vibeship.com/help">
      Get Expert Help
    </Button>
  </Card>

{:else if variant === 'banner'}
  <div class="vibeship-cta-banner">
    <div class="banner-content">
      <strong>Ship faster with Vibeship</strong>
      <p>Let our experts handle security while you build.</p>
    </div>
    <Button variant="primary" href="https://vibeship.com">
      Learn More
    </Button>
  </div>
{/if}
```

---

## Feedback Components

### FeedbackButtons

Quick feedback collection.

```svelte
<!-- feedback/FeedbackButtons.svelte -->
<script lang="ts">
  import { submitFeedback } from '$lib/api/feedback';

  export let scanId: string;
  export let findingId: string;

  let submitted = false;
  let submitting = false;

  async function submit(type: 'true_positive' | 'false_positive') {
    submitting = true;
    await submitFeedback({ scanId, findingId, type });
    submitted = true;
    submitting = false;
  }
</script>

<div class="feedback-buttons">
  {#if submitted}
    <span class="feedback-thanks">Thanks for your feedback!</span>
  {:else}
    <span class="feedback-prompt">Is this accurate?</span>
    <Button
      variant="ghost"
      size="sm"
      on:click={() => submit('true_positive')}
      disabled={submitting}
    >
      👍 Yes
    </Button>
    <Button
      variant="ghost"
      size="sm"
      on:click={() => submit('false_positive')}
      disabled={submitting}
    >
      👎 No
    </Button>
  {/if}
</div>
```

---

### EmailCapture

Email collection modal.

```svelte
<!-- feedback/EmailCapture.svelte -->
<script lang="ts">
  import { captureEmail } from '$lib/api/email';

  export let scanId: string;
  export let open: boolean = false;

  let email = '';
  let loading = false;
  let success = false;
</script>

<Modal bind:open title="Get Your Report">
  {#if success}
    <div class="success-message">
      <p>Check your email for your security report!</p>
      <Button on:click={() => open = false}>Done</Button>
    </div>
  {:else}
    <form on:submit|preventDefault={handleSubmit}>
      <p>Enter your email to receive a detailed security report.</p>

      <Input
        type="email"
        placeholder="you@example.com"
        bind:value={email}
        required
      />

      <Button type="submit" {loading}>
        Send Report
      </Button>

      <p class="privacy-note">
        We'll only email you about this scan. No spam.
      </p>
    </form>
  {/if}
</Modal>
```

---

## Layout Components

### Header

Global navigation header.

```svelte
<!-- layout/Header.svelte -->
<script lang="ts">
  import { user } from '$lib/stores/user';
</script>

<header class="site-header">
  <a href="/" class="logo">
    <img src="/logo.svg" alt="Vibeship Scanner" />
  </a>

  <nav class="main-nav">
    <a href="/scan">Scan</a>
    <a href="/pro">Pro</a>
    <a href="https://vibeship.com">Vibeship</a>
  </nav>

  <div class="user-nav">
    {#if $user}
      <a href="/scans">My Scans</a>
      <button on:click={logout}>Log Out</button>
    {:else}
      <Button variant="ghost" href="/auth">Sign In</Button>
    {/if}
  </div>
</header>
```

---

## Design Tokens

### Colors
```css
:root {
  --vibeship-purple: #9333ea;
  --vibeship-purple-light: #a855f7;
  --vibeship-purple-dark: #7e22ce;

  --severity-critical: #dc2626;
  --severity-high: #ea580c;
  --severity-medium: #ca8a04;
  --severity-low: #2563eb;
  --severity-info: #6b7280;

  --grade-a: #22c55e;
  --grade-b: #84cc16;
  --grade-c: #eab308;
  --grade-d: #f97316;
  --grade-f: #ef4444;
}
```

### Typography
```css
:root {
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;

  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-xl: 1.25rem;
  --text-2xl: 1.5rem;
  --text-3xl: 1.875rem;
  --text-4xl: 2.25rem;
}
```

### Spacing
```css
:root {
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;
  --space-12: 3rem;
  --space-16: 4rem;
}
```

### Animations
```css
:root {
  --transition-fast: 150ms ease;
  --transition-base: 200ms ease;
  --transition-slow: 300ms ease;

  --spring-bounce: cubic-bezier(0.68, -0.55, 0.265, 1.55);
}
```
