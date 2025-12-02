# Vibeship Scanner — PRD v4

## The Living Security Scanner

**Version:** 4.0  
**Status:** Ready for Development  
**Philosophy:** Scan free. Ship safe. Get help when you need it.

---

## Executive Summary

**Vibeship Scanner** is not a separate product — it's Vibeship's front door. A free, world-class security scanner that:

1. **Hooks users** with genuinely useful free scans
2. **Builds trust** by finding real issues (not false positives)
3. **Converts users** to Vibeship expert services

Every scan promotes Vibeship. Every finding has a "Get help" CTA. Every badge says "Scanned by Vibeship."

---

## Table of Contents

1. [Strategic Positioning](#part-1-strategic-positioning)
2. [Architecture Overview](#part-2-architecture-overview)
3. [Tech Stack](#part-3-tech-stack)
4. [Tiered Scanning Pipeline](#part-4-tiered-scanning-pipeline)
5. [Intelligence System](#part-5-intelligence-system)
6. [Privacy & Security Protocol](#part-6-privacy--security-protocol)
7. [Experience Layer](#part-7-experience-layer)
8. [Free vs Pro Split](#part-8-free-vs-pro-split)
9. [Database Schema](#part-9-database-schema)
10. [Development Roadmap](#part-10-development-roadmap)
11. [Success Metrics](#part-11-success-metrics)

---

## Part 1: Strategic Positioning

### The Funnel

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VIBESHIP SCANNER FUNNEL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                          ┌───────────────────┐                              │
│                          │   AWARENESS       │                              │
│                          │                   │                              │
│                          │  • Reddit posts   │                              │
│                          │  • Twitter/X      │                              │
│                          │  • Badge backlinks│                              │
│                          │  • Word of mouth  │                              │
│                          └─────────┬─────────┘                              │
│                                    │                                         │
│                                    ▼                                         │
│                          ┌───────────────────┐                              │
│                          │   HOOK            │                              │
│                          │                   │                              │
│                          │  "Scan your app   │                              │
│                          │   free in 30 sec" │                              │
│                          │                   │                              │
│                          └─────────┬─────────┘                              │
│                                    │                                         │
│                                    ▼                                         │
│                          ┌───────────────────┐                              │
│                          │   VALUE           │                              │
│                          │                   │                              │
│                          │  Score + Issues   │                              │
│                          │  + Actionable     │                              │
│                          │    Fixes          │                              │
│                          │                   │                              │
│                          └─────────┬─────────┘                              │
│                                    │                                         │
│                         ┌──────────┴──────────┐                             │
│                         │                     │                             │
│                         ▼                     ▼                             │
│              ┌─────────────────┐   ┌─────────────────┐                     │
│              │   SELF-SERVE    │   │   GET HELP      │                     │
│              │                 │   │                 │                     │
│              │  Fix it myself  │   │  "Fix this for  │                     │
│              │  (free)         │   │   me" → Vibeship│                     │
│              │                 │   │   Expert ($$$)  │                     │
│              └────────┬────────┘   └────────┬────────┘                     │
│                       │                     │                               │
│                       │                     ▼                               │
│                       │            ┌─────────────────┐                     │
│                       │            │   REVENUE       │                     │
│                       │            │                 │                     │
│                       │            │  • One-time fix │                     │
│                       │            │  • Code audit   │                     │
│                       │            │  • Ongoing help │                     │
│                       │            │                 │                     │
│                       │            └─────────────────┘                     │
│                       │                                                     │
│                       ▼                                                     │
│              ┌─────────────────┐                                           │
│              │   VIRAL LOOP    │                                           │
│              │                 │                                           │
│              │  • Share score  │                                           │
│              │  • Embed badge  │                                           │
│              │  • Tell friends │                                           │
│              │                 │                                           │
│              └─────────────────┘                                           │
│                       │                                                     │
│                       └──────────────► (Back to Awareness)                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Works

| Traditional Security Scanners | Vibeship Scanner |
|------------------------------|------------------|
| Intimidating, technical | Friendly, approachable |
| Overwhelming results | Prioritized, actionable |
| "Figure it out yourself" | "We'll help you fix it" |
| Separate brand | Integrated funnel to services |
| Generic fixes | Stack-specific, copy-paste ready |
| No follow-up | Natural path to paid help |

---

## Part 2: Architecture Overview

### The Three Layers (Simplified)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      VIBESHIP SCANNER ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ╔═══════════════════════════════════════════════════════════════════════╗  │
│  ║                  LAYER 3: INTELLIGENCE (Background)                    ║  │
│  ║                                                                         ║  │
│  ║  ┌──────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │                     SAFETY GATES                                  │  ║  │
│  ║  │                                                                   │  ║  │
│  ║  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │  ║  │
│  ║  │  │   SHADOW    │ →  │  VALIDATE   │ →  │   PROMOTE   │          │  ║  │
│  ║  │  │    MODE     │    │   (95%+)    │    │  TO ACTIVE  │          │  ║  │
│  ║  │  └─────────────┘    └─────────────┘    └─────────────┘          │  ║  │
│  ║  │                                                                   │  ║  │
│  ║  └──────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                                                         ║  │
│  ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   ║  │
│  ║  │   PATTERN   │  │    RULE     │  │    FIX      │  │  COMMUNITY  │   ║  │
│  ║  │   LEARNER   │  │  EVOLUTION  │  │  IMPROVER   │  │   STATS     │   ║  │
│  ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   ║  │
│  ║                                                                         ║  │
│  ╚═══════════════════════════════════════════════════════════════════════╝  │
│                                      │                                       │
│                                      ▼                                       │
│  ╔═══════════════════════════════════════════════════════════════════════╗  │
│  ║                  LAYER 2: EXPERIENCE (User-Facing)                     ║  │
│  ║                                                                         ║  │
│  ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   ║  │
│  ║  │   SCORE     │  │   FINDING   │  │    FIX      │  │  VIBESHIP   │   ║  │
│  ║  │   REVEAL    │  │   CARDS     │  │   GUIDES    │  │    CTA      │   ║  │
│  ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   ║  │
│  ║                                                                         ║  │
│  ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   ║  │
│  ║  │   CHARTS    │  │   BADGES    │  │   SHARING   │  │    PDF      │   ║  │
│  ║  │             │  │             │  │             │  │   REPORT    │   ║  │
│  ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   ║  │
│  ║                                                                         ║  │
│  ╚═══════════════════════════════════════════════════════════════════════╝  │
│                                      │                                       │
│                                      ▼                                       │
│  ╔═══════════════════════════════════════════════════════════════════════╗  │
│  ║                  LAYER 1: SCANNING (Tiered Pipeline)                   ║  │
│  ║                                                                         ║  │
│  ║  TIER 1 (Fast & Free)           TIER 2 (Deep Analysis - Pro)          ║  │
│  ║  ┌─────────────────────────┐    ┌─────────────────────────────────┐   ║  │
│  ║  │ Semgrep │ Trivy │ Leaks │    │ Claude AI │ Anomaly │ Deep Fix  │   ║  │
│  ║  │  SAST   │ Deps  │ Secrets│    │ Analysis  │ Detect  │ Generation│   ║  │
│  ║  └─────────────────────────┘    └─────────────────────────────────┘   ║  │
│  ║                                                                         ║  │
│  ╚═══════════════════════════════════════════════════════════════════════╝  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Tech Stack

### Simplified & Cost-Optimized

```yaml
# ============================================
# FRONTEND
# ============================================
Framework: SvelteKit 2.0
  Why: Fastest, smallest bundles, native animations
  
Styling: Tailwind CSS 4.0

Charts: Apache ECharts 5 (lazy-loaded)
  Critical: Only load when score reveal happens
  Size: ~800KB, so lazy load is essential

Animation: 
  - Svelte transitions (free, fast)
  - Motion One (3KB, for complex sequences)

# ============================================
# BACKEND
# ============================================
API: SvelteKit API Routes
  - Type-safe
  - Edge-ready
  - Simple

Database: Supabase
  PostgreSQL:
    - Main data store
    - pgvector for embeddings (no separate Pinecone)
    - Full-text search
    
  Realtime:
    - Live scan progress
    - No polling needed
    
  Auth:
    - GitHub OAuth (for private repos)
    - Anonymous sessions (for quick scans)
    
  Storage:
    - PDF reports
    - Badge cache

Cache: Upstash Redis
  - Rate limiting
  - Scan result cache
  - Session storage

Background Jobs: Trigger.dev
  - Scan orchestration
  - Long-running tasks
  - Automatic retries

# ============================================
# SCANNING INFRASTRUCTURE
# ============================================
Compute: Fly.io Machines
  Spec:
    - 512MB RAM (1GB for large repos)
    - 0.5 CPU
    - 90 second timeout
    - Auto-destroy after scan

Tier 1 Scanners (Always Run):
  - Semgrep (SAST, custom rules)
  - Trivy (dependencies, CVEs)
  - Gitleaks (secrets)

Tier 2 Scanners (Pro Only):
  - Claude AI (deep analysis)
  - Nuclei (DAST for URLs)
  - Custom anomaly detection

# ============================================
# INTELLIGENCE (Simplified)
# ============================================
LLM: Claude API
  Primary: claude-sonnet-4-20250514
  Fallback: claude-3-5-haiku (cost optimization)
  
  Router: Simple internal router
    - Classification tasks → Haiku
    - Code analysis → Sonnet
    - Fix generation → Sonnet

Vector Storage: Supabase pgvector
  Why: Already using Supabase, simplifies RLS, cascading deletes
  Tradeoff: Less performant than Pinecone at scale
  Decision: Good enough for MVP, migrate later if needed

Memory: Supabase tables + pgvector
  No Metorial for MVP - too complex
  Simple tables for:
    - Aggregate patterns (not user-specific)
    - Fix effectiveness tracking
    - Community benchmarks

# ============================================
# OBSERVABILITY
# ============================================
Errors: Sentry
Analytics: PostHog
Uptime: Checkly (or just UptimeRobot)
Logging: Axiom (or Supabase logs for MVP)
```

### Cost Projection

| Component | Free Tier | Paid Estimate |
|-----------|-----------|---------------|
| Supabase | 500MB DB, 2GB storage | $25/mo (Pro) |
| Fly.io | 3 shared VMs | ~$20/mo |
| Upstash Redis | 10K commands/day | $10/mo |
| Trigger.dev | 5K runs/mo | $30/mo |
| Claude API | - | ~$50/mo @ 1K scans |
| Vercel | 100GB bandwidth | Free tier likely enough |
| **Total** | **~$0** (MVP) | **~$135/mo** (scaling) |

---

## Part 4: Tiered Scanning Pipeline

### The Cost Problem (And Solution)

Running Claude + vector search + Fly machines on every scan is expensive. Most scans don't need AI.

**Solution: Tiered Pipeline**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIERED SCANNING PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  TIER 1: FAST SCAN (Free)                                            │   │
│  │  ────────────────────────                                            │   │
│  │                                                                       │   │
│  │  Cost: ~$0.001 per scan                                              │   │
│  │  Time: 10-30 seconds                                                 │   │
│  │                                                                       │   │
│  │  What runs:                                                           │   │
│  │  ├── Semgrep (500+ custom rules)                                     │   │
│  │  ├── Trivy (dependency CVEs)                                         │   │
│  │  ├── Gitleaks (secret detection)                                     │   │
│  │  └── Stack detection (package.json, etc.)                            │   │
│  │                                                                       │   │
│  │  Output:                                                              │   │
│  │  ├── Security score                                                  │   │
│  │  ├── Findings with severity                                          │   │
│  │  ├── Template-based fix suggestions                                  │   │
│  │  └── Community benchmarks                                            │   │
│  │                                                                       │   │
│  │  ✅ Sufficient for 90% of scans                                      │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│                                    │                                         │
│                                    │ Escalate if:                            │
│                                    │ • User requests "Deep Scan"             │
│                                    │ • Complex issues found                  │
│                                    │ • Anomaly detected                      │
│                                    │ • Pro user                              │
│                                    ▼                                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  TIER 2: DEEP SCAN (Pro)                                             │   │
│  │  ───────────────────────                                             │   │
│  │                                                                       │   │
│  │  Cost: ~$0.05-0.15 per scan                                          │   │
│  │  Time: 30-60 seconds additional                                      │   │
│  │                                                                       │   │
│  │  What runs (in addition to Tier 1):                                  │   │
│  │  ├── Claude AI code analysis                                         │   │
│  │  ├── Anomaly detection (pattern matching)                            │   │
│  │  ├── AI-generated personalized fixes                                 │   │
│  │  ├── Nuclei DAST (for URLs)                                          │   │
│  │  └── Prediction engine ("what's likely next")                        │   │
│  │                                                                       │   │
│  │  Output:                                                              │   │
│  │  ├── Everything from Tier 1                                          │   │
│  │  ├── AI explanations (technical + founder mode)                      │   │
│  │  ├── Custom fix code for YOUR codebase                               │   │
│  │  ├── Attack demonstrations                                           │   │
│  │  └── PDF report with full analysis                                   │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Implementation

```typescript
// lib/scanning/pipeline.ts

async function runScan(target: ScanTarget, options: ScanOptions): Promise<ScanResult> {
  const { userId, tier } = options;
  
  // Always run Tier 1
  const tier1Results = await runTier1(target);
  
  // Determine if we should escalate
  const shouldEscalate = 
    tier === 'pro' ||
    options.deepScan ||
    hasComplexFindings(tier1Results) ||
    hasAnomalies(tier1Results);
  
  if (!shouldEscalate) {
    // Return Tier 1 results with template fixes
    return {
      ...tier1Results,
      fixes: await getTemplateFixes(tier1Results.findings),
      tier: 'standard'
    };
  }
  
  // Run Tier 2
  const tier2Results = await runTier2(target, tier1Results);
  
  return {
    ...tier1Results,
    ...tier2Results,
    tier: 'deep'
  };
}

async function runTier1(target: ScanTarget): Promise<Tier1Result> {
  // Run in parallel for speed
  const [semgrepResults, trivyResults, gitleaksResults, stackInfo] = 
    await Promise.all([
      runSemgrep(target),
      runTrivy(target),
      runGitleaks(target),
      detectStack(target)
    ]);
  
  // Merge and dedupe findings
  const findings = mergeFindings([
    ...semgrepResults.findings,
    ...trivyResults.findings,
    ...gitleaksResults.findings
  ]);
  
  // Apply environment-aware scoring
  const scoredFindings = applyContextualScoring(findings, stackInfo);
  
  // Calculate score
  const score = calculateScore(scoredFindings);
  
  return {
    findings: scoredFindings,
    score,
    stack: stackInfo,
    benchmarks: await getCommunityBenchmarks(stackInfo)
  };
}

async function runTier2(
  target: ScanTarget, 
  tier1: Tier1Result
): Promise<Tier2Result> {
  // AI analysis of complex findings
  const aiAnalysis = await analyzeWithClaude(
    tier1.findings.filter(f => f.severity === 'critical' || f.severity === 'high'),
    tier1.stack
  );
  
  // Generate personalized fixes
  const aiFixes = await generateAIFixes(tier1.findings, target);
  
  // Run anomaly detection
  const anomalies = await detectAnomalies(target, tier1.stack);
  
  // Generate predictions
  const predictions = await generatePredictions(tier1, target);
  
  return {
    aiAnalysis,
    aiFixes,
    anomalies,
    predictions
  };
}
```

### Environment-Aware Scoring

```typescript
// lib/scoring/contextual.ts

interface ScoringContext {
  filePath: string;
  isTestFile: boolean;
  isExampleFile: boolean;
  isInMainBundle: boolean;
  importedByEntryPoint: boolean;
}

function applyContextualScoring(
  findings: Finding[],
  stackInfo: StackInfo
): Finding[] {
  return findings.map(finding => {
    const context = analyzeFileContext(finding.file, stackInfo);
    
    // Downgrade severity for non-production code
    if (context.isTestFile || context.isExampleFile) {
      return {
        ...finding,
        severity: downgradeSeverity(finding.severity),
        contextNote: 'Found in test/example file - lower risk'
      };
    }
    
    // Upgrade severity for critical paths
    if (context.isInMainBundle && finding.category === 'secrets') {
      return {
        ...finding,
        severity: 'critical',
        contextNote: 'Exposed in client bundle - highest risk'
      };
    }
    
    return finding;
  });
}

function downgradeSeverity(severity: Severity): Severity {
  const downgrade: Record<Severity, Severity> = {
    critical: 'high',
    high: 'medium',
    medium: 'low',
    low: 'info',
    info: 'info'
  };
  return downgrade[severity];
}
```

---

## Part 5: Intelligence System

### Safety-First Learning

The biggest risk with "learning" systems is deploying bad rules. **All AI-generated rules must pass through Shadow Mode.**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RULE LIFECYCLE WITH SAFETY GATES                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 1: DISCOVERY                                                  │   │
│  │  ─────────────────────                                               │   │
│  │                                                                       │   │
│  │  Sources:                                                             │   │
│  │  • AI pattern detection from scans                                   │   │
│  │  • User feedback ("this is a real issue")                            │   │
│  │  • Manual rule creation                                              │   │
│  │  • CVE/security feed imports                                         │   │
│  │                                                                       │   │
│  │  Output: Candidate rule                                               │   │
│  │                                                                       │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 2: SHADOW MODE (1-2 weeks)                                    │   │
│  │  ────────────────────────────────                                    │   │
│  │                                                                       │   │
│  │  • Rule runs on ALL scans silently                                   │   │
│  │  • Findings are logged but NOT shown to users                        │   │
│  │  • Collects:                                                          │   │
│  │    - Match count                                                      │   │
│  │    - Code context of matches                                          │   │
│  │    - Stack distribution                                               │   │
│  │                                                                       │   │
│  │  Exit criteria:                                                       │   │
│  │  • Minimum 50 matches collected                                      │   │
│  │  • OR 2 weeks elapsed                                                │   │
│  │                                                                       │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 3: VALIDATION                                                 │   │
│  │  ────────────────────                                                │   │
│  │                                                                       │   │
│  │  Automated checks:                                                    │   │
│  │  • Run against known-good test cases (must pass)                     │   │
│  │  • Run against known-bad test cases (must catch)                     │   │
│  │  • Check false positive rate estimate                                │   │
│  │                                                                       │   │
│  │  Human review (for high-severity rules):                             │   │
│  │  • Sample 10 matches reviewed by team                                │   │
│  │  • Confirm ≥95% are true positives                                   │   │
│  │                                                                       │   │
│  │  Decision:                                                            │   │
│  │  ├── ✅ PASS: Precision ≥95% → Promote                               │   │
│  │  ├── ⚠️ REFINE: Precision 80-95% → Back to Discovery                 │   │
│  │  └── ❌ REJECT: Precision <80% → Archive                             │   │
│  │                                                                       │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 4: ACTIVE DEPLOYMENT                                          │   │
│  │  ──────────────────────────────                                      │   │
│  │                                                                       │   │
│  │  • Rule now runs and shows findings to users                         │   │
│  │  • Continuous monitoring:                                             │   │
│  │    - Track "not an issue" feedback                                   │   │
│  │    - Alert if false positive rate exceeds 5%                         │   │
│  │                                                                       │   │
│  │  Demotion triggers:                                                   │   │
│  │  • >5% false positive rate → Back to Shadow                          │   │
│  │  • >10% false positive rate → Immediate disable                      │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Cold Start Solution

Don't wait for user scans to train the system. Pre-seed intelligence before launch.

```typescript
// scripts/cold-start.ts

const SEED_REPOS = [
  // Popular starter templates
  'vercel/next.js/examples/*',
  'supabase/supabase/examples/*',
  'shadcn/ui/apps/*',
  
  // Real-world vibe-coded apps (public)
  'github search: "built with cursor" stars:>10',
  'github search: "vibe coded" stars:>5',
  
  // Intentionally vulnerable (for training)
  'OWASP/NodeGoat',
  'juice-shop/juice-shop'
];

async function runColdStart() {
  console.log('🌱 Starting cold start seeding...');
  
  for (const repo of SEED_REPOS) {
    // Run full Tier 1 scan
    const result = await runScan({ url: repo, type: 'github' });
    
    // Feed into pattern learner
    await recordPatterns(result);
    
    // Build community benchmarks
    await updateStackBenchmarks(result);
    
    // Populate fix effectiveness (from known fixes)
    await seedFixTemplates(result);
  }
  
  console.log('✅ Cold start complete');
  console.log(`   Scanned: ${SEED_REPOS.length} repos`);
  console.log(`   Patterns: ${await countPatterns()}`);
  console.log(`   Benchmarks: ${await countBenchmarks()}`);
}
```

### Simplified Memory (No Metorial for MVP)

Instead of complex external memory systems, use simple Supabase tables:

```sql
-- Aggregate patterns (not user-specific)
CREATE TABLE learned_patterns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  pattern_type TEXT NOT NULL,
  stack_signature TEXT,
  
  -- Anonymized pattern (no actual code)
  pattern_hash TEXT NOT NULL,
  pattern_description TEXT NOT NULL,
  
  -- Statistics
  occurrence_count INTEGER DEFAULT 1,
  true_positive_count INTEGER DEFAULT 0,
  false_positive_count INTEGER DEFAULT 0,
  
  -- Calculated precision
  precision NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN (true_positive_count + false_positive_count) > 0 
    THEN true_positive_count::NUMERIC / (true_positive_count + false_positive_count)
    ELSE 0 END
  ) STORED,
  
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Fix effectiveness tracking
CREATE TABLE fix_effectiveness (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  finding_type TEXT NOT NULL,
  stack_signature TEXT,
  fix_template_id TEXT NOT NULL,
  
  -- Effectiveness tracking
  times_suggested INTEGER DEFAULT 0,
  times_applied INTEGER DEFAULT 0,  -- User clicked "copy"
  times_verified INTEGER DEFAULT 0, -- Issue gone on rescan
  
  success_rate NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN times_applied > 0 
    THEN times_verified::NUMERIC / times_applied
    ELSE 0 END
  ) STORED,
  
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Community benchmarks by stack
CREATE TABLE stack_benchmarks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  stack_signature TEXT NOT NULL,
  date DATE NOT NULL DEFAULT CURRENT_DATE,
  
  -- Score distribution
  scan_count INTEGER DEFAULT 0,
  avg_score NUMERIC(5,2),
  median_score INTEGER,
  p25_score INTEGER,
  p75_score INTEGER,
  
  -- Common issues
  top_issues JSONB DEFAULT '[]',
  
  UNIQUE(stack_signature, date)
);
```

---

## Part 6: Privacy & Security Protocol

### The Problem

Storing code snippets creates a honeypot. If breached, users' vulnerabilities are exposed.

### The Solution: Privacy-Preserving Intelligence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DATA SANITIZATION PROTOCOL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  WHAT WE STORE                          WHAT WE DON'T STORE         │   │
│  │  ─────────────────                      ────────────────────        │   │
│  │                                                                       │   │
│  │  ✅ Vulnerability type                  ❌ Actual code snippets      │   │
│  │     "SQL Injection in Node.js"             (beyond active session)   │   │
│  │                                                                       │   │
│  │  ✅ Pattern hash                        ❌ Variable/function names   │   │
│  │     (anonymized signature)                                           │   │
│  │                                                                       │   │
│  │  ✅ Stack combination                   ❌ String literals           │   │
│  │     "nextjs,supabase,typescript"                                     │   │
│  │                                                                       │   │
│  │  ✅ Aggregate statistics                ❌ Repository URLs           │   │
│  │     "67% of Supabase apps have X"          (hashed only)             │   │
│  │                                                                       │   │
│  │  ✅ Fix effectiveness rates             ❌ User-identifiable data    │   │
│  │     "This fix works 85% of time"           in long-term storage      │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Retention Policy

| Data Type | Retention | Reason |
|-----------|-----------|--------|
| Full scan results | 30 days | User reference, re-scan comparison |
| Code snippets in findings | 30 days | Part of scan results |
| Repository code | 0 (immediate delete) | Never stored after scan |
| Anonymized patterns | Permanent | Learning, no PII |
| Aggregate benchmarks | Permanent | Community value, no PII |
| User email | Until unsubscribe | Communication |
| IP addresses | 24 hours | Rate limiting only |

### Code Anonymization

Before any code enters long-term storage or LLM context for learning:

```typescript
// lib/privacy/anonymize.ts

function anonymizeCodePattern(code: string): AnonymizedPattern {
  // Replace string literals
  let anonymized = code.replace(
    /(["'`])(?:(?!\1)[^\\]|\\.)*\1/g, 
    '"<STRING>"'
  );
  
  // Replace variable names with generic tokens
  anonymized = anonymized.replace(
    /\b(const|let|var)\s+(\w+)/g,
    '$1 <VAR>'
  );
  
  // Replace function names
  anonymized = anonymized.replace(
    /function\s+(\w+)/g,
    'function <FUNC>'
  );
  
  // Remove comments
  anonymized = anonymized.replace(/\/\/.*/g, '');
  anonymized = anonymized.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // Hash the pattern
  const patternHash = crypto
    .createHash('sha256')
    .update(anonymized)
    .digest('hex')
    .slice(0, 16);
  
  return {
    hash: patternHash,
    structure: anonymized,
    // Original code is NOT stored
  };
}
```

### Rate Limiting & Abuse Prevention

```typescript
// lib/security/rate-limit.ts

const RATE_LIMITS = {
  anonymous: {
    scansPerHour: 3,
    scansPerDay: 10,
  },
  authenticated: {
    scansPerHour: 10,
    scansPerDay: 50,
  },
  pro: {
    scansPerHour: 50,
    scansPerDay: 200,
  }
};

// Additional protections
const ABUSE_PREVENTION = {
  // CAPTCHA after 2 scans from same IP
  captchaThreshold: 2,
  
  // Block scanning same repo more than 5x/day
  repoScanLimit: 5,
  
  // Require GitHub auth for private repos
  privateRepoRequiresAuth: true,
  
  // Block known abuse patterns
  blockPatterns: [
    'scanning other users repos without permission',
    'automated bulk scanning',
    'competitive intelligence gathering'
  ]
};
```

---

## Part 7: Experience Layer

### Founder Mode vs Developer Mode

```typescript
// lib/ui/explanation-modes.ts

interface ExplanationModes {
  founder: {
    style: 'analogies and business impact';
    example: {
      issue: 'SQL Injection vulnerability';
      explanation: `
        🔓 Think of this like leaving your store's back door unlocked.
        
        Right now, anyone can type special commands into your search box
        that let them see, change, or delete ALL your customer data.
        
        💰 Business impact:
        • Customer data could be stolen
        • You could face legal liability (GDPR, etc.)
        • Reputation damage if breached
        
        ⏱️ Fix time: ~5 minutes
        
        [Fix it myself] [Get Vibeship to fix it →]
      `;
    };
  };
  
  developer: {
    style: 'technical details and CVE references';
    example: {
      issue: 'SQL Injection vulnerability';
      explanation: `
        🔴 CWE-89: SQL Injection
        
        User input is concatenated directly into SQL query without
        parameterization or sanitization.
        
        Vulnerable code:
        \`\`\`javascript
        const query = \`SELECT * FROM users WHERE id = \${req.params.id}\`;
        \`\`\`
        
        Attack vector:
        \`\`\`
        GET /user/1; DROP TABLE users;--
        \`\`\`
        
        Fix: Use parameterized queries
        \`\`\`javascript
        const { data } = await supabase
          .from('users')
          .select('*')
          .eq('id', req.params.id);
        \`\`\`
        
        References:
        • OWASP: https://owasp.org/...
        • CWE-89: https://cwe.mitre.org/...
        
        [Copy fix] [View full context]
      `;
    };
  };
}
```

### UI Implementation

```svelte
<!-- components/FindingCard.svelte -->
<script lang="ts">
  import { userPreferences } from '$lib/stores/preferences';
  
  export let finding: Finding;
  
  $: mode = $userPreferences.explanationMode; // 'founder' | 'developer'
</script>

<div class="finding-card">
  <header>
    <span class="severity-badge {finding.severity}">
      {finding.severity.toUpperCase()}
    </span>
    <h3>{finding.title}</h3>
  </header>
  
  <!-- Mode toggle -->
  <div class="mode-toggle">
    <button 
      class:active={mode === 'founder'}
      on:click={() => userPreferences.setMode('founder')}
    >
      🎯 Founder Mode
    </button>
    <button
      class:active={mode === 'developer'}
      on:click={() => userPreferences.setMode('developer')}
    >
      💻 Developer Mode
    </button>
  </div>
  
  <!-- Explanation based on mode -->
  {#if mode === 'founder'}
    <FounderExplanation {finding} />
  {:else}
    <DeveloperExplanation {finding} />
  {/if}
  
  <!-- Always show: Vibeship CTA -->
  <div class="cta-section">
    <button class="btn-secondary" on:click={copyFix}>
      📋 Copy Fix
    </button>
    <a href="/get-help?issue={finding.id}" class="btn-primary">
      Get Vibeship to Fix This →
    </a>
  </div>
</div>
```

### Future: Auto-PR Feature (Phase 2)

Instead of copy-paste, create a PR directly:

```typescript
// lib/fixes/auto-pr.ts (Phase 2)

async function createFixPR(
  finding: Finding,
  repoUrl: string,
  accessToken: string
): Promise<PullRequest> {
  const octokit = new Octokit({ auth: accessToken });
  const { owner, repo } = parseGitHubUrl(repoUrl);
  
  // Create branch
  const branchName = `vibeship-fix/${finding.id}`;
  await octokit.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branchName}`,
    sha: await getMainBranchSha(owner, repo)
  });
  
  // Apply fix
  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: finding.file,
    message: `fix: ${finding.title} (via Vibeship)`,
    content: Buffer.from(finding.fix.code).toString('base64'),
    branch: branchName
  });
  
  // Create PR
  const pr = await octokit.pulls.create({
    owner,
    repo,
    title: `🔒 Security Fix: ${finding.title}`,
    body: generatePRBody(finding),
    head: branchName,
    base: 'main'
  });
  
  return pr.data;
}
```

---

## Part 8: Free vs Pro Split

### Clear Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FREE VS PRO COMPARISON                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FEATURE                           FREE              PRO ($29/mo)           │
│  ───────────────────────────────────────────────────────────────────────    │
│                                                                              │
│  SCANNING                                                                    │
│  ─────────                                                                   │
│  Scans per month                   10                Unlimited              │
│  Public repos                      ✅                ✅                     │
│  Private repos                     ❌                ✅                     │
│  Scan history                      7 days            Forever                │
│                                                                              │
│  ANALYSIS                                                                    │
│  ────────                                                                    │
│  Tier 1 (Semgrep/Trivy/Gitleaks)   ✅                ✅                     │
│  Tier 2 (AI Deep Analysis)         ❌                ✅                     │
│  AI-generated fixes                ❌                ✅                     │
│  Anomaly detection                 ❌                ✅                     │
│  Predictions ("what's next")       ❌                ✅                     │
│                                                                              │
│  EXPLANATIONS                                                                │
│  ────────────                                                                │
│  Template fix suggestions          ✅                ✅                     │
│  Founder/Developer mode            ✅                ✅                     │
│  AI explanations                   First 3 only     Unlimited              │
│  Attack demonstrations             ❌                ✅                     │
│                                                                              │
│  REPORTS & SHARING                                                          │
│  ─────────────────                                                          │
│  Score & badge                     ✅                ✅                     │
│  Social sharing                    ✅                ✅                     │
│  PDF report                        ❌                ✅                     │
│  Historical trends                 ❌                ✅                     │
│                                                                              │
│  INTEGRATIONS                                                                │
│  ────────────                                                                │
│  GitHub badge                      ✅                ✅                     │
│  Auto-PR fixes                     ❌                ✅ (coming)            │
│  CI/CD integration                 ❌                ✅ (coming)            │
│  Slack notifications               ❌                ✅ (coming)            │
│                                                                              │
│  SUPPORT                                                                     │
│  ───────                                                                     │
│  Community benchmarks              ✅                ✅                     │
│  Email support                     ❌                ✅                     │
│  Priority Vibeship booking         ❌                ✅                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Upgrade Triggers

Strategic moments to show upgrade prompts:

```typescript
const UPGRADE_TRIGGERS = [
  {
    trigger: 'scan_limit_reached',
    message: "You've used all 10 free scans this month. Upgrade for unlimited.",
    urgency: 'high'
  },
  {
    trigger: 'complex_finding',
    message: "This issue needs AI analysis to explain. Upgrade to see details.",
    urgency: 'medium'
  },
  {
    trigger: 'wants_private_repo',
    message: "Private repos require Pro. Upgrade to scan your full codebase.",
    urgency: 'high'
  },
  {
    trigger: 'wants_pdf',
    message: "PDF reports are Pro only. Upgrade to share with investors.",
    urgency: 'low'
  },
  {
    trigger: 'third_ai_explanation',
    message: "You've used 3 free AI explanations. Upgrade for unlimited.",
    urgency: 'medium'
  }
];
```

---

## Part 9: Database Schema

### Core Tables

```sql
-- ============================================
-- SCANS
-- ============================================
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Target
  target_type TEXT NOT NULL CHECK (target_type IN ('github', 'gitlab', 'url')),
  target_url TEXT NOT NULL,
  target_url_hash TEXT NOT NULL, -- For privacy
  target_branch TEXT DEFAULT 'main',
  is_private BOOLEAN DEFAULT false,
  
  -- Status
  status TEXT NOT NULL DEFAULT 'pending',
  error_message TEXT,
  
  -- Results
  score INTEGER CHECK (score >= 0 AND score <= 100),
  grade CHAR(1),
  ship_status TEXT,
  findings JSONB DEFAULT '[]',
  finding_counts JSONB DEFAULT '{}',
  
  -- Tier
  tier TEXT DEFAULT 'standard' CHECK (tier IN ('standard', 'deep')),
  
  -- Stack
  detected_stack JSONB DEFAULT '{}',
  stack_signature TEXT,
  
  -- Timing
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,
  
  -- User
  user_id UUID REFERENCES auth.users(id),
  session_id TEXT,
  is_pro BOOLEAN DEFAULT false,
  
  -- Visibility
  is_public BOOLEAN DEFAULT false,
  
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_scans_user ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status) WHERE status != 'complete';
CREATE INDEX idx_scans_stack ON scans(stack_signature);

-- ============================================
-- SCAN PROGRESS (Realtime)
-- ============================================
CREATE TABLE scan_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  
  step TEXT NOT NULL,
  step_number INTEGER NOT NULL,
  total_steps INTEGER DEFAULT 5,
  message TEXT,
  
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER PUBLICATION supabase_realtime ADD TABLE scan_progress;

-- ============================================
-- RULES (with Shadow Mode)
-- ============================================
CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  
  -- Content
  rule_yaml TEXT NOT NULL,
  version INTEGER DEFAULT 1,
  
  -- Status
  status TEXT DEFAULT 'shadow' CHECK (status IN (
    'shadow',      -- Running silently, collecting data
    'validating',  -- Being reviewed
    'active',      -- Deployed to users
    'deprecated',  -- Phasing out
    'retired'      -- No longer running
  )),
  
  -- Source
  source TEXT CHECK (source IN ('manual', 'ai_generated', 'imported')),
  
  -- Metrics
  shadow_matches INTEGER DEFAULT 0,
  active_matches INTEGER DEFAULT 0,
  true_positives INTEGER DEFAULT 0,
  false_positives INTEGER DEFAULT 0,
  
  precision NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN (true_positives + false_positives) > 0 
    THEN true_positives::NUMERIC / (true_positives + false_positives)
    ELSE 0 END
  ) STORED,
  
  -- Lifecycle
  shadow_started_at TIMESTAMPTZ,
  promoted_at TIMESTAMPTZ,
  deprecated_at TIMESTAMPTZ,
  
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- LEARNING SIGNALS
-- ============================================
CREATE TABLE learning_signals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  signal_type TEXT NOT NULL CHECK (signal_type IN (
    'true_positive',
    'false_positive', 
    'fix_applied',
    'fix_verified',
    'fix_failed'
  )),
  
  scan_id UUID REFERENCES scans(id),
  finding_id TEXT,
  rule_id TEXT REFERENCES rules(id),
  
  -- Anonymized context (no actual code)
  context JSONB DEFAULT '{}',
  
  processed BOOLEAN DEFAULT false,
  
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- FIX TEMPLATES & EFFECTIVENESS
-- ============================================
CREATE TABLE fix_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  finding_type TEXT NOT NULL,
  stack_signature TEXT, -- NULL = generic
  
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  code_template TEXT NOT NULL,
  estimated_minutes INTEGER,
  
  -- Effectiveness
  times_shown INTEGER DEFAULT 0,
  times_copied INTEGER DEFAULT 0,
  times_verified INTEGER DEFAULT 0,
  
  success_rate NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN times_copied > 0 
    THEN times_verified::NUMERIC / times_copied
    ELSE 0 END
  ) STORED,
  
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- COMMUNITY BENCHMARKS
-- ============================================
CREATE TABLE stack_benchmarks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  stack_signature TEXT NOT NULL,
  week DATE NOT NULL, -- Week start date
  
  scan_count INTEGER DEFAULT 0,
  avg_score NUMERIC(5,2),
  median_score INTEGER,
  p25_score INTEGER,
  p75_score INTEGER,
  
  top_issues JSONB DEFAULT '[]',
  
  UNIQUE(stack_signature, week)
);

-- ============================================
-- BADGES
-- ============================================
CREATE TABLE badges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  
  tier TEXT DEFAULT 'scanned',
  style TEXT DEFAULT 'flat',
  
  svg_cache TEXT,
  cached_at TIMESTAMPTZ,
  
  view_count INTEGER DEFAULT 0,
  embed_count INTEGER DEFAULT 0,
  
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- RATE LIMITING
-- ============================================
CREATE TABLE rate_limits (
  identifier TEXT PRIMARY KEY, -- IP or user ID
  identifier_type TEXT NOT NULL,
  
  scans_this_hour INTEGER DEFAULT 0,
  scans_this_day INTEGER DEFAULT 0,
  
  hour_reset_at TIMESTAMPTZ,
  day_reset_at TIMESTAMPTZ,
  
  flagged BOOLEAN DEFAULT false,
  flag_reason TEXT
);
```

---

## Part 10: Development Roadmap

### Phase 1: MVP (Weeks 1-4)

**Goal:** Working scanner with core funnel

```
Week 1: Infrastructure
├── SvelteKit project setup
├── Supabase database + auth
├── Fly.io machine config
├── Trigger.dev job setup
└── Basic CI/CD

Week 2: Tier 1 Scanning
├── Semgrep integration + rules
├── Trivy integration
├── Gitleaks integration
├── Stack detection
├── Scoring algorithm
└── Template fixes (20+)

Week 3: Core UI
├── Landing page with scan input
├── Real-time progress
├── Results page (score + findings)
├── Finding cards (basic)
├── Founder/Developer mode toggle
└── Vibeship CTA integration

Week 4: Polish & Launch Prep
├── Badge generation
├── Social sharing
├── Rate limiting
├── Error handling
├── Mobile responsive
└── Cold start seeding (100 repos)
```

**Week 4 Deliverable:** Public beta, 100 cold-start scans complete

### Phase 2: Experience (Weeks 5-8)

**Goal:** Delightful experience that drives sharing

```
Week 5: Score Reveal
├── Animated score counter
├── Confetti for high scores
├── Category breakdown cascade
└── Percentile comparison

Week 6: Charts & Visualization
├── ECharts integration (lazy)
├── Radar chart
├── Severity breakdown
├── Stack comparison
└── Historical trends (Pro)

Week 7: AI Features (Pro)
├── Claude integration
├── AI explanations
├── AI fix generation
├── Tier 2 pipeline
└── Pro paywall

Week 8: Reports & Badges
├── PDF report generation
├── Badge styles (4 variants)
├── Embed codes
├── Verification pages
└── Badge analytics
```

### Phase 3: Intelligence (Weeks 9-12)

**Goal:** Learning flywheel operational

```
Week 9: Signal Collection
├── User feedback UI
├── Signal recording
├── Fix tracking
└── Rescan detection

Week 10: Shadow Mode
├── Rule shadow deployment
├── Silent match collection
├── Validation dashboard
├── Promotion workflow

Week 11: Pattern Learning
├── Pattern anonymization
├── Community benchmarks
├── Fix effectiveness ranking
└── Basic predictions

Week 12: Evolution v1
├── Daily evolution job
├── Rule improvement proposals
├── Automated validation
└── Monitoring dashboards
```

### Phase 4: Scale (Weeks 13-16)

```
Week 13-14: Integrations
├── GitHub App (Auto-PR)
├── CI/CD integration
├── Slack notifications
└── API for developers

Week 15-16: Enterprise
├── Team accounts
├── Org-wide scanning
├── Custom rules
├── Priority support
└── SLA guarantees
```

---

## Part 11: Success Metrics

### North Star

**Weekly Scans Completed** — Measures awareness, activation, and value delivery

### Funnel Metrics

| Stage | Metric | Week 4 | Week 12 |
|-------|--------|--------|---------|
| Awareness | Unique visitors | 1,000 | 10,000 |
| Activation | Scans started | 300 (30%) | 3,000 (30%) |
| Completion | Scans completed | 255 (85%) | 2,550 (85%) |
| Capture | Email captured | 150 (60%) | 1,500 (60%) |
| Convert | Vibeship lead | 15 (10%) | 150 (10%) |
| Revenue | Paid help | 3 (20%) | 30 (20%) |

### Quality Metrics

| Metric | Target | Alert |
|--------|--------|-------|
| False positive rate | <5% | >10% |
| Scan completion rate | >90% | <80% |
| Scan time (p95) | <45s | >90s |
| Fix copy rate | >30% | <15% |
| Rescan rate (7 days) | >25% | <10% |

### Intelligence Metrics

| Metric | Target |
|--------|--------|
| Rules in shadow mode | 10+/month |
| Rules promoted | 5+/month |
| Pattern precision | >95% |
| Fix success rate | >80% |

### Business Metrics

| Metric | Week 4 | Week 12 | Week 24 |
|--------|--------|---------|---------|
| Scans | 500 | 5,000 | 20,000 |
| Pro subscribers | 5 | 50 | 200 |
| MRR (Pro) | $145 | $1,450 | $5,800 |
| Vibeship revenue | $500 | $5,000 | $20,000 |

---

## Summary: What's New in v4

### From Gemini's Feedback

| Feedback | Implementation |
|----------|----------------|
| ✅ Shadow Mode | Full lifecycle: shadow → validate → active → retire |
| ✅ Privacy Protocol | Anonymization, retention limits, no code storage |
| ✅ Tiered Scanning | Tier 1 (free/fast) + Tier 2 (Pro/AI) |
| ✅ Environment Scoring | Test files downgraded, production upgraded |
| ✅ ELI5 Toggle | Founder Mode vs Developer Mode |
| ✅ Cold Start | Pre-seed 100+ repos before launch |
| ✅ Free/Pro Split | Clear boundaries defined |
| ✅ pgvector | Single DB, no Pinecone complexity |

### Additional Improvements

| Change | Reason |
|--------|--------|
| Rebrand to "Vibeship Scanner" | One brand, one funnel |
| Vibeship CTA on every finding | Direct revenue path |
| Simplified memory (no Metorial) | MVP scope reduction |
| LLM router concept | Cost optimization |
| Auto-PR as Phase 2 | Reduces launch complexity |
| Realistic timeline | 16 weeks total |

---

## Conclusion

Vibeship Scanner v4 is:

1. **Strategically aligned** — Every scan promotes Vibeship
2. **Operationally feasible** — Tiered costs, safety gates
3. **Privacy-first** — No code storage, anonymized patterns
4. **Trust-building** — Shadow mode prevents false positives
5. **Conversion-focused** — Clear path from free scan to paid help

The scanner isn't the product. **Vibeship is the product.** The scanner is the best free tool on the internet that happens to lead to Vibeship.

---

*Let's build it.*
