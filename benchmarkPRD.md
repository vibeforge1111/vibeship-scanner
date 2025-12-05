# Benchmark Dashboard PRD (Product Requirements Document)

## Executive Summary

The Vibeship Scanner Benchmark Dashboard is a tool for measuring and improving scanner detection accuracy against known vulnerable repositories. This document analyzes the current implementation, identifies gaps, and defines requirements for a complete auto-improve loop.

---

## Current Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (SvelteKit)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  /benchmark                    │  /benchmark/report/[repo]                  │
│  - Dashboard UI                │  - Detailed report viewer                  │
│  - Auto-Improve trigger        │  - Coverage analysis                       │
│  - Gap Summary display         │  - Findings list                           │
│  - localStorage persistence    │  - JSON export                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           API PROXY LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  /api/benchmark/scan           → POST /benchmark/scan-single                │
│  /api/benchmark/auto-improve   → POST /benchmark/auto-improve               │
│  /api/benchmark/job/[jobId]    → GET  /benchmark/job/{jobId}               │
│  /api/benchmark/generate-rules → Claude API (rule generation)               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     BACKEND SCANNER (Fly.io - Python/Flask)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  server.py                                                                   │
│  ├── /benchmark/repos          - List available repos                       │
│  ├── /benchmark/scan-single    - Scan one repo, return results              │
│  ├── /benchmark/auto-improve   - Start background auto-improve job          │
│  └── /benchmark/job/{jobId}    - Check job status                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  benchmark/                                                                  │
│  ├── benchmark.py              - BenchmarkRunner class                      │
│  ├── auto_improve.py           - AutoImprover class                         │
│  ├── known_vulns.py            - Vulnerability database                     │
│  └── rule_generator.py         - Semgrep rule generation                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Current Workflow Analysis

### What Happens When You Click "Auto-Improve"

#### Step 1: Frontend Initiates Sequential Scanning
**File:** `src/routes/benchmark/+page.svelte` (lines 530-613)

```
User clicks "Auto-Improve" button
         │
         ▼
startAutoImprove() is called
         │
         ▼
┌────────────────────────────────────────────┐
│ For each repo in repos (sequentially):     │
│   1. Update status: "Scanning {repo}..."   │
│   2. Call scanSingleRepo(repo)             │
│   3. Wait for scan to complete             │
│   4. Collect missed_vulns into allGaps[]   │
│   5. Small delay (500ms)                   │
│   6. Move to next repo                     │
└────────────────────────────────────────────┘
         │
         ▼
All scans complete → Show Gap Summary Banner
```

#### Step 2: Single Repo Scan Flow
**Files:** `+page.svelte` → `/api/benchmark/scan` → `server.py` → `benchmark.py`

```
scanSingleRepo(repoName)
         │
         ▼
POST /api/benchmark/scan { repo: "owner/repo" }
         │
         ▼
Proxy to: POST scanner-fly.dev/benchmark/scan-single
         │
         ▼
BenchmarkRunner.run_single_repo(repo)
         │
         ├── Clone repo to temp directory
         ├── Detect stack (languages, frameworks)
         ├── Run Opengrep/Semgrep scan
         ├── Run Trivy dependency scan
         ├── Run Gitleaks secrets scan
         ├── Deduplicate findings
         ├── Match findings against known_vulns.py
         └── Return: { coverage, detected, missed, findings, score }
```

#### Step 3: Coverage Calculation
**File:** `scanner/benchmark/benchmark.py` (lines 122-147)

```python
For each known vulnerability in repo:
    For each finding from scan:
        If finding.message/location matches vuln.pattern:
            → Add to detected[]
        Else:
            → Add to missed[]

coverage = len(detected) / len(known_vulns)
```

#### Step 4: Gap Summary Display
**File:** `+page.svelte` (lines 934-968)

After all scans complete:
- `showGapSummary = true`
- `gapSummaryData = allGaps[]` (array of missed vulnerabilities)
- Banner shows: "Detection Gaps Found - Ready for Rule Generation"
- "Copy Gaps for Claude Code" button available

---

## Current State: What's Implemented vs What's Missing

### ✅ FULLY IMPLEMENTED

| Feature | Location | Description |
|---------|----------|-------------|
| Dashboard UI | `/benchmark` | Password-protected admin interface |
| Single repo scan | `scanSingleRepo()` | Scan one repo and get results |
| Sequential scan | `startAutoImprove()` | Scan all repos one by one |
| Parallel scan | `scanAllParallel()` | Scan up to 2 repos at once |
| Coverage calculation | `benchmark.py` | Match findings vs known vulns |
| Gap detection | `calculate_coverage()` | Identify missed vulnerabilities |
| Gap summary UI | Gap Summary Banner | Display missed vulns grouped by repo |
| Report viewer | `/benchmark/report/[repo]` | Detailed findings and coverage |
| localStorage | `saveToStorage()` | Persist results across sessions |
| Manual gap export | `copyGapsForClaude()` | Copy gaps to clipboard for Claude Code |
| Progress animation | `startProgressAnimation()` | Logarithmic 0-90% animation |

### ⚠️ PARTIALLY IMPLEMENTED (Needs Work)

| Feature | Issue | What's Missing |
|---------|-------|----------------|
| Backend auto-improve | `auto_improve.py` exists | Not connected to frontend - frontend does its own scanning |
| Job polling | `/api/benchmark/job/[jobId]` | Frontend doesn't use it - does scanning locally instead |
| Rule generation API | `/api/benchmark/generate-rules` | Exists but not called automatically after gap detection |
| Rule deployment | `add_rule_to_file()` | Rules written but not deployed to Fly.io |

### ❌ NOT IMPLEMENTED (Critical Gaps)

| Feature | Impact | Description |
|---------|--------|-------------|
| **Automated rule generation** | HIGH | After gaps found, should auto-generate Semgrep rules |
| **Rule validation** | HIGH | Generated rules should be validated with `semgrep --validate` |
| **Auto-deploy to scanner** | HIGH | New rules should deploy to Fly.io automatically |
| **Re-scan verification** | HIGH | After rule deployment, re-scan to verify improvement |
| **Loop continuation** | HIGH | Should loop until target coverage or no improvement |
| **Database persistence** | MEDIUM | Only localStorage - no Supabase integration |
| **Real-time WebSocket** | LOW | Polling instead of push updates |

---

## The Ideal Auto-Improve Loop

### Target Workflow (What Should Happen)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE AUTO-IMPROVE LOOP                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                        ┌─────────────────────────┐
                        │  1. SCAN ALL REPOS      │
                        │  - Sequential scanning  │
                        │  - Real-time progress   │
                        └───────────┬─────────────┘
                                    │
                                    ▼
                        ┌─────────────────────────┐
                        │  2. CALCULATE COVERAGE  │
                        │  - Match vs known vulns │
                        │  - Identify gaps        │
                        └───────────┬─────────────┘
                                    │
                       ┌────────────┴────────────┐
                       │                         │
                       ▼                         ▼
            ┌──────────────────┐     ┌──────────────────┐
            │  Coverage >= 95% │     │  Coverage < 95%  │
            │  TARGET MET!     │     │  GAPS EXIST      │
            └────────┬─────────┘     └────────┬─────────┘
                     │                         │
                     ▼                         ▼
              ┌──────────────┐      ┌─────────────────────────┐
              │  STOP LOOP   │      │  3. GENERATE RULES      │
              │  Show Report │      │  - Claude API generates │
              └──────────────┘      │  - Semgrep YAML rules   │
                                    └───────────┬─────────────┘
                                                │
                                                ▼
                                    ┌─────────────────────────┐
                                    │  4. VALIDATE RULES      │
                                    │  - semgrep --validate   │
                                    │  - Syntax check         │
                                    └───────────┬─────────────┘
                                                │
                                    ┌───────────┴───────────┐
                                    │                       │
                                    ▼                       ▼
                         ┌──────────────────┐    ┌──────────────────┐
                         │  VALID RULES     │    │  INVALID RULES   │
                         └────────┬─────────┘    └────────┬─────────┘
                                  │                       │
                                  ▼                       ▼
                        ┌─────────────────────┐   ┌─────────────────┐
                        │  5. DEPLOY RULES    │   │  LOG ERROR      │
                        │  - Add to YAML      │   │  Skip this rule │
                        │  - Deploy to Fly.io │   └─────────────────┘
                        └───────────┬─────────┘
                                    │
                                    ▼
                        ┌─────────────────────────┐
                        │  6. RE-SCAN TO VERIFY   │
                        │  - Run same scan again  │
                        │  - Check if gaps fixed  │
                        └───────────┬─────────────┘
                                    │
                       ┌────────────┴────────────┐
                       │                         │
                       ▼                         ▼
            ┌──────────────────┐     ┌──────────────────────┐
            │  Coverage >= 95% │     │  No improvement OR   │
            │  OR max_iter     │     │  More gaps exist     │
            └────────┬─────────┘     └───────────┬──────────┘
                     │                           │
                     ▼                           │
              ┌──────────────┐                   │
              │  STOP LOOP   │◄──────────────────┘
              │  Show Report │   (loop back to step 3)
              └──────────────┘
```

---

## Gap Analysis: Current vs Ideal

### Critical Path Breakdown

| Step | Current State | Ideal State | Gap |
|------|--------------|-------------|-----|
| 1. Scan repos | ✅ Working | ✅ Same | None |
| 2. Detect gaps | ✅ Working | ✅ Same | None |
| 3. Generate rules | ⚠️ Manual (copy to Claude) | Auto-call Claude API | **AUTOMATION NEEDED** |
| 4. Validate rules | ❌ Not done | `semgrep --validate` | **NEW FEATURE** |
| 5. Deploy rules | ❌ Manual | Auto `fly deploy` | **AUTOMATION NEEDED** |
| 6. Re-scan | ❌ Manual | Auto-trigger | **AUTOMATION NEEDED** |
| 7. Loop until done | ❌ One-shot | While coverage < target | **LOOP LOGIC NEEDED** |

---

## Detailed Requirements

### Requirement 1: Automated Rule Generation

**Current:** User clicks "Copy Gaps for Claude Code" and manually runs Claude Code
**Required:** Automatic rule generation via Claude API

```typescript
// After gaps detected, automatically call:
async function generateRulesForGaps(gaps: Gap[]): Promise<GeneratedRule[]> {
    const response = await fetch('/api/benchmark/generate-rules', {
        method: 'POST',
        body: JSON.stringify({ gaps })
    });
    return response.json();
}
```

**UI Changes:**
- Add "Auto-Generate Rules" button after gap detection
- Show generated rules in a review panel
- Allow user to approve/reject individual rules

### Requirement 2: Rule Validation

**Current:** No validation
**Required:** Validate before deployment

```python
# In scanner/benchmark/auto_improve.py
def validate_rule(rule_yaml: str) -> bool:
    """Validate a Semgrep rule before adding it"""
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
        f.write(rule_yaml.encode())
        f.flush()

        result = subprocess.run(
            ['semgrep', '--validate', '--config', f.name],
            capture_output=True
        )
        return result.returncode == 0
```

### Requirement 3: Auto-Deploy to Scanner

**Current:** Manual `fly deploy`
**Required:** Triggered after rules added

**Options:**
1. **Git-based deploy**: Commit rules to repo → trigger CI/CD
2. **API-based deploy**: Call Fly.io API to rebuild and deploy
3. **Hot-reload**: Scanner watches rules directory (not recommended for production)

**Recommended:** Git-based deploy with GitHub Actions

```yaml
# .github/workflows/deploy-scanner.yml
name: Deploy Scanner
on:
  push:
    paths:
      - 'scanner/rules/**'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: superfly/flyctl-actions/setup-flyctl@master
      - run: flyctl deploy --remote-only
```

### Requirement 4: Re-Scan Verification Loop

**Current:** One-shot scan
**Required:** Loop until target met

```typescript
// In +page.svelte - New function
async function runAutoImproveLoop(targetCoverage: number = 0.95, maxIterations: number = 5) {
    let iteration = 0;
    let currentCoverage = 0;

    while (iteration < maxIterations && currentCoverage < targetCoverage) {
        iteration++;

        // Step 1: Scan all repos
        autoImproveStatus = `Iteration ${iteration}: Scanning repos...`;
        await scanAllReposSequentially();

        // Step 2: Calculate coverage
        currentCoverage = overallCoverage / 100;

        if (currentCoverage >= targetCoverage) {
            autoImproveStatus = `Target reached! ${(currentCoverage * 100).toFixed(1)}% coverage`;
            break;
        }

        // Step 3: Generate rules for gaps
        autoImproveStatus = `Iteration ${iteration}: Generating rules for ${gapSummaryData.length} gaps...`;
        const rules = await generateRulesForGaps(gapSummaryData);

        if (rules.length === 0) {
            autoImproveStatus = `No rules generated. Stopping.`;
            break;
        }

        // Step 4: Validate rules
        autoImproveStatus = `Iteration ${iteration}: Validating ${rules.length} rules...`;
        const validRules = await validateRules(rules);

        // Step 5: Deploy rules
        autoImproveStatus = `Iteration ${iteration}: Deploying ${validRules.length} rules...`;
        await deployRules(validRules);

        // Wait for deployment to complete
        await waitForDeployment();

        // Loop continues - will re-scan in next iteration
    }

    // Show final report
    showFinalReport(iteration, currentCoverage);
}
```

---

## UI/UX Improvements Needed

### Current UI Issues

1. **Gap Summary is passive** - Just shows gaps, no action buttons
2. **No iteration tracking** - Can't see which iteration we're on
3. **No rule preview** - Can't see what rules will be generated
4. **No deployment status** - Don't know when scanner is updated

### Proposed UI Changes

#### 1. Enhanced Auto-Improve Panel

```
┌─────────────────────────────────────────────────────────────────┐
│  🔄 Auto-Improve Loop                              [Stop] [x]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Iteration 2 of 5                     Target: 95% | Current: 72% │
│  ════════════════════════════════════════════════              │
│  [████████████████████░░░░░░░░░░] 72%                          │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Step 3: Generating rules for 12 gaps...                 │   │
│  │ ├── juice-shop: sqli-login, xss-dom, path-traversal     │   │
│  │ ├── NodeGoat: nosql-where, eval-injection               │   │
│  │ └── dvna: command-injection, xxe                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  History:                                                       │
│  ✓ Iteration 1: 65% → 72% (+7 rules deployed)                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2. Rule Preview Modal

```
┌─────────────────────────────────────────────────────────────────┐
│  Generated Rules (5)                                [Deploy All] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ☑ vibeship-sqli-login         [HIGH confidence]      [Preview] │
│  ☑ vibeship-xss-dom            [MEDIUM confidence]    [Preview] │
│  ☐ vibeship-path-traversal     [LOW confidence]       [Preview] │
│  ☑ vibeship-nosql-where        [HIGH confidence]      [Preview] │
│  ☑ vibeship-eval-injection     [HIGH confidence]      [Preview] │
│                                                                 │
│  ─────────────────────────────────────────────────────────────  │
│  Selected: 4 rules | Rejected: 1 rule                           │
│                                                                 │
│                                          [Cancel] [Deploy 4]    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technical Implementation Plan

### Phase 1: Backend Auto-Improve Integration (Priority: HIGH)

1. **Connect frontend to backend auto-improve**
   - Remove local sequential scanning from `startAutoImprove()`
   - Call `POST /api/benchmark/auto-improve` instead
   - Poll `/api/benchmark/job/[jobId]` for progress
   - Display real-time status from backend

2. **Enhance backend auto-improve**
   - Add webhook support to report progress
   - Implement SSE or WebSocket for real-time updates
   - Add iteration tracking to job status

### Phase 2: Automated Rule Generation (Priority: HIGH)

1. **Frontend rule generation trigger**
   - After gaps detected, show "Generate Rules" button
   - Call `/api/benchmark/generate-rules` with gaps
   - Display generated rules for review

2. **Backend rule validation**
   - Add `semgrep --validate` step in `auto_improve.py`
   - Return validation status per rule
   - Only add validated rules to YAML files

### Phase 3: Auto-Deploy Pipeline (Priority: MEDIUM)

1. **Git-based deployment**
   - Create GitHub Action for scanner deployment
   - Trigger on changes to `scanner/rules/**`
   - Notify frontend when deployment complete

2. **Deployment status tracking**
   - Add `/benchmark/deployment-status` endpoint
   - Track deployment in progress / complete / failed
   - Show deployment status in UI

### Phase 4: Full Loop Automation (Priority: HIGH)

1. **Loop logic in backend**
   - `AutoImprover.run_until_target()` already exists
   - Connect it properly to frontend
   - Add progress callbacks for UI updates

2. **Stop conditions**
   - Target coverage reached
   - Max iterations reached
   - No new rules generated (plateau)
   - User manual stop

### Phase 5: Persistence & History (Priority: LOW)

1. **Supabase integration**
   - Store benchmark results in database
   - Track rule generation history
   - Cross-session persistence

2. **Analytics dashboard**
   - Coverage trend over time
   - Rules generated per iteration
   - Detection improvement metrics

---

## Data Models

### Gap Object
```typescript
interface Gap {
    repo: string;           // "juice-shop/juice-shop"
    repoName: string;       // "OWASP Juice Shop"
    vulnId: string;         // "sqli-login"
    vulnType: string;       // "sql-injection"
    description: string;    // "SQL injection in login via template literal"
    file?: string;          // "routes/login.ts"
    language: string;       // "javascript"
    severity: string;       // "critical"
}
```

### Generated Rule Object
```typescript
interface GeneratedRule {
    id: string;             // "vibeship-sqli-login"
    language: string;       // "javascript"
    yaml: string;           // Full YAML rule content
    vulnId: string;         // "sqli-login"
    confidence: 'high' | 'medium' | 'low';
    validated?: boolean;
    validationError?: string;
}
```

### Auto-Improve Job Object
```typescript
interface AutoImproveJob {
    jobId: string;
    status: 'pending' | 'scanning' | 'generating' | 'validating' | 'deploying' | 'complete' | 'failed';
    iteration: number;
    maxIterations: number;
    targetCoverage: number;
    currentCoverage: number;
    rulesGenerated: number;
    rulesDeployed: number;
    gapsRemaining: number;
    startedAt: string;
    completedAt?: string;
    error?: string;
}
```

---

## API Contracts

### POST /api/benchmark/auto-improve (Enhanced)

**Request:**
```json
{
    "target_coverage": 0.95,
    "max_iterations": 5,
    "auto_deploy": true,
    "webhook_url": "https://vibeship.co/api/benchmark/webhook"
}
```

**Response:**
```json
{
    "status": "started",
    "job_id": "abc12345",
    "message": "Auto-improve loop started"
}
```

### GET /api/benchmark/job/[jobId] (Enhanced)

**Response:**
```json
{
    "job_id": "abc12345",
    "status": "generating",
    "iteration": 2,
    "max_iterations": 5,
    "target_coverage": 0.95,
    "current_coverage": 0.72,
    "step": "Generating rules for 12 gaps",
    "gaps_found": 12,
    "rules_generated": 5,
    "rules_deployed": 5,
    "history": [
        {
            "iteration": 1,
            "coverage_before": 0.65,
            "coverage_after": 0.72,
            "rules_added": 7
        }
    ]
}
```

### POST /api/benchmark/generate-rules (Existing - No Change)

**Request:**
```json
{
    "gaps": [
        {
            "repo": "juice-shop/juice-shop",
            "repoName": "OWASP Juice Shop",
            "vulnId": "sqli-login",
            "vulnType": "sql-injection",
            "description": "SQL injection in login",
            "language": "javascript"
        }
    ]
}
```

**Response:**
```json
{
    "rules": [
        {
            "id": "vibeship-sqli-login",
            "language": "javascript",
            "yaml": "rules:\n  - id: vibeship-sqli-login\n...",
            "vulnId": "sqli-login",
            "confidence": "high"
        }
    ],
    "message": "Generated 1 rules for 1 gaps"
}
```

---

## Known Vulnerabilities Database

**File:** `scanner/benchmark/known_vulns.py`

Currently tracks **7 repositories** with **50 known vulnerabilities**:

| Repository | Language | Vulns | Coverage Target |
|------------|----------|-------|-----------------|
| juice-shop/juice-shop | JavaScript | 10 | 90% |
| OWASP/NodeGoat | JavaScript | 9 | 90% |
| appsecco/dvna | JavaScript | 7 | 90% |
| erev0s/VAmPI | Python | 7 | 90% |
| samoylenko/vulnerable-app-nodejs-express | JavaScript | 4 | 90% |
| digininja/DVWA | PHP | 7 | 90% |
| OWASP/crAPI | Python | 6 | 90% |

**Expansion Needed:** Add more repos from SECURITY_TEST_PROCEDURE.md (30 total repos available).

---

## Success Metrics

### Key Performance Indicators

1. **Coverage Achievement**
   - Target: 95% average coverage across all benchmark repos
   - Current: Varies (needs baseline measurement)

2. **False Positive Rate**
   - Target: < 5% false positive rate on generated rules
   - Measured by: Manual review of flagged findings

3. **Auto-Improve Efficiency**
   - Target: Reach 95% coverage in ≤ 3 iterations
   - Measured by: Iteration count to target

4. **Rule Generation Success**
   - Target: 80% of generated rules pass validation
   - Measured by: Valid rules / Total generated

---

## Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Generated rules have false positives | HIGH | MEDIUM | Human review step before deploy |
| Claude API rate limits | MEDIUM | HIGH | Batch gap processing, caching |
| Fly.io deploy failures | LOW | HIGH | Retry logic, rollback capability |
| Infinite loop (no improvement) | MEDIUM | LOW | Max iteration limit, plateau detection |
| Database storage costs | LOW | LOW | Pruning old results, aggregation |

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Backend Integration | 2-3 days | None |
| Phase 2: Rule Generation | 2-3 days | Phase 1 |
| Phase 3: Auto-Deploy | 3-4 days | Phase 2 |
| Phase 4: Full Loop | 2-3 days | Phase 3 |
| Phase 5: Persistence | 2-3 days | Phase 4 |
| **Total** | **11-16 days** | |

---

## Conclusion

The benchmark dashboard has a solid foundation with scanning, gap detection, and UI components in place. The critical missing pieces are:

1. **Automated rule generation** (Claude API is ready, needs integration)
2. **Rule validation** (Semgrep validate step needed)
3. **Auto-deployment** (CI/CD pipeline needed)
4. **Loop automation** (Backend logic exists, needs frontend connection)

Completing these will enable a fully automated scanner improvement loop that continuously increases detection coverage against known vulnerable repositories.

---

## Appendix: File Reference

| File | Purpose | Lines |
|------|---------|-------|
| `src/routes/benchmark/+page.svelte` | Dashboard UI | ~2,800 |
| `src/routes/benchmark/report/[repo]/+page.svelte` | Report viewer | ~943 |
| `src/routes/api/benchmark/scan/+server.ts` | Scan proxy | 31 |
| `src/routes/api/benchmark/auto-improve/+server.ts` | Auto-improve proxy | 26 |
| `src/routes/api/benchmark/job/[jobId]/+server.ts` | Job status proxy | 17 |
| `src/routes/api/benchmark/generate-rules/+server.ts` | Claude rule gen | 131 |
| `scanner/server.py` | Flask API server | 399 |
| `scanner/benchmark/benchmark.py` | Benchmark runner | 410 |
| `scanner/benchmark/auto_improve.py` | Auto-improve logic | 452 |
| `scanner/benchmark/known_vulns.py` | Vuln database | 480 |
