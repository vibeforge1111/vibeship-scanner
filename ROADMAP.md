# Vibeship Scanner - Development Roadmap

## Quick Start

```bash
# Week 1: Start here
npm create svelte@latest vibeship-scanner
cd vibeship-scanner
npm install
```

---

## Phase 1: MVP (Weeks 1-4)

### Week 1: Foundation
```
┌─────────────────────────────────────────────────────────────────┐
│  WEEK 1: INFRASTRUCTURE                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Day 1-2: Project Setup                                         │
│  ├── SvelteKit + TypeScript                                     │
│  ├── Tailwind CSS                                               │
│  ├── ESLint/Prettier                                            │
│  └── Git repo + CI/CD                                           │
│                                                                  │
│  Day 3-4: Backend Services                                      │
│  ├── Supabase project + schema                                  │
│  ├── Upstash Redis instance                                     │
│  ├── Trigger.dev setup                                          │
│  └── Fly.io app configuration                                   │
│                                                                  │
│  Day 5: Scanner VM                                              │
│  ├── Dockerfile with Semgrep/Trivy/Gitleaks                     │
│  ├── Deploy to Fly.io                                           │
│  └── Test ephemeral machine creation                            │
│                                                                  │
│  DELIVERABLE: Infrastructure ready, "Hello World" deployed      │
└─────────────────────────────────────────────────────────────────┘
```

### Week 2: Scanning Engine
```
┌─────────────────────────────────────────────────────────────────┐
│  WEEK 2: TIER 1 SCANNING                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Day 1: Stack Detection                                         │
│  ├── Detect package.json, requirements.txt, etc.                │
│  ├── Framework detection (Next.js, SvelteKit, etc.)             │
│  └── Generate stack signature                                   │
│                                                                  │
│  Day 2: Semgrep Integration                                     │
│  ├── Load custom rules                                          │
│  ├── Run scan                                                   │
│  └── Parse results                                              │
│                                                                  │
│  Day 3: Trivy + Gitleaks                                        │
│  ├── Dependency scanning                                        │
│  ├── Secret detection                                           │
│  └── Result normalization                                       │
│                                                                  │
│  Day 4: Result Aggregation                                      │
│  ├── Deduplication                                              │
│  ├── Severity normalization                                     │
│  └── Context attachment                                         │
│                                                                  │
│  Day 5: Scoring                                                 │
│  ├── Score calculation                                          │
│  ├── Grade assignment                                           │
│  └── Template fix matching                                      │
│                                                                  │
│  DELIVERABLE: Full scan pipeline working E2E                    │
└─────────────────────────────────────────────────────────────────┘
```

### Week 3: Core UI
```
┌─────────────────────────────────────────────────────────────────┐
│  WEEK 3: USER INTERFACE                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Day 1: Landing Page                                            │
│  ├── Hero with scan input                                       │
│  ├── How it works                                               │
│  └── Vibeship branding                                          │
│                                                                  │
│  Day 2: Scan Progress                                           │
│  ├── Realtime subscription                                      │
│  ├── Step indicators                                            │
│  └── Progress bar                                               │
│                                                                  │
│  Day 3: Results - Score                                         │
│  ├── Score display                                              │
│  ├── Grade badge                                                │
│  └── Category summary                                           │
│                                                                  │
│  Day 4: Results - Findings                                      │
│  ├── Finding cards                                              │
│  ├── Severity badges                                            │
│  ├── Code snippets                                              │
│  └── Fix templates                                              │
│                                                                  │
│  Day 5: Actions                                                 │
│  ├── Copy fix button                                            │
│  ├── Vibeship CTA                                               │
│  └── Share functionality                                        │
│                                                                  │
│  DELIVERABLE: Complete scan flow UI                             │
└─────────────────────────────────────────────────────────────────┘
```

### Week 4: Launch Prep
```
┌─────────────────────────────────────────────────────────────────┐
│  WEEK 4: POLISH & LAUNCH                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Day 1: Badges                                                  │
│  ├── SVG generation                                             │
│  ├── Embed codes                                                │
│  └── Caching                                                    │
│                                                                  │
│  Day 2: Security                                                │
│  ├── Rate limiting                                              │
│  ├── Input validation                                           │
│  └── Error handling                                             │
│                                                                  │
│  Day 3: Mobile                                                  │
│  ├── Responsive design                                          │
│  ├── Touch interactions                                         │
│  └── Performance optimization                                   │
│                                                                  │
│  Day 4: Cold Start                                              │
│  ├── Scan 100 repos                                             │
│  ├── Populate benchmarks                                        │
│  └── Validate rules                                             │
│                                                                  │
│  Day 5: Launch                                                  │
│  ├── Final testing                                              │
│  ├── Documentation                                              │
│  └── 🚀 PUBLIC BETA                                             │
│                                                                  │
│  DELIVERABLE: Public beta live!                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 2: Experience (Weeks 5-8)

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2 OVERVIEW                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Week 5: Score Reveal Animation                                 │
│  ├── Animated counter                                           │
│  ├── Confetti for high scores                                   │
│  ├── Category cascade reveal                                    │
│  └── Percentile comparison                                      │
│                                                                  │
│  Week 6: Charts & Visualization                                 │
│  ├── ECharts lazy loading                                       │
│  ├── Radar chart (categories)                                   │
│  ├── Donut chart (severities)                                   │
│  └── Trend chart (Pro)                                          │
│                                                                  │
│  Week 7: AI Features (Pro)                                      │
│  ├── Claude API integration                                     │
│  ├── AI explanations                                            │
│  ├── AI fix generation                                          │
│  └── Pro tier paywall                                           │
│                                                                  │
│  Week 8: Reports & Badges                                       │
│  ├── PDF report generation                                      │
│  ├── Badge verification pages                                   │
│  ├── Embed code generator                                       │
│  └── Badge analytics                                            │
│                                                                  │
│  DELIVERABLE: Premium experience, Pro tier live                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 3: Intelligence (Weeks 9-12)

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3 OVERVIEW                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Week 9: Signal Collection                                      │
│  ├── Feedback UI (👍👎 buttons)                                 │
│  ├── Signal recording                                           │
│  ├── Fix tracking (copy + rescan)                               │
│  └── Anonymization                                              │
│                                                                  │
│  Week 10: Shadow Mode                                           │
│  ├── Rule status workflow                                       │
│  ├── Silent match collection                                    │
│  ├── Validation dashboard                                       │
│  └── Promotion pipeline                                         │
│                                                                  │
│  Week 11: Pattern Learning                                      │
│  ├── Code pattern extraction                                    │
│  ├── Community benchmarks                                       │
│  ├── Fix effectiveness ranking                                  │
│  └── Stack-specific insights                                    │
│                                                                  │
│  Week 12: Evolution v1                                          │
│  ├── Daily evolution job                                        │
│  ├── Rule improvement proposals                                 │
│  ├── Automated validation                                       │
│  └── Monitoring dashboard                                       │
│                                                                  │
│  DELIVERABLE: Self-improving scanner                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 4: Scale (Weeks 13-16)

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4 OVERVIEW                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Weeks 13-14: Integrations                                      │
│  ├── GitHub App (Auto-PR fixes)                                 │
│  ├── CI/CD integration (GitHub Actions)                         │
│  ├── Slack notifications                                        │
│  └── Public API                                                 │
│                                                                  │
│  Weeks 15-16: Enterprise                                        │
│  ├── Team accounts                                              │
│  ├── Org-wide scanning                                          │
│  ├── Custom rules UI                                            │
│  └── SLA & priority support                                     │
│                                                                  │
│  DELIVERABLE: Enterprise-ready product                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Milestone Checklist

### MVP Launch (Week 4)
- [ ] Scan public GitHub repos
- [ ] Display security score
- [ ] Show findings with fixes
- [ ] Generate embeddable badge
- [ ] Vibeship CTA on every finding
- [ ] Rate limiting in place
- [ ] Mobile responsive

### Pro Launch (Week 8)
- [ ] Stripe billing integration
- [ ] AI-powered explanations
- [ ] AI-generated fixes
- [ ] PDF report download
- [ ] Private repo scanning
- [ ] Scan history

### Intelligence Launch (Week 12)
- [ ] User feedback collection
- [ ] Shadow mode for new rules
- [ ] Rule precision tracking
- [ ] Community benchmarks
- [ ] Fix effectiveness metrics

### Enterprise Launch (Week 16)
- [ ] GitHub App integration
- [ ] CI/CD blocking
- [ ] Team management
- [ ] Custom rules
- [ ] API access

---

## Success Metrics by Phase

| Metric | Week 4 | Week 8 | Week 12 | Week 16 |
|--------|--------|--------|---------|---------|
| Weekly Scans | 500 | 2,000 | 5,000 | 10,000 |
| Completion Rate | 85% | 90% | 92% | 95% |
| Pro Subscribers | - | 20 | 100 | 300 |
| Vibeship Leads | 10 | 50 | 150 | 400 |
| False Positive Rate | <10% | <7% | <5% | <3% |
| Avg Scan Time | <45s | <40s | <35s | <30s |

---

## Tech Stack Summary

```
Frontend:     SvelteKit 2.0 + Tailwind CSS 4.0
Database:     Supabase (PostgreSQL + pgvector)
Cache:        Upstash Redis
Background:   Trigger.dev
Compute:      Fly.io Machines
AI:           Claude API (Sonnet/Haiku)
Hosting:      Vercel Edge
Monitoring:   Sentry + PostHog
```

---

## Getting Started

1. **Clone the starter template**
   ```bash
   npx degit vibeship/scanner-template vibeship-scanner
   cd vibeship-scanner
   npm install
   ```

2. **Set up services**
   - Create Supabase project
   - Create Upstash Redis instance
   - Create Fly.io app
   - Create Trigger.dev project

3. **Configure environment**
   ```bash
   cp .env.example .env.local
   # Fill in API keys
   ```

4. **Run locally**
   ```bash
   npm run dev
   ```

5. **Deploy**
   ```bash
   # Push to GitHub, Vercel auto-deploys
   git push origin main
   ```

---

## Resources

- [PRD.md](./PRD.md) - Product requirements
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [TASKS.md](./TASKS.md) - Detailed task breakdown
- [API_SPEC.md](./API_SPEC.md) - API documentation
- [COMPONENTS.md](./COMPONENTS.md) - UI components
- [SCANNING_RULES.md](./SCANNING_RULES.md) - Security rules

---

*Let's build it.*
