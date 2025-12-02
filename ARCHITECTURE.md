# Vibeship Scanner - Architecture Document

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           VIBESHIP SCANNER SYSTEM                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐     ┌─────────────────────────────────────────────────────┐   │
│  │   Client    │     │                    VERCEL EDGE                       │   │
│  │  (Browser)  │────▶│  ┌─────────────────────────────────────────────┐    │   │
│  └─────────────┘     │  │           SvelteKit Application              │    │   │
│                      │  │                                               │    │   │
│                      │  │  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │    │   │
│                      │  │  │  Pages  │  │   API   │  │  Realtime   │  │    │   │
│                      │  │  │         │  │ Routes  │  │  Handlers   │  │    │   │
│                      │  │  └─────────┘  └────┬────┘  └──────┬──────┘  │    │   │
│                      │  └────────────────────┼──────────────┼─────────┘    │   │
│                      └───────────────────────┼──────────────┼──────────────┘   │
│                                              │              │                   │
│         ┌────────────────────────────────────┼──────────────┼───────────────┐  │
│         │                                    ▼              ▼                │  │
│         │  ┌─────────────────────────────────────────────────────────────┐  │  │
│         │  │                      SUPABASE                                │  │  │
│         │  │                                                              │  │  │
│         │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │  │  │
│         │  │  │PostgreSQL│  │ Realtime │  │   Auth   │  │ Storage  │   │  │  │
│         │  │  │+pgvector │  │          │  │ (GitHub) │  │ (PDFs)   │   │  │  │
│         │  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │  │  │
│         │  └─────────────────────────────────────────────────────────────┘  │  │
│         │                                                                    │  │
│         │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │  │
│         │  │  UPSTASH REDIS  │  │   TRIGGER.DEV   │  │   FLY.IO VMS    │   │  │
│         │  │                 │  │                 │  │                 │   │  │
│         │  │ • Rate limiting │  │ • Scan jobs     │  │ • Semgrep       │   │  │
│         │  │ • Session cache │  │ • Orchestration │  │ • Trivy         │   │  │
│         │  │ • Result cache  │  │ • Retries       │  │ • Gitleaks      │   │  │
│         │  └─────────────────┘  └────────┬────────┘  └────────┬────────┘   │  │
│         │                                │                    │             │  │
│         │                                └────────────────────┘             │  │
│         │                                         │                         │  │
│         │  ┌──────────────────────────────────────▼──────────────────────┐  │  │
│         │  │                     CLAUDE API                               │  │  │
│         │  │                                                              │  │  │
│         │  │  • Tier 2 deep analysis                                     │  │  │
│         │  │  • AI fix generation                                        │  │  │
│         │  │  • Founder-mode explanations                                │  │  │
│         │  └──────────────────────────────────────────────────────────────┘  │  │
│         │                                                                    │  │
│         └────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Frontend Layer (SvelteKit)

```
src/
├── routes/
│   ├── +page.svelte              # Landing page with scan input
│   ├── +layout.svelte            # Global layout with nav/footer
│   ├── scan/
│   │   ├── +page.svelte          # Scan progress page
│   │   └── [id]/
│   │       └── +page.svelte      # Results page
│   ├── api/
│   │   ├── scan/
│   │   │   ├── +server.ts        # POST: Start scan
│   │   │   └── [id]/
│   │   │       └── +server.ts    # GET: Scan status/results
│   │   ├── feedback/
│   │   │   └── +server.ts        # POST: User feedback
│   │   ├── badge/
│   │   │   └── [id]/
│   │   │       └── +server.ts    # GET: Badge SVG
│   │   └── webhooks/
│   │       └── trigger/
│   │           └── +server.ts    # Trigger.dev callbacks
│   ├── auth/
│   │   ├── callback/
│   │   │   └── +server.ts        # GitHub OAuth callback
│   │   └── +page.svelte          # Auth page
│   └── pro/
│       └── +page.svelte          # Pro upgrade page
├── lib/
│   ├── components/
│   │   ├── ui/                   # Base UI components
│   │   ├── scan/                 # Scan-related components
│   │   ├── results/              # Results display components
│   │   └── charts/               # ECharts wrappers
│   ├── stores/
│   │   ├── scan.ts               # Scan state
│   │   ├── user.ts               # User/auth state
│   │   └── preferences.ts        # UI preferences
│   ├── server/
│   │   ├── db.ts                 # Supabase client
│   │   ├── redis.ts              # Upstash client
│   │   └── trigger.ts            # Trigger.dev client
│   ├── scanning/
│   │   ├── pipeline.ts           # Main scanning orchestration
│   │   ├── tier1/                # Tier 1 scanner integrations
│   │   └── tier2/                # Tier 2 AI analysis
│   ├── scoring/
│   │   ├── calculator.ts         # Score calculation
│   │   └── contextual.ts         # Environment-aware adjustments
│   └── utils/
│       ├── anonymize.ts          # Code anonymization
│       └── rate-limit.ts         # Rate limiting helpers
└── static/
    └── badges/                   # Badge templates
```

### 2. Data Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              SCAN DATA FLOW                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  1. INITIATION                                                                │
│  ─────────────                                                                │
│  User submits URL → API validates → Create scan record → Return scan ID      │
│                                                                               │
│  2. QUEUE                                                                     │
│  ────────                                                                     │
│  Scan record created → Trigger.dev job queued → Fly.io VM provisioned        │
│                                                                               │
│  3. TIER 1 SCANNING (Parallel)                                                │
│  ───────────────────────────────                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐               │     │
│  │  │   Semgrep   │   │    Trivy    │   │  Gitleaks   │               │     │
│  │  │   (SAST)    │   │   (Deps)    │   │  (Secrets)  │               │     │
│  │  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │     │
│  │         │                 │                 │                       │     │
│  │         └─────────────────┼─────────────────┘                       │     │
│  │                           ▼                                         │     │
│  │                   ┌───────────────┐                                 │     │
│  │                   │ Merge & Dedup │                                 │     │
│  │                   └───────┬───────┘                                 │     │
│  └───────────────────────────┼─────────────────────────────────────────┘     │
│                              ▼                                                │
│  4. SCORING                                                                   │
│  ──────────                                                                   │
│  Findings → Context analysis → Severity adjustment → Score calculation        │
│                                                                               │
│  5. TIER 2 (If Pro/Deep Scan)                                                 │
│  ───────────────────────────────                                              │
│  Critical findings → Claude API → AI explanations + custom fixes              │
│                                                                               │
│  6. PERSIST & NOTIFY                                                          │
│  ────────────────────                                                         │
│  Update scan record → Send realtime update → User sees results                │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3. Database Schema (Supabase PostgreSQL)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATABASE SCHEMA                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐         ┌─────────────────┐                            │
│  │      users      │         │      scans      │                            │
│  │─────────────────│         │─────────────────│                            │
│  │ id (PK)         │◄────────│ user_id (FK)    │                            │
│  │ email           │         │ id (PK)         │                            │
│  │ tier            │         │ target_url_hash │                            │
│  │ created_at      │         │ status          │                            │
│  └─────────────────┘         │ score           │                            │
│                              │ findings (JSONB)│                            │
│                              │ stack_signature │                            │
│                              │ tier            │                            │
│                              │ created_at      │                            │
│                              └────────┬────────┘                            │
│                                       │                                      │
│                                       │ 1:N                                  │
│                                       ▼                                      │
│                              ┌─────────────────┐                            │
│                              │  scan_progress  │                            │
│                              │─────────────────│                            │
│                              │ id (PK)         │                            │
│                              │ scan_id (FK)    │                            │
│                              │ step            │                            │
│                              │ message         │                            │
│                              │ created_at      │                            │
│                              └─────────────────┘                            │
│                                                                              │
│  ┌─────────────────┐         ┌─────────────────┐         ┌───────────────┐  │
│  │      rules      │         │ learning_signals│         │ fix_templates │  │
│  │─────────────────│         │─────────────────│         │───────────────│  │
│  │ id (PK)         │◄────────│ rule_id (FK)    │         │ id (PK)       │  │
│  │ rule_yaml       │         │ signal_type     │         │ finding_type  │  │
│  │ status          │         │ scan_id (FK)    │         │ stack_sig     │  │
│  │ precision       │         │ context (JSONB) │         │ code_template │  │
│  │ shadow_matches  │         │ created_at      │         │ success_rate  │  │
│  └─────────────────┘         └─────────────────┘         └───────────────┘  │
│                                                                              │
│  ┌─────────────────┐         ┌─────────────────┐                            │
│  │ stack_benchmarks│         │     badges      │                            │
│  │─────────────────│         │─────────────────│                            │
│  │ id (PK)         │         │ id (PK)         │                            │
│  │ stack_signature │         │ scan_id (FK)    │                            │
│  │ week            │         │ tier            │                            │
│  │ avg_score       │         │ svg_cache       │                            │
│  │ top_issues      │         │ view_count      │                            │
│  └─────────────────┘         └─────────────────┘                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4. API Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API ENDPOINTS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PUBLIC ENDPOINTS                                                            │
│  ────────────────                                                            │
│                                                                              │
│  POST   /api/scan              Start a new scan                              │
│         Body: { url, type?, deep? }                                          │
│         Returns: { scanId, estimatedTime }                                   │
│                                                                              │
│  GET    /api/scan/[id]         Get scan status/results                       │
│         Returns: { status, progress?, results? }                             │
│                                                                              │
│  GET    /api/badge/[id]        Get badge SVG                                 │
│         Query: { style? }                                                    │
│         Returns: SVG image                                                   │
│                                                                              │
│  AUTHENTICATED ENDPOINTS                                                     │
│  ───────────────────────                                                     │
│                                                                              │
│  POST   /api/feedback          Submit finding feedback                       │
│         Body: { scanId, findingId, type, comment? }                          │
│                                                                              │
│  GET    /api/scans             List user's scans                             │
│         Query: { page?, limit? }                                             │
│                                                                              │
│  POST   /api/scan/[id]/rescan  Trigger rescan                                │
│                                                                              │
│  PRO ENDPOINTS                                                               │
│  ─────────────                                                               │
│                                                                              │
│  POST   /api/scan/[id]/deep    Trigger Tier 2 analysis                       │
│                                                                              │
│  GET    /api/scan/[id]/pdf     Generate PDF report                           │
│                                                                              │
│  GET    /api/scan/[id]/ai-fix  Get AI-generated fix                          │
│         Query: { findingId }                                                 │
│                                                                              │
│  INTERNAL ENDPOINTS (Webhook)                                                │
│  ────────────────────────────                                                │
│                                                                              │
│  POST   /api/webhooks/trigger  Trigger.dev job callbacks                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5. Scanner Integration Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SCANNER INTEGRATION                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                       FLY.IO EPHEMERAL VM                              │  │
│  │                                                                        │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  1. Clone Repository (shallow, specific branch)                  │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                   │                                    │  │
│  │                                   ▼                                    │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  2. Detect Stack                                                 │ │  │
│  │   │     • package.json → Node.js ecosystem                          │ │  │
│  │   │     • requirements.txt → Python                                  │ │  │
│  │   │     • Cargo.toml → Rust                                         │ │  │
│  │   │     • go.mod → Go                                               │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                   │                                    │  │
│  │                                   ▼                                    │  │
│  │   ┌────────────────┬────────────────┬────────────────┐               │  │
│  │   │    SEMGREP     │     TRIVY      │   GITLEAKS     │               │  │
│  │   │────────────────│────────────────│────────────────│               │  │
│  │   │ • Custom rules │ • CVE lookup   │ • Pattern scan │               │  │
│  │   │ • SAST         │ • SBOM gen     │ • Entropy      │               │  │
│  │   │ • 500+ checks  │ • License      │ • Regex        │               │  │
│  │   └───────┬────────┴───────┬────────┴───────┬────────┘               │  │
│  │           │                │                │                         │  │
│  │           └────────────────┼────────────────┘                         │  │
│  │                            ▼                                          │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  3. Normalize & Merge Results                                    │ │  │
│  │   │     • Deduplicate overlapping findings                          │ │  │
│  │   │     • Normalize severity levels                                 │ │  │
│  │   │     • Attach file context                                       │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                   │                                    │  │
│  │                                   ▼                                    │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  4. Delete Repository (immediate, never persisted)              │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6. Scoring Algorithm

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SCORING ALGORITHM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  BASE SCORE: 100                                                             │
│                                                                              │
│  DEDUCTIONS:                                                                 │
│  ───────────                                                                 │
│  Critical finding  →  -25 points (max 4 = -100)                              │
│  High finding      →  -10 points (max 5 = -50)                               │
│  Medium finding    →   -5 points (max 10 = -50)                              │
│  Low finding       →   -2 points (max 10 = -20)                              │
│  Info finding      →   -0 points (informational only)                        │
│                                                                              │
│  CONTEXT MODIFIERS:                                                          │
│  ──────────────────                                                          │
│  Test file         →  Severity reduced by 1 level                            │
│  Example file      →  Severity reduced by 1 level                            │
│  Config file       →  Severity reduced by 1 level (unless secrets)           │
│  Main bundle       →  Secrets upgraded to Critical                           │
│  Entry point       →  Injection upgraded to Critical                         │
│                                                                              │
│  SCORE MAPPING:                                                              │
│  ──────────────                                                              │
│  90-100  →  A  →  "Ship It!"       →  Green                                  │
│  80-89   →  B  →  "Almost There"   →  Light Green                            │
│  70-79   →  C  →  "Needs Work"     →  Yellow                                 │
│  60-69   →  D  →  "Risky"          →  Orange                                 │
│  0-59    →  F  →  "Do Not Ship"    →  Red                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7. Caching Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CACHING STRATEGY                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  UPSTASH REDIS                                                               │
│  ─────────────                                                               │
│                                                                              │
│  rate_limit:{ip}           →  TTL: 1 hour   →  Rate limit counters          │
│  rate_limit:{user_id}      →  TTL: 1 day    →  User rate limits             │
│  scan_result:{url_hash}    →  TTL: 6 hours  →  Recent scan cache            │
│  session:{session_id}      →  TTL: 7 days   →  Anonymous sessions           │
│  badge_svg:{scan_id}       →  TTL: 1 hour   →  Badge SVG cache              │
│                                                                              │
│  SUPABASE (Persistent)                                                       │
│  ─────────────────────                                                       │
│                                                                              │
│  scans table               →  TTL: 30 days  →  Full scan results            │
│  stack_benchmarks          →  TTL: none     →  Aggregate statistics         │
│  fix_templates             →  TTL: none     →  Fix effectiveness            │
│                                                                              │
│  BROWSER (Local Storage)                                                     │
│  ───────────────────────                                                     │
│                                                                              │
│  userPreferences           →  TTL: none     →  UI mode, theme               │
│  recentScans               →  TTL: none     →  Quick access list            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8. Security Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  AUTHENTICATION                                                              │
│  ──────────────                                                              │
│  • GitHub OAuth for private repos                                            │
│  • Anonymous sessions for public scans                                       │
│  • JWT tokens via Supabase Auth                                              │
│                                                                              │
│  AUTHORIZATION                                                               │
│  ─────────────                                                               │
│  • Row Level Security (RLS) on all tables                                    │
│  • Users can only see their own scans                                        │
│  • Pro features gated by tier check                                          │
│                                                                              │
│  DATA PROTECTION                                                             │
│  ───────────────                                                             │
│  • Repository code: NEVER stored (deleted after scan)                        │
│  • URL hashing: Original URLs not stored                                     │
│  • Code anonymization: Patterns stripped of identifiers                      │
│  • 30-day retention on scan results                                          │
│                                                                              │
│  RATE LIMITING                                                               │
│  ─────────────                                                               │
│  Anonymous:     3/hour,  10/day                                              │
│  Authenticated: 10/hour, 50/day                                              │
│  Pro:           50/hour, 200/day                                             │
│                                                                              │
│  ABUSE PREVENTION                                                            │
│  ────────────────                                                            │
│  • CAPTCHA after 2 scans from same IP                                        │
│  • Block same repo >5 scans/day                                              │
│  • Private repos require GitHub auth                                         │
│  • Ownership verification for private repos                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DEPLOYMENT ARCHITECTURE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PRODUCTION                                                                  │
│  ──────────                                                                  │
│                                                                              │
│  ┌───────────┐     ┌───────────┐     ┌───────────┐                          │
│  │  Vercel   │     │ Supabase  │     │  Fly.io   │                          │
│  │  (Edge)   │     │  (Data)   │     │ (Compute) │                          │
│  └─────┬─────┘     └─────┬─────┘     └─────┬─────┘                          │
│        │                 │                 │                                 │
│        │    ┌────────────┴────────────┐    │                                │
│        └───▶│      Trigger.dev        │◄───┘                                │
│             │    (Orchestration)      │                                      │
│             └─────────────────────────┘                                      │
│                                                                              │
│  STAGING                                                                     │
│  ───────                                                                     │
│  • Vercel preview deployments                                                │
│  • Supabase staging project                                                  │
│  • Fly.io staging app                                                        │
│                                                                              │
│  CI/CD (GitHub Actions)                                                      │
│  ─────────────────────                                                       │
│  • Lint + type check on PR                                                   │
│  • Unit tests on PR                                                          │
│  • E2E tests on staging                                                      │
│  • Auto-deploy to production on main                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Technology Choices

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Frontend | SvelteKit 2.0 | Fastest, smallest bundles, native animations |
| Styling | Tailwind CSS 4.0 | Utility-first, rapid development |
| Charts | Apache ECharts 5 | Feature-rich, lazy-loadable |
| Database | Supabase (PostgreSQL) | Managed, realtime, auth included |
| Vector DB | pgvector (in Supabase) | No separate service needed |
| Cache | Upstash Redis | Serverless, edge-compatible |
| Background Jobs | Trigger.dev | Managed, retries, visibility |
| Scanner Compute | Fly.io Machines | Ephemeral, global, cheap |
| AI | Claude API (Sonnet/Haiku) | Best reasoning, cost-effective routing |
| Hosting | Vercel | Edge-ready, free tier generous |
| Monitoring | Sentry + PostHog | Errors + analytics |

## Key Design Decisions

1. **Tiered Scanning**: 90% of scans use Tier 1 only (cheap/fast), Tier 2 reserved for Pro users
2. **No Code Storage**: Repository code deleted immediately after scan
3. **Shadow Mode**: All AI-generated rules run silently for 2 weeks before activation
4. **pgvector over Pinecone**: Simpler architecture, sufficient for MVP scale
5. **Trigger.dev over Bull/Redis**: Managed service reduces ops burden
6. **Fly.io Machines**: Ephemeral VMs perfect for short-lived scan workloads
