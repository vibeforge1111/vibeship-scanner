# Vibeship Scanner - Tasks

## Completed
- [x] Set up SvelteKit frontend with Supabase integration
- [x] Create scanner service with Semgrep, Trivy, and Gitleaks
- [x] Deploy web app to Railway (Nixpacks)
- [x] Deploy scanner service to Fly.io (Docker)
- [x] Configure Supabase database with scans table
- [x] Fix RLS policies for anonymous access
- [x] Fix supabase/gotrue package compatibility (pinned to v1.0.4)
- [x] Connect web app to scanner API
- [x] End-to-end scan working: clone -> analyze -> results
- [x] Score reveal animation with count-up and confetti
- [x] Founder/Developer mode toggle for findings
- [x] Expandable finding cards with better styling
- [x] Share section (copy link, Twitter share, badge embed)
- [x] Scan history on homepage (localStorage + Supabase)
- [x] Real-time scan progress with Supabase Realtime

## Environment Variables

### Railway (Web App)
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `SCANNER_API_URL=https://scanner-empty-field-5676.fly.dev`

### Fly.io (Scanner)
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

---

## P0: Critical (Scanner Not Working Correctly)

### Fix Custom Rules Loading
- [ ] **scan.py uses `--config auto` but ignores our custom rules!**
- [ ] Update Semgrep to use `--config rules/vibeship.yaml --config auto`
- [ ] Update Gitleaks to use `--config gitleaks.toml`

### Context-Aware Scoring (PRD Requirement)
- [ ] Detect test files (`*.test.ts`, `*.spec.ts`, `__tests__/`)
- [ ] Detect example files (`example/`, `sample/`, `demo/`)
- [ ] Downgrade severity by 1 level for test/example files
- [ ] Detect main bundle (client-side code)
- [ ] Upgrade secrets in client bundle to CRITICAL
- [ ] Add `contextNote` field to findings

---

## P1: High Priority (Missing Core Features)

### More Semgrep Rules (Current: 14, Target: 50+)

**SQL Injection:**
- [ ] String concatenation: `"SELECT * FROM " + id`
- [ ] Prisma $queryRaw with user input
- [ ] Drizzle sql`` with user input
- [ ] Sequelize literal()

**XSS:**
- [ ] document.write()
- [ ] Svelte {@html} without sanitization
- [ ] Vue v-html
- [ ] jQuery .html()

**Injection:**
- [ ] new Function() with user input
- [ ] child_process.exec with user input
- [ ] fs path traversal (user input in file paths)
- [ ] SSRF (fetch/axios to user-controlled URL)

**Auth Issues:**
- [ ] Missing auth middleware on API routes
- [ ] Broken access control (IDOR patterns)
- [ ] Insecure password reset flows
- [ ] Session fixation

**SvelteKit-Specific:**
- [ ] Unvalidated load function params
- [ ] {@html} without sanitization
- [ ] +server.ts without auth check
- [ ] Form actions without CSRF protection

**Supabase-Specific:**
- [ ] RLS bypass patterns
- [ ] Anon key + no RLS warning
- [ ] Direct table access patterns

**Config Issues:**
- [ ] Debug mode in production
- [ ] Source maps in production
- [ ] .env file committed
- [ ] Verbose error responses
- [ ] Missing security headers

### Finding Deduplication
- [ ] Merge overlapping findings from different tools
- [ ] Prefer more specific finding (Semgrep > Gitleaks for secrets)
- [ ] Keep highest severity when merging

### Gitleaks Additional Rules
- [ ] Replicate API keys
- [ ] Pinecone API keys
- [ ] Clerk/Auth0 secrets
- [ ] Vercel Edge Config tokens
- [ ] Resend API keys
- [ ] Upstash tokens

---

## P2: Medium Priority (Better UX)

### Structured Fix Templates
- [ ] Create FixTemplate interface with code examples
- [ ] Add before/after code blocks
- [ ] Add estimated fix time
- [ ] Add stack-specific variations
- [ ] Implement template lookup by finding type

### Enhanced Finding Metadata
- [ ] Add CWE reference to all code findings
- [ ] Extract CVSS score from Trivy CVEs
- [ ] Add exploit availability flag
- [ ] Add business impact description (Founder mode)
- [ ] Add attack demonstration (Pro feature)

### Community Benchmarks
- [ ] Store stack_signature in scans table
- [ ] Create stack_benchmarks table
- [ ] Weekly aggregation job
- [ ] Display "Better than X% of similar apps"
- [ ] Show top issues by stack

---

## P3: Future Features

### GitHub OAuth & Private Repos
- [ ] Add GitHub OAuth for authenticated scans
- [ ] Add support for private repositories
- [ ] Verify repository ownership

### Pro Features
- [ ] Tier 2 AI analysis with Claude
- [ ] AI-generated personalized fixes
- [ ] PDF report generation
- [ ] Historical trend charts
- [ ] Auto-PR fix integration

### Integrations
- [ ] GitHub App for PR comments
- [ ] CI/CD integration (GitHub Actions)
- [ ] Slack notifications

---

## Gap Analysis Summary

| Category | Current | Target | Gap |
|----------|---------|--------|-----|
| Semgrep Rules | 14 | 50+ | Missing SQL variants, auth, framework-specific |
| Gitleaks Rules | 20 | 30+ | Missing newer AI/cloud service keys |
| Context Scoring | 0% | 100% | Not implemented at all |
| Deduplication | No | Yes | Multiple tools find same issue |
| Fix Templates | Generic text | Code examples | No structured templates |
| Benchmarks | None | Stack comparison | Not implemented |

---

## URLs
- Local dev: http://localhost:5173
- Scanner API: https://scanner-empty-field-5676.fly.dev
- Scanner health: https://scanner-empty-field-5676.fly.dev/health
