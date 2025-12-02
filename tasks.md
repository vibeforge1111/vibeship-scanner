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
- [x] Fix custom rules loading (vibeship.yaml + gitleaks.toml)
- [x] Context-aware scoring (test/example file detection, client bundle secrets)
- [x] Expand Semgrep rules (14 → 43 rules)
- [x] Finding deduplication across tools
- [x] Structured fix templates with before/after code examples
- [x] CWE/CVSS metadata for all findings (28 CWE entries)
- [x] Category-based deduplication (hardcoded_credential, sql_injection, xss, etc.)
- [x] Add 50+ JS/TS security rules (SQL/NoSQL injection, XXE, deserialization, open redirect, prototype pollution, SSRF, ReDoS)
- [x] Fix [object Object] display bug in Vulnerable Code section
- [x] Remove technical/non-technical mode toggle - unified explanations
- [x] Remove "What's the risk" header - show explanations directly
- [x] Add 35+ Java security rules (XXE, Path Traversal, Deserialization, JWT, SSRF, LDAP)
- [x] Fix hardcoded password false positives (was matching any "password" string)
- [x] Add JNDI injection rules (Log4Shell style attacks)
- [x] Add Spring Security misconfiguration rules
- [x] Add enhanced XXE detection patterns
- [x] Upgrade Node.js to 20 (Railway deprecation warning)

## Environment Variables

### Railway (Web App)
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `SCANNER_API_URL=https://scanner-empty-field-5676.fly.dev`

### Fly.io (Scanner)
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

---

## P1: High Priority (Next Up)

### Community Benchmarks
- [ ] Store stack_signature in scans table
- [ ] Create stack_benchmarks table
- [ ] Weekly aggregation job
- [ ] Display "Better than X% of similar apps"
- [ ] Show top issues by stack

### More Gitleaks Rules
- [x] Replicate API keys
- [x] Pinecone API keys
- [x] Clerk/Auth0 secrets
- [x] Vercel Edge Config tokens
- [x] Resend API keys
- [x] Upstash tokens

### Enhanced Finding Metadata
- [x] Extract CVSS score from Trivy CVEs
- [x] Add exploit availability flag
- [ ] Add attack demonstration (Pro feature)

---

## P2: Medium Priority (Better UX)

### UI Improvements
- [ ] Dark/light theme toggle
- [ ] Mobile responsive improvements
- [ ] Keyboard navigation for findings
- [ ] Print-friendly view

### Reporting
- [ ] PDF report generation
- [ ] Email report delivery
- [ ] Scheduled re-scans

---

## P3: Future Features

### GitHub OAuth & Private Repos
- [ ] Add GitHub OAuth for authenticated scans
- [ ] Add support for private repositories
- [ ] Verify repository ownership

### Pro Features
- [ ] Tier 2 AI analysis with Claude
- [ ] AI-generated personalized fixes
- [ ] Historical trend charts
- [ ] Auto-PR fix integration

### Integrations
- [ ] GitHub App for PR comments
- [ ] CI/CD integration (GitHub Actions)
- [ ] Slack notifications

---

## Current Stats

| Category | Status |
|----------|--------|
| Semgrep Rules | 130+ custom rules |
| Gitleaks Rules | 70+ patterns |
| Context Scoring | ✅ Implemented |
| Deduplication | ✅ Category-based |
| Fix Templates | 18 detailed templates |
| CWE Database | 28 entries with CVSS |
| Java Security | ✅ XXE, Path Traversal, Deserialization, JWT, SSRF, JNDI |
| Spring Security | ✅ CSRF, Headers, Frame Options |

---

## URLs
- **Frontend**: https://vibeship-scanner-production.up.railway.app
- Local dev: http://localhost:5173
- Scanner API: https://scanner-empty-field-5676.fly.dev
- Scanner health: https://scanner-empty-field-5676.fly.dev/health
- GitHub: https://github.com/vibeforge1111/vibeship-scanner
