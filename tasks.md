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
- [x] Fix broken Semgrep rules causing validation errors (exit code 7)
- [x] Add PHP taint-mode rules (SQL injection, file inclusion, command injection, code injection)
- [x] Add Ruby taint-mode rules (SQL injection, command injection, open redirect)
- [x] Learn Semgrep PHP/Ruby limitations (language constructs can't be used as patterns)
- [x] Create CURRENT-PRODUCT.md documenting full product state
- [x] Fix CVE-2025-43859 (h11 HTTP smuggling) - upgraded h11>=0.16.0, httpx>=0.27.0, supabase>=2.0.0
- [x] Fix CVE-2024-1135, CVE-2024-6827, AIKIDO-2024-10216 (gunicorn) - upgraded to >=23.0.0
- [x] Update landing page copy (vibe coder tone, consolidated steps)
- [x] Fix YAML escaping error in javascript.yaml (@ts-ignore rules)
- [x] Remove noisy bash set-e/pipefail rules (was causing 180+ false positives)
- [x] Add comprehensive Node.js security rules (SQL injection, XSS, NoSQL, SSRF, path traversal, XXE, etc.)
- [x] Remove "Get Vibeship to fix this" from vulnerability cards
- [x] Add info count display in Security Summary
- [x] Add DVNA-targeted vulnerability patterns (SQL injection concat, mathjs.eval, node-serialize, libxmljs XXE)
- [x] Add MongoDB/Mongoose NoSQL injection rules (find, update, delete, regex, operator injection)
- [x] Add XSS template rules (Swig, EJS, Pug, Handlebars)
- [x] Add IDOR/authorization bypass patterns
- [x] Add enhanced SSRF detection
- [x] Add session security rules (fixation, cookie flags)
- [x] Add sensitive data exposure rules
- [x] Add 50+ Python/Flask API security rules (OWASP API Top 10, SQLAlchemy, Flask auth)
- [x] Tune SSRF detection to reduce false positives (VAmPI scan improved from 27 to 5 findings)
- [x] Add VAmPI-specific vulnerability patterns (BOLA, mass assignment, user enumeration, ReDoS)
- [x] Add 30+ Express.js security rules (SSTI, IDOR, JWT decode, path traversal, mass assignment)
- [x] Add enhanced IDOR detection (generic function call with user ID patterns)
- [x] Add XSS detection for Express views (res.send, template variables, EJS unescaped)
- [x] Add broken access control patterns (admin param, user ID comparison)
- [x] Add sensitive data exposure rules (password/token in response)
- [x] Add insecure randomness detection (Math.random, weak token generation)
- [x] Add 25+ VAmPI-specific Python patterns (SQL injection f-string, mass assignment, BOLA, user enumeration, ReDoS, weak JWT, debug endpoints, plaintext passwords)

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

### GitHub OAuth & Private Repos (Paid Tier)
Prerequisites: Solid detection rates on public repos, user demand
- [ ] Create GitHub OAuth App (scope: repo read access)
- [ ] Add "Connect GitHub" button in UI
- [ ] Store encrypted access tokens in Supabase
- [ ] Build repo picker dropdown (list user's repos)
- [ ] Modify scanner to use token for private clone
- [ ] Add user accounts/auth to frontend
- [ ] Verify repository ownership
- [ ] Auto-delete cloned repos after scan
- [ ] Add billing/subscription for private repo scans
- [ ] Update privacy policy for code access

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
| Semgrep Rules | 188 validated custom rules |
| Gitleaks Rules | 70+ patterns |
| Context Scoring | ✅ Implemented |
| Deduplication | ✅ Category-based |
| Fix Templates | 20+ detailed templates |
| CWE Database | 28 entries with CVSS |
| Java Security | ✅ XXE, Path Traversal, Deserialization, JWT, SSRF, JNDI |
| Spring Security | ✅ CSRF, Headers, Frame Options |
| PHP Security | ✅ Taint-mode rules (SQLi, File ops, Command injection) |
| Ruby Security | ✅ Taint-mode rules (SQLi, Command injection, Open redirect) |

---

## URLs
- **Frontend**: https://vibeship-scanner-production.up.railway.app
- Local dev: http://localhost:5173
- Scanner API: https://scanner-empty-field-5676.fly.dev
- Scanner health: https://scanner-empty-field-5676.fly.dev/health
- GitHub: https://github.com/vibeforge1111/vibeship-scanner
