# CURRENT-PRODUCT.md - Vibeship Scanner Current State

**Last Updated:** December 3, 2025

This document describes the current state of Vibeship Scanner as deployed in production.

---

## Product Overview

**Vibeship Scanner** is a free, instant security scanner for public GitHub/GitLab repositories. It's designed for developers using AI coding tools (Claude Code, Cursor, Windsurf, Replit, GPT, Gemini) who want to quickly check their code for security vulnerabilities before shipping.

**Live URLs:**
- **Frontend:** https://vibeship-scanner-production.up.railway.app
- **Scanner API:** https://scanner-empty-field-5676.fly.dev

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                            │
│                                                                 │
│  ┌─────────────────┐     ┌──────────────────────────────────┐  │
│  │   Home Page     │────▶│      Results Page                │  │
│  │  (+page.svelte) │     │  (/scan/[id]/+page.svelte)       │  │
│  │                 │     │                                   │  │
│  │ • URL input     │     │ • Score animation (0-100)        │  │
│  │ • Recent scans  │     │ • Grade (A-F)                    │  │
│  │ • AI tools list │     │ • Ship status indicator          │  │
│  └────────┬────────┘     │ • Findings list (expandable)     │  │
│           │              │ • CWE/CVSS info                   │  │
│           │              │ • Fix templates (before/after)   │  │
│           │              │ • Export report (txt download)   │  │
│           │              │ • Share to X/Twitter             │  │
│           │              │ • Real-time progress updates     │  │
│           ▼              └──────────────────────────────────┘  │
└───────────┼─────────────────────────────────────────────────────┘
            │
            │ POST /api/scan
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SVELTEKIT FRONTEND (Railway)                  │
│                                                                 │
│  src/routes/api/scan/+server.ts                                 │
│  • Rate limiting (20 scans/hour per IP)                        │
│  • URL validation (GitHub/GitLab patterns)                      │
│  • Creates scan record in Supabase                              │
│  • Triggers scanner service asynchronously                      │
│                                                                 │
│  src/lib/                                                       │
│  • supabase.ts     - Supabase client                           │
│  • fixTemplates.ts - 20+ vulnerability fix guides              │
│  • cweDatabase.ts  - CWE info with CVSS scores                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ POST /scan (async, fire-and-forget)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SCANNER SERVICE (Fly.io)                     │
│                    Sydney Region (syd)                          │
│                    1GB RAM, 1 shared CPU                        │
│                                                                 │
│  scanner/server.py - Flask API                                  │
│  • /health - Health check                                       │
│  • /scan   - Starts scan in background thread                  │
│                                                                 │
│  scanner/scan.py - Orchestrator                                 │
│  1. Clone repo (shallow, 120s timeout)                         │
│  2. Detect stack (languages, frameworks)                       │
│  3. Run Semgrep (SAST, 300s timeout)                          │
│  4. Run Trivy (dependencies + secrets, 300s timeout)           │
│  5. Run Gitleaks (secrets, 300s timeout)                       │
│  6. Deduplicate findings                                        │
│  7. Calculate score (0-100)                                     │
│  8. Update Supabase with results                                │
│                                                                 │
│  scanner/rules/                                                 │
│  • core.yaml    - 188 custom Semgrep rules                     │
│  • vibeship.yaml - Extended rules                               │
│  • gitleaks.toml - Secret detection config                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Realtime updates via Postgres changes
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                         SUPABASE                                │
│                                                                 │
│  Tables:                                                        │
│  • scans          - Scan records and results                   │
│  • scan_progress  - Step-by-step progress updates              │
│                                                                 │
│  Features:                                                      │
│  • Realtime subscriptions for live progress                    │
│  • Row Level Security (RLS) for data access                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Scanning Tools

### 1. Semgrep (SAST - Static Application Security Testing)
- **Rules:** 188 custom rules in `core.yaml`
- **Languages:** JavaScript, TypeScript, Python, PHP, Ruby, Java, Go, C#
- **Categories:**
  - SQL Injection (standard + NoSQL)
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - SSRF (Server-Side Request Forgery)
  - Open Redirect
  - Hardcoded Secrets/Credentials
  - Insecure Deserialization
  - Weak Cryptography
  - Missing Authentication
  - Prototype Pollution
  - Code Injection (eval)
  - JWT Issues
  - Cookie Security
  - CORS Misconfiguration

- **PHP Taint-Mode Rules:** Uses `mode: taint` with pattern-sources and pattern-sinks for:
  - SQL injection via mysqli, PDO, pg_query
  - File inclusion (include/require)
  - Command injection (shell_exec, system, passthru)
  - File operations (file_put_contents, unlink)
  - Code injection (eval, create_function)

- **Ruby Taint-Mode Rules:**
  - SQL injection via ActiveRecord
  - Command injection (system, exec, backticks)
  - Open redirect (redirect_to)

### 2. Trivy (Dependency Scanning)
- Scans package manifests (package.json, requirements.txt, pom.xml, etc.)
- Reports known CVEs with CVSS scores
- Provides upgrade recommendations
- Also detects secrets in files

### 3. Gitleaks (Secret Detection)
- Scans entire codebase for exposed secrets
- Detects: API keys, passwords, tokens, private keys
- Custom config in `gitleaks.toml`

---

## Scoring System

**Score Calculation (0-100):**
```
Starting score: 100

Deductions per finding:
- Critical: -25 points (max -100)
- High:     -10 points (max -50)
- Medium:   -5 points  (max -30)
- Low:      -2 points  (max -15)
- Info:     0 points
```

**Grade Mapping:**
| Score Range | Grade |
|-------------|-------|
| 90-100      | A     |
| 80-89       | B     |
| 70-79       | C     |
| 60-69       | D     |
| 0-59        | F     |

**Ship Status:**
| Score Range | Status          | Indicator       |
|-------------|-----------------|-----------------|
| 90-100      | Ship It!        | 🚀              |
| 70-89       | Needs Review    | ⚠️              |
| 50-69       | Fix Required    | 🔧              |
| 0-49        | Do Not Ship     | 🛑              |

---

## Frontend Features

### Home Page (`/`)
- Repository URL input (supports GitHub/GitLab)
- Shorthand formats: `user/repo` → `https://github.com/user/repo`
- Recent scans list (stored in localStorage, fetched from Supabase)
- Rotating AI tool names animation
- "How it works" section
- CTA to Vibeship expert services

### Results Page (`/scan/[id]`)
- **Progress View (during scan):**
  - 7-step progress indicator with icons
  - Security facts carousel (46 facts from IBM, Verizon, OWASP reports)
  - Progress bar with percentage
  - Cancel scan button
  - 15-minute timeout with auto-fail

- **Results View (after completion):**
  - Animated score reveal (counts up from 0)
  - Confetti animation for scores ≥80
  - Grade badge with color coding
  - Ship status message
  - Stack detection results (languages, frameworks)

- **Findings Section:**
  - Expandable cards for each finding
  - Severity badges (Critical/High/Medium/Low)
  - CWE information with CVSS scores
  - Code snippets showing vulnerable code
  - Fix templates with before/after examples
  - Estimated fix time and difficulty
  - References to OWASP/documentation

- **Export/Share:**
  - Copy link button
  - Share to X/Twitter
  - Download full report (txt format)
  - Copy full report to clipboard

---

## Fix Templates

20+ built-in fix templates for common vulnerabilities:
- `sql-injection` / `sql-injection-prisma`
- `xss-innerhtml` / `xss-svelte`
- `hardcoded-secret` / `hardcoded-jwt-secret`
- `missing-auth` / `missing-auth-sveltekit`
- `cors-allow-all`
- `weak-password-hashing`
- `jwt-no-expiry`
- `command-injection`
- `path-traversal`
- `ssrf`
- `insecure-cookie`
- `eval-usage`
- `disabled-ssl-verification`
- `open-redirect`
- `supabase-service-role`

Each template includes:
- Title and description
- Estimated fix time
- Difficulty level (easy/medium/hard)
- Before (vulnerable) code
- After (safe) code
- Explanation
- Reference links

---

## CWE Database

Includes detailed information for 20+ common CWEs:
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting (XSS)
- CWE-798: Hardcoded Credentials
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-306: Missing Authentication
- CWE-352: Cross-Site Request Forgery (CSRF)
- CWE-327: Weak Cryptography
- And more...

Each CWE entry includes:
- Name and description
- Severity level
- CVSS base score
- Exploitability rating
- Impact description
- Category
- References

---

## Rate Limiting

- **20 scans per hour** per IP address
- Tracked via `session_id` field in scans table
- Returns 429 status with `remaining` count when exceeded

---

## Stack Detection

Automatically detects:
- **Languages:** JavaScript, TypeScript, Python, Go, Rust
- **Frameworks:** React, Vue, SvelteKit, Next.js, Express, Django, Supabase, MongoDB

Detection based on:
- `package.json` dependencies
- `requirements.txt` / `pyproject.toml`
- `go.mod`
- `Cargo.toml`
- `manage.py` (Django)

---

## Deployment

### Frontend (Railway)
- SvelteKit with Node adapter
- Auto-deploys on push to main
- Environment variables:
  - `PUBLIC_SUPABASE_URL`
  - `PUBLIC_SUPABASE_ANON_KEY`
  - `SCANNER_API_URL`

### Scanner (Fly.io)
- Docker container with Python + security tools
- Sydney region (`syd`)
- 1GB RAM, 1 shared CPU
- Always-on (min 1 machine)
- Manual deploy: `fly deploy --remote-only`
- Secrets via `fly secrets set`

---

## File Structure

```
vibeship-scanner/
├── src/
│   ├── routes/
│   │   ├── +page.svelte           # Home page
│   │   ├── +layout.svelte         # App layout
│   │   ├── api/
│   │   │   └── scan/
│   │   │       └── +server.ts     # Scan API endpoint
│   │   └── scan/
│   │       └── [id]/
│   │           └── +page.svelte   # Results page
│   ├── lib/
│   │   ├── supabase.ts            # Supabase client
│   │   ├── fixTemplates.ts        # Fix code templates
│   │   ├── cweDatabase.ts         # CWE information
│   │   ├── stores/
│   │   │   └── preferences.ts     # User preferences
│   │   ├── types/
│   │   │   └── database.ts        # TypeScript types
│   │   └── server/
│   │       └── scan.ts            # Server-side scan utils
│   └── app.html                   # HTML template
├── scanner/
│   ├── scan.py                    # Scanning orchestrator
│   ├── server.py                  # Flask API server
│   ├── rules/
│   │   ├── core.yaml              # 188 Semgrep rules
│   │   └── vibeship.yaml          # Extended rules
│   ├── gitleaks.toml              # Secret detection config
│   ├── Dockerfile                 # Scanner container
│   └── fly.toml                   # Fly.io config
├── package.json                   # Frontend dependencies
├── vite.config.ts                 # Vite configuration
├── tsconfig.json                  # TypeScript config
└── CLAUDE.md                      # AI assistant instructions
```

---

## Current Limitations

1. **Public repos only** - Private repositories not supported
2. **No authentication** - Users can't save or manage scans
3. **No CI/CD integration** - No GitHub Actions, no PR comments
4. **No API access** - No programmatic access for external tools
5. **Single region** - Scanner runs only in Sydney
6. **No custom rules** - Users can't add their own Semgrep rules
7. **No historical trends** - Can't track security score over time
8. **Basic deduplication** - Some duplicate findings may appear
9. **No severity adjustment** - Can't customize severity levels
10. **Limited language support** - PHP/Ruby rules limited by Semgrep syntax

---

## Recent Changes (December 2025)

- Added **PHP taint-mode rules** for SQL injection, file operations, command injection
- Added **Ruby taint-mode rules** for SQL injection, command injection, open redirect
- Fixed Semgrep validation errors (reduced rules from ~250 to 188 valid rules)
- Learned PHP/Ruby language construct limitations in Semgrep patterns

---

## Test Results

**OWASP WebGoat scan:**
- 6 Critical, 13 High, 4 Medium, 1 Low
- Mostly dependency vulnerabilities (axis, log4j, commons-*)
- Score: 0/100, Grade: F

**OWASP DVWA scan:** (pending verification of PHP rules)

---

## Links

- **Production:** https://vibeship-scanner-production.up.railway.app
- **Scanner API:** https://scanner-empty-field-5676.fly.dev
- **Vibeship (expert help):** https://vibeship.com
