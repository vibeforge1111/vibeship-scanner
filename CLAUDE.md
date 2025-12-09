# CLAUDE.md - Vibeship Scanner Development Guide

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Vibeship Scanner is a security scanning tool that analyzes GitHub repositories for vulnerabilities using:
- **Opengrep** - Static Application Security Testing (SAST) - open-source Semgrep fork
- **Trivy** - Dependency vulnerability scanning
- **Gitleaks** - Secret detection

## IMPORTANT: How to Trigger Scans

**ALWAYS use the deployed Vibeship Scanner API for scans** - never run local semgrep/opengrep commands directly.

### Scan Procedure (MUST FOLLOW)

```bash
# 1. Generate a UUID for the scan
SCAN_ID=$(python -c "import uuid; print(uuid.uuid4())")

# 2. Trigger the scan via curl
curl -X POST https://scanner-empty-field-5676.fly.dev/scan \
  -H "Content-Type: application/json" \
  -d "{\"scanId\": \"$SCAN_ID\", \"repoUrl\": \"https://github.com/OWNER/REPO\"}"

# 3. Provide the scan URLs to the user
echo "View at: http://localhost:5173/scan/$SCAN_ID"
echo "View at: https://vibeship.co/scan/$SCAN_ID"
```

### Quick One-Liner Template
```bash
SCAN_ID=$(python -c "import uuid; print(uuid.uuid4())") && \
echo "Scan ID: $SCAN_ID" && \
echo "View at: http://localhost:5173/scan/$SCAN_ID" && \
echo "View at: https://vibeship.co/scan/$SCAN_ID" && \
curl -X POST https://scanner-empty-field-5676.fly.dev/scan \
  -H "Content-Type: application/json" \
  -d "{\"scanId\": \"$SCAN_ID\", \"repoUrl\": \"https://github.com/OWNER/REPO\"}"
```

### View Results At
- **Local dev**: `http://localhost:5173/scan/<scanId>`
- **Production**: `https://vibeship.co/scan/<scanId>`

### Why This Matters
1. Results are saved to Supabase and viewable in the web UI
2. All four scanners run (Opengrep + Trivy + Gitleaks + npm audit)
3. Consistent rule versions from deployed scanner
4. Scan progress is tracked in real-time

### Monitoring Scans
```bash
# Watch scanner logs in real-time
fly logs -a scanner-empty-field-5676

# Get recent logs (no streaming)
fly logs -a scanner-empty-field-5676 --no-tail | tail -100
```

### Common Issues
- **Scan stuck in "scanning"**: Check Fly.io logs for errors
- **Database errors**: Ensure scan row is created with proper schema (target_url, target_url_hash, target_branch)
- **Deployment kills running scans**: Fly.io restarts terminate in-progress scans - wait for completion before deploying

## Architecture

```
vibeship-scanner/
├── src/                    # SvelteKit frontend
│   ├── routes/             # Pages and API routes
│   ├── lib/                # Shared utilities
│   └── app.html            # HTML template
├── scanner/                # Python scanner service (Fly.io)
│   ├── scan.py             # Main scanning orchestrator
│   ├── server.py           # Flask API server
│   ├── rules/              # Semgrep rule files
│   │   ├── core.yaml       # Core security rules
│   │   └── vibeship.yaml   # Extended rules
│   └── Dockerfile          # Scanner container
└── docs/                   # Documentation
```

## Development Commands

```bash
# Start frontend dev server
npm run dev

# Build for production
npm run build

# Deploy scanner to Fly.io
cd scanner && fly deploy --remote-only

# Validate Semgrep rules
semgrep --validate --config scanner/rules/
```

## Key Files

- `scanner/rules/core.yaml` - Core Semgrep security rules
- `scanner/rules/vibeship.yaml` - Extended Semgrep rules
- `scanner/scan.py` - Main scanning logic
- `src/routes/api/scan/+server.ts` - Scan API endpoint
- `src/routes/scan/[id]/+page.svelte` - Scan results page

## Security Knowledge Base

### IMPORTANT: Maintaining SECURITY_COMMONS.md

The `SECURITY_COMMONS.md` file is our **living security vulnerability database**. It must be continuously updated with:

1. **New vulnerability patterns** discovered during:
   - Research on vulnerable applications (DVWA, Juice Shop, etc.)
   - Analysis of GitHub security advisories
   - Review of scan results from real repositories
   - CVE database monitoring

2. **For each vulnerability, document**:
   - CWE ID and name
   - Risk level (Critical/High/Medium/Low)
   - Vulnerable code examples
   - Secure code examples
   - Key prevention points

3. **Use this database to**:
   - Improve Semgrep rules in `scanner/rules/`
   - Enhance scanner explanations
   - Provide accurate fix recommendations
   - Train and validate scanner accuracy

4. **After finding new vulnerabilities**:
   - Add to SECURITY_COMMONS.md with examples
   - Consider adding new Semgrep rules if detectable
   - Update SECURITY_TEST_PROCEDURE.md if needed

### Testing Against Vulnerable Apps

**IMPORTANT**: Follow `SECURITY_TEST_PROCEDURE.md` for systematic scanner improvement.

The test procedure contains **30 vulnerable repositories** organized by priority:
- **Tier 1 (Critical)**: DVWA, Juice Shop, crAPI, NodeGoat, WebGoat, DVNA
- **Tier 2 (Language-Specific)**: RailsGoat, Django.nV, Flask, DSVW, PHP, Java apps
- **Tier 3 (Specialized)**: API security, SSRF, XXE, GraphQL, CI/CD, secrets
- **Tier 4 (Additional)**: Mobile, .NET, Kubernetes, CTF tools

**Workflow for each repository**:
1. Scan the repo
2. Document findings in SECURITY_TEST_PROCEDURE.md
3. Identify gaps (vulnerabilities not detected)
4. Add new Semgrep rules for detectable gaps
5. Update SECURITY_COMMONS.md with new patterns
6. Re-scan to verify improvements
7. Commit and deploy

**Current Progress** (track in SECURITY_TEST_PROCEDURE.md):
- ✅ digininja/DVWA - 18 high findings
- ✅ OWASP/crAPI - 137 findings
- ⏳ 28 more repos pending

## Semgrep Rule Guidelines

When adding rules to `scanner/rules/`:

1. **YAML syntax**: Quote patterns containing colons
   ```yaml
   # GOOD
   pattern: 'subprocess.call($CMD, shell=True)'

   # BAD - will fail validation
   pattern: subprocess.call($CMD, shell=True)
   ```

2. **Always validate** before deploying:
   ```bash
   semgrep --validate --config scanner/rules/core.yaml
   ```

3. **Include**:
   - Unique rule ID
   - Clear message
   - Severity (ERROR/WARNING/INFO)
   - Target languages

## Environment Variables

Frontend (.env):
- `PUBLIC_SUPABASE_URL`
- `PUBLIC_SUPABASE_ANON_KEY`
- `SCANNER_API_URL`

Scanner (Fly.io secrets):
- Set via `fly secrets set KEY=value`

## Deployment

**Frontend**: Auto-deploys via Vercel on push to main

**Scanner**: Manual deploy to Fly.io
```bash
cd scanner
fly deploy --remote-only --no-cache
```

## Code Style

- TypeScript for frontend
- Python for scanner
- No comments unless explaining complex logic
- Use existing patterns and utilities

## MCP Servers Configuration

The project has MCP servers configured in `.mcp.json`:

### vibeship-scanner MCP (Custom)
**Location:** `~/.claude/mcp-servers/vibeship-scanner/`
**Python:** `~/.claude/mcp-servers/vibeship-scanner/.venv/Scripts/python.exe`

Tools:
- `scan_repo` - Trigger security scan on GitHub repo
- `get_scan_status` - Check scan progress
- `lookup_cve` - Query NVD for CVE details
- `lookup_ghsa` - Query GitHub Security Advisories
- `get_cwe_info` - Get CWE weakness details + OWASP mapping
- `validate_opengrep_rule` - Validate rule YAML before deployment

### fetch MCP
HTTP requests for custom API queries.

### github MCP
Repository operations, PR creation (requires GITHUB_TOKEN env var).

## Security Rule Development Skill

Use the `security-rule-development` skill when:
- Creating new Opengrep detection rules
- Benchmarking against vulnerable repos
- Researching CVEs/CWEs for rule metadata
- Improving scanner coverage

Skill location: `~/.claude/skills/security-rule-development/`
