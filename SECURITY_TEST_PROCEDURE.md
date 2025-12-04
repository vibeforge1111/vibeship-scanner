# Vibeship Scanner - Security Test Procedure

This document outlines the testing procedure for validating Vibeship Scanner against intentionally vulnerable applications.

## Purpose

Ensure the scanner accurately detects known vulnerabilities in well-documented vulnerable applications. This helps:
- Validate scanner detection capabilities
- Identify gaps in rule coverage
- Benchmark scanner performance
- Document expected vs actual findings
- **Continuously improve SECURITY_COMMONS.md and Semgrep rules**

---

## Complete Vulnerable Repository Checklist

Work through each repository systematically. After scanning, document findings and update rules/SECURITY_COMMONS.md.

### Tier 1: Critical (Must Complete First)

| # | Repository | Language | Status | Findings | Notes |
|---|------------|----------|--------|----------|-------|
| 1 | [digininja/DVWA](https://github.com/digininja/DVWA) | PHP | ✅ Done | 151 | Baseline test, PHP rules |
| 2 | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | JS/Node | ✅ Done | 931 | OWASP Top 10 coverage |
| 3 | [OWASP/crAPI](https://github.com/OWASP/crAPI) | Python/JS | ✅ Done | 137 | API security focused |
| 4 | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript | ⏳ Pending | - | OWASP Top 10 for Node |
| 5 | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | Java | ⏳ Pending | - | Java vulnerabilities |
| 6 | [appsecco/dvna](https://github.com/appsecco/dvna) | JavaScript | ⏳ Pending | - | Node.js focused |
| + | [trottomv/python-insecure-app](https://github.com/trottomv/python-insecure-app) | Python | ✅ Done | 8 | SSTI, SSRF, secrets |
| + | [SirAppSec/vuln-node.js-express.js-app](https://github.com/SirAppSec/vuln-node.js-express.js-app) | JS/Node | ✅ Done | 15+ | SSTI, XSS, weak auth |

### Tier 2: Language-Specific

| # | Repository | Language | Status | Findings | Notes |
|---|------------|----------|--------|----------|-------|
| 7 | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | Ruby | ⏳ Pending | - | Ruby/Rails vulns |
| 8 | [nVisium/django.nV](https://github.com/nVisium/django.nV) | Python | ⏳ Pending | - | Django security |
| 9 | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Python | ⏳ Pending | - | Flask/SSTI |
| 10 | [stamparm/DSVW](https://github.com/stamparm/DSVW) | Python | ⏳ Pending | - | Minimal vuln app |
| 11 | [OWASP/OWASPWebGoatPHP](https://github.com/OWASP/OWASPWebGoatPHP) | PHP | ⏳ Pending | - | PHP variant |
| 12 | [SasanLabs/VulnerableApp](https://github.com/SasanLabs/VulnerableApp) | Java | ⏳ Pending | - | Java security |

### Tier 3: Specialized Vulnerabilities

| # | Repository | Focus Area | Status | Findings | Notes |
|---|------------|------------|--------|----------|-------|
| 13 | [erev0s/VAmPI](https://github.com/erev0s/VAmPI) | REST API | ⏳ Pending | - | OWASP API Top 10 |
| 14 | [incredibleindishell/SSRF_Vulnerable_Lab](https://github.com/incredibleindishell/SSRF_Vulnerable_Lab) | SSRF | ⏳ Pending | - | Server-side request forgery |
| 15 | [jbarone/xxelab](https://github.com/jbarone/xxelab) | XXE | ⏳ Pending | - | XML External Entity |
| 16 | [OWASP/wrongsecrets](https://github.com/OWASP/wrongsecrets) | Secrets | ⏳ Pending | - | Secret management |
| 17 | [step-security/github-actions-goat](https://github.com/step-security/github-actions-goat) | CI/CD | ⏳ Pending | - | GitHub Actions security |
| 18 | [dolevf/Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | GraphQL | ⏳ Pending | - | GraphQL vulns |
| 19 | [payatu/Tiredful-API](https://github.com/payatu/Tiredful-API) | REST API | ⏳ Pending | - | API security |
| 20 | [optiv/InsecureShop](https://github.com/optiv/InsecureShop) | Android | ⏳ Pending | - | Mobile app security |

### Tier 4: Additional Test Repos

| # | Repository | Focus Area | Status | Findings | Notes |
|---|------------|------------|--------|----------|-------|
| 21 | [bkimminich/juice-shop-ctf](https://github.com/bkimminich/juice-shop-ctf) | CTF Tools | ⏳ Pending | - | CTF extensions |
| 22 | [OWASP/Vulnerable-Web-Application](https://github.com/OWASP/Vulnerable-Web-Application) | General | ⏳ Pending | - | OWASP collection |
| 23 | [rapid7/hackazon](https://github.com/rapid7/hackazon) | E-commerce | ⏳ Pending | - | Real-world simulation |
| 24 | [globocom/secDevLabs](https://github.com/globocom/secDevLabs) | Multi-lang | ⏳ Pending | - | Various vulns |
| 25 | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) | Dependencies | ⏳ Pending | - | Dependency vulns |
| 26 | [CSPF-Founder/JavaVulnerableLab](https://github.com/CSPF-Founder/JavaVulnerableLab) | Java | ⏳ Pending | - | Java-specific |
| 27 | [Contrast-Security-OSS/DotNetGoat](https://github.com/Contrast-Security-OSS/DotNetGoat) | .NET | ⏳ Pending | - | .NET vulnerabilities |
| 28 | [payatu/diva-android](https://github.com/payatu/diva-android) | Android | ⏳ Pending | - | Mobile security |
| 29 | [OWASP/iGoat-Swift](https://github.com/OWASP/iGoat-Swift) | iOS/Swift | ⏳ Pending | - | iOS security |
| 30 | [commjoen/wrongsecrets-ctf-party](https://github.com/commjoen/wrongsecrets-ctf-party) | Kubernetes | ⏳ Pending | - | K8s secrets |

---

## Test Execution Workflow

### For Each Repository:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. SCAN                                                        │
│     └─> Run scan via vibeship.co or API                        │
│                                                                 │
│  2. DOCUMENT                                                    │
│     └─> Record findings in this file                           │
│     └─> Note what was found vs expected                        │
│                                                                 │
│  3. ANALYZE GAPS                                                │
│     └─> List vulnerabilities NOT detected                      │
│     └─> Determine if detectable by SAST                        │
│                                                                 │
│  4. IMPROVE SCANNER                                             │
│     └─> Add new Semgrep rules for gaps                         │
│     └─> Update scanner/rules/core.yaml or vibeship.yaml        │
│     └─> Validate rules: semgrep --validate                     │
│                                                                 │
│  5. UPDATE SECURITY_COMMONS.md                                  │
│     └─> Add new vulnerability patterns discovered              │
│     └─> Include vulnerable & secure code examples              │
│     └─> Add CWE references                                     │
│                                                                 │
│  6. RE-SCAN & VERIFY                                            │
│     └─> Re-scan after rule updates                             │
│     └─> Confirm new findings detected                          │
│                                                                 │
│  7. COMMIT & DEPLOY                                             │
│     └─> git push changes                                       │
│     └─> fly deploy scanner if rules changed                    │
└─────────────────────────────────────────────────────────────────┘
```

### Test Execution Template

```markdown
## Scan Report: [Repository Name]

**Repository**: [github url]
**Date**: [YYYY-MM-DD]
**Scanner Version**: [commit hash]

### Results
- **Score**: [X]/100
- **Grade**: [A-F]
- **Ship Status**: [ship/review/fix/danger]
- **Scan Duration**: [Xs]

### Findings by Severity
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Info | X |

### Findings by Category
| Category | Count |
|----------|-------|
| Code (Semgrep) | X |
| Dependencies (Trivy) | X |
| Secrets (Gitleaks) | X |

### Expected vs Detected

| Vulnerability | Expected | Detected | Rule ID |
|--------------|----------|----------|---------|
| SQL Injection | Yes | ✅/❌ | [rule-id] |
| XSS | Yes | ✅/❌ | [rule-id] |
| Command Injection | Yes | ✅/❌ | [rule-id] |
| [etc...] | | | |

### Gaps Identified
1. [Vulnerability not detected]
   - Reason: [pattern not covered / needs DAST / etc]
   - Action: [Add rule / Not detectable / etc]

### New Rules Added
- [rule-id]: [description]

### SECURITY_COMMONS.md Updates
- Added: [vulnerability pattern]
- Updated: [existing section]

### Notes
- [observations, false positives, etc]
```

---

## Vulnerability Categories to Track

For each scan, check detection of:

### Injection
- [ ] SQL Injection (CWE-89)
- [ ] NoSQL Injection (CWE-943)
- [ ] Command Injection (CWE-78)
- [ ] LDAP Injection (CWE-90)
- [ ] XPath Injection (CWE-643)
- [ ] Template Injection (SSTI)

### XSS
- [ ] Reflected XSS (CWE-79)
- [ ] Stored XSS (CWE-79)
- [ ] DOM-based XSS (CWE-79)

### Authentication
- [ ] Hardcoded Credentials (CWE-798)
- [ ] Weak Password Storage (CWE-916)
- [ ] Missing Authentication (CWE-306)
- [ ] Broken Session Management (CWE-384)

### Authorization
- [ ] IDOR/BOLA (CWE-639)
- [ ] Privilege Escalation (CWE-269)
- [ ] Missing Access Control (CWE-862)

### Cryptography
- [ ] Weak Hash (MD5/SHA1) (CWE-327)
- [ ] Weak Encryption (DES) (CWE-327)
- [ ] Hardcoded Keys (CWE-321)
- [ ] Missing TLS Verification (CWE-295)

### Data Exposure
- [ ] Sensitive Data in Logs (CWE-532)
- [ ] Debug Mode Enabled (CWE-489)
- [ ] Error Message Disclosure (CWE-209)
- [ ] Exposed Secrets (API keys, passwords)

### File Handling
- [ ] Path Traversal (CWE-22)
- [ ] Unrestricted Upload (CWE-434)
- [ ] File Inclusion (LFI/RFI) (CWE-98)

### Deserialization
- [ ] Insecure Deserialization (CWE-502)
- [ ] Pickle/YAML/XML issues

### Other
- [ ] SSRF (CWE-918)
- [ ] XXE (CWE-611)
- [ ] Open Redirect (CWE-601)
- [ ] CSRF (CWE-352)
- [ ] ReDoS (CWE-1333)

---

## DVWA Detailed Results

### Scan #2: 2025-12-02 (After PHP Rules Added)

**Results**: Score 20/100, Grade F, 102 High + 49 Medium = 151 findings

| Category | Count | Rule IDs |
|----------|-------|----------|
| PHP File Inclusion | 50+ | php-require-var, php-include-var |
| PHP Command Injection | 14 | php-shell-exec, php-exec |
| PHP Weak Crypto (MD5) | 22 | php-md5-password |
| PHP SSRF | 25 | php-file-get-contents-url |
| PHP Eval | 4 | php-eval |
| PHP File Upload | 3 | php-move-uploaded-file |
| PHP SQL Injection | 1 | php-mysqli-query-concat |
| JavaScript XSS | 12 | innerhtml-assignment, xss-innerhtml |
| JavaScript Eval | 6 | eval-user-input |

### Improvements Made (v2)
- Added 35+ PHP security rules
- Detection improved from 18 to 151 findings
- Now detecting: shell_exec, exec, eval, include/require, MD5, file_get_contents, move_uploaded_file

### Known False Positives
- `require_once(DVWA_WEB_PAGE_TO_ROOT...)` - uses constant, not user input
- Could be improved with taint tracking

### Still Not Detected (Requires DAST)
- CSRF vulnerabilities
- Weak session management
- CSP bypass issues
- Brute force susceptibility

---

### Scan #1: 2025-12-02 (Initial Baseline)

**Results**: Score 45/100, Grade F, 18 High findings

| Module | Vulnerability | Detected | Rule ID | Notes |
|--------|--------------|----------|---------|-------|
| Brute Force | Weak auth | Partial | - | Runtime issue |
| Command Injection | OS injection | ✅ Yes | exec-call | shell_exec found |
| CSRF | CSRF | ❌ No | - | Needs DAST |
| File Inclusion | LFI/RFI | ✅ Yes | - | include() patterns |
| File Upload | Unrestricted | ✅ Yes | - | Extension checks |
| Insecure CAPTCHA | Weak CAPTCHA | ❌ No | - | Logic issue |
| SQL Injection | SQLi | ✅ Yes | sql-injection | mysqli_query patterns |
| SQL Injection (Blind) | Blind SQLi | ✅ Yes | sql-injection | Same rule |
| Weak Session IDs | Session mgmt | ❌ No | - | Runtime issue |
| XSS (DOM) | DOM XSS | Partial | - | Some patterns |
| XSS (Reflected) | Reflected XSS | ✅ Yes | innerhtml-xss | echo patterns |
| XSS (Stored) | Stored XSS | ✅ Yes | innerhtml-xss | Database + echo |
| CSP Bypass | CSP | ❌ No | - | Config issue |
| JavaScript | Client issues | Partial | eval-injection | eval() found |

---

## Test Schedule

| Frequency | Action |
|-----------|--------|
| Before release | Full Tier 1 test suite |
| Weekly | 2 random Tier 1/2 repos |
| After rule changes | Re-test affected languages |
| Monthly | Tier 3 specialized repos |
| Quarterly | Full all-tier regression |

---

## Version History

| Date | Scanner Version | Repos Tested | Notes |
|------|-----------------|--------------|-------|
| 2025-12-04 | ef26ba7 | python-insecure-app | New secret detection rules working |
| 2025-12-04 | ed6c8bf | vuln-node.js-express.js-app | Added SSTI, XSS, weak auth rules |
| 2025-12-02 | 310bd3d | DVWA | Added 35+ PHP rules, 151 findings |
| 2025-12-02 | 67a8c5f | DVWA, crAPI | Initial baseline, 18 findings |

---

## python-insecure-app Results

### Scan: 2025-12-04

**Repository**: https://github.com/trottomv/python-insecure-app
**Score**: 30/100, Grade F, Do Not Ship

### Findings by Severity
| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 1 |
| Medium | 2 |
| Low | 0 |
| Info | 3 |

### Expected vs Detected

| Vulnerability | Expected | Detected | Tool | Notes |
|--------------|----------|----------|------|-------|
| Hardcoded Secrets | Yes | ✅ | Gitleaks + Semgrep | SUPER_SECRET_TOKEN caught |
| SSTI (Jinja2) | Yes | ✅ | Semgrep | main.py:41 |
| SSRF | Yes | ✅ | Semgrep | main.py:31 |
| Insecure Dependencies | Yes | ⚠️ | Trivy | Needs dependency scan |

### Key Detections
1. **Critical**: Generic Secret Assignment in `.env_temp:7` (Gitleaks)
2. **Critical**: Generic Secret Assignment in `app/config.py:15` (Gitleaks) - SUPER_SECRET_TOKEN
3. **High**: Jinja2 SSTI in `app/main.py:41`
4. **Medium**: Hardcoded secret variable assignment `app/config.py:15` (Semgrep)
5. **Medium**: SSRF potential in `app/main.py:31`

### Improvements Made
- Added `generic-secret-assignment` Gitleaks rule - working!
- Added `py-secret-in-variable-name-regex` Semgrep rule - working!
- Score correctly dropped from 85 to 30 after improvements

---

## vuln-node.js-express.js-app Results

### Scan: 2025-12-04

**Repository**: https://github.com/SirAppSec/vuln-node.js-express.js-app

### Gaps Identified & Rules Added
1. **SSTI (nunjucks.renderString)** - Added `nunjucks-ssti-regex` rule
2. **XSS in redirects** - Added `xss-redirect-url-param-concat` rule
3. **Weak password comparison** - Added `weak-password-compare-regex` rule

---

## Juice Shop Results

### Scan: 2025-12-04

**Repository**: https://github.com/juice-shop/juice-shop
**Score**: 0/100, Grade F, Do Not Ship
**Languages**: Bash, JavaScript, Python, Solidity, TypeScript, YAML
**Framework**: Express

### Findings by Severity
| Severity | Count |
|----------|-------|
| Critical | 276 |
| High | 72 |
| Medium | 405 |
| Low | 0 |
| Info | 178 |
| **Total** | **931** |

### Detection Categories

| Category | Found | Examples |
|----------|-------|----------|
| Hardcoded Secrets | ✅ 276+ | Generic secrets in components, config files |
| Weak Crypto (MD5) | ✅ Yes | lib/insecurity.ts:43 |
| RSA Private Keys | ✅ Yes | lib/insecurity.ts:23 |
| Missing Auth on Routes | ✅ Many | PUT/DELETE routes in server.ts |
| Insecure Randomness | ✅ Many | Math.random() usage throughout |
| Curl piped to Bash | ✅ Yes | .github/workflows/ci.yml:326 |
| Security Suppression Comments | ✅ Yes | Multiple eslint-disable |
| AWS Secret Patterns | ✅ Yes | Multiple locations |
| File Upload Issues | ✅ Some | Found 15 references |
| Redirect Patterns | ✅ Some | 931 references to location/redirect |
| JWT/Token Handling | ✅ Some | 12 references |
| Captcha Issues | ✅ Some | routes/captcha.ts |

### OWASP Top 10 Coverage
- ✅ A01:2021 Broken Access Control - Missing auth on routes detected
- ✅ A02:2021 Cryptographic Failures - MD5/weak crypto detected
- ✅ A03:2021 Injection - Some patterns detected
- ⚠️ A04:2021 Insecure Design - Runtime issue, needs DAST
- ✅ A05:2021 Security Misconfiguration - Security suppression comments found
- ✅ A06:2021 Vulnerable Components - Would need Trivy dependency scan
- ⚠️ A07:2021 Auth Failures - Partial (weak password storage found)
- ⚠️ A08:2021 Data Integrity Failures - Partial
- ✅ A09:2021 Security Logging Failures - Debug patterns detected
- ⚠️ A10:2021 SSRF - Limited detection

### Notes
- Excellent coverage of hardcoded secrets (Gitleaks rules working well)
- Strong detection of cryptographic issues
- Many findings in test/spec files (localhost:3000 hardcoded) - could consider excluding
- 931 findings shows comprehensive detection for intentionally vulnerable app

---

*Keep this document updated after every test run. Use findings to continuously improve the scanner.*
