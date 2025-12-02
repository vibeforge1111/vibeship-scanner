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
| 1 | [digininja/DVWA](https://github.com/digininja/DVWA) | PHP | ✅ Done | 18 high | Baseline test |
| 2 | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | JS/Node | ⏳ Pending | - | Large, comprehensive |
| 3 | [OWASP/crAPI](https://github.com/OWASP/crAPI) | Python/JS | ✅ Done | 137 | API security focused |
| 4 | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript | ⏳ Pending | - | OWASP Top 10 for Node |
| 5 | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | Java | ⏳ Pending | - | Java vulnerabilities |
| 6 | [appsecco/dvna](https://github.com/appsecco/dvna) | JavaScript | ⏳ Pending | - | Node.js focused |

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
| 2025-12-02 | b3ac8e2 | DVWA | Added 60+ PHP rules targeting DVWA patterns |
| 2025-12-02 | 310bd3d | DVWA | Added 35+ PHP rules, 151 findings |
| 2025-12-02 | 67a8c5f | DVWA, crAPI | Initial baseline, 18 findings |

---

*Keep this document updated after every test run. Use findings to continuously improve the scanner.*
