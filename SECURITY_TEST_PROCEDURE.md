# Vibeship Scanner - Security Test Procedure

This document outlines the testing procedure for validating Vibeship Scanner against intentionally vulnerable applications.

## Purpose

Ensure the scanner accurately detects known vulnerabilities in well-documented vulnerable applications. This helps:
- Validate scanner detection capabilities
- Identify gaps in rule coverage
- Benchmark scanner performance
- Document expected vs actual findings

## Test Applications

### Tier 1: Primary Test Repos (Must Pass)

| Repository | Language | Expected Vulnerabilities | Min Findings |
|------------|----------|-------------------------|--------------|
| [DVWA](https://github.com/digininja/DVWA) | PHP | SQLi, XSS, Command Injection, File Inclusion, CSRF | 15+ |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | JavaScript/Node | SQLi, XSS, Auth bypass, Sensitive data exposure | 20+ |
| [OWASP crAPI](https://github.com/OWASP/crAPI) | Python/JS | BOLA, Auth issues, Mass assignment, SSRF | 50+ |
| [NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript | SQLi, XSS, CSRF, Insecure dependencies | 15+ |
| [WebGoat](https://github.com/WebGoat/WebGoat) | Java | SQLi, XSS, XXE, Deserialization | 20+ |

### Tier 2: Secondary Test Repos

| Repository | Language | Expected Vulnerabilities |
|------------|----------|-------------------------|
| [Damn Vulnerable NodeJS App](https://github.com/appsecco/dvna) | JavaScript | Command injection, eval, XSS |
| [RailsGoat](https://github.com/OWASP/railsgoat) | Ruby | Mass assignment, SQLi, XSS |
| [Django.nV](https://github.com/nVisium/django.nV) | Python | SQLi, XSS, CSRF, Debug mode |
| [Vulnerable Flask App](https://github.com/we45/Vulnerable-Flask-App) | Python | SQLi, SSTI, Command injection |
| [DSVW](https://github.com/stamparm/DSVW) | Python | SQLi, XSS, XXE, SSRF |

## Test Procedure

### 1. Pre-Test Setup
```bash
# Ensure scanner is deployed and running
fly status -a scanner-empty-field-5676

# Verify Semgrep rules are valid
fly ssh console -a scanner-empty-field-5676 -C "semgrep --validate --config /scanner/rules/"
```

### 2. Run Test Suite
For each test repository:

1. **Submit scan** via UI or API
2. **Record results**:
   - Total findings count
   - Findings by severity (critical/high/medium/low)
   - Findings by category (code/secrets/dependencies)
   - Scan duration
3. **Compare against expected**:
   - Check minimum finding threshold
   - Verify key vulnerability types detected

### 3. Test Execution Template

```
Repository: [name]
URL: [github url]
Date: [YYYY-MM-DD]
Scanner Version: [commit hash]

Results:
- Score: [X]/100
- Grade: [A-F]
- Total Findings: [N]
  - Critical: [N]
  - High: [N]
  - Medium: [N]
  - Low: [N]
  - Info: [N]

Expected Vulnerabilities Found:
- [ ] SQL Injection
- [ ] XSS (Reflected/Stored/DOM)
- [ ] Command Injection
- [ ] File Inclusion (LFI/RFI)
- [ ] Hardcoded Secrets
- [ ] Insecure Dependencies
- [ ] CSRF
- [ ] Authentication Issues

Missing Expected Findings:
- [List any expected vulns not detected]

Notes:
- [Any observations]
```

### 4. Pass/Fail Criteria

**PASS** if:
- Tier 1 repos meet minimum finding thresholds
- All critical vulnerability categories detected
- No false negatives on documented vulnerabilities
- Scan completes within 5 minutes

**FAIL** if:
- Fewer than 50% of expected findings
- Critical vulnerabilities missed
- Scanner errors or timeouts

## DVWA Expected Findings

DVWA contains these intentional vulnerability modules:

| Module | Vulnerability Type | Should Detect |
|--------|-------------------|---------------|
| Brute Force | Weak authentication | Partial |
| Command Injection | OS command injection | Yes |
| CSRF | Cross-site request forgery | Partial |
| File Inclusion | LFI/RFI | Yes |
| File Upload | Unrestricted file upload | Yes |
| Insecure CAPTCHA | Weak CAPTCHA | Partial |
| SQL Injection | SQL injection | Yes |
| SQL Injection (Blind) | Blind SQLi | Yes |
| Weak Session IDs | Session management | Partial |
| XSS (DOM) | DOM-based XSS | Partial |
| XSS (Reflected) | Reflected XSS | Yes |
| XSS (Stored) | Stored XSS | Yes |
| CSP Bypass | CSP issues | No (runtime) |
| JavaScript | Client-side issues | Partial |

**Note**: Some vulnerabilities require runtime analysis (DAST) and won't be detected by static analysis (SAST) alone.

## Test Schedule

- **Before release**: Run full Tier 1 test suite
- **Weekly**: Spot check 2 random Tier 1 repos
- **After rule changes**: Run full test suite
- **Monthly**: Run Tier 2 repos

## Reporting

After each test run, update:
1. This document with latest results
2. GitHub issue if new gaps found
3. Rule files if improvements needed

## Version History

| Date | Scanner Version | Tester | Notes |
|------|-----------------|--------|-------|
| 2025-12-02 | Initial | - | Document created |
