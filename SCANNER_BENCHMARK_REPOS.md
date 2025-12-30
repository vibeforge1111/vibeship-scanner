# Vibeship Scanner Benchmark Repository Guide

This document maps our 10 scanners to intentionally vulnerable repositories for coverage testing.

---

## Scanner-to-Benchmark Matrix

| Scanner | Type | Target | Benchmark Repos |
|---------|------|--------|-----------------|
| **Opengrep** | Universal | All languages | All repos below |
| **Trivy** | Universal | Dependencies, Secrets | All repos with package files |
| **Gitleaks** | Universal | Secrets | All repos |
| **Bandit** | Stack | Python | PyGoat, DSVW |
| **Gosec** | Stack | Go | go-test-bench, GoVWA |
| **Hadolint** | Stack | Dockerfiles | TerraGoat, CfnGoat |
| **Checkov** | Stack | IaC (Terraform, K8s, CFN) | TerraGoat, CfnGoat |
| **Brakeman** | Stack | Ruby on Rails | RailsGoat |
| **Slither** | Stack | Solidity | Damn Vulnerable DeFi, Ethernaut |
| **Retire.js** | Stack | JavaScript deps | Juice Shop, NodeGoat |

---

## Benchmark Repositories by Scanner

### 1. Bandit (Python SAST)

#### PyGoat - OWASP Python/Django
- **URL**: https://github.com/adeyosemanputra/pygoat
- **Framework**: Django
- **Documented Vulns**: OWASP Top 10 (2017 + 2021)
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Command Injection
  - SSTI (Server-Side Template Injection)
  - Cryptographic Failures
  - SSRF
  - Broken Access Control
- **Why Good**: Official OWASP project, clear lab-based structure

#### DSVW (Damn Small Vulnerable Web)
- **URL**: https://github.com/stamparm/DSVW
- **Framework**: Pure Python (single file!)
- **Documented Vulns**:
  - SQL Injection (blind, error-based, UNION)
  - XSS (reflected, stored)
  - Command Injection
  - XXE
  - SSRF
  - Path Traversal
- **Why Good**: Minimal, focused, each vuln is clearly labeled

---

### 2. Gosec (Go Security)

#### go-test-bench
- **URL**: https://github.com/Contrast-Security-OSS/go-test-bench
- **Framework**: Multiple (net/http, Gin, Echo, Chi)
- **Documented Vulns**: OWASP Top 10
  - Command Injection
  - SQL Injection
  - Path Traversal
  - XSS
  - SSRF
- **Why Good**: Industry-standard, multiple framework implementations

#### GoVWA (Go Vulnerable Web Application)
- **URL**: https://github.com/0c34/govwa
- **Framework**: Native Go
- **Documented Vulns**:
  - SQL Injection
  - IDOR (Insecure Direct Object Reference)
  - Command Injection
  - Session Management flaws
- **Why Good**: Pentester-focused, clear vulnerability documentation

---

### 3. Hadolint (Dockerfile Linting)

#### TerraGoat
- **URL**: https://github.com/bridgecrewio/terragoat
- **Contains**: Dockerfiles with misconfigurations
- **Documented Issues**:
  - Running as root
  - Missing health checks
  - Insecure base images
  - ADD instead of COPY
- **Why Good**: Official Bridgecrew training project

---

### 4. Checkov (IaC Security)

#### TerraGoat (Terraform)
- **URL**: https://github.com/bridgecrewio/terragoat
- **Platform**: AWS, Azure, GCP
- **Documented Misconfigs**:
  - S3 buckets without encryption
  - Security groups with 0.0.0.0/0
  - IAM policies with wildcards
  - Unencrypted RDS instances
  - Public EC2 instances
  - Missing logging/monitoring
- **Why Good**: 200+ intentional misconfigurations

#### CfnGoat (CloudFormation)
- **URL**: https://github.com/bridgecrewio/cfngoat
- **Platform**: AWS
- **Documented Misconfigs**:
  - Unencrypted EBS volumes
  - Open security groups
  - S3 public access
  - Missing VPC flow logs
- **Why Good**: Complements TerraGoat for CFN coverage

---

### 5. Brakeman (Ruby on Rails)

#### RailsGoat
- **URL**: https://github.com/OWASP/railsgoat
- **Framework**: Rails 3-6
- **Documented Vulns** (with Capybara specs!):
  - SQL Injection
  - Command Injection
  - XSS (multiple types)
  - Mass Assignment
  - Insecure Direct Object Reference
  - Session Fixation
  - Remote Code Execution (Marshal.load)
  - CSRF vulnerabilities
- **Why Good**: Official OWASP, has failing security specs

---

### 6. Slither (Solidity Smart Contracts)

#### Damn Vulnerable DeFi
- **URL**: https://github.com/theredguild/damn-vulnerable-defi
- **Website**: https://www.damnvulnerabledefi.xyz/
- **Documented Vulns**:
  - Reentrancy
  - Flash Loan attacks
  - Price Oracle manipulation
  - Access Control flaws
  - Governance attacks
  - Upgradeable proxy vulnerabilities
  - Integer overflow/underflow
- **Why Good**: Most comprehensive DeFi vulnerability set

#### Ethernaut (OpenZeppelin)
- **URL**: https://github.com/OpenZeppelin/ethernaut
- **Website**: https://ethernaut.openzeppelin.com/
- **Documented Vulns**:
  - Fallback function abuse
  - Delegatecall vulnerabilities
  - tx.origin phishing
  - Denial of Service
  - Re-entrancy
  - Self-destruct abuse
- **Why Good**: Classic CTF, foundational vulnerabilities

#### Not So Smart Contracts
- **URL**: https://github.com/crytic/not-so-smart-contracts
- **By**: Trail of Bits (Slither creators)
- **Documented Vulns**:
  - Bad randomness
  - Denial of service
  - Forced ether reception
  - Incorrect interface
  - Integer overflow
  - Race condition
  - Reentrancy
  - Unchecked external call
  - Unprotected function
  - Variable shadowing
- **Why Good**: Created by Slither team, perfect test cases

---

### 7. Retire.js + Trivy (JavaScript Dependencies)

#### Juice Shop
- **URL**: https://github.com/juice-shop/juice-shop
- **Framework**: Node.js, Angular
- **Documented Vulns**: 100+ challenges
  - Known vulnerable dependencies
  - Injection attacks
  - Broken authentication
  - XSS variants
- **Why Good**: Most comprehensive web app vuln project

#### NodeGoat
- **URL**: https://github.com/OWASP/NodeGoat
- **Framework**: Node.js, Express
- **Documented Vulns**: OWASP Top 10
  - Injection
  - Broken Auth
  - XSS
  - Insecure Dependencies
- **Why Good**: Official OWASP, Node.js focused

---

## Testing Methodology

### Phase 1: Baseline Scans
For each benchmark repo:
```bash
SCAN_ID=$(python -c "import uuid; print(uuid.uuid4())")
echo "Scanning [REPO_NAME]: $SCAN_ID"
curl -X POST https://scanner-empty-field-5676.fly.dev/scan \
  -H "Content-Type: application/json" \
  -d "{\"scanId\": \"$SCAN_ID\", \"repoUrl\": \"[REPO_URL]\"}"
```

### Phase 2: Gap Analysis
1. Get documented vulnerabilities from repo's README/wiki
2. Compare against scan findings
3. Calculate: `Coverage = Detected / SAST-Detectable`

### Phase 3: Rule Development
For each gap:
1. Identify the vulnerable code pattern
2. Write Opengrep rule targeting that pattern
3. Add to `scanner/rules/[language].yaml`
4. Validate: `semgrep --validate --config scanner/rules/`

### Phase 4: Re-scan & Verify
1. Deploy updated rules
2. Re-scan the benchmark repo
3. Confirm new detection
4. Document in coverage matrix

---

## Scan Results Summary (2024-12-30)

### Completed Benchmark Scans

| Repo | Scan ID | Total | Key Scanner Results |
|------|---------|-------|---------------------|
| **PyGoat** | [`078f279f`](https://scanner.vibeship.co/scan/078f279f-406c-4146-ac5e-f1364b778ecb) | 969 | Opengrep: 998, Trivy: 100, Gitleaks: 92, Checkov: 9 |
| **go-test-bench** | [`b1f8777a`](https://scanner.vibeship.co/scan/b1f8777a-a475-4cbb-88dd-c0fbc9cd96ba) | 190 | Opengrep: 175, Trivy: 23, Hadolint: 8, Checkov: 11 |
| **TerraGoat** | [`3a5c326c`](https://scanner.vibeship.co/scan/3a5c326c-f209-4627-a8d1-6bed9645419c) | 103 | **Checkov: 305**, Gitleaks: 9, Trivy: 2 |
| **RailsGoat** | [`e3c43296`](https://scanner.vibeship.co/scan/e3c43296-4e70-40c8-800a-5050e81298d7) | 368 | Opengrep: 906, **Brakeman: 18**, Gitleaks: 27, Hadolint: 14 |
| **DamnVulnDeFi** | [`c3b062a9`](https://scanner.vibeship.co/scan/c3b062a9-058d-456a-bbbb-97fd717c6777) | 1166 | Opengrep: 1709, Trivy: 81, Checkov: 73, Gitleaks: 64, Bandit: 6 |

### Scanner Performance Analysis

| Scanner | Expected Repo | Findings | Status |
|---------|---------------|----------|--------|
| **Checkov** | TerraGoat | 305 | WORKING - Excellent IaC detection |
| **Brakeman** | RailsGoat | 18 | WORKING - Rails vulns detected |
| **Hadolint** | Multiple | 8-17 per repo | WORKING - Dockerfile issues found |
| **Gitleaks** | All repos | 9-92 per repo | WORKING - Secrets detected |
| **Trivy** | All repos | 2-100 per repo | WORKING - Dependencies scanned |
| **Bandit** | PyGoat | 0 | NEEDS INVESTIGATION |
| **Gosec** | go-test-bench | 0 | NEEDS INVESTIGATION |
| **Slither** | DamnVulnDeFi | 0 | NEEDS INVESTIGATION |

### Issues to Investigate

1. **Bandit (Python)**: Found 0 on PyGoat despite being a Python Django app
   - PyGoat has documented SQL injection, command injection, SSTI
   - Bandit should detect these patterns

2. **Gosec (Go)**: Found 0 on go-test-bench despite being a Go vuln app
   - go-test-bench has command injection, SQL injection, path traversal
   - Gosec should detect unsafe function usage

3. **Slither (Solidity)**: Found 0 on Damn Vulnerable DeFi
   - DeFi project has reentrancy, flash loan attacks, access control issues
   - Slither exit code was 1 (error) - may need Foundry/Forge setup

---

## Scan Tracking Table

| Repo | Scanner Focus | Scan ID | Status | Coverage |
|------|---------------|---------|--------|----------|
| PyGoat | Bandit, Opengrep | `078f279f-406c-4146-ac5e-f1364b778ecb` | Complete | TBD |
| DSVW | Bandit, Opengrep | | Pending | |
| go-test-bench | Gosec, Opengrep | `b1f8777a-a475-4cbb-88dd-c0fbc9cd96ba` | Complete | TBD |
| GoVWA | Gosec, Opengrep | | Pending | |
| TerraGoat | Checkov, Hadolint | `3a5c326c-f209-4627-a8d1-6bed9645419c` | Complete | TBD |
| CfnGoat | Checkov | | Pending | |
| RailsGoat | Brakeman, Opengrep | `e3c43296-4e70-40c8-800a-5050e81298d7` | Complete | TBD |
| Damn Vulnerable DeFi | Slither, Opengrep | `c3b062a9-058d-456a-bbbb-97fd717c6777` | Complete | TBD |
| Ethernaut | Slither, Opengrep | | Pending | |
| Not So Smart Contracts | Slither, Opengrep | | Pending | |
| Juice Shop | Retire.js, Trivy | | Pending | |
| NodeGoat | Retire.js, Trivy | | Pending | |

---

## Priority Order

Based on scanner newness and testing needs:

### High Priority (New Scanners, Need Validation)
1. **PyGoat** - Test Bandit Python detection
2. **go-test-bench** - Test Gosec Go detection
3. **TerraGoat** - Test Checkov IaC + Hadolint Docker
4. **RailsGoat** - Test Brakeman Rails detection
5. **Damn Vulnerable DeFi** - Test Slither Solidity detection

### Medium Priority (Existing Scanners, Coverage Improvement)
6. **DSVW** - Improve Python SAST rules
7. **GoVWA** - Additional Go coverage
8. **CfnGoat** - CloudFormation coverage
9. **Ethernaut** - Classic Solidity vulns
10. **Not So Smart Contracts** - Trail of Bits test cases

### Lower Priority (Well-Tested Already)
11. **Juice Shop** - JavaScript/Node coverage
12. **NodeGoat** - Additional Node.js coverage

---

## Sources

### Python
- [PyGoat - OWASP](https://owasp.org/www-project-pygoat/)
- [Bandit SAST Guide](https://dev.to/angelvargasgutierrez/bandit-python-static-application-security-testing-guide-47l0)

### Go
- [go-test-bench](https://github.com/Contrast-Security-OSS/go-test-bench)
- [GoVWA](https://github.com/0c34/govwa)
- [Gosec](https://github.com/securego/gosec)

### IaC
- [TerraGoat](https://github.com/bridgecrewio/terragoat)
- [CfnGoat](https://github.com/bridgecrewio/cfngoat)
- [Checkov](https://github.com/bridgecrewio/checkov)

### Ruby
- [RailsGoat](https://github.com/OWASP/railsgoat)
- [Brakeman](https://brakemanscanner.org/)

### Solidity
- [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi)
- [Ethernaut](https://github.com/OpenZeppelin/ethernaut)
- [Not So Smart Contracts](https://github.com/crytic/not-so-smart-contracts)
- [Slither](https://github.com/crytic/slither)

### JavaScript
- [Juice Shop](https://github.com/juice-shop/juice-shop)
- [NodeGoat](https://github.com/OWASP/NodeGoat)
