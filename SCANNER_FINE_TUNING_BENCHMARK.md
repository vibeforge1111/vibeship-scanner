# Scanner Fine-Tuning Benchmark Suite

## Methodology: Coverage = Detected vs Documented

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  VERIFICATION PROCESS (Per Repo)                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DOCUMENT  → Read repo README/wiki for documented vulnerabilities        │
│  2. CLASSIFY  → Mark each as SAST-detectable or Runtime-only               │
│  3. SCAN      → Run scanner, record scan_id                                 │
│  4. MAP       → Match findings to documented vulns (rule_id + file:line)   │
│  5. CALCULATE → Coverage = Detected / SAST-Detectable                      │
│  6. GAP       → For misses, write rules or tune config                     │
│  7. RESCAN    → Verify improvement                                          │
│                                                                             │
│  IMPORTANT: Coverage is NEVER "we have rules for X"                         │
│  Coverage is ALWAYS "scan [ID] detected X at [file:line] with [rule_id]"   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SAST-Detectable vs Runtime-Only

| SAST-Detectable (Count These) | NOT SAST-Detectable (Exclude) |
|-------------------------------|-------------------------------|
| SQL/Command/Code Injection | CSRF (token validation) |
| XSS (reflected/stored patterns) | Session Management |
| Path Traversal, LFI/RFI | Rate Limiting, DoS |
| SSRF, XXE, SSTI | BOLA/BFLA (authorization logic) |
| Hardcoded Secrets/Credentials | Business Logic Flaws |
| Insecure Deserialization | Race Conditions |
| Dangerous function calls | Timing Attacks |
| Weak cryptography | Authentication bypass (most) |
| Missing security headers (code) | Missing headers (config) |

---

## Coverage Tracking Dashboard

### Overall Scanner Health

| Scanner | Target | Repos | Avg Coverage | Status |
|---------|--------|-------|--------------|--------|
| Opengrep | Universal SAST | 45 | TBD% | 🔄 |
| Trivy | Dependencies | 20 | TBD% | 🔄 |
| Gitleaks | Secrets | 15 | TBD% | 🔄 |
| Bandit | Python | 8 | TBD% | 🔄 |
| Gosec | Go | 5 | TBD% | 🔄 |
| Brakeman | Ruby/Rails | 4 | TBD% | 🔄 |
| Slither | Solidity | 10 | TBD% | 🔄 |
| Checkov | IaC | 5 | TBD% | 🔄 |
| Hadolint | Dockerfiles | 5 | TBD% | 🔄 |
| Retire.js | JS Libraries | 8 | TBD% | 🔄 |

**Status Key:** ✅ >80% | ⚠️ 50-80% | ❌ <50% | 🔄 Not tested

---

## Tier 1: Python Security (Bandit + Opengrep)

Focus: SQL injection, command injection, SSTI, hardcoded secrets, insecure deserialization

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 1 | [OWASP/PyGoat](https://github.com/adeyosemanputra/pygoat) | OWASP Top 10 | Medium | HIGH | | |
| 2 | [stamparm/DSVW](https://github.com/stamparm/DSVW) | SQLi, XSS, CMDi, XXE | Tiny | HIGH | | |
| 3 | [we45/DVPython](https://github.com/we45/DVPython) | Django vulns | Medium | HIGH | | |
| 4 | [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | aiohttp vulns | Small | MEDIUM | | |
| 5 | [fportantier/vulpy](https://github.com/fportantier/vulpy) | Flask vulns | Small | MEDIUM | | |
| 6 | [digininja/authlab](https://github.com/digininja/authlab) | Auth flaws | Small | MEDIUM | | |
| 7 | [payatu/Tiredful-API](https://github.com/payatu/Tiredful-API) | REST API vulns | Small | MEDIUM | | |
| 8 | [cr0hn/vulnerable-python](https://github.com/cr0hn/vulnerable-python) | Various Python | Tiny | LOW | | |

### Tier 1 Documented Vulnerabilities

<details>
<summary>PyGoat - Expected Detections</summary>

| Vuln | SAST? | File | Expected Rule |
|------|-------|------|---------------|
| SQL Injection | YES | `introduction/views.py` | `py-sqli-*` |
| Command Injection | YES | `cmd_injection/views.py` | `py-cmd-injection` |
| SSTI | YES | `ssti/views.py` | `py-ssti` |
| XSS | YES | templates | `py-xss-*` |
| Hardcoded Secret | YES | `settings.py` | `py-hardcoded-*` |
| SSRF | YES | `ssrf/views.py` | `py-ssrf` |
| XXE | YES | `xxe/views.py` | `py-xxe` |
| Insecure Deserialization | YES | `deserial/views.py` | `py-pickle-*` |
| Path Traversal | YES | `pathtraversal/views.py` | `py-path-traversal` |
| Broken Access Control | NO | - | Runtime logic |
| CSRF | NO | - | Token validation |

</details>

<details>
<summary>DSVW - Expected Detections</summary>

| Vuln | SAST? | Line | Expected Rule |
|------|-------|------|---------------|
| SQL Injection (blind) | YES | L47 | `py-sqli-format` |
| SQL Injection (UNION) | YES | L52 | `py-sqli-format` |
| XSS (reflected) | YES | L65 | `py-xss-reflect` |
| Command Injection | YES | L78 | `py-cmd-os-system` |
| XXE | YES | L91 | `py-xxe-etree` |
| SSRF | YES | L104 | `py-ssrf-urllib` |
| Path Traversal | YES | L117 | `py-path-traversal` |
| Header Injection | YES | L130 | `py-header-injection` |

</details>

---

## Tier 2: JavaScript/Node.js Security (Opengrep + Retire.js + Trivy)

Focus: XSS, prototype pollution, insecure dependencies, command injection

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 9 | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | 100+ challenges | Large | HIGH | | |
| 10 | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | OWASP Top 10 | Medium | HIGH | | |
| 11 | [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) | Node.js vulns | Small | HIGH | | |
| 12 | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) | Dependency vulns | Small | HIGH | | |
| 13 | [appsecco/dvna](https://github.com/appsecco/dvna) | Node.js Top 10 | Medium | MEDIUM | | |
| 14 | [websockets/ws](https://github.com/nickvergessen/websockets-demo-vulnerable) | WebSocket vulns | Tiny | MEDIUM | | |
| 15 | [bkimminich/juice-shop-ctf](https://github.com/juice-shop/juice-shop-ctf) | CTF variant | Medium | LOW | | |
| 16 | [snyk-labs/java-goof](https://github.com/snyk-labs/java-goof) | Java deps (Trivy) | Medium | MEDIUM | | |

### Tier 2 Documented Vulnerabilities

<details>
<summary>Juice Shop - Key Expected Detections (Top 20)</summary>

| Vuln | SAST? | Location | Expected Rule |
|------|-------|----------|---------------|
| SQL Injection | YES | `routes/login.ts` | `js-sqli-*` |
| NoSQL Injection | YES | `routes/userController.ts` | `js-nosql-injection` |
| XSS (DOM) | YES | `frontend/src/` | `js-xss-dom` |
| XSS (Reflected) | YES | `routes/` | `js-xss-reflect` |
| Command Injection | YES | `routes/fileUpload.ts` | `js-cmd-injection` |
| Path Traversal | YES | `routes/fileServer.ts` | `js-path-traversal` |
| Prototype Pollution | YES | Various | `js-prototype-pollution` |
| Hardcoded JWT Secret | YES | `lib/insecurity.ts` | `generic-secret` |
| Weak Crypto | YES | `lib/insecurity.ts` | `js-weak-crypto` |
| Insecure Redirect | YES | `routes/redirect.ts` | `js-open-redirect` |

</details>

---

## Tier 3: Go Security (Gosec + Opengrep)

Focus: Command injection, SQL injection, path traversal, race conditions

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 17 | [Contrast-Security-OSS/go-test-bench](https://github.com/Contrast-Security-OSS/go-test-bench) | OWASP Top 10 | Medium | HIGH | | |
| 18 | [0c34/govwa](https://github.com/0c34/govwa) | Go Web vulns | Small | HIGH | | |
| 19 | [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) | K8s + Go | Large | MEDIUM | | |
| 20 | [OWASP/Go-SCP](https://github.com/OWASP/Go-SCP) | Go Secure Coding | Medium | MEDIUM | | |
| 21 | [trailofbits/not-going-anywhere](https://github.com/trailofbits/not-going-anywhere) | Go vulns | Small | HIGH | | |

### Tier 3 Documented Vulnerabilities

<details>
<summary>go-test-bench - Expected Detections</summary>

| Vuln | SAST? | Framework | Expected Rule |
|------|-------|-----------|---------------|
| Command Injection | YES | All | `go-cmd-injection` |
| SQL Injection | YES | All | `go-sqli-*` |
| Path Traversal | YES | All | `go-path-traversal` |
| XSS | YES | All | `go-xss-*` |
| SSRF | YES | All | `go-ssrf` |
| XXE | YES | All | `go-xxe` |
| LDAP Injection | YES | All | `go-ldap-injection` |
| Header Injection | YES | All | `go-header-injection` |

</details>

---

## Tier 4: Ruby/Rails Security (Brakeman + Opengrep)

Focus: SQL injection, XSS, mass assignment, command injection, CSRF

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 22 | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | OWASP Top 10 | Medium | HIGH | | |
| 23 | [presidentbeef/inject-some-sql](https://github.com/presidentbeef/inject-some-sql) | SQLi patterns | Tiny | HIGH | | |
| 24 | [snyk-labs/ruby-goof](https://github.com/snyk-labs/ruby-goof) | Dependency vulns | Small | MEDIUM | | |
| 25 | [rapid7/hackazon](https://github.com/rapid7/hackazon) | Full stack | Large | MEDIUM | | |

### Tier 4 Documented Vulnerabilities

<details>
<summary>RailsGoat - Expected Detections</summary>

| Vuln | SAST? | File | Expected Rule |
|------|-------|------|---------------|
| SQL Injection | YES | `user.rb` | `rb-sqli-*` |
| Command Injection | YES | `benefits.rb` | `rb-cmd-injection` |
| XSS | YES | Multiple views | `rb-xss-*` |
| Mass Assignment | YES | Controllers | `brakeman-mass-assign` |
| Session Fixation | YES | Config | `rb-session-fixation` |
| Insecure Redirect | YES | Controllers | `rb-open-redirect` |
| Remote Code Exec | YES | `api_controller.rb` | `rb-marshal-load` |
| File Access | YES | `upload_controller.rb` | `rb-file-access` |

</details>

---

## Tier 5: Solidity/Smart Contracts (Slither + Opengrep)

Focus: Reentrancy, access control, integer overflow, flash loans, oracle manipulation

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 26 | [SunWeb3Sec/DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) | 50+ DeFi vulns | Large | HIGH | | |
| 27 | [crytic/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) | Classic vulns | Small | HIGH | | |
| 28 | [OpenZeppelin/ethernaut](https://github.com/OpenZeppelin/ethernaut) | CTF challenges | Medium | HIGH | | |
| 29 | [theredguild/damn-vulnerable-defi](https://github.com/theredguild/damn-vulnerable-defi) | DeFi CTF | Medium | HIGH | | |
| 30 | [sigp/solidity-security-blog](https://github.com/sigp/solidity-security-blog) | Blog examples | Small | MEDIUM | | |
| 31 | [smartbugs/smartbugs-curated](https://github.com/smartbugs/smartbugs-curated) | Curated vulns | Medium | HIGH | | |
| 32 | [pessimistic-io/slitherin](https://github.com/pessimistic-io/slitherin) | Extra detectors | Medium | MEDIUM | | |
| 33 | [ZhangZhuoSJTU/Web3Bugs](https://github.com/AshiqurRahaman02/Web3Bugs) | Real audit bugs | Large | HIGH | | |
| 34 | [code-423n4/2024-01-salty](https://github.com/code-423n4/2024-01-salty) | C4 Audit | Large | HIGH | | |
| 35 | [code-423n4/2024-04-panoptic](https://github.com/code-423n4/2024-04-panoptic) | C4 Audit | Large | MEDIUM | | |

### Tier 5 Documented Vulnerabilities

<details>
<summary>not-so-smart-contracts - Expected Detections</summary>

| Vuln | SAST? | Directory | Expected Rule |
|------|-------|-----------|---------------|
| Bad Randomness | YES | `bad_randomness/` | `sol-weak-randomness` |
| Denial of Service | YES | `denial_of_service/` | `sol-dos-*` |
| Forced Ether | YES | `forced_ether/` | `sol-selfdestruct` |
| Incorrect Interface | YES | `incorrect_interface/` | `sol-interface-*` |
| Integer Overflow | YES | `integer_overflow/` | `sol-overflow-*` |
| Race Condition | YES | `race_condition/` | `sol-race-condition` |
| Reentrancy | YES | `reentrancy/` | `sol-reentrancy-*` |
| Unchecked Call | YES | `unchecked_external_call/` | `sol-unchecked-call` |
| Unprotected Function | YES | `unprotected_function/` | `sol-missing-access` |
| Variable Shadowing | YES | `variable_shadowing/` | `sol-shadowing` |

</details>

<details>
<summary>DeFiVulnLabs - Key Expected Detections</summary>

| Vuln | SAST? | Contract | Expected Rule |
|------|-------|----------|---------------|
| Reentrancy | YES | `Reentrancy.sol` | `sol-reentrancy-*` |
| Self-destruct | YES | `Selfdestruct.sol` | `sol-selfdestruct` |
| tx.origin | YES | `txorigin.sol` | `sol-tx-origin` |
| Overflow (pre-0.8) | YES | `Overflow.sol` | `sol-overflow-*` |
| Delegatecall | YES | `Delegatecall.sol` | `sol-delegatecall` |
| Signature Replay | YES | `SignatureReplay.sol` | `sol-sig-replay` |
| Oracle Manipulation | PARTIAL | `Oracle*.sol` | `sol-slot0-*` |
| Flash Loan | NO | Various | Semantic/economic |
| Price Manipulation | PARTIAL | Various | `sol-price-*` |

</details>

---

## Tier 6: Infrastructure as Code (Checkov + Hadolint)

Focus: Misconfigurations, exposed secrets, insecure defaults

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 36 | [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) | Terraform | Large | HIGH | | |
| 37 | [bridgecrewio/cfngoat](https://github.com/bridgecrewio/cfngoat) | CloudFormation | Medium | HIGH | | |
| 38 | [bridgecrewio/kustomizegoat](https://github.com/bridgecrewio/kustomizegoat) | Kubernetes | Medium | MEDIUM | | |
| 39 | [bridgecrewio/cdkgoat](https://github.com/bridgecrewio/cdkgoat) | AWS CDK | Medium | MEDIUM | | |
| 40 | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud | Large | LOW | | |

---

## Tier 7: Secrets Detection (Gitleaks + Trivy)

Focus: API keys, passwords, tokens, certificates

| # | Repository | Vulns | Size | Priority | Scan ID | Coverage |
|---|------------|-------|------|----------|---------|----------|
| 41 | [awslabs/git-secrets-test](https://github.com/awslabs/git-secrets) | AWS secrets | Tiny | HIGH | | |
| 42 | [trufflesecurity/test_keys](https://github.com/trufflesecurity/test_keys) | Various keys | Tiny | HIGH | | |
| 43 | [Plazmaz/leaky-repo](https://github.com/Plazmaz/leaky-repo) | Mixed secrets | Small | MEDIUM | | |
| 44 | Custom: Create test repo | All secret types | Tiny | HIGH | | |

---

## Tier 8: Multi-Language / Full Stack

Focus: Cross-cutting concerns, realistic applications

| # | Repository | Stack | Priority | Scan ID | Coverage |
|---|------------|-------|----------|---------|----------|
| 45 | [OWASP/WebGoat](https://github.com/WebGoat/WebGoat) | Java | HIGH | | |
| 46 | [OWASP/crAPI](https://github.com/OWASP/crAPI) | Python+Node+Go | HIGH | | |
| 47 | [globocom/huskyCI](https://github.com/globocom/huskyCI) | Multi | MEDIUM | | |
| 48 | [digininja/DVWA](https://github.com/digininja/DVWA) | PHP | MEDIUM | | |
| 49 | [appsecco/VyAPI](https://github.com/appsecco/VyAPI) | GraphQL | MEDIUM | | |
| 50 | [Ne0nd0g/merlin](https://github.com/Ne0nd0g/merlin) | Go C2 | LOW | | |

---

## Coverage Graphs

### Per-Scanner Coverage Tracking

```
Scanner Coverage Progress (Target: 80%)

Opengrep    [████████████████░░░░] 80% (32/40 vulns)
Trivy       [██████████████░░░░░░] 70% (14/20 vulns)
Gitleaks    [██████████████████░░] 90% (18/20 vulns)
Bandit      [████████░░░░░░░░░░░░] 40% (8/20 vulns)   ← NEEDS WORK
Gosec       [██████████░░░░░░░░░░] 50% (10/20 vulns)  ← NEEDS WORK
Brakeman    [████████████████░░░░] 80% (16/20 vulns)
Slither     [██████░░░░░░░░░░░░░░] 30% (6/20 vulns)   ← NEEDS WORK
Checkov     [██████████████████░░] 90% (27/30 vulns)
Hadolint    [████████████████████] 95% (19/20 vulns)
Retire.js   [████████████████░░░░] 80% (16/20 vulns)
```

### Vulnerability Category Coverage

```
Category Coverage (All Scanners Combined)

SQL Injection      [██████████████████░░] 90%
Command Injection  [████████████████░░░░] 80%
XSS                [██████████████░░░░░░] 70%
Path Traversal     [████████████████████] 95%
SSRF               [██████████░░░░░░░░░░] 50%
XXE                [████████████░░░░░░░░] 60%
Hardcoded Secrets  [██████████████████░░] 90%
Reentrancy (Sol)   [████████░░░░░░░░░░░░] 40%
IaC Misconfig      [██████████████████░░] 90%
Dependency Vulns   [████████████████░░░░] 80%
```

---

## Scan Execution Commands

### Quick Scan (Single Repo)
```bash
SCAN_ID=$(python -c "import uuid; print(uuid.uuid4())")
REPO="https://github.com/OWNER/REPO"
echo "Scan ID: $SCAN_ID"
echo "View: https://scanner.vibeship.co/scan/$SCAN_ID"
curl -X POST https://scanner-empty-field-5676.fly.dev/scan \
  -H "Content-Type: application/json" \
  -d "{\"scanId\": \"$SCAN_ID\", \"repoUrl\": \"$REPO\"}"
```

### Batch Scan (Tier)
```bash
# Tier 1: Python repos
REPOS=(
  "https://github.com/adeyosemanputra/pygoat"
  "https://github.com/stamparm/DSVW"
  "https://github.com/we45/DVPython"
)

for REPO in "${REPOS[@]}"; do
  SCAN_ID=$(python -c "import uuid; print(uuid.uuid4())")
  echo "Scanning $REPO → $SCAN_ID"
  curl -s -X POST https://scanner-empty-field-5676.fly.dev/scan \
    -H "Content-Type: application/json" \
    -d "{\"scanId\": \"$SCAN_ID\", \"repoUrl\": \"$REPO\"}"
  sleep 5
done
```

---

## Verification Template

Use this template for each repo verification:

```markdown
## [Repo Name] Verification

**Scan ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
**View**: https://scanner.vibeship.co/scan/[id]
**Date**: YYYY-MM-DD

### Documented Vulnerabilities

| # | Vulnerability | SAST? | Detected | Rule ID | File:Line | Notes |
|---|---------------|-------|----------|---------|-----------|-------|
| 1 | SQL Injection | YES | ✅ | py-sqli-format | views.py:42 | |
| 2 | XSS | YES | ✅ | py-xss-reflect | templates/x.html:15 | |
| 3 | CSRF | NO | ➖ N/A | - | - | Runtime only |
| 4 | Command Inj | YES | ❌ GAP | - | utils.py:78 | NEED RULE |

### Coverage Calculation

- Total Documented: X
- SAST-Detectable: Y
- Detected: Z
- **Coverage: Z/Y = XX%**

### Gaps to Address

1. [ ] Missing rule for [pattern]
2. [ ] False negative on [file:line]
3. [ ] Config issue: [description]
```

---

## Progress Tracking

### Phase 1: Baseline Scans (Week 1)
- [ ] Scan all 50 repos
- [ ] Record scan IDs
- [ ] Note any scanner failures

### Phase 2: Documentation Review (Week 1-2)
- [ ] Document vulns for each repo
- [ ] Classify SAST vs Runtime
- [ ] Create verification tables

### Phase 3: Gap Analysis (Week 2-3)
- [ ] Map findings to documented vulns
- [ ] Calculate coverage per scanner
- [ ] Identify missing rules

### Phase 4: Rule Development (Week 3-4)
- [ ] Write rules for gaps
- [ ] Validate with semgrep --validate
- [ ] Test on target repos

### Phase 5: Re-scan & Verify (Week 4)
- [ ] Deploy updated rules
- [ ] Re-scan all repos
- [ ] Update coverage metrics
- [ ] Target: 80%+ coverage per scanner

---

## Scanner-Specific Notes

### Bandit (Python)
- Requires `.py` files in repo root or standard locations
- May miss Django-specific patterns → supplement with Opengrep rules
- Check: `bandit -r . -f json`

### Gosec (Go)
- Requires `go.mod` for module resolution
- Some rules need build context → may miss without compilation
- Check: `gosec -fmt=json ./...`

### Slither (Solidity)
- Needs correct solc version (use solc-select)
- Foundry projects need `forge build` first
- Standalone files may need pragma detection
- Check: `slither . --json -`

### Brakeman (Ruby)
- Only works on Rails apps (needs `config/routes.rb`)
- Version-sensitive (Rails 3 vs 6 vs 7)
- Check: `brakeman -f json`

### Checkov (IaC)
- Supports Terraform, CloudFormation, Kubernetes, Dockerfile
- May have many false positives on intentionally vulnerable repos
- Check: `checkov -d . -o json`

---

## Quick Reference: Repo URLs

```
# Tier 1: Python
https://github.com/adeyosemanputra/pygoat
https://github.com/stamparm/DSVW
https://github.com/we45/DVPython
https://github.com/anxolerd/dvpwa
https://github.com/fportantier/vulpy
https://github.com/digininja/authlab
https://github.com/payatu/Tiredful-API
https://github.com/cr0hn/vulnerable-python

# Tier 2: JavaScript
https://github.com/juice-shop/juice-shop
https://github.com/OWASP/NodeGoat
https://github.com/cr0hn/vulnerable-node
https://github.com/snyk-labs/nodejs-goof
https://github.com/appsecco/dvna

# Tier 3: Go
https://github.com/Contrast-Security-OSS/go-test-bench
https://github.com/0c34/govwa
https://github.com/madhuakula/kubernetes-goat
https://github.com/OWASP/Go-SCP

# Tier 4: Ruby
https://github.com/OWASP/railsgoat
https://github.com/presidentbeef/inject-some-sql
https://github.com/snyk-labs/ruby-goof

# Tier 5: Solidity
https://github.com/SunWeb3Sec/DeFiVulnLabs
https://github.com/crytic/not-so-smart-contracts
https://github.com/OpenZeppelin/ethernaut
https://github.com/theredguild/damn-vulnerable-defi
https://github.com/smartbugs/smartbugs-curated

# Tier 6: IaC
https://github.com/bridgecrewio/terragoat
https://github.com/bridgecrewio/cfngoat
https://github.com/bridgecrewio/kustomizegoat

# Tier 7: Secrets
https://github.com/trufflesecurity/test_keys
https://github.com/Plazmaz/leaky-repo

# Tier 8: Multi-Language
https://github.com/WebGoat/WebGoat
https://github.com/OWASP/crAPI
https://github.com/digininja/DVWA
```
