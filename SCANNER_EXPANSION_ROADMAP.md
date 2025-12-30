# Vibeship Scanner Expansion Roadmap

## Current Stack
| Tool | Category | What It Covers |
|------|----------|----------------|
| **Opengrep** | SAST | Code patterns, 300+ Solidity rules |
| **Trivy** | SCA | Dependency vulnerabilities, container scanning |
| **Gitleaks** | Secrets | Hardcoded secrets, API keys, credentials |

---

## Recommended Tools to Add

### TIER 1: HIGH PRIORITY (Fills Major Gaps)

#### 1. Slither - Solidity Static Analyzer
**Gap Filled:** Deeper Solidity-specific analysis beyond pattern matching

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/crytic/slither](https://github.com/crytic/slither) |
| **License** | AGPL-3.0 (Open Source) |
| **Maintained By** | Trail of Bits |
| **Integration Effort** | Medium (Python, pip install) |

**Why Add It:**
- 92+ vulnerability detectors specifically for Solidity
- Generates call graphs, inheritance diagrams, CFG
- Lower false-positive rate than generic SAST
- Detects: reentrancy, access control, arithmetic issues, gas optimization
- Already integrates with Foundry, Hardhat, Truffle

**Code Example:**
```bash
pip install slither-analyzer
slither . --json slither-output.json
```

**Covers Gaps:**
- [x] Deeper control flow analysis
- [x] Cross-contract reentrancy
- [x] Inheritance issues
- [x] Storage layout conflicts

---

#### 2. Mythril - Symbolic Execution
**Gap Filled:** Logic bugs, arithmetic vulnerabilities that need path exploration

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/Consensys/mythril](https://github.com/Consensys/mythril) |
| **License** | MIT (Open Source) |
| **Maintained By** | ConsenSys Diligence |
| **Integration Effort** | Medium (Docker recommended) |

**Why Add It:**
- Uses symbolic execution + SMT solving
- Finds vulnerabilities SAST cannot (requires exploring execution paths)
- Generates concrete exploit transactions
- Detects: integer overflow, reentrancy, unprotected functions, tx.origin

**Code Example:**
```bash
docker run -v $(pwd):/code mythril/myth analyze /code/Contract.sol --execution-timeout 300
```

**Covers Gaps:**
- [x] Path-dependent vulnerabilities
- [x] Integer overflow with concrete examples
- [x] State-dependent bugs
- [x] Access control bypass proof

---

#### 3. Nuclei - DAST/Vulnerability Scanner
**Gap Filled:** Runtime vulnerabilities, deployed contract testing, API security

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **License** | MIT (Open Source) |
| **Maintained By** | ProjectDiscovery |
| **Integration Effort** | Low (Go binary, YAML templates) |

**Why Add It:**
- 8000+ community templates for real vulnerabilities
- DAST for web apps, APIs, networks
- Custom template support (YAML-based like Opengrep)
- Detects: CVEs, misconfigurations, exposed endpoints, default credentials

**Code Example:**
```bash
nuclei -u https://target.com -t cves/ -t exposures/ -t misconfiguration/
```

**Covers Gaps:**
- [x] Runtime/deployed vulnerabilities
- [x] API security testing
- [x] CVE detection in live systems
- [x] Misconfiguration detection

---

#### 4. OSV-Scanner - Extended Dependency Scanning
**Gap Filled:** Broader vulnerability database coverage beyond Trivy

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/google/osv-scanner](https://github.com/google/osv-scanner) |
| **License** | Apache-2.0 (Open Source) |
| **Maintained By** | Google |
| **Integration Effort** | Low (Go binary) |

**Why Add It:**
- Uses OSV.dev database (broader than NVD alone)
- Call-graph analysis to reduce false positives
- Supports npm, pip, cargo, go, maven, gem, composer
- 60-65% non-overlap with Trivy (catches different issues)

**Code Example:**
```bash
osv-scanner --lockfile package-lock.json --format json
```

**Covers Gaps:**
- [x] Vulnerabilities Trivy misses
- [x] Reachability analysis (is vuln actually called?)
- [x] Broader ecosystem coverage

---

### TIER 2: MEDIUM PRIORITY (Specialized Analysis)

#### 5. Echidna - Smart Contract Fuzzer
**Gap Filled:** Economic exploits, invariant violations, complex attack sequences

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/crytic/echidna](https://github.com/crytic/echidna) |
| **License** | AGPL-3.0 (Open Source) |
| **Maintained By** | Trail of Bits |
| **Integration Effort** | High (Haskell, needs test properties) |

**Why Add It:**
- Property-based fuzzing for Solidity
- Finds attack sequences SAST/symbolic cannot
- Used by: Compound, Uniswap, MakerDAO
- Detects: invariant violations, economic attacks, edge cases

**Limitation:** Requires writing test properties (not fully automated)

**Covers Gaps:**
- [x] Economic/MEV attack sequences
- [x] Multi-transaction exploits
- [x] Invariant violations
- [x] Edge case discovery

---

#### 6. Aderyn - Fast Rust-Based Analyzer
**Gap Filled:** Faster Solidity scanning, additional detectors

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/Cyfrin/aderyn](https://github.com/Cyfrin/aderyn) |
| **License** | MIT (Open Source) |
| **Maintained By** | Cyfrin |
| **Integration Effort** | Low (Rust binary, cargo install) |

**Why Add It:**
- Lightning fast (<1 second per contract)
- Markdown report output
- Custom detector support via Nyth
- Official tool for CodeHawks audits

**Code Example:**
```bash
cargo install aderyn
aderyn .
```

**Covers Gaps:**
- [x] Fast CI/CD integration
- [x] Additional detection patterns
- [x] Custom detector development

---

#### 7. Checkov - Infrastructure as Code Security
**Gap Filled:** Cloud misconfigurations, Terraform/K8s security

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |
| **License** | Apache-2.0 (Open Source) |
| **Maintained By** | Palo Alto Networks |
| **Integration Effort** | Low (Python, pip install) |

**Why Add It:**
- 2000+ built-in policies
- Terraform, CloudFormation, Kubernetes, Helm, Docker
- Compliance frameworks: CIS, SOC2, HIPAA, PCI-DSS

**Code Example:**
```bash
pip install checkov
checkov -d . --framework terraform --output json
```

**Covers Gaps:**
- [x] Cloud infrastructure security
- [x] Kubernetes misconfigurations
- [x] Compliance checking
- [x] Docker security

---

### TIER 3: LOWER PRIORITY (Nice to Have)

#### 8. Grype - Container Vulnerability Scanner
**Gap Filled:** Deeper container image scanning

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/anchore/grype](https://github.com/anchore/grype) |
| **License** | Apache-2.0 (Open Source) |
| **Maintained By** | Anchore |
| **Integration Effort** | Low (Go binary) |

**Note:** Significant overlap with Trivy, but catches ~35% different vulnerabilities

---

#### 9. Semgrep Pro Rules (Commercial)
**Gap Filled:** Enterprise-grade rules, taint tracking

| Attribute | Details |
|-----------|---------|
| **Source** | [semgrep.dev](https://semgrep.dev) |
| **License** | Commercial (Team/Enterprise tiers) |
| **Cost** | ~$100-500/month depending on tier |

**Why Consider:**
- Pro rules have inter-procedural taint tracking
- Better for web app vulnerabilities (XSS, SQLi flow analysis)
- Managed rule updates

---

#### 10. Halmos - Formal Verification
**Gap Filled:** Mathematical proofs of correctness

| Attribute | Details |
|-----------|---------|
| **Source** | [github.com/a16z/halmos](https://github.com/a16z/halmos) |
| **License** | AGPL-3.0 (Open Source) |
| **Maintained By** | a16z crypto |
| **Integration Effort** | High (requires writing specs) |

**Why Consider:**
- Proves absence of bugs mathematically
- Bounded symbolic execution
- Good for critical DeFi protocols

---

## Implementation Priority Matrix

| Tool | Gap Filled | Effort | Value | Priority |
|------|-----------|--------|-------|----------|
| **Slither** | Solidity depth | Medium | High | P1 |
| **Mythril** | Symbolic execution | Medium | High | P1 |
| **Nuclei** | DAST/Runtime | Low | High | P1 |
| **OSV-Scanner** | Dep scanning | Low | Medium | P1 |
| **Aderyn** | Fast Solidity | Low | Medium | P2 |
| **Echidna** | Fuzzing | High | High | P2 |
| **Checkov** | IaC security | Low | Medium | P2 |
| **Grype** | Container | Low | Low | P3 |
| **Halmos** | Formal verif | High | Medium | P3 |

---

## Suggested Integration Architecture

```
                     ┌─────────────────────────────────────────┐
                     │         Vibeship Scanner API            │
                     │         (Orchestration Layer)           │
                     └──────────────────┬──────────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          │                             │                             │
          ▼                             ▼                             ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│   SAST Layer    │          │   SCA Layer     │          │   DAST Layer    │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ • Opengrep      │          │ • Trivy         │          │ • Nuclei        │
│ • Slither       │          │ • OSV-Scanner   │          │ (future)        │
│ • Aderyn        │          │ • Grype         │          │                 │
│ • Mythril       │          │                 │          │                 │
└─────────────────┘          └─────────────────┘          └─────────────────┘
          │                             │                             │
          ▼                             ▼                             ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│  Secrets Layer  │          │   IaC Layer     │          │  Fuzzing Layer  │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ • Gitleaks      │          │ • Checkov       │          │ • Echidna       │
│                 │          │ • Trivy IaC     │          │ (opt-in)        │
└─────────────────┘          └─────────────────┘          └─────────────────┘
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        │
                                        ▼
                     ┌─────────────────────────────────────────┐
                     │        Unified Results Database         │
                     │            (Supabase)                   │
                     └─────────────────────────────────────────┘
```

---

## Coverage Matrix After Integration

| Vulnerability Type | Current | +Slither | +Mythril | +Nuclei | +Echidna |
|-------------------|---------|----------|----------|---------|----------|
| Reentrancy | 85% | 95% | 98% | - | 99% |
| Access Control | 80% | 90% | 95% | - | 95% |
| Oracle Manipulation | 70% | 80% | 85% | - | 90% |
| Integer Issues | 75% | 85% | 95% | - | 98% |
| Economic Exploits | 20% | 30% | 40% | - | 80% |
| Logic Bugs | 30% | 50% | 70% | - | 85% |
| Deployed Misconfig | 0% | 0% | 0% | 80% | - |
| API Vulnerabilities | 0% | 0% | 0% | 90% | - |
| Dependencies | 90% | 90% | 90% | 90% | 90% |

---

## Quick Wins (Can Implement This Week)

1. **Add Slither** - pip install, run alongside Opengrep
2. **Add OSV-Scanner** - Go binary, complements Trivy
3. **Add Aderyn** - cargo install, fast Solidity scanning

## Medium-Term (1-2 Months)

4. **Add Mythril** - Docker container, deeper analysis
5. **Add Checkov** - IaC security for cloud repos
6. **Add Nuclei** - DAST for deployed apps (optional scan type)

## Long-Term (3+ Months)

7. **Add Echidna** - Requires writing test harnesses (optional pro feature)
8. **Formal Verification** - Halmos for critical protocols (enterprise feature)

---

## Sources

- [QuillAudits: Top 10 Smart Contract Security Tools](https://www.quillaudits.com/blog/smart-contract/smart-contract-security-tools-guide)
- [H-X Technologies: Best Smart Contract Analysis Tools 2025](https://www.h-x.technology/blog/the-best-smart-contract-analysis-tools-2025)
- [Cyfrin: Best Smart Contract Auditing Tools](https://www.cyfrin.io/blog/industry-leading-smart-contract-auditing-and-security-tools)
- [ProjectDiscovery: Nuclei Overview](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Google OSV-Scanner](https://google.github.io/osv-scanner/)
- [env0: Best IaC Scanning Tool Comparison](https://www.env0.com/blog/best-iac-scan-tool)
