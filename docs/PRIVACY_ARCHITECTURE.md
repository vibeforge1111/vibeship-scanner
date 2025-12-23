# Vibeship Scanner - Ultra-Privacy False Positive Feedback Architecture

## Executive Summary

This document defines the privacy-first architecture for collecting false positive feedback. Our goal is to be **the most privacy-protective security scanner** in the industry, collecting only the absolute minimum data needed to improve rule accuracy.

## Research Summary: Industry Practices

### What Leading Tools Do

| Tool | Data Collection | Privacy Model | Key Insight |
|------|----------------|---------------|-------------|
| **Semgrep** | Code never uploaded by default, metrics opt-in | Local analysis, cloud opt-in | "After all, we are a security tool!" |
| **SonarQube** | Self-hosted, no telemetry to vendor | Full user control | GDPR anonymization features |
| **Snyk** | Cloud-based but GDPR compliant | Processor model for customer data | Third-party audit (ISO/SOC2) |
| **CodeQL** | Open source rules, no telemetry | Local execution only | GitHub hosts, no user data |

### Privacy Technologies Used by Industry Leaders

| Company | Technology | Purpose |
|---------|------------|---------|
| **Mozilla** | Prio (Distributed Aggregation Protocol) | Aggregate counts without seeing individual data |
| **Apple** | Local Differential Privacy | Randomize data on-device before transmission |
| **Google** | RAPPOR | Learn statistics while preserving privacy |
| **Microsoft** | Differential Privacy | Windows telemetry with privacy guarantees |

---

## Vibeship Privacy Principles

### 1. ZERO CODE COLLECTION
**We NEVER collect actual code. Period.**

What we collect instead:
- Rule ID that triggered
- Structural pattern (AST skeleton)
- Reason category
- Framework hints (e.g., "uses OpenZeppelin")

### 2. LOCAL-FIRST PRIVACY
**All sanitization happens on the client, BEFORE any network transmission.**

```
User's Code → [LOCAL SANITIZER] → Structural Pattern Only → Server
              ↑
              No identifiable data leaves this point
```

### 3. DATA MINIMIZATION (GDPR Article 5(1)(c))
**Collect only what is strictly necessary for the purpose.**

| Purpose | Data Needed | Data NOT Needed |
|---------|-------------|-----------------|
| Fix false positive rule | Pattern structure | Variable names |
| Improve detection | AST skeleton | Comments |
| Add framework support | Framework hints | File paths |

### 4. PRIVACY BY DEFAULT (GDPR Article 25)
**Maximum privacy is the default. Users must explicitly opt-in to share more.**

```
Consent Level 1 (DEFAULT): Anonymous pattern only
Consent Level 2 (OPT-IN): + Sanitized context
Consent Level 3 (OPT-IN): + More detail (still heavily sanitized)
```

---

## Current Implementation Gaps & Improvements

### GAP 1: AST-Only Pattern Extraction
**Current**: We sanitize code with regex replacements
**Better**: Extract only AST structure, never touch actual code

```python
# CURRENT (still has risk)
code = "require(balances[msg.sender] >= amount);"
sanitized = "$FUNC($VAR1[$VAR2.$VAR3] >= $VAR4);"  # Still resembles code

# BETTER (pure structure)
ast_pattern = "CallExpression(BinaryExpression(MemberAccess, >=, Identifier))"
# This is JUST structure - impossible to reverse
```

**Recommendation**: Implement pure AST extraction that outputs ONLY node types, never any actual tokens from the code.

### GAP 2: Differential Privacy for Aggregation
**Current**: We store individual reports
**Better**: Aggregate with differential privacy before storage

```python
# Instead of storing: "Rule X had 50 false positives with pattern Y"
# Store: "Rule X had ~50±5 false positives" (noise added)
```

**Recommendation**: Implement local differential privacy (ε-LDP) where:
- Data is randomized on client before submission
- Server only sees aggregated, noisy data
- Individual submissions cannot be traced back

### GAP 3: No Hash of Repo URL at Any Level
**Current**: At consent level 3, we hash the repo URL
**Better**: Never store ANY repo identifier, even hashed

**Recommendation**: Remove `anonymized_repo_hash` entirely. It serves no purpose for rule improvement.

### GAP 4: Client-Side-Only Preview is Not Enforced
**Current**: Preview is optional before submission
**Better**: Require preview before any submission is allowed

**Recommendation**:
- Make `scanner_preview_false_positive` a REQUIRED step
- `scanner_report_false_positive` should fail if preview wasn't called first
- Server should verify preview was shown (via signed token)

### GAP 5: No Data Retention Policy
**Current**: Data is stored indefinitely
**Better**: Auto-delete after use

**Recommendation**:
- Process feedback within 30 days
- Delete raw reports after processing
- Keep only aggregated statistics

### GAP 6: Pattern Similarity Could Enable Fingerprinting
**Current**: Unique patterns could fingerprint a codebase
**Better**: K-anonymity for patterns

**Recommendation**:
- Only store patterns that match ≥k other reports (k=5)
- Generalize patterns that are too unique
- Use fuzzy matching instead of exact patterns

---

## Proposed Ultra-Privacy Architecture

### Phase 1: Pure Structural Extraction (No Code)

```
┌─────────────────────────────────────────────────────────────────┐
│  USER'S CODE                                                    │
│  function withdraw(uint amount) {                               │
│      require(balances[msg.sender] >= amount);                   │
│      (bool success,) = msg.sender.call{value: amount}("");      │
│      balances[msg.sender] -= amount;                            │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AST EXTRACTION (client-side)                                   │
│                                                                 │
│  FunctionDef                                                    │
│  ├─ RequireStmt                                                 │
│  │   └─ BinaryOp(>=)                                            │
│  │       ├─ IndexAccess(MemberAccess)                           │
│  │       └─ Identifier                                          │
│  ├─ VariableDecl + LowLevelCall                                 │
│  └─ AssignmentOp(-=)                                            │
│      └─ IndexAccess(MemberAccess)                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  WHAT GETS SENT                                                 │
│                                                                 │
│  {                                                              │
│    "rule_id": "sol-reentrancy",                                 │
│    "ast_structure": "FunctionDef>RequireStmt>LowLevelCall>Assign",
│    "ast_depth": 3,                                              │
│    "reason": "safe_pattern",                                    │
│    "framework": "OpenZeppelin"                                  │
│  }                                                              │
│                                                                 │
│  NO CODE. NO IDENTIFIERS. NO PATHS. JUST STRUCTURE.             │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 2: K-Anonymity Aggregation

```
Before storing any pattern:

1. Check if ≥k similar patterns exist
2. If yes: Store (pattern is common enough to not be identifying)
3. If no: Generalize until ≥k similar patterns exist
         OR discard (pattern too unique)

Example:
- "FunctionDef>RequireStmt>LowLevelCall" → Common (k=47) ✓ Store
- "FunctionDef>CustomModifier>RareOp"    → Rare (k=2) ✗ Generalize to "FunctionDef>Modifier>Op"
```

### Phase 3: Differential Privacy Layer

```python
# Client-side randomization (Local Differential Privacy)
def submit_feedback_ldp(pattern_category: str, epsilon: float = 2.0):
    """
    Randomizes the category before submission.
    Even if server is compromised, individual responses are protected.
    """
    categories = ["safe_pattern", "framework_handled", "test_code",
                  "intentional", "wrong_context", "other"]

    true_index = categories.index(pattern_category)

    # Randomized response with probability
    p = math.exp(epsilon) / (math.exp(epsilon) + len(categories) - 1)

    if random.random() < p:
        return categories[true_index]  # True answer
    else:
        return random.choice(categories)  # Random answer
```

### Phase 4: Distributed Aggregation (Mozilla Prio-style)

```
User Device                  Server A                 Server B
    │                           │                        │
    │  share_A = encrypt(data)  │                        │
    │──────────────────────────>│                        │
    │                           │                        │
    │  share_B = encrypt(data)  │                        │
    │──────────────────────────────────────────────────>│
    │                           │                        │
    │                           │  partial_sum_A         │
    │                           │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>│ partial_sum_B
    │                           │                        │
    │                           │  combined_aggregate    │
    │                           │========================│
    │                           │                        │

Neither server can see individual data.
Only the combined aggregate is visible.
```

---

## Implementation Roadmap

### Immediate (This Week)
- [ ] Remove `anonymized_repo_hash` from all consent levels
- [ ] Make preview mandatory before submission
- [ ] Add "Data will be deleted after 30 days" notice
- [ ] Stricter sanitizer: Remove any token > 3 chars that isn't a keyword

### Short-term (This Month)
- [ ] Implement pure AST extraction (no code tokens)
- [ ] Add k-anonymity check before storage (k=5)
- [ ] Add data retention auto-delete

### Medium-term (Next Quarter)
- [ ] Implement local differential privacy (ε-LDP)
- [ ] Add cryptographic proof that preview was shown
- [ ] Third-party privacy audit

### Long-term (Future)
- [ ] Investigate Prio/DAP for distributed aggregation
- [ ] GDPR Article 35 Data Protection Impact Assessment
- [ ] ISO 27701 Privacy Information Management certification

---

## What We Will NEVER Collect

| Category | Examples | Why |
|----------|----------|-----|
| **Source Code** | Any actual code text | Core privacy promise |
| **Identifiers** | Variable/function names | Could identify project |
| **Paths** | File paths, directories | Could identify project |
| **URLs** | Repo URLs, API endpoints | Could identify project |
| **Secrets** | API keys, credentials | Obviously sensitive |
| **Comments** | Code comments, TODOs | Could contain PII |
| **Strings** | String literals | Could contain anything |
| **Numbers** | Numeric values | Could be identifying |
| **Repo Hashes** | Even hashed URLs | Serves no purpose |

---

## Privacy Guarantees Summary

1. **No code ever leaves the user's machine** - Only structural patterns
2. **Default is maximum privacy** - Opt-in for any additional data
3. **Preview before submit** - Users see exactly what's shared
4. **Auto-delete after use** - 30-day retention max
5. **K-anonymity** - Patterns must match ≥5 others to be stored
6. **No fingerprinting** - Cannot identify project from pattern

---

## Sources

- [Semgrep Privacy Notice](https://semgrep.dev/legal/privacy/)
- [Semgrep Metrics Documentation](https://semgrep.dev/docs/metrics)
- [Mozilla Prio: Privacy-Preserving Telemetry](https://blog.mozilla.org/security/2019/06/06/next-steps-in-privacy-preserving-telemetry-with-prio/)
- [Mozilla OHTTP and Prio Partnership](https://hacks.mozilla.org/2023/10/built-for-privacy-partnering-to-deploy-oblivious-http-and-prio-in-firefox/)
- [Apple Differential Privacy Overview](https://www.apple.com/privacy/docs/Differential_Privacy_Overview.pdf)
- [Apple Learning with Privacy at Scale](https://machinelearning.apple.com/research/learning-with-privacy-at-scale)
- [Microsoft Collecting Telemetry Privately](https://www.microsoft.com/en-us/research/blog/collecting-telemetry-data-privately/)
- [NIST Differential Privacy Blog Series](https://www.nist.gov/blogs/cybersecurity-insights/differential-privacy-privacy-preserving-data-analysis-introduction-our)
- [Harvard Privacy Tools - Differential Privacy](https://privacytools.seas.harvard.edu/differential-privacy)
- [GDPR Data Minimization](https://www.cookieyes.com/blog/gdpr-data-minimization/)
- [Privacy by Design Principles (OneTrust)](https://www.onetrust.com/blog/principles-of-privacy-by-design/)
- [How Snyk Handles Your Data](https://docs.snyk.io/more-info/how-snyk-handles-your-data)
- [SonarQube GDPR Compliance](https://docs.sonar.expert/sonar-security-certifications/sonar-and-general-data-protection-regulation-gdpr)
- [K-Anonymity Model (Sweeney)](https://epic.org/wp-content/uploads/privacy/reidentification/Sweeney_Article.pdf)
- [K-Anonymity Guide (Immuta)](https://www.immuta.com/blog/k-anonymity-everything-you-need-to-know-2021-guide/)
