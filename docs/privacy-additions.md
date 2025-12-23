# Future Privacy Additions for Vibeship Scanner

**Status**: Planned improvements beyond current ultra-privacy implementation
**Last Updated**: December 2024

---

## Current State

We already implement:
- Pure AST extraction (no code tokens)
- Zero repo identification
- Preview before submit
- Minimal data collection (rule_id, ast_structure, reason_category only)

This document outlines **additional privacy enhancements** for future implementation.

---

## Phase 1: K-Anonymity (Short-term)

### What It Is
K-anonymity ensures that any pattern we store matches at least K other submissions, making it impossible to identify a specific project from its patterns.

### Implementation

```python
# Before storing any pattern:
async def store_with_k_anonymity(pattern: str, k: int = 5):
    """Only store patterns that match ≥k other reports."""

    # Count similar patterns in database
    similar_count = await db.count_similar_patterns(pattern, threshold=0.8)

    if similar_count >= k:
        # Pattern is common enough - safe to store
        await db.store_pattern(pattern)
    else:
        # Pattern too unique - generalize it
        generalized = generalize_pattern(pattern)

        if await db.count_similar_patterns(generalized) >= k:
            await db.store_pattern(generalized)
        else:
            # Still too unique - discard entirely
            logger.info(f"Discarding unique pattern for privacy")
            return None

def generalize_pattern(pattern: str) -> str:
    """
    Make pattern less specific to increase k-anonymity.

    Example:
    - "FunctionDef>RequireStmt>LowLevelCall>CompoundAssign"
    - Becomes: "FunctionDef>RequireStmt>LowLevelCall"
    """
    parts = pattern.split(">")
    # Remove most specific part
    return ">".join(parts[:-1]) if len(parts) > 2 else parts[0]
```

### Benefits
- Prevents fingerprinting codebases by unique patterns
- Aggregates data for statistical analysis only
- Mathematically provable privacy guarantee

### Effort
- Database schema changes for pattern similarity search
- Background job for pattern aggregation
- Estimated: 1-2 weeks implementation

---

## Phase 2: Local Differential Privacy (Medium-term)

### What It Is
Local Differential Privacy (LDP) randomizes data on the user's device BEFORE transmission. Even if our server is compromised, individual responses are protected.

### Implementation

```python
import math
import random
from typing import List

def submit_with_ldp(true_category: str, epsilon: float = 2.0) -> str:
    """
    Randomized Response with Local Differential Privacy.

    Args:
        true_category: The actual reason category
        epsilon: Privacy budget (lower = more private, less accurate)

    Returns:
        Potentially randomized category
    """
    categories = [
        "safe_pattern",
        "framework_handled",
        "test_code",
        "intentional",
        "wrong_context",
        "other"
    ]

    n = len(categories)
    true_index = categories.index(true_category)

    # Probability of reporting true answer
    p = math.exp(epsilon) / (math.exp(epsilon) + n - 1)

    if random.random() < p:
        return categories[true_index]  # Report true answer
    else:
        # Report random answer (excluding true)
        other_categories = [c for i, c in enumerate(categories) if i != true_index]
        return random.choice(other_categories)


# Server-side aggregation with noise correction
def aggregate_ldp_responses(responses: List[str], epsilon: float = 2.0) -> dict:
    """
    Aggregate randomized responses and estimate true distribution.
    """
    categories = ["safe_pattern", "framework_handled", "test_code",
                  "intentional", "wrong_context", "other"]
    n = len(categories)
    total = len(responses)

    p = math.exp(epsilon) / (math.exp(epsilon) + n - 1)
    q = 1 / n  # Probability of random selection

    estimated = {}
    for category in categories:
        observed_count = responses.count(category)
        # Correct for randomization bias
        estimated_count = (observed_count - total * q) / (p - q)
        estimated[category] = max(0, estimated_count)  # Can't be negative

    return estimated
```

### Privacy Guarantees
| Epsilon | True Answer Probability | Privacy Level |
|---------|------------------------|---------------|
| 0.5 | ~62% | Very High |
| 1.0 | ~73% | High |
| 2.0 | ~88% | Moderate |
| 4.0 | ~98% | Low |

Recommendation: Use ε=2.0 for good balance of privacy and utility.

### Benefits
- Even with server breach, individual data is protected
- Mathematically proven privacy (used by Apple, Google)
- No trust required in server-side processing

### Effort
- Client-side implementation in MCP tools
- Server-side aggregation logic
- Statistical analysis adjustments
- Estimated: 2-3 weeks implementation

---

## Phase 3: Distributed Aggregation - Mozilla Prio (Long-term)

### What It Is
Prio (Privacy-preserving Input Operations) splits data across multiple non-colluding servers. Neither server can see individual submissions, only the combined aggregate.

### Architecture

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

### Implementation Options

1. **ISRG Divvi Up** (Recommended)
   - Production-ready Prio implementation
   - Used by Mozilla Firefox
   - Open source: https://github.com/divviup/divviup-server

2. **Self-Hosted Two Servers**
   - Run two separate Fly.io apps
   - Different cloud providers for non-collusion guarantee
   - More complex but full control

### Integration Sketch

```python
from divviup import Client, Task

async def submit_prio_feedback(ast_structure: str, reason: str):
    """Submit feedback using Prio distributed aggregation."""

    # Encode as histogram bucket
    buckets = encode_to_histogram(ast_structure, reason)

    # Split and submit to both aggregators
    client = Client(
        leader_url="https://aggregator-a.vibeship.co",
        helper_url="https://aggregator-b.vibeship.co",
        task_id="false-positive-feedback"
    )

    await client.upload(buckets)
    # Neither server sees the actual values
    # Only the sum across all submissions
```

### Benefits
- Strongest possible privacy guarantee
- Used by Mozilla for Firefox telemetry
- Zero knowledge of individual submissions
- Cryptographic security

### Effort
- Significant infrastructure changes
- Two separate server deployments
- Integration with Prio protocol
- Estimated: 1-2 months implementation

---

## Phase 4: Cryptographic Preview Verification

### What It Is
Ensure users actually saw the preview before submitting, with cryptographic proof.

### Implementation

```python
import hmac
import time
from hashlib import sha256

SECRET_KEY = os.environ["PREVIEW_HMAC_SECRET"]

def generate_preview_token(data_hash: str) -> str:
    """Generate signed token proving preview was shown."""
    timestamp = int(time.time())
    message = f"{data_hash}:{timestamp}"
    signature = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        sha256
    ).hexdigest()
    return f"{timestamp}:{signature}"

def verify_preview_token(data_hash: str, token: str, max_age: int = 300) -> bool:
    """Verify token is valid and not expired (5 min default)."""
    try:
        timestamp, signature = token.split(":")
        timestamp = int(timestamp)

        # Check not expired
        if time.time() - timestamp > max_age:
            return False

        # Verify signature
        message = f"{data_hash}:{timestamp}"
        expected = hmac.new(
            SECRET_KEY.encode(),
            message.encode(),
            sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)
    except:
        return False
```

### Flow
1. User calls `scanner_preview_false_positive`
2. Preview shows data + returns signed token
3. User calls `scanner_report_false_positive` with token
4. Server verifies token before accepting submission
5. Submissions without valid token are rejected

### Benefits
- Guarantees informed consent
- Prevents automated bulk submissions
- Audit trail of user acknowledgment

### Effort
- Token generation/verification logic
- MCP tool updates
- Estimated: 3-5 days implementation

---

## Phase 5: Data Retention Automation

### What It Is
Automatically delete raw feedback data after processing, keeping only aggregated statistics.

### Implementation

```sql
-- Supabase scheduled function (pg_cron)
SELECT cron.schedule(
    'delete-old-feedback',
    '0 3 * * *',  -- Run daily at 3 AM
    $$
    -- Delete raw feedback older than 30 days
    DELETE FROM false_positive_feedback
    WHERE created_at < NOW() - INTERVAL '30 days'
    AND processed = true;

    -- Log deletion for audit
    INSERT INTO privacy_audit_log (action, count, timestamp)
    SELECT 'feedback_deletion', COUNT(*), NOW()
    FROM false_positive_feedback
    WHERE created_at < NOW() - INTERVAL '30 days';
    $$
);
```

### Aggregation Before Deletion

```python
async def aggregate_before_delete():
    """Convert raw feedback to anonymous statistics before deletion."""

    # Get feedback to be deleted
    old_feedback = await db.query("""
        SELECT rule_id, reason_category, COUNT(*) as count
        FROM false_positive_feedback
        WHERE created_at < NOW() - INTERVAL '30 days'
        GROUP BY rule_id, reason_category
    """)

    # Update aggregated statistics
    for row in old_feedback:
        await db.execute("""
            INSERT INTO rule_statistics (rule_id, reason, count)
            VALUES ($1, $2, $3)
            ON CONFLICT (rule_id, reason)
            DO UPDATE SET count = rule_statistics.count + $3
        """, row.rule_id, row.reason_category, row.count)

    # Now safe to delete raw data
    await db.execute("""
        DELETE FROM false_positive_feedback
        WHERE created_at < NOW() - INTERVAL '30 days'
    """)
```

### Benefits
- GDPR compliance (storage limitation)
- Reduced database size
- Cannot reconstruct individual submissions

### Effort
- Database triggers and scheduled jobs
- Aggregation table schema
- Estimated: 1 week implementation

---

## Phase 6: Third-Party Privacy Audit

### What It Is
Independent security firm validates our privacy implementation.

### Audit Scope
1. Code review of sanitizer.py
2. Data flow analysis
3. Database access patterns
4. Network traffic analysis
5. Penetration testing

### Certifications to Consider
| Certification | Focus | Cost Range |
|--------------|-------|------------|
| SOC 2 Type II | Security controls | $20k-50k |
| ISO 27701 | Privacy management | $30k-60k |
| GDPR Article 35 DPIA | Data protection impact | $10k-20k |

### Timeline
- Preparation: 1-2 months
- Audit: 2-4 weeks
- Remediation: 1-2 months
- Certification: 2-4 weeks

---

## Implementation Priority

```
┌─────────────────────────────────────────────────────────────────┐
│  PRIVACY ENHANCEMENT ROADMAP                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NOW ─────────────────────────────────────────────────> FUTURE  │
│                                                                 │
│  [✅ DONE]        [NEXT]         [LATER]        [LONG-TERM]    │
│                                                                 │
│  • Pure AST       • K-Anonymity   • Local DP    • Prio/DAP     │
│  • No repo ID     • Crypto        • Auto-delete • ISO 27701    │
│  • Preview tool     preview       • Third-party • SOC 2        │
│  • PRIVACY.md                       audit                      │
│                                                                 │
│  Effort: Done     1-2 weeks      2-4 weeks      2-4 months     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Wins (Can Implement This Week)

1. **Add preview token verification** - 2-3 days
2. **Rate limiting on feedback endpoint** - 1 day
3. **Add "delete my feedback" endpoint** - 1 day
4. **Privacy policy link in MCP responses** - 1 hour

---

## References

- [Mozilla Prio Paper](https://crypto.stanford.edu/prio/)
- [Apple Differential Privacy](https://www.apple.com/privacy/docs/Differential_Privacy_Overview.pdf)
- [RAPPOR: Google's DP](https://research.google/pubs/pub42852/)
- [ISRG Divvi Up](https://divviup.org/)
- [K-Anonymity Original Paper](https://epic.org/wp-content/uploads/privacy/reidentification/Sweeney_Article.pdf)
- [GDPR Data Minimization](https://gdpr-info.eu/art-5-gdpr/)
