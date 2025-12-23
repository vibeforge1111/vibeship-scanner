# Vibeship Scanner Privacy Policy

**Last Updated: December 2024**

## Our Privacy Commitment

Vibeship Scanner is designed with **privacy-first principles**. We are a security tool, and we take your privacy as seriously as your security.

**TL;DR: We don't collect your code. Ever.**

---

## What We Collect During Scans

### Repository Scanning
When you scan a repository:
- **We clone the repo temporarily** to run security checks
- **All analysis happens on our servers** - no code is sent to third parties
- **Repos are deleted immediately** after scanning completes
- **Scan results are stored** in your account (findings, not code)

### What We DON'T Collect
- We don't store your source code
- We don't train AI models on your code
- We don't share code with third parties
- We don't retain cloned repositories

---

## False Positive Feedback (Optional)

If you **choose** to report a false positive, here's exactly what we collect:

### What Gets Sent (Complete List)
| Data | Example | Why |
|------|---------|-----|
| Rule ID | `sol-reentrancy` | To improve the specific rule |
| AST Structure | `FunctionDef>RequireStmt>LowLevelCall` | Pattern structure only |
| Structural Hints | `["low-level-call"]` | Generic vulnerability type |
| Framework Hints | `["OpenZeppelin"]` | To add framework exceptions |
| Reason Category | `safe_pattern` | Why it's a false positive |

### What We NEVER Collect
- Source code (any form, any amount)
- Variable names, function names, class names
- File paths or directory structure
- URLs, domains, or IP addresses
- Email addresses
- API keys, secrets, or credentials
- Repository URLs, names, or hashes
- Comments or documentation
- String literals or numeric values
- Any user-identifying information

### Preview Before Submit
You can **always preview exactly what will be sent** before submitting feedback. We show you the exact data that will be transmitted.

### Data Retention
- Feedback is processed within 30 days
- Raw reports are deleted after processing
- Only aggregated statistics are retained

---

## Account Data

If you create an account:
- Email address (for authentication)
- Scan history (finding summaries, not code)
- Subscription status

We don't sell your data. We don't share it with advertisers.

---

## Third-Party Services

| Service | Purpose | Data Shared |
|---------|---------|-------------|
| Supabase | Database | Scan results, account info |
| Fly.io | Hosting | Server logs only |
| Vercel | Frontend hosting | Anonymous analytics |

None of these services receive your source code.

---

## Your Rights (GDPR)

If you're in the EU, you have the right to:
- **Access** your data
- **Delete** your account and all associated data
- **Export** your scan history
- **Object** to processing

Contact: privacy@vibeship.co

---

## Data Security

- All data encrypted in transit (TLS 1.3)
- All data encrypted at rest
- SOC 2 Type II compliant infrastructure (via Supabase/Fly.io)
- No plaintext secrets stored

---

## Changes to This Policy

We'll notify you of significant changes via:
- Email (if you have an account)
- Banner on the website
- Changelog in our GitHub repo

---

## Contact

Questions about privacy? Contact us:
- Email: privacy@vibeship.co
- GitHub: https://github.com/vibeforge1111/vibeship-scanner/issues

---

## Technical Details

For the technically curious, our privacy implementation is documented in:
- [PRIVACY_ARCHITECTURE.md](./PRIVACY_ARCHITECTURE.md) - Full technical details
- [scanner/feedback/sanitizer.py](../scanner/feedback/sanitizer.py) - Source code

We believe in transparency. Our privacy code is open source.
