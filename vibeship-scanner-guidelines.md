# VibeShip Scanner Output Guidelines

## The Philosophy

> **Security scanners talk to security people. VibeShip Scanner talks to builders.**

Every output from Scanner should pass the "paste test": a vibe coder should be able to copy the fix recommendation directly into Claude Code, Cursor, or their AI tool of choice and have the problem solved in one prompt.

---

## Part 1: Language Translation Rules

### Never Use → Always Use

| Security Jargon | Plain English |
|----------------|---------------|
| SQL Injection vulnerability | Someone could delete your entire database |
| XSS (Cross-Site Scripting) | Attackers can run code in your users' browsers |
| CSRF vulnerability | Hackers can trick users into doing things they didn't mean to |
| Authentication bypass | Anyone can pretend to be any user |
| Authorization flaw | Users can access stuff they shouldn't |
| Hardcoded credentials | Your passwords are visible to anyone who sees the code |
| Insecure deserialization | Attackers can run any code they want on your server |
| Path traversal | Hackers can read any file on your server |
| SSRF | Your server can be tricked into attacking other systems |
| RCE (Remote Code Execution) | Complete takeover - attackers run anything they want |
| Information disclosure | You're accidentally showing private data |
| Insufficient input validation | You're trusting user input you shouldn't |
| Insecure direct object reference | Users can access other users' data by changing IDs |
| Missing rate limiting | Bots can spam your API forever |
| Weak cryptography | Your "encryption" can be cracked |
| Session fixation | Attackers can hijack user sessions |
| Open redirect | Your site can be used to trick users into visiting malicious sites |
| CVE-XXXX-XXXXX | [Never show CVE numbers - describe the actual risk] |
| CWE-XXX | [Never show CWE numbers - describe what could happen] |

### Severity Translation

| Technical Severity | VibeShip Label | What It Means |
|-------------------|----------------|---------------|
| Critical | 🔴 **Fix Before You Ship** | Your app is hackable right now |
| High | 🟠 **Fix This Week** | Real risk if anyone looks |
| Medium | 🟡 **Fix When You Can** | Not urgent but don't ignore |
| Low | 🟢 **Nice to Fix** | Good practice, low actual risk |
| Informational | 💡 **Pro Tip** | Not a vulnerability, just advice |

---

## Part 2: The Finding Format

Every finding follows this exact structure:

```
═══════════════════════════════════════════════════════════════════════
🔴 FIX BEFORE YOU SHIP
═══════════════════════════════════════════════════════════════════════

📍 WHERE
   File: src/api/users.ts
   Line: 47

😰 WHAT'S WRONG
   Your database query takes user input directly. An attacker could 
   type something like `'; DROP TABLE users; --` and delete everything.

💥 WHAT COULD HAPPEN  
   • All your user data could be deleted
   • Attackers could steal email addresses and passwords
   • Your entire database could be downloaded

📊 CONTEXT
   This is the #1 vulnerability in Supabase + Next.js apps.
   We found the same issue in 73% of AI-generated backends this month.

───────────────────────────────────────────────────────────────────────
🛠️ AI FIX PROMPT — Copy this into Claude Code / Cursor
───────────────────────────────────────────────────────────────────────

Fix the SQL injection vulnerability in src/api/users.ts at line 47.

The current code does this:
```ts
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`)
```

Replace it with a parameterized query:
```ts
const user = await db.query('SELECT * FROM users WHERE id = $1', [userId])
```

Make sure to:
1. Use parameterized queries for ALL database calls in this file
2. Never concatenate user input into SQL strings
3. Show me the complete updated function when done

───────────────────────────────────────────────────────────────────────
```

---

## Part 3: AI Fix Prompt Templates

### Template Structure

Every AI fix prompt must include:

1. **The action** - What to fix and where
2. **The current code** - Show exactly what's wrong
3. **The fixed code** - Show exactly what it should be
4. **The scope** - Tell the AI to check for the same issue elsewhere
5. **The verification** - Ask the AI to confirm the fix

### Templates by Vulnerability Type

---

#### SQL Injection

```
Fix the SQL injection vulnerability in [FILE] at line [LINE].

The current code does this:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Replace it with a parameterized query:
```[LANGUAGE]
[FIXED_CODE]
```

After fixing this:
1. Search the entire codebase for similar patterns: string concatenation in database queries
2. Fix any other instances you find
3. List all files you modified
```

---

#### Hardcoded Secrets

```
Remove the hardcoded [SECRET_TYPE] from [FILE] at line [LINE].

Current code:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Fix by:
1. Create a .env file (or add to existing) with:
   [ENV_VAR_NAME]=[PLACEHOLDER]

2. Update the code to:
```[LANGUAGE]
[FIXED_CODE]
```

3. Add .env to .gitignore if not already there
4. Check if this secret was already committed to git history (warn me if so)
5. Search for other hardcoded secrets in the codebase (API keys, passwords, tokens)
```

---

#### Missing Authentication

```
Add authentication check to [FILE] at line [LINE].

This endpoint is currently accessible without login:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Add authentication middleware:
```[LANGUAGE]
[FIXED_CODE]
```

Also:
1. Check all other API routes in this file for the same issue
2. List any other unprotected endpoints you find
3. If using [FRAMEWORK], use the standard auth pattern for this framework
```

---

#### Missing Authorization (IDOR)

```
Add authorization check to [FILE] at line [LINE].

Currently, any logged-in user can access any [RESOURCE]:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Add ownership verification:
```[LANGUAGE]
[FIXED_CODE]
```

Check that:
1. The user can only access their own [RESOURCE]s
2. Admin routes properly check for admin role
3. Similar endpoints in this file have the same protection
```

---

#### XSS (Cross-Site Scripting)

```
Fix the XSS vulnerability in [FILE] at line [LINE].

User input is being rendered without sanitization:
```[LANGUAGE]
[VULNERABLE_CODE]
```

[FOR REACT]:
Use safe rendering instead of dangerouslySetInnerHTML:
```[LANGUAGE]
[FIXED_CODE]
```

[FOR VANILLA JS]:
Use textContent instead of innerHTML, or sanitize with DOMPurify:
```[LANGUAGE]
[FIXED_CODE]
```

Also check for:
1. Other uses of innerHTML or dangerouslySetInnerHTML in this file
2. Any place user input is rendered in HTML
3. URL parameters being displayed without encoding
```

---

#### Insecure CORS

```
Fix the overly permissive CORS configuration in [FILE] at line [LINE].

Current config allows any origin:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Restrict to your actual domains:
```[LANGUAGE]
[FIXED_CODE]
```

For development, you can use:
```[LANGUAGE]
[DEV_CONFIG]
```

Make sure to:
1. Set different CORS rules for development vs production
2. Never use "*" for Access-Control-Allow-Origin in production
3. List the specific origins you need to allow
```

---

#### Missing Rate Limiting

```
Add rate limiting to [FILE] to protect against abuse.

This endpoint has no rate limiting:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Add rate limiting middleware:
```[LANGUAGE]
[FIXED_CODE]
```

Recommended limits:
- Login/auth endpoints: 5 requests per minute per IP
- API endpoints: 100 requests per minute per user
- Public endpoints: 30 requests per minute per IP

Apply rate limiting to all sensitive endpoints in this file.
```

---

#### Sensitive Data Exposure

```
Remove sensitive data from [FILE] at line [LINE].

The API response includes data that shouldn't be exposed:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Only return necessary fields:
```[LANGUAGE]
[FIXED_CODE]
```

Also:
1. Check other API responses for password hashes, tokens, or internal IDs
2. Create a sanitize function if you're returning user objects in multiple places
3. Never return: passwords, password hashes, session tokens, API keys, internal IDs
```

---

#### Insecure File Upload

```
Secure the file upload in [FILE] at line [LINE].

Current upload accepts any file:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Add proper validation:
```[LANGUAGE]
[FIXED_CODE]
```

Security checklist:
1. Validate file type by checking magic bytes, not just extension
2. Limit file size (recommend: 5MB for images, 25MB for documents)
3. Generate random filenames, don't use user-provided names
4. Store uploads outside the web root or use a CDN
5. Scan for malware if accepting documents
```

---

#### Missing HTTPS/Security Headers

```
Add security headers to [FILE].

Your app is missing important security headers.

Add this middleware:
```[LANGUAGE]
[FIXED_CODE]
```

These headers:
- Strict-Transport-Security: Forces HTTPS
- X-Content-Type-Options: Prevents MIME sniffing
- X-Frame-Options: Prevents clickjacking
- Content-Security-Policy: Prevents XSS and injection attacks

If using Vercel/Netlify, you can add these in vercel.json or netlify.toml instead.
```

---

#### Weak Password Requirements

```
Strengthen password requirements in [FILE] at line [LINE].

Current validation is too weak:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Use stronger validation:
```[LANGUAGE]
[FIXED_CODE]
```

Minimum requirements:
- At least 8 characters (12+ recommended)
- Mix of letters, numbers, and symbols
- Not in common password lists
- Consider using a library like zxcvbn for strength scoring
```

---

#### Unvalidated Redirects

```
Fix the open redirect in [FILE] at line [LINE].

Current code redirects to any URL:
```[LANGUAGE]
[VULNERABLE_CODE]
```

Validate the redirect destination:
```[LANGUAGE]
[FIXED_CODE]
```

Rules:
1. Only allow redirects to your own domain(s)
2. Use a whitelist of allowed paths if possible
3. Never redirect to URLs from user input without validation
```

---

## Part 4: Stack-Specific Context

Add relevant context based on detected stack:

### Next.js + Supabase
```
📊 CONTEXT
   This is common in Next.js + Supabase apps because Supabase's 
   client-side library makes it easy to forget server-side validation.
   
   73% of AI-generated Supabase backends we scanned have this issue.
   
   💡 Supabase has Row Level Security (RLS) that can prevent this at 
   the database level. Consider enabling it as a second line of defense.
```

### Express.js
```
📊 CONTEXT
   Express doesn't include security middleware by default.
   This is the #2 most common issue in Express apps built with AI tools.
   
   💡 Consider adding the 'helmet' package - it adds most security 
   headers automatically with one line of code.
```

### Firebase
```
📊 CONTEXT
   Firebase Security Rules are often left too permissive during 
   development and forgotten before launch.
   
   💡 Your Firestore rules at firestore.rules should be reviewed.
   Never use "allow read, write: if true" in production.
```

### Vercel Deployment
```
📊 CONTEXT
   Environment variables in Vercel need to be set in the dashboard,
   not just in .env files. The .env file only works locally.
   
   💡 Go to Vercel Dashboard → Settings → Environment Variables
```

---

## Part 5: The Production Readiness Score

After all findings, show a summary:

```
═══════════════════════════════════════════════════════════════════════
📊 PRODUCTION READINESS SCORE
═══════════════════════════════════════════════════════════════════════

   🔴 NOT READY TO SHIP
   
   Score: 34/100

   ┌─────────────────────────────────────────────────────────────────┐
   │  🔴 Fix Before You Ship    3 issues                            │
   │  🟠 Fix This Week          5 issues                            │
   │  🟡 Fix When You Can       12 issues                           │
   │  🟢 Nice to Fix            4 issues                            │
   └─────────────────────────────────────────────────────────────────┘

   Your app is vulnerable to real attacks right now.
   Fix the 3 critical issues before going live.

───────────────────────────────────────────────────────────────────────
🚀 GET TO GREEN FAST
───────────────────────────────────────────────────────────────────────

Copy this into Claude Code / Cursor to fix all critical issues:

"""
I need to fix 3 critical security issues in my codebase:

1. SQL Injection in src/api/users.ts line 47
   - Change direct query to parameterized query
   
2. Hardcoded API key in src/lib/stripe.ts line 12
   - Move to environment variable STRIPE_SECRET_KEY
   
3. Missing auth on src/api/admin/users.ts line 8
   - Add authentication middleware

For each fix:
- Show me the before and after code
- Check for similar issues in nearby files
- Confirm when complete

Let's start with #1.
"""

───────────────────────────────────────────────────────────────────────
🆘 NEED HELP?
───────────────────────────────────────────────────────────────────────

Can't fix it yourself? 

→ Get a VibeShip Expert to fix it for you (from $50)
→ Ask in the VibeShip Discord - someone's solved this before
→ Book a 15-min security review call

═══════════════════════════════════════════════════════════════════════
```

---

## Part 6: Tone & Voice Rules

### Do ✅
- Sound like a helpful friend who happens to know security
- Use "you" and "your" - make it personal
- Explain why something is dangerous, not just that it is
- Give specific, actionable next steps
- Acknowledge that AI tools make these mistakes (not the developer)

### Don't ❌
- Sound like a compliance audit
- Use passive voice ("a vulnerability was detected")
- List CVE/CWE numbers without explanation
- Assume knowledge of security concepts
- Blame the developer
- Be condescending about "basic" mistakes

### Example Transformations

**Bad:**
> CVE-2024-1234: Potential SQL injection vulnerability detected in database query construction. Severity: High. Remediation: Use parameterized queries.

**Good:**
> 🔴 Someone could delete your entire database
> 
> In `src/api/users.ts`, line 47, your database query takes user input directly. This is a classic AI-generated mistake - Claude and Cursor both do this constantly.
>
> An attacker could type something like `'; DROP TABLE users; --` as their "user ID" and wipe your data.
>
> Here's the exact prompt to fix it → [AI Fix Prompt]

---

## Part 7: Edge Cases

### When the AI Can't Auto-Fix

Some issues need human judgment. Be clear about this:

```
═══════════════════════════════════════════════════════════════════════
🟡 FIX WHEN YOU CAN — Needs Human Decision
═══════════════════════════════════════════════════════════════════════

📍 WHERE
   File: src/api/posts.ts
   Line: 23-45

😰 WHAT'S WRONG
   Your API returns all posts to all users. This might be intentional 
   (public blog) or a bug (private posts leaking).

🤔 QUESTION FOR YOU
   Should posts be:
   A) Public to everyone (current behavior)
   B) Only visible to the author
   C) Visible to logged-in users only
   D) Something else (followers, team members, etc.)

───────────────────────────────────────────────────────────────────────
🛠️ AI FIX PROMPTS — Pick the one that matches your intent
───────────────────────────────────────────────────────────────────────

OPTION A - Keep public (add rate limiting only):
[prompt]

OPTION B - Author only:
[prompt]

OPTION C - Logged-in users:
[prompt]

───────────────────────────────────────────────────────────────────────
```

### When There's No Issue

Don't just say "no issues found" - celebrate and add value:

```
═══════════════════════════════════════════════════════════════════════
✅ LOOKING GOOD!
═══════════════════════════════════════════════════════════════════════

   Score: 94/100 — Ready to Ship 🚀

   We scanned 47 files and found no critical or high-severity issues.

   You're doing better than 89% of AI-generated codebases we scan.

   Minor suggestions (optional):
   • Consider adding rate limiting to your public API
   • Your session timeout is 30 days - consider reducing to 7

───────────────────────────────────────────────────────────────────────
📈 BEFORE YOU LAUNCH
───────────────────────────────────────────────────────────────────────

   □ Set up error monitoring (Sentry, LogRocket)
   □ Enable database backups
   □ Set up uptime monitoring
   □ Review your Supabase RLS rules one more time

   Want a human expert to do a final review? → Book a VibeShip audit

═══════════════════════════════════════════════════════════════════════
```

---

## Part 8: Output Format Options

### Default: Rich Terminal/Web
Full formatting with boxes, colors, and prompts as shown above.

### JSON Export
For integrations and CI/CD:

```json
{
  "score": 34,
  "status": "not_ready",
  "summary": {
    "critical": 3,
    "high": 5,
    "medium": 12,
    "low": 4
  },
  "findings": [
    {
      "id": "sql-injection-001",
      "severity": "critical",
      "title": "Someone could delete your entire database",
      "file": "src/api/users.ts",
      "line": 47,
      "description": "Your database query takes user input directly...",
      "ai_fix_prompt": "Fix the SQL injection vulnerability in...",
      "context": {
        "stack": "nextjs-supabase",
        "prevalence": "73% of similar apps",
        "ai_tool_pattern": "cursor"
      }
    }
  ],
  "master_fix_prompt": "I need to fix 3 critical security issues..."
}
```

### Markdown Export
For sharing in docs, PRs, or Notion:

```markdown
# Security Scan Results

**Score:** 34/100 🔴 Not Ready to Ship

## Critical Issues (3)

### 1. Someone could delete your entire database
**File:** `src/api/users.ts` line 47
...
```

---

## Appendix: The AI Pattern Database

Track which AI tools generate which vulnerabilities. This becomes Scanner's unique dataset:

| Pattern | Claude Code | Cursor | v0 | Bolt | Replit |
|---------|-------------|--------|-----|------|--------|
| SQL injection in examples | High | Medium | Low | Medium | High |
| Hardcoded API keys | High | Low | Low | High | High |
| Missing auth middleware | Medium | High | N/A | High | Medium |
| XSS via innerHTML | Low | Medium | High | Medium | Low |
| Overly permissive CORS | High | High | Medium | High | High |
| .env in git | Medium | Low | N/A | High | High |

Use this data in context messages:
> "This is a signature Cursor pattern - it often skips auth middleware when generating new API routes."

---

## Implementation Checklist

- [ ] Every finding has a plain English title
- [ ] Every finding has an AI fix prompt
- [ ] Every fix prompt includes the current code
- [ ] Every fix prompt includes the fixed code
- [ ] Every fix prompt asks AI to check for similar issues
- [ ] Context shows stack-specific information
- [ ] Context shows prevalence data when available
- [ ] Summary includes a single "master fix prompt" for all critical issues
- [ ] Clear CTA to VibeShip Experts for issues that need human help
