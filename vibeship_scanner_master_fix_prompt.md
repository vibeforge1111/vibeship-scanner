# Security Fix Guide

I need help fixing 18 security vulnerabilities in my codebase.

**Repository:** https://github.com/ApprenticeofEnder/FastAPI-automated-security-testing

**Severity Breakdown:** 🟠 2 High | 🟡 16 Medium

> 📊 **Note:** 24 total findings consolidated into 18 unique issues.

## Quick Summary (18 unique issues)

1. [HIGH] Potential SSRF - HTTP request with user-controlled URL parameter (OWASP API7) → `app/v1/ssrf/routes.py:13`
2. [HIGH] SSRF - requests.get() with object attribute - validate URL against allowlist (CWE-918) → `app/v1/ssrf/routes.py:13`
3. [MEDIUM] Authorization header parsed without Bearer prefix validation (CWE-287) → `app/shared/dependencies.py:15`
4. [MEDIUM] open() with variable path - path traversal if user-controlled (CWE-22) → `app/v1/broken_access_control/routes.py:16`
5. [MEDIUM] File open with user input - potential path traversal → `app/v1/broken_access_control/routes.py:16` (2 occurrences)
6. [MEDIUM] Potential path traversal - validate file path is not user-controlled (CWE-22) → `app/v1/broken_access_control/routes.py:16` (2 occurrences)
7. [MEDIUM] File open with variable path - validate path to prevent path traversal (CWE-22) → `app/v1/broken_access_control/routes.py:16` (2 occurrences)
8. [MEDIUM] File open with os.path.join() - validate path segments to prevent relative path traversal (CWE-23) → `app/v1/broken_access_control/routes.py:27`
9. [MEDIUM] BOLA vulnerability - returning item without ownership verification (CWE-285) → `app/v1/broken_access_control/routes.py:46`
10. [MEDIUM] FastAPI CRUD endpoint without authentication dependency - add Depends(get_current_user) (CWE-306) → `app/v1/ssrf/routes.py:11`
11. [MEDIUM] HTTP request with user input - potential SSRF → `app/v1/ssrf/routes.py:13`
12. [MEDIUM] File open with user input - potential path traversal → `app/v2/broken_access_control/routes.py:17` (2 occurrences)
13. [MEDIUM] Potential path traversal - validate file path is not user-controlled (CWE-22) → `app/v2/broken_access_control/routes.py:17` (2 occurrences)
14. [MEDIUM] File open with os.path.join() - validate path segments to prevent relative path traversal (CWE-23) → `app/v2/broken_access_control/routes.py:17`
15. [MEDIUM] File open with variable path - validate path to prevent path traversal (CWE-22) → `app/v2/broken_access_control/routes.py:17` (2 occurrences)
16. [MEDIUM] FastAPI CRUD endpoint without authentication dependency - add Depends(get_current_user) (CWE-306) → `app/v2/ssrf/routes.py:16`
17. [MEDIUM] HTTP request with user input - potential SSRF → `app/v2/ssrf/routes.py:22`
18. [MEDIUM] requests: requests: Requests vulnerable to .netrc credentials leak via malicious URLs → `requirements.txt`

---

## Detailed Fix Instructions

*Sections are ordered by severity - most critical vulnerability types appear first.*

## 🟠 Server-Side Request Forgery (SSRF)

**Affected Locations:**
- `app/v1/ssrf/routes.py:13` [HIGH] Potential SSRF - HTTP request with user-controlled URL parameter (OWASP API7)
- `app/v1/ssrf/routes.py:13` [HIGH] SSRF - requests.get() with object attribute - validate URL against allowlist (CWE-918)
- `app/v1/ssrf/routes.py:13` [MEDIUM] HTTP request with user input - potential SSRF
- `app/v2/ssrf/routes.py:22` [MEDIUM] HTTP request with user input - potential SSRF

**What's Wrong:**
User-supplied URLs are fetched by the server without validation, allowing attackers to access internal services or cloud metadata.

**How to Fix:**

Validate URLs before fetching:

```javascript
// ❌ VULNERABLE
const response = await fetch(userProvidedUrl);

// ✅ FIXED
const url = new URL(userProvidedUrl);
const blockedHosts = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0'];
const blockedProtocols = ['file:', 'ftp:', 'gopher:'];

if (blockedHosts.includes(url.hostname) ||
    blockedProtocols.includes(url.protocol) ||
    url.hostname.endsWith('.internal')) {
  throw new Error('URL not allowed');
}
const response = await fetch(url.toString());
```

**After Fixing:**
- Test with: `http://169.254.169.254/latest/meta-data/`
- Test with: `http://localhost:3000/admin`
- Block internal IP ranges and cloud metadata endpoints

---

## 🟡 Security Misconfiguration

**Affected Locations:**
- `app/shared/dependencies.py:15` [MEDIUM] Authorization header parsed without Bearer prefix validation (CWE-287)

**What's Wrong:**
Insecure default configurations, debug mode enabled in production, or missing security headers.

**How to Fix:**

Apply secure configurations:

```javascript
// Disable debug in production
if (process.env.NODE_ENV === 'production') {
  app.set('env', 'production');
}

// Add security headers (helmet)
const helmet = require('helmet');
app.use(helmet());

// Configure CORS properly
app.use(cors({
  origin: ['https://yourdomain.com'],
  credentials: true
}));

// Disable X-Powered-By
app.disable('x-powered-by');
```

**After Fixing:**
- Check NODE_ENV in production
- Verify security headers with securityheaders.com
- Ensure debug/verbose logging is disabled

---

## 🟠 Path Traversal

**Affected Locations:**
- `app/v1/broken_access_control/routes.py:16` [MEDIUM] open() with variable path - path traversal if user-controlled (CWE-22)
- `app/v1/broken_access_control/routes.py:16` [MEDIUM] File open with user input - potential path traversal
- `app/v1/broken_access_control/routes.py:16` [MEDIUM] Potential path traversal - validate file path is not user-controlled (CWE-22)
- `app/v1/broken_access_control/routes.py:16` [MEDIUM] File open with variable path - validate path to prevent path traversal (CWE-22)
- `app/v1/broken_access_control/routes.py:27` [MEDIUM] File open with os.path.join() - validate path segments to prevent relative path traversal (CWE-23)
- `app/v2/broken_access_control/routes.py:17` [MEDIUM] File open with user input - potential path traversal
- `app/v2/broken_access_control/routes.py:17` [MEDIUM] Potential path traversal - validate file path is not user-controlled (CWE-22)
- `app/v2/broken_access_control/routes.py:17` [MEDIUM] File open with os.path.join() - validate path segments to prevent relative path traversal (CWE-23)
- `app/v2/broken_access_control/routes.py:17` [MEDIUM] File open with variable path - validate path to prevent path traversal (CWE-22)

**What's Wrong:**
User input is used to construct file paths without validation, allowing attackers to access files outside the intended directory.

**How to Fix:**

Validate and sanitize file paths:

```javascript
// ❌ VULNERABLE
const filePath = `./uploads/${req.params.filename}`;
fs.readFile(filePath);

// ✅ FIXED
const path = require('path');
const safePath = path.join('./uploads', path.basename(req.params.filename));
// Verify it's still under uploads
if (!safePath.startsWith(path.resolve('./uploads'))) {
  throw new Error('Invalid path');
}
fs.readFile(safePath);
```

```python
# ❌ VULNERABLE
file_path = f"./uploads/{filename}"

# ✅ FIXED
import os
safe_path = os.path.join('./uploads', os.path.basename(filename))
if not os.path.abspath(safe_path).startswith(os.path.abspath('./uploads')):
    raise ValueError('Invalid path')
```

**After Fixing:**
- Test with: `../../../etc/passwd`
- Ensure all file operations validate paths
- Use allowlists when possible

---

## ⚠️ Security Issue

**Affected Locations:**
- `app/v1/broken_access_control/routes.py:46` [MEDIUM] BOLA vulnerability - returning item without ownership verification (CWE-285)
- `app/v1/ssrf/routes.py:11` [MEDIUM] FastAPI CRUD endpoint without authentication dependency - add Depends(get_current_user) (CWE-306)
- `app/v2/ssrf/routes.py:16` [MEDIUM] FastAPI CRUD endpoint without authentication dependency - add Depends(get_current_user) (CWE-306)

**What's Wrong:**
A security issue was detected that requires attention.

**How to Fix:**

Review the specific finding details and apply appropriate fixes based on the vulnerability type. General security principles:

1. **Validate all input** - Never trust user input
2. **Encode all output** - Prevent injection attacks
3. **Use parameterized queries** - Prevent SQL injection
4. **Implement proper authentication** - Verify identity
5. **Apply authorization checks** - Verify permissions
6. **Use HTTPS everywhere** - Encrypt data in transit
7. **Keep dependencies updated** - Patch known vulnerabilities

**After Fixing:**
- Review the specific CVE/CWE if provided
- Test the fix manually
- Consider security code review

---

## 🔴 Hardcoded Secrets

**Affected Locations:**
- `requirements.txt` [MEDIUM] requests: requests: Requests vulnerable to .netrc credentials leak via malicious URLs

**What's Wrong:**
Sensitive credentials (API keys, passwords, tokens) are committed to source code, exposing them to anyone with repository access.

**How to Fix:**

Move secrets to environment variables or a secrets manager:

```javascript
// ❌ VULNERABLE
const apiKey = "sk-1234567890abcdef";
const dbPassword = "admin123";

// ✅ FIXED
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
```

**Setup:**
1. Create `.env` file (add to `.gitignore`!):
   ```
   API_KEY=sk-1234567890abcdef
   DB_PASSWORD=admin123
   ```

2. Load with dotenv:
   ```javascript
   require('dotenv').config();
   ```

3. For production, use your platform's secrets management (Vercel, Fly.io, AWS Secrets Manager)

**After Fixing:**
- Add `.env` to `.gitignore`
- Run: `gitleaks detect` to find remaining secrets
- Rotate any exposed credentials immediately

---


## How to Work Through This

1. **Go section by section** - Start with the first vulnerability type (most critical)
2. **Read the file** - Open each listed file and find the vulnerable code at the specified line
3. **Apply the fix pattern** - Use the code examples provided as templates
4. **Search for similar issues** - After fixing, grep the codebase for similar vulnerable patterns
5. **Verify the fix** - Make sure the code still works after your changes
6. **Move to the next** - Continue until all issues are resolved

## After All Fixes

- Run the application and test that everything works
- Run any existing tests: `npm test` or equivalent
- List all files you modified
- Summarize what you changed

Let's start! Begin with the first section above.
