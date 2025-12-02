# Security Commons - Common Vulnerabilities & Best Practices

A reference guide for understanding common security vulnerabilities detected by Vibeship Scanner and how to fix them.

## Table of Contents
1. [Injection Attacks](#injection-attacks)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Authentication & Session Issues](#authentication--session-issues)
4. [Sensitive Data Exposure](#sensitive-data-exposure)
5. [Security Misconfigurations](#security-misconfigurations)
6. [Insecure Dependencies](#insecure-dependencies)
7. [File Handling Vulnerabilities](#file-handling-vulnerabilities)

---

## Injection Attacks

### SQL Injection (CWE-89)

**What it is**: Attacker injects malicious SQL code through user input to manipulate database queries.

**Risk Level**: Critical

**Vulnerable Code**:
```javascript
// BAD - String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// BAD - Template literal without parameterization
db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**Secure Code**:
```javascript
// GOOD - Parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// GOOD - Using ORM
const user = await User.findOne({ where: { id: userId } });

// GOOD - Prepared statement
const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
stmt.get(email);
```

**Key Points**:
- Never concatenate user input into SQL queries
- Use parameterized queries or prepared statements
- Use ORMs with proper escaping (Prisma, Sequelize, TypeORM)
- Validate and sanitize input as defense-in-depth

---

### Command Injection (CWE-78)

**What it is**: Attacker executes arbitrary system commands through user input.

**Risk Level**: Critical

**Vulnerable Code**:
```javascript
// BAD - User input in shell command
const { exec } = require('child_process');
exec(`ping ${userInput}`);

// BAD - eval with user input
eval(userProvidedCode);
```

**Secure Code**:
```javascript
// GOOD - Use execFile with arguments array
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', validatedHost]);

// GOOD - Whitelist allowed values
const allowedCommands = ['status', 'info', 'version'];
if (allowedCommands.includes(userInput)) {
  execFile(userInput);
}

// GOOD - Avoid shell entirely, use native libraries
const dns = require('dns');
dns.lookup(hostname, callback);
```

**Key Points**:
- Never pass user input directly to shell commands
- Use `execFile` instead of `exec` (no shell interpretation)
- Whitelist allowed values when possible
- Use native libraries instead of shell commands

---

### NoSQL Injection (CWE-943)

**What it is**: Exploiting NoSQL databases (MongoDB, etc.) through malicious query operators.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - Direct user input in query
db.users.findOne({ username: req.body.username, password: req.body.password });
// Attacker sends: { "username": "admin", "password": { "$ne": "" } }
```

**Secure Code**:
```javascript
// GOOD - Validate input types
const username = String(req.body.username);
const password = String(req.body.password);
db.users.findOne({ username, password });

// GOOD - Use mongoose with schema validation
const UserSchema = new Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
});

// GOOD - Sanitize query operators
import mongoSanitize from 'express-mongo-sanitize';
app.use(mongoSanitize());
```

---

## Cross-Site Scripting (XSS)

### Reflected XSS (CWE-79)

**What it is**: Malicious script reflects off web server in error messages, search results, or any response that includes user input.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - innerHTML with user input
element.innerHTML = userInput;

// BAD - document.write
document.write(location.search);

// BAD - React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

**Secure Code**:
```javascript
// GOOD - Use textContent
element.textContent = userInput;

// GOOD - Use framework auto-escaping
// React automatically escapes
<div>{userInput}</div>

// GOOD - Sanitize if HTML is needed
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Stored XSS

**What it is**: Malicious script is permanently stored on target server (database, message forum, comment field).

**Prevention**:
- Sanitize all user input before storing
- Encode output when rendering
- Use Content Security Policy (CSP) headers
- HttpOnly cookies prevent session theft

---

## Authentication & Session Issues

### Hardcoded Credentials (CWE-798)

**What it is**: Passwords, API keys, or secrets embedded directly in source code.

**Risk Level**: Critical

**Vulnerable Code**:
```javascript
// BAD - Hardcoded secret
const JWT_SECRET = "super-secret-key-123";
jwt.sign(payload, JWT_SECRET);

// BAD - Hardcoded API key
const apiKey = "sk_live_abc123xyz";
```

**Secure Code**:
```javascript
// GOOD - Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
jwt.sign(payload, JWT_SECRET);

// GOOD - Secrets manager
import { SecretsManager } from 'aws-sdk';
const secret = await secretsManager.getSecretValue({ SecretId: 'api-key' });
```

**Key Points**:
- Never commit secrets to version control
- Use environment variables or secrets managers
- Rotate credentials regularly
- Use `.env` files locally (add to `.gitignore`)

---

### Weak Password Comparison (CWE-521)

**What it is**: Comparing passwords using insecure methods.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - Plaintext comparison
if (password === user.password) { }

// BAD - Timing attack vulnerable
if (hash1 === hash2) { }
```

**Secure Code**:
```javascript
// GOOD - Use bcrypt
import bcrypt from 'bcrypt';

// Hashing
const hash = await bcrypt.hash(password, 12);

// Comparing
const match = await bcrypt.compare(password, storedHash);
```

---

### Insecure JWT (CWE-347)

**What it is**: JWT tokens with weak secrets, missing validation, or insecure algorithms.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - Hardcoded weak secret
jwt.sign(payload, "secret");

// BAD - Not verifying algorithm
jwt.verify(token, secret);  // Allows algorithm switching attacks
```

**Secure Code**:
```javascript
// GOOD - Strong secret from env, explicit algorithm
jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });

jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
```

---

## Sensitive Data Exposure

### Weak Cryptography (CWE-327)

**What it is**: Using broken or weak cryptographic algorithms.

**Risk Level**: Medium-High

**Vulnerable Code**:
```javascript
// BAD - MD5 is broken
crypto.createHash('md5').update(data).digest('hex');

// BAD - SHA1 is deprecated
crypto.createHash('sha1').update(data).digest('hex');

// BAD - DES is weak
crypto.createCipheriv('des', key, iv);
```

**Secure Code**:
```javascript
// GOOD - SHA256 or SHA3 for hashing
crypto.createHash('sha256').update(data).digest('hex');

// GOOD - AES-256-GCM for encryption
crypto.createCipheriv('aes-256-gcm', key, iv);

// GOOD - Use bcrypt/argon2 for passwords
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
```

---

### TLS/SSL Issues (CWE-295)

**What it is**: Disabling certificate verification or using weak TLS.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - Disables certificate verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// BAD - rejectUnauthorized: false
https.request({ rejectUnauthorized: false });
```

**Secure Code**:
```javascript
// GOOD - Always verify certificates
https.request({
  rejectUnauthorized: true,
  ca: fs.readFileSync('ca-cert.pem')
});

// GOOD - Use proper CA bundle
// Node.js uses system CA by default
```

---

## Security Misconfigurations

### Debug Mode in Production

**Vulnerable**:
```javascript
// BAD - Debug enabled in production
app.use(errorHandler({ debug: true }));

// BAD - Stack traces exposed
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});
```

**Secure**:
```javascript
// GOOD - Environment-aware error handling
app.use((err, req, res, next) => {
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;
  res.status(500).json({ error: message });
});
```

---

### Open Redirect (CWE-601)

**What it is**: Redirecting users to untrusted sites based on user input.

**Risk Level**: Medium

**Vulnerable Code**:
```javascript
// BAD - Unvalidated redirect
res.redirect(req.query.returnUrl);
```

**Secure Code**:
```javascript
// GOOD - Whitelist allowed domains
const allowedHosts = ['example.com', 'app.example.com'];
const url = new URL(req.query.returnUrl, 'https://example.com');
if (allowedHosts.includes(url.host)) {
  res.redirect(url.toString());
} else {
  res.redirect('/');
}

// GOOD - Only allow relative paths
const returnPath = req.query.returnUrl;
if (returnPath.startsWith('/') && !returnPath.startsWith('//')) {
  res.redirect(returnPath);
}
```

---

## Insecure Dependencies

### Known Vulnerable Packages (CWE-1035)

**What it is**: Using npm/pip packages with known CVEs.

**Detection**:
```bash
# npm
npm audit

# yarn
yarn audit

# pip
pip-audit
safety check
```

**Prevention**:
- Run `npm audit` / `pip-audit` in CI/CD
- Use Dependabot or Renovate for auto-updates
- Pin dependency versions
- Review changelogs before major updates

---

## File Handling Vulnerabilities

### Path Traversal (CWE-22)

**What it is**: Accessing files outside intended directory using `../` sequences.

**Risk Level**: High

**Vulnerable Code**:
```javascript
// BAD - User controls file path
const filePath = `/uploads/${req.query.filename}`;
fs.readFile(filePath);
// Attacker: ?filename=../../../etc/passwd
```

**Secure Code**:
```javascript
// GOOD - Resolve and validate path
const path = require('path');
const uploadsDir = '/var/app/uploads';
const filename = path.basename(req.query.filename); // Strips directory components
const filePath = path.join(uploadsDir, filename);

// Verify it's still in uploads directory
if (!filePath.startsWith(uploadsDir)) {
  throw new Error('Invalid path');
}
```

---

### Unrestricted File Upload (CWE-434)

**What it is**: Allowing upload of dangerous file types (PHP, JS, executables).

**Risk Level**: Critical

**Vulnerable Code**:
```javascript
// BAD - No file type validation
app.post('/upload', upload.single('file'), (req, res) => {
  // Accepts any file
});
```

**Secure Code**:
```javascript
// GOOD - Validate file type and content
const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
const fileFilter = (req, file, cb) => {
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

// GOOD - Also check magic bytes
import fileType from 'file-type';
const type = await fileType.fromBuffer(buffer);
if (!allowedMimes.includes(type?.mime)) {
  throw new Error('Invalid file');
}

// GOOD - Store outside webroot, randomize names
const filename = crypto.randomUUID() + '.jpg';
```

---

## Insecure Deserialization

### Pickle/YAML/JSON Deserialization (CWE-502)

**What it is**: Deserializing untrusted data can execute arbitrary code.

**Risk Level**: Critical

**Vulnerable Code (Python)**:
```python
# BAD - pickle with untrusted data
import pickle
data = pickle.loads(user_input)

# BAD - yaml.load without safe loader
import yaml
data = yaml.load(user_input)
```

**Secure Code (Python)**:
```python
# GOOD - Use safe loader
import yaml
data = yaml.safe_load(user_input)

# GOOD - Use JSON instead of pickle
import json
data = json.loads(user_input)
```

---

## Quick Reference: OWASP Top 10 Mapping

| OWASP 2021 | CWE | Detected By |
|------------|-----|-------------|
| A01 Broken Access Control | CWE-22, CWE-601 | Semgrep |
| A02 Cryptographic Failures | CWE-327, CWE-798 | Semgrep, Gitleaks |
| A03 Injection | CWE-78, CWE-79, CWE-89 | Semgrep |
| A04 Insecure Design | Various | Manual Review |
| A05 Security Misconfiguration | CWE-295 | Semgrep |
| A06 Vulnerable Components | CWE-1035 | Trivy |
| A07 Auth Failures | CWE-521, CWE-287 | Semgrep |
| A08 Data Integrity Failures | CWE-502 | Semgrep |
| A09 Logging Failures | CWE-778 | Manual Review |
| A10 SSRF | CWE-918 | Semgrep |

---

## Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Semgrep Rules Registry](https://semgrep.dev/r)

---

*This document is maintained by the Vibeship Scanner team. Last updated: 2025-12-02*
