# Vibeship Scanner - Scanning Rules Documentation

## Overview

Vibeship Scanner uses three primary scanning tools, each with custom rule configurations optimized for vibe-coded applications.

## Scanner Configuration

### 1. Semgrep (SAST)

Static Application Security Testing for code vulnerabilities.

#### Installation
```dockerfile
RUN pip install semgrep
```

#### Rule Categories

##### A. Secrets in Code
```yaml
rules:
  - id: hardcoded-api-key
    patterns:
      - pattern-either:
          - pattern: $KEY = "sk-..."
          - pattern: $KEY = "pk_..."
          - pattern: apiKey = "..."
          - pattern: api_key = "..."
    message: "Hardcoded API key detected"
    severity: CRITICAL
    metadata:
      category: secrets
      fix_template: env_variable

  - id: hardcoded-jwt-secret
    patterns:
      - pattern-either:
          - pattern: jwt.sign($PAYLOAD, "...")
          - pattern: JWT_SECRET = "..."
          - pattern: jwtSecret = "..."
    message: "Hardcoded JWT secret"
    severity: CRITICAL
    metadata:
      category: secrets
      fix_template: env_variable

  - id: hardcoded-database-url
    patterns:
      - pattern-either:
          - pattern: DATABASE_URL = "postgres://..."
          - pattern: connectionString = "mongodb://..."
          - pattern: mysql.createConnection({..., password: "..."})
    message: "Hardcoded database credentials"
    severity: CRITICAL
    metadata:
      category: secrets
      fix_template: env_variable
```

##### B. SQL Injection
```yaml
rules:
  - id: sql-injection-template-string
    patterns:
      - pattern-either:
          - pattern: $DB.query(`... ${$VAR} ...`)
          - pattern: $DB.execute(`... ${$VAR} ...`)
          - pattern: |
              $QUERY = `SELECT ... ${$VAR} ...`
              $DB.query($QUERY)
    message: "SQL injection via template string"
    severity: CRITICAL
    metadata:
      category: code
      cwe: CWE-89
      fix_template: parameterized_query

  - id: sql-injection-string-concat
    patterns:
      - pattern: $DB.query("..." + $VAR + "...")
    message: "SQL injection via string concatenation"
    severity: CRITICAL
    metadata:
      category: code
      cwe: CWE-89
      fix_template: parameterized_query

  - id: prisma-raw-query
    patterns:
      - pattern: prisma.$queryRaw`... ${$VAR} ...`
      - pattern: prisma.$executeRaw`... ${$VAR} ...`
    message: "Prisma raw query with user input"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-89
      fix_template: prisma_safe_query
```

##### C. XSS (Cross-Site Scripting)
```yaml
rules:
  - id: xss-innerhtml
    patterns:
      - pattern: $EL.innerHTML = $VAR
    message: "XSS via innerHTML assignment"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-79
      fix_template: text_content

  - id: xss-dangerously-set-html
    patterns:
      - pattern: dangerouslySetInnerHTML={{__html: $VAR}}
    message: "XSS via dangerouslySetInnerHTML"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-79
      fix_template: sanitize_html

  - id: xss-document-write
    patterns:
      - pattern: document.write($VAR)
    message: "XSS via document.write"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-79
      fix_template: safe_dom_manipulation
```

##### D. Authentication Issues
```yaml
rules:
  - id: missing-auth-check-api
    patterns:
      - pattern-inside: |
          export async function $METHOD(req, res) {
            ...
          }
      - pattern-not: |
          if (!$AUTH) { ... }
      - pattern-not: |
          await $AUTH($REQ)
      - metavariable-pattern:
          metavariable: $METHOD
          patterns:
            - pattern-either:
                - pattern: POST
                - pattern: PUT
                - pattern: DELETE
    message: "API route may be missing authentication check"
    severity: MEDIUM
    metadata:
      category: code
      cwe: CWE-306
      fix_template: add_auth_middleware

  - id: weak-password-hashing
    patterns:
      - pattern-either:
          - pattern: md5($PASSWORD)
          - pattern: sha1($PASSWORD)
          - pattern: crypto.createHash("md5").update($PASSWORD)
    message: "Weak password hashing algorithm"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-328
      fix_template: bcrypt_hash

  - id: jwt-no-expiry
    patterns:
      - pattern: jwt.sign($PAYLOAD, $SECRET)
      - pattern-not: jwt.sign($PAYLOAD, $SECRET, {..., expiresIn: ...})
    message: "JWT token without expiration"
    severity: MEDIUM
    metadata:
      category: code
      cwe: CWE-613
      fix_template: jwt_with_expiry
```

##### E. Insecure Configuration
```yaml
rules:
  - id: cors-allow-all
    patterns:
      - pattern-either:
          - pattern: "cors({ origin: '*' })"
          - pattern: "cors({ origin: true })"
          - pattern: 'Access-Control-Allow-Origin: "*"'
    message: "CORS allows all origins"
    severity: MEDIUM
    metadata:
      category: code
      cwe: CWE-942
      fix_template: cors_whitelist

  - id: disabled-ssl-verification
    patterns:
      - pattern-either:
          - pattern: rejectUnauthorized = false
          - pattern: NODE_TLS_REJECT_UNAUTHORIZED = "0"
          - pattern: verify = False
    message: "SSL certificate verification disabled"
    severity: HIGH
    metadata:
      category: code
      cwe: CWE-295
      fix_template: enable_ssl_verify

  - id: debug-mode-production
    patterns:
      - pattern-either:
          - pattern: DEBUG = True
          - pattern: debug = true
          - pattern: app.debug = True
    message: "Debug mode may be enabled in production"
    severity: LOW
    metadata:
      category: code
      fix_template: check_environment
```

##### F. Framework-Specific Rules

###### Next.js
```yaml
rules:
  - id: nextjs-api-no-auth
    patterns:
      - pattern-inside: |
          export default function handler(req, res) {
            ...
          }
      - pattern: res.json($DATA)
      - pattern-not-inside: |
          if (!$AUTH) { ... }
    message: "Next.js API route may lack authentication"
    severity: MEDIUM

  - id: nextjs-exposed-server-action
    patterns:
      - pattern: |
          'use server'
          ...
          export async function $FUNC($PARAMS) {
            ...
          }
      - pattern-not: |
          const session = await $AUTH()
    message: "Server action may be missing auth check"
    severity: MEDIUM
```

###### SvelteKit
```yaml
rules:
  - id: sveltekit-unvalidated-load
    patterns:
      - pattern-inside: |
          export async function load({ params }) {
            ...
          }
      - pattern: $DB.find({..., id: params.$ID})
      - pattern-not: |
          if (!$VALIDATE(params.$ID)) { ... }
    message: "SvelteKit load function with unvalidated params"
    severity: MEDIUM

  - id: sveltekit-html-unsafe
    patterns:
      - pattern: "{@html $VAR}"
    message: "Unescaped HTML in Svelte template"
    severity: HIGH
```

###### Supabase
```yaml
rules:
  - id: supabase-rls-bypass
    patterns:
      - pattern: supabase.from($TABLE).select().single()
      - pattern-not-inside: |
          supabase.auth.getUser()
    message: "Supabase query may bypass RLS"
    severity: MEDIUM

  - id: supabase-service-role-client
    patterns:
      - pattern: createClient($URL, $SERVICE_ROLE_KEY)
    message: "Service role key used in client-side code"
    severity: CRITICAL
```

---

### 2. Trivy (Dependency Scanning)

Vulnerability scanning for dependencies.

#### Installation
```dockerfile
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

#### Configuration
```yaml
# trivy.yaml
scan:
  scanners:
    - vuln
    - secret
    - misconfig

vulnerability:
    type:
      - os
      - library

severity:
    - CRITICAL
    - HIGH
    - MEDIUM
    - LOW

ignore-unfixed: false
```

#### Severity Mapping
| Trivy Severity | Vibeship Severity |
|----------------|-------------------|
| CRITICAL | critical |
| HIGH | high |
| MEDIUM | medium |
| LOW | low |
| UNKNOWN | info |

#### Output Parsing
```typescript
interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Severity: string;
  Title: string;
  Description: string;
  References: string[];
}

function parseTrivyResult(result: TrivyResult): Finding[] {
  return result.Results.flatMap(r =>
    r.Vulnerabilities?.map(v => ({
      id: v.VulnerabilityID,
      ruleId: `trivy-${v.VulnerabilityID}`,
      severity: mapSeverity(v.Severity),
      category: 'dependencies',
      title: `${v.PkgName}: ${v.Title || v.VulnerabilityID}`,
      description: v.Description,
      location: {
        file: r.Target,
        line: 0
      },
      fix: {
        available: !!v.FixedVersion,
        template: v.FixedVersion
          ? `Update ${v.PkgName} to ${v.FixedVersion}`
          : null
      },
      references: v.References
    })) || []
  );
}
```

---

### 3. Gitleaks (Secret Detection)

Pattern-based secret detection.

#### Installation
```dockerfile
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.0_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/
```

#### Custom Rules
```toml
# gitleaks.toml

title = "Vibeship Gitleaks Config"

[[rules]]
id = "openai-api-key"
description = "OpenAI API Key"
regex = '''sk-[a-zA-Z0-9]{48}'''
secretGroup = 0
keywords = ["openai", "sk-"]

[[rules]]
id = "anthropic-api-key"
description = "Anthropic API Key"
regex = '''sk-ant-[a-zA-Z0-9-]{95}'''
secretGroup = 0
keywords = ["anthropic", "claude", "sk-ant"]

[[rules]]
id = "stripe-secret-key"
description = "Stripe Secret Key"
regex = '''sk_live_[a-zA-Z0-9]{24,}'''
secretGroup = 0
keywords = ["stripe", "sk_live"]

[[rules]]
id = "stripe-publishable-key-in-server"
description = "Stripe Publishable Key in Server Code"
regex = '''pk_live_[a-zA-Z0-9]{24,}'''
path = '''(server|api|backend|\.server\.)'''
secretGroup = 0

[[rules]]
id = "supabase-service-role"
description = "Supabase Service Role Key"
regex = '''eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'''
keywords = ["supabase", "service_role"]

[[rules]]
id = "firebase-config"
description = "Firebase Configuration"
regex = '''AIza[0-9A-Za-z-_]{35}'''
keywords = ["firebase", "apiKey"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
secretGroup = 0

[[rules]]
id = "aws-secret-key"
description = "AWS Secret Access Key"
regex = '''[a-zA-Z0-9+/]{40}'''
keywords = ["aws_secret", "secret_access_key"]
entropy = 4.5

[[rules]]
id = "github-token"
description = "GitHub Token"
regex = '''gh[pousr]_[A-Za-z0-9_]{36,}'''
secretGroup = 0

[[rules]]
id = "vercel-token"
description = "Vercel Token"
regex = '''[a-zA-Z0-9]{24}'''
keywords = ["vercel", "VERCEL_TOKEN"]

[[rules]]
id = "database-url"
description = "Database Connection URL"
regex = '''(postgres|mysql|mongodb)://[^:]+:[^@]+@[^\s]+'''
secretGroup = 0

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'''
secretGroup = 0

[[rules]]
id = "jwt-secret"
description = "JWT Secret"
regex = '''.{20,}'''
keywords = ["JWT_SECRET", "jwt_secret", "jwtSecret"]
entropy = 4.0

[allowlist]
description = "Global allowlist"
paths = [
  '''\.test\.(js|ts|tsx)$''',
  '''\.spec\.(js|ts|tsx)$''',
  '''__tests__''',
  '''__mocks__''',
  '''\.example$''',
  '''\.sample$''',
  '''node_modules''',
  '''\.md$'''
]
```

---

## Fix Templates

### Template Structure
```typescript
interface FixTemplate {
  id: string;
  title: string;
  description: string;
  category: 'code' | 'dependencies' | 'secrets';
  stacks: string[];
  codeTemplate: string;
  estimatedMinutes: number;
}
```

### Common Fix Templates

#### env_variable
```typescript
{
  id: 'env_variable',
  title: 'Move to Environment Variable',
  description: 'Store sensitive values in environment variables instead of code',
  category: 'secrets',
  stacks: ['*'],
  codeTemplate: `
// Before (insecure)
const API_KEY = "sk-abc123...";

// After (secure)
const API_KEY = process.env.API_KEY;

// Add to .env.local (do NOT commit this file)
API_KEY=sk-abc123...

// Add to .env.example (commit this)
API_KEY=your-api-key-here
  `,
  estimatedMinutes: 2
}
```

#### parameterized_query
```typescript
{
  id: 'parameterized_query',
  title: 'Use Parameterized Queries',
  description: 'Prevent SQL injection by using parameterized queries',
  category: 'code',
  stacks: ['node', 'postgres', 'mysql'],
  codeTemplate: `
// Before (vulnerable)
const query = \`SELECT * FROM users WHERE id = \${userId}\`;
await db.query(query);

// After (secure) - PostgreSQL
const query = 'SELECT * FROM users WHERE id = $1';
await db.query(query, [userId]);

// After (secure) - MySQL
const query = 'SELECT * FROM users WHERE id = ?';
await db.query(query, [userId]);
  `,
  estimatedMinutes: 5
}
```

#### prisma_safe_query
```typescript
{
  id: 'prisma_safe_query',
  title: 'Use Prisma ORM Methods',
  description: 'Use Prisma built-in methods instead of raw queries',
  category: 'code',
  stacks: ['prisma'],
  codeTemplate: `
// Before (risky)
const users = await prisma.$queryRaw\`
  SELECT * FROM users WHERE name = \${name}
\`;

// After (secure)
const users = await prisma.user.findMany({
  where: { name }
});
  `,
  estimatedMinutes: 5
}
```

#### text_content
```typescript
{
  id: 'text_content',
  title: 'Use textContent Instead of innerHTML',
  description: 'Prevent XSS by using textContent for text-only content',
  category: 'code',
  stacks: ['javascript', 'typescript'],
  codeTemplate: `
// Before (vulnerable)
element.innerHTML = userInput;

// After (secure)
element.textContent = userInput;
  `,
  estimatedMinutes: 2
}
```

#### sanitize_html
```typescript
{
  id: 'sanitize_html',
  title: 'Sanitize HTML Before Rendering',
  description: 'Use DOMPurify to sanitize user-provided HTML',
  category: 'code',
  stacks: ['react', 'vue', 'svelte'],
  codeTemplate: `
// Install DOMPurify
npm install dompurify

// Before (vulnerable)
<div dangerouslySetInnerHTML={{__html: userHtml}} />

// After (secure)
import DOMPurify from 'dompurify';

const cleanHtml = DOMPurify.sanitize(userHtml);
<div dangerouslySetInnerHTML={{__html: cleanHtml}} />
  `,
  estimatedMinutes: 5
}
```

#### bcrypt_hash
```typescript
{
  id: 'bcrypt_hash',
  title: 'Use bcrypt for Password Hashing',
  description: 'Replace weak hashing with bcrypt',
  category: 'code',
  stacks: ['node'],
  codeTemplate: `
// Install bcrypt
npm install bcrypt

// Before (weak)
const hash = crypto.createHash('md5').update(password).digest('hex');

// After (secure)
import bcrypt from 'bcrypt';

const saltRounds = 10;
const hash = await bcrypt.hash(password, saltRounds);

// To verify
const match = await bcrypt.compare(password, hash);
  `,
  estimatedMinutes: 10
}
```

#### add_auth_middleware
```typescript
{
  id: 'add_auth_middleware',
  title: 'Add Authentication Middleware',
  description: 'Protect API routes with authentication checks',
  category: 'code',
  stacks: ['nextjs'],
  codeTemplate: `
// lib/auth.ts
import { getServerSession } from "next-auth";

export async function requireAuth(req: Request) {
  const session = await getServerSession();
  if (!session) {
    throw new Response("Unauthorized", { status: 401 });
  }
  return session;
}

// app/api/protected/route.ts
import { requireAuth } from "@/lib/auth";

export async function POST(req: Request) {
  const session = await requireAuth(req);

  // Now safe to handle request
  // ...
}
  `,
  estimatedMinutes: 15
}
```

#### cors_whitelist
```typescript
{
  id: 'cors_whitelist',
  title: 'Configure CORS Whitelist',
  description: 'Replace wildcard CORS with explicit origin whitelist',
  category: 'code',
  stacks: ['express', 'node'],
  codeTemplate: `
// Before (too permissive)
app.use(cors({ origin: '*' }));

// After (secure)
const allowedOrigins = [
  'https://yourdomain.com',
  'https://app.yourdomain.com',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : null
].filter(Boolean);

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
  `,
  estimatedMinutes: 10
}
```

---

## Severity Classification

### Severity Levels

| Level | Score Impact | Response Time | Description |
|-------|-------------|---------------|-------------|
| Critical | -25 | Immediate | Active exploit possible, secrets exposed |
| High | -10 | 24 hours | Significant vulnerability, likely exploitable |
| Medium | -5 | 1 week | Moderate risk, requires specific conditions |
| Low | -2 | 1 month | Minor issue, limited impact |
| Info | 0 | Optional | Best practice recommendation |

### Severity Assignment Rules

```typescript
function assignSeverity(finding: RawFinding): Severity {
  if (finding.category === 'secrets') {
    if (isProductionSecret(finding)) return 'critical';
    if (isLiveApiKey(finding)) return 'critical';
    return 'high';
  }

  if (finding.category === 'dependencies') {
    if (finding.cvssScore >= 9.0) return 'critical';
    if (finding.cvssScore >= 7.0) return 'high';
    if (finding.cvssScore >= 4.0) return 'medium';
    return 'low';
  }

  if (finding.cwe) {
    if (CRITICAL_CWES.includes(finding.cwe)) return 'critical';
    if (HIGH_CWES.includes(finding.cwe)) return 'high';
  }

  return finding.originalSeverity || 'medium';
}

const CRITICAL_CWES = [
  'CWE-89',   // SQL Injection
  'CWE-78',   // OS Command Injection
  'CWE-94',   // Code Injection
  'CWE-502',  // Deserialization
];

const HIGH_CWES = [
  'CWE-79',   // XSS
  'CWE-352',  // CSRF
  'CWE-918',  // SSRF
  'CWE-611',  // XXE
];
```

---

## Context-Aware Adjustments

### File Context Modifiers

```typescript
function adjustForContext(finding: Finding, context: FileContext): Finding {
  if (context.isTestFile) {
    return {
      ...finding,
      severity: downgradeSeverity(finding.severity),
      contextNote: 'Found in test file - lower production risk'
    };
  }

  if (context.isExampleFile) {
    return {
      ...finding,
      severity: downgradeSeverity(finding.severity),
      contextNote: 'Found in example file - may be intentional for demonstration'
    };
  }

  if (context.isMainBundle && finding.category === 'secrets') {
    return {
      ...finding,
      severity: 'critical',
      contextNote: 'Secret exposed in client-side bundle - critical risk'
    };
  }

  return finding;
}

function isTestFile(filePath: string): boolean {
  return /\.(test|spec)\.(js|ts|jsx|tsx)$/.test(filePath) ||
         filePath.includes('__tests__') ||
         filePath.includes('__mocks__');
}

function isExampleFile(filePath: string): boolean {
  return filePath.includes('example') ||
         filePath.includes('sample') ||
         filePath.includes('demo') ||
         filePath.endsWith('.example');
}

function isMainBundle(filePath: string, stack: StackInfo): boolean {
  if (stack.frameworks.includes('nextjs')) {
    return filePath.startsWith('app/') ||
           filePath.startsWith('pages/') ||
           filePath.startsWith('components/');
  }
  return filePath.startsWith('src/');
}
```

---

## Rule Lifecycle

### Shadow Mode Process

1. **Creation**: New rule added with `status: 'shadow'`
2. **Collection**: Rule runs on all scans, matches logged silently
3. **Validation**: After 50 matches or 2 weeks:
   - Sample 10 matches for review
   - Calculate precision estimate
4. **Promotion**: If precision >= 95%, promote to `status: 'active'`
5. **Monitoring**: Track false positive feedback
6. **Demotion**: If FP rate > 5%, demote back to shadow

### Rule Schema

```typescript
interface Rule {
  id: string;
  version: number;
  status: 'shadow' | 'validating' | 'active' | 'deprecated' | 'retired';
  source: 'manual' | 'ai_generated' | 'imported';

  ruleYaml: string;

  shadowMatches: number;
  activeMatches: number;
  truePositives: number;
  falsePositives: number;
  precision: number;

  shadowStartedAt: Date | null;
  promotedAt: Date | null;
  deprecatedAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
}
```
