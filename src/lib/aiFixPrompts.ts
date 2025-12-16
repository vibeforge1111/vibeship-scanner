/**
 * AI Fix Prompts - Copy-paste ready prompts for Claude Code, Cursor, and other AI tools
 *
 * Design principles:
 * 1. Specific location - File and line number
 * 2. Show the problem - Include the vulnerable code
 * 3. Show the solution - Include fixed code example
 * 4. Scope expansion - Ask AI to check for similar issues
 * 5. Verification - Ask AI to confirm the fix works
 * 6. Framework-aware - Use patterns for their specific framework
 */

export interface FindingContext {
	file: string;
	line?: number;
	code?: string;
	language?: string;
	framework?: string;
	title?: string;
	category?: string;
}

type PromptGenerator = (ctx: FindingContext) => string;

/**
 * SQL Injection - The #1 most dangerous vulnerability
 */
const sqlInjectionPrompt: PromptGenerator = (ctx) => `
Fix the SQL injection vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The current vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the database query that uses string concatenation with user input.'}

Replace it with a parameterized query. Here's how for common libraries:

**For pg/node-postgres:**
\`\`\`javascript
// Instead of: db.query("SELECT * FROM users WHERE id = " + userId)
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
\`\`\`

**For mysql2:**
\`\`\`javascript
// Instead of: connection.query("SELECT * FROM users WHERE id = " + userId)
const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
\`\`\`

**For Prisma:**
\`\`\`javascript
// Instead of: prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE id = \${userId}\`)
const user = await prisma.user.findUnique({ where: { id: userId } });
// Or if raw SQL needed:
const user = await prisma.$queryRaw(Prisma.sql\`SELECT * FROM users WHERE id = \${userId}\`);
\`\`\`

After fixing this location:
1. Search the entire codebase for similar patterns: look for string concatenation (+) or template literals (\${}) inside SQL queries
2. Fix ALL instances you find - SQL injection is critical
3. List every file you modified
4. Show me the complete updated code for each fix
`.trim();

/**
 * XSS - Cross-Site Scripting
 */
const xssPrompt: PromptGenerator = (ctx) => `
Fix the XSS (Cross-Site Scripting) vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The current vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is being rendered without sanitization.'}

Here's how to fix it depending on your situation:

**Option 1: For plain text display (most common):**
\`\`\`javascript
// Instead of: element.innerHTML = userInput
element.textContent = userInput;  // Safe - treats everything as text
\`\`\`

**Option 2: If you MUST render HTML, sanitize it:**
\`\`\`javascript
import DOMPurify from 'dompurify';

// Instead of: element.innerHTML = userInput
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

**For React:**
\`\`\`jsx
// Safe by default - React escapes content:
<div>{userInput}</div>

// If you MUST use dangerouslySetInnerHTML:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
\`\`\`

**For Svelte:**
\`\`\`svelte
<!-- Safe by default: -->
<p>{userInput}</p>

<!-- If you MUST use @html: -->
<script>
  import DOMPurify from 'dompurify';
  $: safeHtml = DOMPurify.sanitize(userInput);
</script>
{@html safeHtml}
\`\`\`

After fixing:
1. Install DOMPurify if needed: \`npm install dompurify\`
2. Search for other uses of innerHTML, dangerouslySetInnerHTML, or {@html} in the codebase
3. Fix any that use unsanitized user input
4. Show me all the changes
`.trim();

/**
 * Hardcoded Secrets - API keys, passwords in code
 */
const hardcodedSecretPrompt: PromptGenerator = (ctx) => `
Remove the hardcoded secret from ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The exposed secret:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the hardcoded API key, password, or secret in this file.'}

**Step 1: Move to environment variables**

Create or update your \`.env\` file:
\`\`\`
# .env (NEVER commit this file!)
DATABASE_URL=your-connection-string
API_KEY=your-api-key
JWT_SECRET=your-jwt-secret
\`\`\`

**Step 2: Update the code**

\`\`\`javascript
// For Node.js / Express:
const apiKey = process.env.API_KEY;

// For Next.js (server-side):
const secret = process.env.JWT_SECRET;

// For Next.js (client-side - only for non-sensitive values):
const publicApiUrl = process.env.NEXT_PUBLIC_API_URL;

// For Vite / SvelteKit:
const apiKey = import.meta.env.VITE_API_KEY;
\`\`\`

**Step 3: Secure your .env file**

Add to \`.gitignore\`:
\`\`\`
.env
.env.local
.env*.local
\`\`\`

**CRITICAL:** If this secret was already committed to git:
1. The secret is exposed in git history forever
2. You MUST rotate/regenerate the secret immediately
3. Check if anyone unauthorized accessed it

After fixing:
1. Search the codebase for other hardcoded secrets (look for patterns like "sk-", "api_key", "password", "secret")
2. Move ALL secrets to environment variables
3. List every secret you found and moved
4. Confirm .env is in .gitignore
`.trim();

/**
 * Command Injection
 */
const commandInjectionPrompt: PromptGenerator = (ctx) => `
Fix the command injection vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is being passed to a shell command.'}

**The Problem:** Using \`exec()\` with user input allows attackers to run ANY command on your server.

**Fix Option 1: Use execFile with separate arguments (preferred)**
\`\`\`javascript
const { execFile } = require('child_process');

// Instead of: exec(\`convert \${userFilename} output.png\`)
execFile('convert', [userFilename, 'output.png'], (error, stdout) => {
  // handle result
});
\`\`\`

**Fix Option 2: Use a library that doesn't shell out**
\`\`\`javascript
// For image processing, use sharp instead of ImageMagick CLI:
import sharp from 'sharp';
await sharp(inputFile).resize(300).toFile(outputFile);

// For git operations, use simple-git instead of CLI:
import simpleGit from 'simple-git';
await simpleGit().clone(repoUrl);
\`\`\`

**Fix Option 3: If you MUST use exec, validate strictly**
\`\`\`javascript
// Whitelist allowed values
const ALLOWED_FORMATS = ['png', 'jpg', 'webp'];
if (!ALLOWED_FORMATS.includes(format)) {
  throw new Error('Invalid format');
}

// Or validate with strict regex
if (!/^[a-zA-Z0-9_-]+$/.test(userInput)) {
  throw new Error('Invalid input');
}
\`\`\`

After fixing:
1. Search for other uses of exec(), execSync(), spawn() with user input
2. Replace them with safe alternatives
3. Show me all changes made
`.trim();

/**
 * Path Traversal
 */
const pathTraversalPrompt: PromptGenerator = (ctx) => `
Fix the path traversal vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is used in a file path.'}

**The Problem:** Attackers can use \`../\` to escape the intended directory and read any file.

**The Fix:**
\`\`\`javascript
import path from 'path';

// Define your safe base directory
const UPLOAD_DIR = path.resolve('./uploads');

function getSafePath(userFilename) {
  // Remove any directory components - only keep the filename
  const safeName = path.basename(userFilename);

  // Resolve the full path
  const fullPath = path.resolve(UPLOAD_DIR, safeName);

  // CRITICAL: Verify the path is still within our safe directory
  if (!fullPath.startsWith(UPLOAD_DIR + path.sep)) {
    throw new Error('Invalid file path');
  }

  return fullPath;
}

// Usage:
const safePath = getSafePath(req.query.filename);
const content = fs.readFileSync(safePath);
\`\`\`

**Additional protection:**
\`\`\`javascript
// Reject suspicious patterns outright
function validateFilename(filename) {
  if (filename.includes('..') ||
      filename.includes('\\0') ||
      path.isAbsolute(filename)) {
    throw new Error('Invalid filename');
  }
  return filename;
}
\`\`\`

After fixing:
1. Search for other places where user input is used with fs operations
2. Apply the same path validation pattern
3. Show me all the files you modified
`.trim();

/**
 * SSRF - Server-Side Request Forgery
 */
const ssrfPrompt: PromptGenerator = (ctx) => `
Fix the SSRF (Server-Side Request Forgery) vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user-provided URLs are being fetched by the server.'}

**The Problem:** Attackers can make your server request internal services, cloud metadata, or scan your network.

**The Fix:**
\`\`\`javascript
function validateUrl(userUrl) {
  const url = new URL(userUrl);

  // Block private IP ranges and localhost
  const blockedPatterns = [
    /^localhost$/i,
    /^127\\./,
    /^10\\./,
    /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./,
    /^192\\.168\\./,
    /^169\\.254\\./, // AWS metadata
    /^0\\./,
    /^\\[::1\\]/,    // IPv6 localhost
    /^\\[fc/i,       // IPv6 private
    /^\\[fd/i,       // IPv6 private
  ];

  if (blockedPatterns.some(p => p.test(url.hostname))) {
    throw new Error('URL not allowed: private address');
  }

  // Only allow HTTPS in production
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
    throw new Error('URL not allowed: HTTPS required');
  }

  // Optional: Whitelist specific domains
  const allowedHosts = ['api.stripe.com', 'api.github.com'];
  if (!allowedHosts.includes(url.hostname)) {
    throw new Error('URL not allowed: domain not in whitelist');
  }

  return url.href;
}

// Usage:
const safeUrl = validateUrl(req.body.webhookUrl);
const response = await fetch(safeUrl);
\`\`\`

After fixing:
1. Search for other fetch(), axios(), or http requests with user-provided URLs
2. Apply URL validation to all of them
3. Show me all changes
`.trim();

/**
 * Missing Authentication
 */
const missingAuthPrompt: PromptGenerator = (ctx) => `
Add authentication to the unprotected endpoint in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The unprotected code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the API endpoint that lacks authentication.'}

**For Express.js:**
\`\`\`javascript
// Create auth middleware
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Apply to routes
router.get('/api/users', requireAuth, (req, res) => {
  // Now req.user is available
});
\`\`\`

**For Next.js API Routes:**
\`\`\`javascript
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export async function GET(request) {
  const session = await getServerSession(authOptions);

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // User is authenticated, proceed
  const users = await db.users.findMany();
  return Response.json(users);
}
\`\`\`

**For SvelteKit:**
\`\`\`javascript
// src/routes/api/users/+server.ts
import { error, json } from '@sveltejs/kit';

export async function GET({ locals }) {
  const session = await locals.getSession();

  if (!session) {
    throw error(401, 'Unauthorized');
  }

  const users = await db.users.findMany();
  return json(users);
}
\`\`\`

After fixing:
1. Check ALL API routes in this file and nearby files
2. Add authentication to any that handle sensitive data
3. List all endpoints you protected
`.trim();

/**
 * Open Redirect
 */
const openRedirectPrompt: PromptGenerator = (ctx) => `
Fix the open redirect vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is used in a redirect.'}

**The Problem:** Attackers can create links like \`yoursite.com/redirect?url=evil.com\` to phish users.

**The Fix:**
\`\`\`javascript
function getSafeRedirectUrl(userUrl, allowedHosts = []) {
  // Default to home page
  if (!userUrl) return '/';

  try {
    // Parse relative to your domain
    const url = new URL(userUrl, 'https://yoursite.com');

    // Allow relative paths (same origin)
    if (url.origin === 'https://yoursite.com') {
      return url.pathname + url.search;
    }

    // Check whitelist for external redirects
    if (allowedHosts.includes(url.hostname)) {
      return userUrl;
    }
  } catch {
    // Invalid URL
  }

  // Default to safe location
  return '/';
}

// Usage:
const returnUrl = getSafeRedirectUrl(
  req.query.returnUrl,
  ['auth.yoursite.com', 'app.yoursite.com']
);
res.redirect(returnUrl);
\`\`\`

**Even simpler - only allow relative paths:**
\`\`\`javascript
function getSafeRedirect(url) {
  // Only allow paths starting with /
  if (url && url.startsWith('/') && !url.startsWith('//')) {
    return url;
  }
  return '/';
}
\`\`\`

After fixing:
1. Search for other res.redirect() or window.location uses with user input
2. Apply validation to all of them
3. Show me the changes
`.trim();

/**
 * Insecure Cookie
 */
const insecureCookiePrompt: PromptGenerator = (ctx) => `
Fix the insecure cookie configuration in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where cookies are being set without proper security flags.'}

**The Fix - Set ALL security flags:**
\`\`\`javascript
res.cookie('session', token, {
  httpOnly: true,     // Prevents JavaScript access (blocks XSS theft)
  secure: true,       // Only sent over HTTPS
  sameSite: 'strict', // Prevents CSRF attacks
  maxAge: 3600000,    // 1 hour - don't make sessions last forever
  path: '/',          // Available site-wide
});

// For development (if you need http://localhost):
res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',    // 'lax' allows some cross-site for OAuth flows
  maxAge: 3600000,
});
\`\`\`

**For Express session middleware:**
\`\`\`javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
\`\`\`

After fixing:
1. Search for other cookie-setting code
2. Ensure all session/auth cookies have these flags
3. Show me all changes
`.trim();

/**
 * Weak Cryptography / Password Hashing
 */
const weakCryptoPrompt: PromptGenerator = (ctx) => `
Fix the weak cryptography in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where MD5, SHA1, or other weak hashing is used.'}

**For Password Hashing - Use bcrypt:**
\`\`\`javascript
import bcrypt from 'bcrypt';

// Hashing a password (registration)
const saltRounds = 12;  // Higher = slower but more secure
const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
// Store hashedPassword in database

// Verifying a password (login)
const isValid = await bcrypt.compare(plainPassword, storedHash);
if (!isValid) {
  throw new Error('Invalid password');
}
\`\`\`

**For General Hashing (not passwords):**
\`\`\`javascript
import crypto from 'crypto';

// Use SHA-256 instead of MD5/SHA1
const hash = crypto.createHash('sha256').update(data).digest('hex');
\`\`\`

**For Encryption:**
\`\`\`javascript
import crypto from 'crypto';

// Use AES-256-GCM for encryption
const algorithm = 'aes-256-gcm';
const key = crypto.scryptSync(password, salt, 32);
const iv = crypto.randomBytes(16);

const cipher = crypto.createCipheriv(algorithm, key, iv);
let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag();
\`\`\`

After fixing:
1. Search for MD5, SHA1, or other weak algorithms
2. Replace with appropriate modern alternatives
3. If passwords were stored with weak hashing, plan a migration
4. Show me all changes
`.trim();

/**
 * Eval Usage
 */
const evalPrompt: PromptGenerator = (ctx) => `
Remove the dangerous eval() usage in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where eval() or new Function() is used with user input.'}

**The Problem:** eval() executes ANY code - attackers have full control of your application.

**Safe Alternatives:**

**For JSON parsing:**
\`\`\`javascript
// Instead of: eval('(' + jsonString + ')')
const data = JSON.parse(jsonString);
\`\`\`

**For math expressions:**
\`\`\`javascript
// Instead of: eval(userExpression)
import { evaluate } from 'mathjs';
const result = evaluate(userExpression); // Only allows math
\`\`\`

**For dynamic property access:**
\`\`\`javascript
// Instead of: eval('obj.' + propName)
const value = obj[propName];

// With validation:
const allowedProps = ['name', 'email', 'age'];
if (allowedProps.includes(propName)) {
  const value = obj[propName];
}
\`\`\`

**For dynamic function calls:**
\`\`\`javascript
// Instead of: eval(functionName + '()')
const handlers = {
  'processA': processA,
  'processB': processB,
};
const handler = handlers[functionName];
if (handler) {
  handler();
}
\`\`\`

After fixing:
1. Search for eval(), new Function(), setTimeout/setInterval with strings
2. Replace all with safe alternatives
3. Show me the changes
`.trim();

/**
 * CORS Misconfiguration
 */
const corsPrompt: PromptGenerator = (ctx) => `
Fix the CORS misconfiguration in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where CORS is configured with overly permissive settings.'}

**The Problem:** \`Access-Control-Allow-Origin: *\` lets ANY website make requests to your API.

**The Fix:**
\`\`\`javascript
import cors from 'cors';

// Define allowed origins
const allowedOrigins = [
  'https://yourapp.com',
  'https://www.yourapp.com',
  'https://app.yourapp.com',
];

// Add development origins only in dev
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000');
  allowedOrigins.push('http://localhost:5173');
}

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,  // If you need cookies/auth headers
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
\`\`\`

**For Next.js API routes:**
\`\`\`javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: 'https://yourapp.com' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,PUT,DELETE' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type,Authorization' },
        ],
      },
    ];
  },
};
\`\`\`

After fixing:
1. List all your legitimate frontend origins
2. Update CORS to only allow those
3. Test that your app still works
4. Show me the changes
`.trim();

/**
 * Prototype Pollution
 */
const prototypePollutionPrompt: PromptGenerator = (ctx) => `
Fix the prototype pollution vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is used as object keys or in recursive merges.'}

**The Problem:** Attackers can inject \`__proto__\` to modify Object.prototype and affect ALL objects.

**Fix Option 1: Validate object keys**
\`\`\`javascript
function safeSet(obj, key, value) {
  // Block prototype pollution keys
  const dangerous = ['__proto__', 'constructor', 'prototype'];
  if (dangerous.includes(key)) {
    throw new Error('Invalid key');
  }
  obj[key] = value;
}
\`\`\`

**Fix Option 2: Use Map instead of objects for user data**
\`\`\`javascript
// Instead of: const data = {}; data[userKey] = userValue;
const data = new Map();
data.set(userKey, userValue);
\`\`\`

**Fix Option 3: Use Object.create(null)**
\`\`\`javascript
// Creates an object with no prototype
const data = Object.create(null);
data[userKey] = userValue; // __proto__ won't affect Object.prototype
\`\`\`

**Fix Option 4: Safe deep merge**
\`\`\`javascript
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Skip dangerous keys
    }
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
\`\`\`

After fixing:
1. Search for dynamic property assignment with user input
2. Search for deep merge/extend functions
3. Apply protections to all of them
4. Show me the changes
`.trim();

/**
 * JWT Issues
 */
const jwtPrompt: PromptGenerator = (ctx) => `
Fix the JWT security issue in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the JWT signing or verification code.'}

**Common JWT Security Fixes:**

**1. Always set expiration:**
\`\`\`javascript
const token = jwt.sign(
  { userId: user.id, email: user.email },
  process.env.JWT_SECRET,
  {
    expiresIn: '15m',  // Access tokens: 15 minutes
    issuer: 'yourapp.com',
    audience: 'yourapp.com'
  }
);
\`\`\`

**2. Use strong secrets:**
\`\`\`bash
# Generate a secure secret (run in terminal):
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
\`\`\`

**3. Verify properly with algorithm restriction:**
\`\`\`javascript
const decoded = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],  // CRITICAL: Specify allowed algorithms
  issuer: 'yourapp.com',
  audience: 'yourapp.com'
});
\`\`\`

**4. Implement refresh tokens:**
\`\`\`javascript
// Short-lived access token
const accessToken = jwt.sign({ userId }, secret, { expiresIn: '15m' });

// Long-lived refresh token (store securely, allow revocation)
const refreshToken = jwt.sign(
  { userId, type: 'refresh' },
  secret,
  { expiresIn: '7d' }
);
\`\`\`

After fixing:
1. Ensure ALL tokens have expiration
2. Move secret to environment variable
3. Add algorithm restriction to all verify() calls
4. Show me the changes
`.trim();

/**
 * NoSQL Injection
 */
const nosqlInjectionPrompt: PromptGenerator = (ctx) => `
Fix the NoSQL injection vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user input is used in MongoDB queries.'}

**The Problem:** Attackers can inject operators like \`{$gt: ""}\` to bypass authentication.

**Fix for MongoDB:**
\`\`\`javascript
// Vulnerable:
const user = await db.collection('users').findOne({
  username: req.body.username,
  password: req.body.password  // Attacker sends: {"$gt": ""}
});

// Safe - validate input types:
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    throw new Error('Invalid input type');
  }
  return input;
}

const user = await db.collection('users').findOne({
  username: sanitizeInput(req.body.username),
  password: sanitizeInput(req.body.password)
});
\`\`\`

**Even better - use schema validation:**
\`\`\`javascript
import { z } from 'zod';

const loginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(100)
});

const { username, password } = loginSchema.parse(req.body);
\`\`\`

**For Mongoose:**
\`\`\`javascript
// Mongoose sanitizes by default, but validate anyway:
import mongoSanitize from 'express-mongo-sanitize';
app.use(mongoSanitize()); // Strips $ and . from req.body
\`\`\`

After fixing:
1. Add input validation to ALL MongoDB queries
2. Consider adding express-mongo-sanitize middleware
3. Show me the changes
`.trim();

/**
 * Insecure Deserialization
 */
const deserializationPrompt: PromptGenerator = (ctx) => `
Fix the insecure deserialization in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where untrusted data is being deserialized.'}

**The Problem:** Deserializing untrusted data can execute arbitrary code.

**Safe Alternatives:**

**Use JSON instead of native serialization:**
\`\`\`javascript
// Instead of: eval(serializedData) or custom deserialize
const data = JSON.parse(jsonString);

// Validate the structure:
import { z } from 'zod';
const schema = z.object({
  id: z.number(),
  name: z.string(),
  // ... define expected shape
});
const validated = schema.parse(JSON.parse(jsonString));
\`\`\`

**If you need to serialize/deserialize complex objects:**
\`\`\`javascript
// Use a safe library like superjson
import superjson from 'superjson';

const serialized = superjson.stringify(data);
const deserialized = superjson.parse(serialized);
\`\`\`

**For Node.js - avoid:**
- \`eval()\`
- \`new Function()\`
- \`node-serialize\` (has known RCE)
- \`serialize-javascript\` with untrusted input

After fixing:
1. Search for serialize/deserialize/eval patterns
2. Replace with JSON.parse + validation
3. Show me the changes
`.trim();

/**
 * CSRF - Cross-Site Request Forgery
 */
const csrfPrompt: PromptGenerator = (ctx) => `
Fix the CSRF vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the form or API endpoint that lacks CSRF protection.'}

**The Problem:** Attackers can trick logged-in users into performing unwanted actions.

**Fix for Express:**
\`\`\`javascript
import csrf from 'csurf';
import cookieParser from 'cookie-parser';

app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Send token to client
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// In your HTML form:
// <input type="hidden" name="_csrf" value="{{csrfToken}}">
\`\`\`

**Fix for SvelteKit:**
\`\`\`javascript
// src/hooks.server.ts
import { csrf } from 'sveltekit-csrf';

export const handle = csrf();

// Forms automatically include CSRF token with use:enhance
\`\`\`

**Fix for Next.js:**
\`\`\`javascript
// Using next-csrf
import { csrf } from 'next-csrf';

const { csrfToken, validateCsrf } = csrf();

export default async function handler(req, res) {
  await validateCsrf(req, res);
  // ... handle request
}
\`\`\`

**Alternative - Use SameSite cookies:**
\`\`\`javascript
// If your API only uses cookies for auth:
res.cookie('session', token, {
  sameSite: 'strict',  // Prevents cross-site requests
  httpOnly: true,
  secure: true
});
\`\`\`

After fixing:
1. Add CSRF protection to all state-changing endpoints (POST, PUT, DELETE)
2. Test that forms still work
3. Show me the changes
`.trim();

/**
 * Information Disclosure
 */
const infoDisclosurePrompt: PromptGenerator = (ctx) => `
Fix the information disclosure in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where sensitive information is being exposed.'}

**Common Fixes:**

**1. Don't expose stack traces in production:**
\`\`\`javascript
app.use((err, req, res, next) => {
  console.error(err); // Log internally

  res.status(500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  });
});
\`\`\`

**2. Don't return sensitive fields in API responses:**
\`\`\`javascript
// Bad: returning entire user object
res.json(user);

// Good: explicitly select safe fields
res.json({
  id: user.id,
  name: user.name,
  email: user.email
  // Don't include: password, passwordHash, internalId, etc.
});

// Or use a transform function
function sanitizeUser(user) {
  const { password, passwordHash, ...safe } = user;
  return safe;
}
\`\`\`

**3. Remove debug endpoints in production:**
\`\`\`javascript
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug/info', (req, res) => {
    // Only available in development
  });
}
\`\`\`

**4. Set proper error pages:**
\`\`\`javascript
// Don't show framework default error pages
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});
\`\`\`

After fixing:
1. Search for console.log, res.send(err), and similar patterns
2. Ensure production only shows generic errors
3. Show me the changes
`.trim();

/**
 * XXE - XML External Entity
 */
const xxePrompt: PromptGenerator = (ctx) => `
Fix the XXE (XML External Entity) vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where XML is being parsed without disabling external entities.'}

**The Problem:** XXE allows attackers to read server files, access internal services, or cause denial of service.

**For Node.js (libxmljs):**
\`\`\`javascript
// Instead of: libxmljs.parseXml(xml, { noent: true })
const doc = libxmljs.parseXml(xml, { noent: false, nonet: true });
\`\`\`

**For Java:**
\`\`\`java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Disable DTDs entirely (most secure)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Or disable external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
\`\`\`

**For Python:**
\`\`\`python
# Use defusedxml instead of xml.etree
from defusedxml.ElementTree import parse, fromstring
doc = parse(xml_file)  # Safe from XXE

# Or disable entities manually:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
\`\`\`

**Best practice:** Use JSON instead of XML when possible.

After fixing:
1. Search for all XML parsing in the codebase
2. Ensure external entities are disabled everywhere
3. Consider migrating to JSON format
`.trim();

/**
 * IDOR - Insecure Direct Object Reference
 */
const idorPrompt: PromptGenerator = (ctx) => `
Fix the IDOR (Insecure Direct Object Reference) vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where user-supplied IDs are used to fetch resources without authorization.'}

**The Problem:** Attackers can access other users' data by changing IDs in the URL or request body.

**The Fix - Add Authorization Checks:**
\`\`\`javascript
// Express example - ALWAYS verify ownership
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const document = await Document.findById(req.params.id);

  if (!document) {
    return res.status(404).json({ error: 'Not found' });
  }

  // CRITICAL: Check if user owns this resource
  if (document.userId.toString() !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(document);
});
\`\`\`

**For list endpoints:**
\`\`\`javascript
// Only return resources belonging to the user
app.get('/api/documents', requireAuth, async (req, res) => {
  // Filter by user ID - never return all records
  const documents = await Document.find({ userId: req.user.id });
  res.json(documents);
});
\`\`\`

**For Prisma/ORMs:**
\`\`\`javascript
const document = await prisma.document.findFirst({
  where: {
    id: req.params.id,
    userId: req.user.id  // Always include user filter
  }
});
\`\`\`

After fixing:
1. Search for all endpoints that accept IDs from user input
2. Add authorization checks to every single one
3. Never trust user-supplied IDs without verification
`.trim();

/**
 * Mass Assignment
 */
const massAssignmentPrompt: PromptGenerator = (ctx) => `
Fix the mass assignment vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where request body is directly assigned to a model without filtering.'}

**The Problem:** Attackers can set fields they shouldn't (like isAdmin, role, balance) by adding them to the request.

**The Fix - Use Allowlists:**
\`\`\`javascript
// Instead of: User.create(req.body) or { ...req.body }

// Explicitly pick allowed fields
const { name, email, bio } = req.body;
const user = await User.create({ name, email, bio });

// Or use a validation library (recommended)
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  bio: z.string().max(500).optional()
  // Note: isAdmin, role, balance are NOT included
});

const validData = createUserSchema.parse(req.body);
const user = await User.create(validData);
\`\`\`

**For Mongoose:**
\`\`\`javascript
// Define allowed fields in schema
const userSchema = new Schema({
  name: String,
  email: String,
  isAdmin: { type: Boolean, default: false }  // Never from user input
});

// Use pick/select for updates
const allowedFields = ['name', 'email', 'bio'];
const updates = pick(req.body, allowedFields);
await User.findByIdAndUpdate(userId, updates);
\`\`\`

**Fields to NEVER accept from users:**
- isAdmin, role, permissions
- userId, ownerId (for other users)
- balance, credits, price
- verified, approved, status
- createdAt, updatedAt

After fixing:
1. Search for req.body spreads and direct assignments
2. Add explicit field allowlists to all create/update operations
3. Use schema validation (Zod, Joi) for all inputs
`.trim();

/**
 * Rate Limiting
 */
const rateLimitPrompt: PromptGenerator = (ctx) => `
Add rate limiting to the endpoint in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The unprotected endpoint:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the authentication or sensitive endpoint lacking rate limiting.'}

**The Problem:** Without rate limiting, attackers can brute-force passwords, enumerate users, or abuse APIs.

**For Express.js:**
\`\`\`javascript
import rateLimit from 'express-rate-limit';

// Strict limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to auth routes
app.post('/api/login', authLimiter, loginHandler);
app.post('/api/register', authLimiter, registerHandler);
app.post('/api/reset-password', authLimiter, resetHandler);

// General API limiter
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
});
app.use('/api/', apiLimiter);
\`\`\`

**For Next.js:**
\`\`\`javascript
// Use Upstash rate limit or similar
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '15 m'),
});

export async function POST(request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'anonymous';
  const { success } = await ratelimit.limit(ip);

  if (!success) {
    return Response.json({ error: 'Rate limited' }, { status: 429 });
  }
  // ... handle request
}
\`\`\`

After fixing:
1. Add rate limiting to ALL auth endpoints (login, register, password reset)
2. Add general rate limiting to the API
3. Consider adding account lockout after failed attempts
`.trim();

/**
 * ReDoS - Regular Expression Denial of Service
 */
const redosPrompt: PromptGenerator = (ctx) => `
Fix the ReDoS vulnerability in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable regex:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find the regular expression with dangerous patterns.'}

**The Problem:** Certain regex patterns can cause exponential backtracking, freezing your server with crafted input.

**Dangerous patterns to avoid:**
- Nested quantifiers: \`(a+)+\`, \`(a*)*\`, \`(a|aa)+\`
- Overlapping alternations: \`(.*a){10}\`
- Quantifiers on groups with overlapping: \`([a-zA-Z]+)*\`

**Safe alternatives:**
\`\`\`javascript
// Instead of: /^(a+)+$/  (vulnerable)
const safe = /^a+$/;  // No nested quantifier

// Instead of: /(.*a){10}/  (vulnerable)
const safe = /(?:[^a]*a){10}/;  // More specific, no .* inside group

// For email validation, use a simple pattern or library:
const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;  // Simple and safe
// Or use: validator.isEmail(input)
\`\`\`

**Best practices:**
\`\`\`javascript
// 1. Limit input length BEFORE regex
if (input.length > 1000) {
  throw new Error('Input too long');
}

// 2. Use RE2 for user-provided patterns (no backtracking)
import RE2 from 're2';
const safeRegex = new RE2(pattern);

// 3. Add timeout to regex operations
import { execWithTimeout } from 'safe-regex';
const result = execWithTimeout(regex, input, 1000); // 1s timeout
\`\`\`

After fixing:
1. Review ALL regex patterns in the codebase
2. Test with redos-detector or regex101's "debugger"
3. Add input length limits before regex matching
`.trim();

/**
 * Security Headers / Helmet
 */
const securityHeadersPrompt: PromptGenerator = (ctx) => `
Add security headers to your application in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

**The Problem:** Missing security headers expose your app to clickjacking, XSS, and other attacks.

**For Express.js - Use Helmet:**
\`\`\`javascript
import helmet from 'helmet';

app.use(helmet()); // Adds all recommended headers

// Or configure individually:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Tighten in production
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,  // 1 year
    includeSubDomains: true,
    preload: true
  }
}));
\`\`\`

**Manual headers (for other frameworks):**
\`\`\`javascript
// Add to all responses
res.setHeader('X-Content-Type-Options', 'nosniff');
res.setHeader('X-Frame-Options', 'DENY');
res.setHeader('X-XSS-Protection', '1; mode=block');
res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
res.setHeader('Content-Security-Policy', "default-src 'self'");
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');
\`\`\`

**For Next.js (next.config.js):**
\`\`\`javascript
module.exports = {
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
      ],
    }];
  },
};
\`\`\`

After fixing:
1. Install helmet: npm install helmet
2. Add to your Express app setup
3. Test with securityheaders.com
`.trim();

/**
 * Debug Mode in Production
 */
const debugModePrompt: PromptGenerator = (ctx) => `
Disable debug mode in production in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

${ctx.code ? `The vulnerable code:
\`\`\`${ctx.language || 'javascript'}
${ctx.code}
\`\`\`` : 'Find where debug mode is enabled in production code.'}

**The Problem:** Debug mode exposes stack traces, internal errors, and potentially sensitive information.

**For Express/Node.js:**
\`\`\`javascript
// Use environment variable
if (process.env.NODE_ENV === 'production') {
  app.set('env', 'production');
}

// Never enable debug output in production
const DEBUG = process.env.NODE_ENV !== 'production';
\`\`\`

**For Flask (Python):**
\`\`\`python
# Never do: app.run(debug=True) in production

import os
DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

if __name__ == '__main__':
    app.run(debug=DEBUG)

# In production, use a proper WSGI server:
# gunicorn -w 4 app:app
\`\`\`

**For Django:**
\`\`\`python
# settings.py
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

# In production: DJANGO_DEBUG=False
\`\`\`

**Environment-based configuration:**
\`\`\`javascript
// config.js
export const config = {
  debug: process.env.NODE_ENV !== 'production',
  logLevel: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
};
\`\`\`

After fixing:
1. Remove all hardcoded debug=true settings
2. Use environment variables for configuration
3. Verify production deployments have correct env vars
`.trim();

// Export all prompt generators
export const promptGenerators: Record<string, PromptGenerator> = {
	'sql-injection': sqlInjectionPrompt,
	'sql_injection': sqlInjectionPrompt,
	'sqli': sqlInjectionPrompt,
	'xss': xssPrompt,
	'cross-site-scripting': xssPrompt,
	'cross_site_scripting': xssPrompt,
	'innerhtml': xssPrompt,
	'dangerously': xssPrompt,
	'hardcoded-secret': hardcodedSecretPrompt,
	'hardcoded_secret': hardcodedSecretPrompt,
	'hardcoded-credential': hardcodedSecretPrompt,
	'hardcoded_credential': hardcodedSecretPrompt,
	'api_key': hardcodedSecretPrompt,
	'api-key': hardcodedSecretPrompt,
	'secret': hardcodedSecretPrompt,
	'password': hardcodedSecretPrompt,
	'command-injection': commandInjectionPrompt,
	'command_injection': commandInjectionPrompt,
	'os-command': commandInjectionPrompt,
	'exec': commandInjectionPrompt,
	'path-traversal': pathTraversalPrompt,
	'path_traversal': pathTraversalPrompt,
	'directory-traversal': pathTraversalPrompt,
	'directory_traversal': pathTraversalPrompt,
	'ssrf': ssrfPrompt,
	'server-side-request': ssrfPrompt,
	'server_side_request': ssrfPrompt,
	'missing-auth': missingAuthPrompt,
	'missing_auth': missingAuthPrompt,
	'authentication': missingAuthPrompt,
	'open-redirect': openRedirectPrompt,
	'open_redirect': openRedirectPrompt,
	'redirect': openRedirectPrompt,
	'insecure-cookie': insecureCookiePrompt,
	'insecure_cookie': insecureCookiePrompt,
	'cookie': insecureCookiePrompt,
	'session': insecureCookiePrompt,
	'weak-crypto': weakCryptoPrompt,
	'weak_crypto': weakCryptoPrompt,
	'weak-hash': weakCryptoPrompt,
	'weak_hash': weakCryptoPrompt,
	'md5': weakCryptoPrompt,
	'sha1': weakCryptoPrompt,
	'eval': evalPrompt,
	'code-injection': evalPrompt,
	'code_injection': evalPrompt,
	'cors': corsPrompt,
	'cross-origin': corsPrompt,
	'prototype-pollution': prototypePollutionPrompt,
	'prototype_pollution': prototypePollutionPrompt,
	'__proto__': prototypePollutionPrompt,
	'jwt': jwtPrompt,
	'token': jwtPrompt,
	'nosql-injection': nosqlInjectionPrompt,
	'nosql_injection': nosqlInjectionPrompt,
	'mongodb': nosqlInjectionPrompt,
	'deserialization': deserializationPrompt,
	'deserialize': deserializationPrompt,
	'serialize': deserializationPrompt,
	'csrf': csrfPrompt,
	'cross-site-request': csrfPrompt,
	'information-disclosure': infoDisclosurePrompt,
	'information_disclosure': infoDisclosurePrompt,
	'error': infoDisclosurePrompt,
	'stack-trace': infoDisclosurePrompt,
	// XXE
	'xxe': xxePrompt,
	'xml-external': xxePrompt,
	'external-entity': xxePrompt,
	// IDOR
	'idor': idorPrompt,
	'direct-object': idorPrompt,
	'insecure-direct': idorPrompt,
	// Mass Assignment
	'mass-assignment': massAssignmentPrompt,
	'mass_assignment': massAssignmentPrompt,
	'over-posting': massAssignmentPrompt,
	// Rate Limiting
	'rate-limit': rateLimitPrompt,
	'rate_limit': rateLimitPrompt,
	'brute-force': rateLimitPrompt,
	'brute_force': rateLimitPrompt,
	// ReDoS
	'redos': redosPrompt,
	'regex-dos': redosPrompt,
	'regex_dos': redosPrompt,
	'catastrophic-backtracking': redosPrompt,
	// Security Headers
	'helmet': securityHeadersPrompt,
	'security-headers': securityHeadersPrompt,
	'security_headers': securityHeadersPrompt,
	'csp': securityHeadersPrompt,
	'content-security-policy': securityHeadersPrompt,
	// Debug Mode
	'debug': debugModePrompt,
	'debug-mode': debugModePrompt,
	'debug_mode': debugModePrompt,
	'development-mode': debugModePrompt,
};

/**
 * Get the appropriate AI fix prompt for a finding
 */
export function getAIFixPrompt(finding: any): string {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const category = finding.category?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';
	const searchKey = `${ruleId} ${category} ${title}`;

	const ctx: FindingContext = {
		file: finding.location?.file || 'the file',
		line: finding.location?.line,
		code: finding.snippet?.code,
		language: detectLanguage(finding.location?.file),
		title: finding.title,
		category: finding.category
	};

	// Find matching prompt generator
	for (const [key, generator] of Object.entries(promptGenerators)) {
		if (searchKey.includes(key)) {
			return generator(ctx);
		}
	}

	// Default prompt if no specific match
	return generateDefaultPrompt(ctx, finding);
}

function detectLanguage(filename?: string): string {
	if (!filename) return 'javascript';
	if (filename.endsWith('.ts') || filename.endsWith('.tsx')) return 'typescript';
	if (filename.endsWith('.py')) return 'python';
	if (filename.endsWith('.rb')) return 'ruby';
	if (filename.endsWith('.go')) return 'go';
	if (filename.endsWith('.java')) return 'java';
	if (filename.endsWith('.php')) return 'php';
	return 'javascript';
}

function generateDefaultPrompt(ctx: FindingContext, finding: any): string {
	return `
Fix the security issue in ${ctx.file}${ctx.line ? ` at line ${ctx.line}` : ''}.

**Issue:** ${finding.title}
**Category:** ${finding.category}
**Severity:** ${finding.severity}

${ctx.code ? `**Current code:**
\`\`\`${ctx.language}
${ctx.code}
\`\`\`` : ''}

Please:
1. Identify exactly what makes this code vulnerable
2. Show me the fixed version of this code
3. Search for similar patterns in this file and fix those too
4. Explain briefly what the fix does and why it's secure
5. List all changes you made
`.trim();
}

/**
 * Generate a master prompt to fix ALL issues at once
 * @param findings - Array of security findings
 * @param includeInfo - Whether to include info-level findings (default: true)
 */
export function generateMasterFixPrompt(findings: any[], includeInfo: boolean = true): string {
	// Filter findings based on includeInfo setting
	const actionableFindings = includeInfo
		? findings
		: findings.filter(f => f.severity !== 'info');

	if (actionableFindings.length === 0) {
		return '';
	}

	// Sort by severity: critical > high > medium > low
	const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
	const sorted = [...actionableFindings].sort((a, b) =>
		(severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3)
	);

	const issueList = sorted.map((f, i) => {
		const location = f.location?.file
			? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
			: 'location unknown';
		const sev = f.severity?.toUpperCase() || 'INFO';
		return `${i + 1}. [${sev}] **${f.title}** in \`${location}\``;
	}).join('\n');

	const fixInstructions = sorted.map((f, i) => {
		const location = f.location?.file || 'the codebase';
		const fixHint = getFixHint(f);
		const sev = f.severity?.toUpperCase() || 'INFO';
		return `**Issue ${i + 1} [${sev}]: ${f.title}**
   - Location: ${location}${f.location?.line ? ` line ${f.location.line}` : ''}
   - Fix: ${fixHint}`;
	}).join('\n\n');

	return `
I need to fix ${sorted.length} security issues in my codebase. Please help me fix all of them systematically, starting with the most critical.

## Issues to Fix:
${issueList}

## Details and Fix Approach:

${fixInstructions}

## How to proceed:

1. **Start with Issue #1** - show me the current vulnerable code and the fixed version
2. **After each fix**, search for similar patterns in the same file and nearby files
3. **Move to the next issue** once the current one is fully resolved
4. **At the end**, give me a summary of all files modified and changes made

Let's start with Issue #1. Show me the vulnerable code and how to fix it.
`.trim();
}

/**
 * Get a specific, actionable fix hint for a security finding
 * These hints are designed to be token-efficient while providing clear guidance
 */
function getFixHint(finding: any): string {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';
	const message = finding.message?.toLowerCase() || '';
	const searchKey = `${ruleId} ${title} ${message}`;
	const file = finding.location?.file?.toLowerCase() || '';

	// Detect language for language-specific hints
	const isPython = file.endsWith('.py');
	const isJava = file.endsWith('.java');
	const isGo = file.endsWith('.go');
	const isPHP = file.endsWith('.php');
	const isRuby = file.endsWith('.rb');

	// === SQL Injection ===
	if (searchKey.includes('sql') && (searchKey.includes('inject') || searchKey.includes('concat') || searchKey.includes('template') || searchKey.includes('interpolat'))) {
		if (isPython) return 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
		if (isJava) return 'Use PreparedStatement: stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setInt(1, userId);';
		if (isPHP) return 'Use PDO prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);';
		if (isRuby) return 'Use parameterized queries: User.where("id = ?", params[:id]) or User.find_by(id: params[:id])';
		return 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId]) - never concatenate user input into SQL';
	}

	// === XSS Vulnerabilities ===
	if (searchKey.includes('xss') || searchKey.includes('innerhtml') || searchKey.includes('dangerously') || searchKey.includes('v-html') || searchKey.includes('@html')) {
		if (searchKey.includes('react') || searchKey.includes('dangerously')) return 'Remove dangerouslySetInnerHTML or sanitize: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}';
		if (searchKey.includes('vue') || searchKey.includes('v-html')) return 'Replace v-html with {{ }} interpolation, or sanitize: v-html="DOMPurify.sanitize(content)"';
		if (searchKey.includes('svelte') || searchKey.includes('@html')) return 'Replace {@html} with {text}, or sanitize: {@html DOMPurify.sanitize(content)}';
		if (searchKey.includes('angular')) return 'Use Angular\'s built-in sanitization or DomSanitizer.sanitize() with SecurityContext.HTML';
		if (searchKey.includes('jquery')) return 'Replace .html(userInput) with .text(userInput) to prevent script execution';
		return 'Use element.textContent instead of innerHTML, or sanitize with DOMPurify.sanitize(userInput) before rendering';
	}

	// === Stored XSS ===
	if (searchKey.includes('stored') && searchKey.includes('xss')) {
		return 'Sanitize content before storing in DB AND before rendering: DOMPurify.sanitize(). Encode output based on context (HTML/JS/URL)';
	}

	// === Template Injection / SSTI ===
	if (searchKey.includes('template') && (searchKey.includes('inject') || searchKey.includes('ssti') || searchKey.includes('user'))) {
		if (isPython) return 'Never pass user input to render_template_string(). Use render_template() with separate template files';
		return 'Never include user input in template strings. Use template variables: render("template.html", { data: userInput })';
	}

	// === Hardcoded Secrets ===
	if (searchKey.includes('secret') || searchKey.includes('hardcoded') || searchKey.includes('api_key') || searchKey.includes('password') || searchKey.includes('credential')) {
		if (searchKey.includes('jwt')) return 'Move JWT secret to env var: process.env.JWT_SECRET. Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"';
		if (searchKey.includes('database') || searchKey.includes('db')) return 'Move DB credentials to env vars. Use: DATABASE_URL=postgres://user:pass@host/db in .env file';
		return 'Move to environment variables: process.env.API_KEY. Add .env to .gitignore. Rotate any exposed secrets immediately';
	}

	// === Command Injection ===
	if (searchKey.includes('command') || searchKey.includes('exec') || searchKey.includes('spawn') || searchKey.includes('shell')) {
		if (searchKey.includes('shell=true') || isPython) return 'Use subprocess.run(["cmd", arg], shell=False) with list arguments. Never shell=True with user input';
		return 'Use execFile() with array args: execFile("convert", [filename, "out.png"]). Avoid exec() which invokes shell';
	}

	// === Path Traversal ===
	if (searchKey.includes('path') && (searchKey.includes('traversal') || searchKey.includes('user') || searchKey.includes('variable'))) {
		return 'Validate path stays in allowed dir: const safePath = path.resolve(baseDir, path.basename(userInput)); if (!safePath.startsWith(baseDir)) throw Error';
	}

	// === SSRF ===
	if (searchKey.includes('ssrf') || (searchKey.includes('fetch') && searchKey.includes('user')) || (searchKey.includes('url') && searchKey.includes('user'))) {
		return 'Validate URLs: block private IPs (127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.x), require HTTPS, use allowlist of domains';
	}

	// === Missing Authentication ===
	if (searchKey.includes('no-auth') || searchKey.includes('missing') && searchKey.includes('auth') || searchKey.includes('no_auth')) {
		return 'Add auth middleware: router.get("/api/data", requireAuth, handler). Check session/token before processing request';
	}

	// === IDOR / Broken Access Control ===
	if (searchKey.includes('idor') || searchKey.includes('direct object') || searchKey.includes('owner') || searchKey.includes('authorization')) {
		return 'Add ownership check: if (resource.userId !== req.user.id) return res.status(403). Never trust user-supplied IDs without authorization';
	}

	// === Open Redirect ===
	if (searchKey.includes('redirect') && (searchKey.includes('open') || searchKey.includes('user') || searchKey.includes('param'))) {
		return 'Validate redirect URL: only allow relative paths (/dashboard) or allowlist of domains. Block external URLs';
	}

	// === Cookie Security ===
	if (searchKey.includes('cookie') && (searchKey.includes('httponly') || searchKey.includes('secure') || searchKey.includes('samesite'))) {
		return 'Set all flags: res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 3600000 })';
	}

	// === Session Security ===
	if (searchKey.includes('session') && (searchKey.includes('insecure') || searchKey.includes('fixation') || searchKey.includes('regenerate'))) {
		if (searchKey.includes('fixation') || searchKey.includes('regenerate')) return 'Regenerate session ID after login: req.session.regenerate(). Destroy old session on logout';
		return 'Configure session: { secret: process.env.SECRET, cookie: { httpOnly: true, secure: true, sameSite: "strict", maxAge: 86400000 } }';
	}

	// === Weak Cryptography ===
	if (searchKey.includes('md5') || searchKey.includes('sha1') || searchKey.includes('weak') && searchKey.includes('hash')) {
		if (searchKey.includes('password')) return 'Use bcrypt: await bcrypt.hash(password, 12) for hashing, await bcrypt.compare(input, hash) for verification';
		return 'Replace with SHA-256 minimum: crypto.createHash("sha256").update(data).digest("hex"). For passwords, always use bcrypt';
	}

	// === Weak Cipher ===
	if (searchKey.includes('cipher') || searchKey.includes('des') || searchKey.includes('rc4') || searchKey.includes('ecb')) {
		return 'Use AES-256-GCM: crypto.createCipheriv("aes-256-gcm", key, iv). Never use DES, RC4, or ECB mode';
	}

	// === Math.random for Security ===
	if (searchKey.includes('math.random') || searchKey.includes('weak') && searchKey.includes('random')) {
		return 'Use crypto.randomBytes(32).toString("hex") for tokens/secrets. Math.random() is predictable';
	}

	// === Eval / Code Injection ===
	if (searchKey.includes('eval') || searchKey.includes('new function') || searchKey.includes('settimeout') && searchKey.includes('string')) {
		return 'Remove eval(). For JSON: JSON.parse(). For math: mathjs.evaluate(). For dynamic props: obj[key]. Never execute user strings';
	}

	// === Dangerous Deserialization ===
	if (searchKey.includes('deserialize') || searchKey.includes('pickle') || searchKey.includes('unserialize') || searchKey.includes('yaml') && searchKey.includes('load')) {
		if (isPython) return 'Never pickle.loads() untrusted data. Use json.loads() with schema validation (e.g., Pydantic)';
		if (searchKey.includes('yaml')) return 'Use yaml.safe_load() instead of yaml.load(). Never deserialize untrusted YAML';
		return 'Use JSON.parse() with schema validation (Zod/Joi). Never deserialize untrusted data with node-serialize or similar';
	}

	// === CORS ===
	if (searchKey.includes('cors') && (searchKey.includes('wildcard') || searchKey.includes('*') || searchKey.includes('credentials'))) {
		return 'Set specific origins: cors({ origin: ["https://app.example.com"], credentials: true }). Never use "*" with credentials';
	}

	// === Prototype Pollution ===
	if (searchKey.includes('prototype') || searchKey.includes('__proto__') || searchKey.includes('constructor.prototype')) {
		return 'Block dangerous keys: if (["__proto__", "constructor", "prototype"].includes(key)) throw Error. Use Map for user-keyed data';
	}

	// === JWT Issues ===
	if (searchKey.includes('jwt')) {
		if (searchKey.includes('none') || searchKey.includes('algorithm')) return 'Specify algorithm in verify: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never allow "none"';
		if (searchKey.includes('expir') || searchKey.includes('exp')) return 'Add expiration: jwt.sign(payload, secret, { expiresIn: "15m" }). Use short-lived access + refresh tokens';
		if (searchKey.includes('secret') || searchKey.includes('hardcoded')) return 'Use env var for secret: process.env.JWT_SECRET. Generate 64+ random bytes';
		return 'Set expiration, specify algorithm in verify, use strong secret from env vars';
	}

	// === NoSQL Injection ===
	if (searchKey.includes('nosql') || searchKey.includes('mongodb') && searchKey.includes('inject')) {
		return 'Validate input type: if (typeof input !== "string") throw Error. Use express-mongo-sanitize middleware. Never allow $ operators from user input';
	}

	// === CSRF ===
	if (searchKey.includes('csrf') || searchKey.includes('cross-site request')) {
		return 'Add CSRF protection: use csurf middleware for Express, SameSite=Strict cookies, or include CSRF token in forms/headers';
	}

	// === XXE ===
	if (searchKey.includes('xxe') || searchKey.includes('xml') && (searchKey.includes('external') || searchKey.includes('entity'))) {
		if (isPython) return 'Use defusedxml: from defusedxml.ElementTree import parse. Never use xml.etree directly with untrusted XML';
		if (isJava) return 'Disable DTDs: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)';
		return 'Disable external entities: parser.setFeature("disallow-doctype-decl"). Use JSON instead of XML when possible';
	}

	// === Information Disclosure / Error Handling ===
	if (searchKey.includes('stack') && searchKey.includes('trace') || searchKey.includes('verbose') && searchKey.includes('error') || searchKey.includes('error') && searchKey.includes('detail')) {
		return 'Return generic errors in production: res.status(500).json({ error: "Internal error" }). Log details server-side only';
	}

	// === Rate Limiting ===
	if (searchKey.includes('rate') && searchKey.includes('limit') || searchKey.includes('brute') || searchKey.includes('no-rate')) {
		return 'Add rate limiting: app.use("/login", rateLimit({ windowMs: 15*60*1000, max: 5 })). Essential for auth endpoints';
	}

	// === User Enumeration ===
	if (searchKey.includes('enumeration') || searchKey.includes('user') && searchKey.includes('exist')) {
		return 'Use generic messages: "Invalid credentials" for both wrong user and wrong password. Same response time for all cases';
	}

	// === Mass Assignment ===
	if (searchKey.includes('mass assignment') || searchKey.includes('mass_assignment') || searchKey.includes('body') && searchKey.includes('spread')) {
		return 'Use allowlist: const { name, email } = req.body; User.create({ name, email }). Never spread req.body directly into model';
	}

	// === ReDoS ===
	if (searchKey.includes('redos') || searchKey.includes('regex') && (searchKey.includes('dos') || searchKey.includes('catastrophic'))) {
		return 'Avoid nested quantifiers like (a+)+. Use RE2 library for untrusted patterns. Add input length limits and timeouts';
	}

	// === Missing Helmet/Security Headers ===
	if (searchKey.includes('helmet') || searchKey.includes('security header') || searchKey.includes('hsts') || searchKey.includes('x-frame')) {
		return 'Add security headers: app.use(helmet()). Or manually set X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security';
	}

	// === Debug Mode in Production ===
	if (searchKey.includes('debug') && (searchKey.includes('true') || searchKey.includes('production') || searchKey.includes('enabled'))) {
		return 'Disable debug in production: DEBUG=False (Django), app.run(debug=False) (Flask), NODE_ENV=production (Node)';
	}

	// === TLS/SSL Certificate Validation ===
	if (searchKey.includes('tls') || searchKey.includes('ssl') || searchKey.includes('verify') && searchKey.includes('false') || searchKey.includes('reject') && searchKey.includes('unauthorized')) {
		return 'Never disable cert validation in production. Remove verify=False (Python) or rejectUnauthorized: false (Node)';
	}

	// === Insecure Password Storage ===
	if (searchKey.includes('password') && (searchKey.includes('plain') || searchKey.includes('cleartext') || searchKey.includes('storage'))) {
		return 'Hash with bcrypt before storage: const hash = await bcrypt.hash(password, 12). Never store plaintext passwords';
	}

	// === Timing Attacks ===
	if (searchKey.includes('timing') || searchKey.includes('constant') && searchKey.includes('time')) {
		return 'Use constant-time comparison: crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)). Never use === for secrets';
	}

	// === File Upload ===
	if (searchKey.includes('upload') || searchKey.includes('multer') && searchKey.includes('filter')) {
		return 'Validate file type by content (magic bytes), not just extension. Limit size, store outside webroot, rename files';
	}

	// === Zip Slip ===
	if (searchKey.includes('zip') && (searchKey.includes('slip') || searchKey.includes('extract') || searchKey.includes('path'))) {
		return 'Validate extracted paths: const dest = path.join(outDir, entry); if (!dest.startsWith(outDir)) throw Error';
	}

	// === Log Injection ===
	if (searchKey.includes('log') && (searchKey.includes('inject') || searchKey.includes('user') || searchKey.includes('input'))) {
		return 'Sanitize log input: remove newlines, encode special chars. Never log sensitive data (passwords, tokens)';
	}

	// === Sensitive Data Exposure ===
	if (searchKey.includes('sensitive') && searchKey.includes('data') || searchKey.includes('password') && searchKey.includes('response') || searchKey.includes('token') && searchKey.includes('response')) {
		return 'Never return sensitive fields in API responses. Use select/projection to exclude: User.findById(id).select("-password -token")';
	}

	// === Admin/Privileged Route Missing Auth ===
	if (searchKey.includes('admin') && (searchKey.includes('no') && searchKey.includes('auth') || searchKey.includes('check'))) {
		return 'Add role check: if (req.user.role !== "admin") return res.status(403). Verify permissions for all privileged operations';
	}

	// === Deprecated/Vulnerable Dependencies ===
	if (searchKey.includes('lodash') || searchKey.includes('vulnerable') && searchKey.includes('version')) {
		return 'Update to latest version: npm update [package]. Use npm audit fix. Remove unused dependencies';
	}

	// === bcrypt Low Rounds ===
	if (searchKey.includes('bcrypt') && (searchKey.includes('rounds') || searchKey.includes('cost'))) {
		return 'Use minimum 12 rounds: bcrypt.hash(password, 12). Higher rounds = slower brute force. 10 is outdated';
	}

	// === HTTP without HTTPS ===
	if (searchKey.includes('http') && searchKey.includes('https') || searchKey.includes('no') && searchKey.includes('tls')) {
		return 'Redirect HTTP to HTTPS: app.use((req, res, next) => { if (!req.secure) res.redirect("https://" + req.host + req.url); })';
	}

	// === Default or empty key catch-all ===
	if (searchKey.includes('default') || searchKey.includes('empty') || searchKey.includes('unsafe')) {
		// Try to extract useful context from the title/message
		if (finding.message && finding.message.length > 20) {
			// Truncate and use as hint
			const msg = finding.message.slice(0, 100).replace(/\s+/g, ' ').trim();
			return `Address: ${msg}`;
		}
	}

	// === Fallback with more context ===
	// Instead of generic advice, provide vulnerability-type-specific guidance based on severity
	const severity = finding.severity?.toLowerCase() || 'medium';
	if (severity === 'critical' || severity === 'high') {
		return `Critical security issue - review ${finding.title || 'this code'} immediately. Check OWASP guidelines for ${finding.category || 'this vulnerability type'}`;
	}

	return `Review and fix: ${finding.title || 'security issue'}. Apply input validation, output encoding, and least privilege principles`;
}
