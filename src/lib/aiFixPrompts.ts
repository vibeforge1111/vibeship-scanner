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
 * Generate a master prompt to fix ALL critical/high issues at once
 */
export function generateMasterFixPrompt(findings: any[]): string {
	const criticalAndHigh = findings.filter(
		f => f.severity === 'critical' || f.severity === 'high'
	);

	if (criticalAndHigh.length === 0) {
		return '';
	}

	const issueList = criticalAndHigh.map((f, i) => {
		const location = f.location?.file
			? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
			: 'location unknown';
		return `${i + 1}. **${f.title}** in \`${location}\``;
	}).join('\n');

	const fixInstructions = criticalAndHigh.map((f, i) => {
		const location = f.location?.file || 'the codebase';
		const fixHint = getFixHint(f);
		return `**Issue ${i + 1}: ${f.title}**
   - Location: ${location}${f.location?.line ? ` line ${f.location.line}` : ''}
   - Fix: ${fixHint}`;
	}).join('\n\n');

	return `
I need to fix ${criticalAndHigh.length} critical security issues in my codebase. Please help me fix all of them systematically.

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

function getFixHint(finding: any): string {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';
	const searchKey = `${ruleId} ${title}`;

	if (searchKey.includes('sql')) return 'Use parameterized queries instead of string concatenation';
	if (searchKey.includes('xss') || searchKey.includes('innerhtml')) return 'Use textContent or sanitize with DOMPurify';
	if (searchKey.includes('secret') || searchKey.includes('hardcoded') || searchKey.includes('api_key')) return 'Move to environment variables';
	if (searchKey.includes('command') || searchKey.includes('exec')) return 'Use execFile with separate arguments, not exec()';
	if (searchKey.includes('path') || searchKey.includes('traversal')) return 'Validate paths stay within allowed directory';
	if (searchKey.includes('ssrf')) return 'Validate URLs and block private IP ranges';
	if (searchKey.includes('auth')) return 'Add authentication middleware';
	if (searchKey.includes('redirect')) return 'Validate redirect URLs against whitelist';
	if (searchKey.includes('cookie') || searchKey.includes('session')) return 'Add httpOnly, secure, sameSite flags';
	if (searchKey.includes('crypto') || searchKey.includes('hash') || searchKey.includes('md5')) return 'Use bcrypt for passwords, SHA-256 for hashing';
	if (searchKey.includes('eval')) return 'Remove eval(), use JSON.parse or safe alternatives';
	if (searchKey.includes('cors')) return 'Restrict to specific allowed origins';
	if (searchKey.includes('jwt')) return 'Add expiration, use strong secret';
	if (searchKey.includes('csrf')) return 'Add CSRF token validation';

	return 'Review the code and apply security best practices';
}
