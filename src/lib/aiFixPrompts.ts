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

	// Group findings by vulnerability type for better organization
	const grouped = groupFindingsByType(sorted);

	// Generate the detailed fix guide for each group
	const fixGuides = Object.entries(grouped).map(([type, findings]) => {
		const guide = getDetailedFixGuide(type, findings);
		return guide;
	}).join('\n\n---\n\n');

	// Summary list for quick reference
	const summaryList = sorted.map((f, i) => {
		const location = f.location?.file
			? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
			: 'location unknown';
		const sev = f.severity?.toUpperCase() || 'INFO';
		return `${i + 1}. [${sev}] ${f.title} → \`${location}\``;
	}).join('\n');

	return `
# Security Fix Guide

I need help fixing ${sorted.length} security vulnerabilities in my codebase. This guide contains everything you need to fix each issue.

## Quick Summary (${sorted.length} issues)

${summaryList}

---

## Detailed Fix Instructions

${fixGuides}

---

## How to Work Through This

1. **Go issue by issue** - Start with the first vulnerability type below
2. **Read the file** - Open each listed file and find the vulnerable code at the specified line
3. **Apply the fix pattern** - Use the code examples provided as templates
4. **Search for similar issues** - After fixing, grep the codebase for similar vulnerable patterns
5. **Verify the fix** - Make sure the code still works after your changes
6. **Move to the next** - Continue until all issues are resolved

## After All Fixes

- Run the application and test that everything works
- Run any existing tests: \`npm test\` or equivalent
- List all files you modified
- Summarize what you changed

Let's start! Begin with the first section below.
`.trim();
}

/**
 * Group findings by vulnerability type for organized output
 */
function groupFindingsByType(findings: any[]): Record<string, any[]> {
	const groups: Record<string, any[]> = {};

	for (const finding of findings) {
		const type = categorizeVulnerability(finding);
		if (!groups[type]) {
			groups[type] = [];
		}
		groups[type].push(finding);
	}

	return groups;
}

/**
 * Categorize a finding into a vulnerability type
 */
function categorizeVulnerability(finding: any): string {
	const searchKey = `${finding.ruleId || ''} ${finding.title || ''} ${finding.message || ''}`.toLowerCase();

	if (searchKey.includes('sql') && (searchKey.includes('inject') || searchKey.includes('query'))) return 'sql-injection';
	if (searchKey.includes('xss') || searchKey.includes('innerhtml') || searchKey.includes('dangerously')) return 'xss';
	if (searchKey.includes('command') || searchKey.includes('exec') || searchKey.includes('shell')) return 'command-injection';
	if (searchKey.includes('path') && searchKey.includes('travers')) return 'path-traversal';
	if (searchKey.includes('ssrf') || (searchKey.includes('url') && searchKey.includes('user'))) return 'ssrf';
	if (searchKey.includes('secret') || searchKey.includes('hardcoded') || searchKey.includes('api_key') || searchKey.includes('password') && searchKey.includes('code')) return 'hardcoded-secrets';
	if (searchKey.includes('auth') && (searchKey.includes('missing') || searchKey.includes('no-') || searchKey.includes('bypass'))) return 'broken-auth';
	if (searchKey.includes('idor') || searchKey.includes('authorization') || searchKey.includes('access control')) return 'broken-access-control';
	if (searchKey.includes('csrf')) return 'csrf';
	if (searchKey.includes('cors')) return 'cors';
	if (searchKey.includes('jwt')) return 'jwt-issues';
	if (searchKey.includes('session')) return 'session-security';
	if (searchKey.includes('cookie')) return 'cookie-security';
	if (searchKey.includes('crypto') || searchKey.includes('md5') || searchKey.includes('sha1') || searchKey.includes('cipher')) return 'weak-crypto';
	if (searchKey.includes('deserial') || searchKey.includes('pickle') || searchKey.includes('unserialize')) return 'insecure-deserialization';
	if (searchKey.includes('xxe') || searchKey.includes('xml')) return 'xxe';
	if (searchKey.includes('redirect')) return 'open-redirect';
	if (searchKey.includes('debug') || searchKey.includes('verbose')) return 'debug-exposure';
	if (searchKey.includes('header') || searchKey.includes('helmet')) return 'security-headers';
	if (searchKey.includes('rate') || searchKey.includes('brute')) return 'rate-limiting';
	if (searchKey.includes('cve-') || searchKey.includes('ghsa-') || searchKey.includes('vulnerable') && searchKey.includes('version')) return 'vulnerable-dependency';
	if (searchKey.includes('log') && (searchKey.includes('sensitive') || searchKey.includes('inject'))) return 'logging-issues';
	if (searchKey.includes('file') || searchKey.includes('upload')) return 'file-security';
	if (searchKey.includes('nosql') || searchKey.includes('mongo')) return 'nosql-injection';
	if (searchKey.includes('template') && searchKey.includes('inject')) return 'template-injection';
	if (searchKey.includes('eval') || searchKey.includes('code') && searchKey.includes('inject')) return 'code-injection';
	if (searchKey.includes('prototype')) return 'prototype-pollution';
	if (searchKey.includes('regex') || searchKey.includes('redos')) return 'regex-dos';
	if (searchKey.includes('random')) return 'weak-random';
	if (searchKey.includes('tls') || searchKey.includes('ssl') || searchKey.includes('certificate')) return 'tls-issues';

	return 'other-security';
}

/**
 * Get detailed fix guide for a vulnerability type with code examples
 */
function getDetailedFixGuide(type: string, findings: any[]): string {
	const locations = findings.map(f => {
		const loc = f.location?.file
			? `- \`${f.location.file}${f.location.line ? `:${f.location.line}` : ''}\``
			: '- Location not specified';
		const severity = f.severity?.toUpperCase() || 'INFO';
		return `${loc} [${severity}] ${f.title || ''}`;
	}).join('\n');

	const guide = getVulnerabilityGuide(type);

	return `## ${guide.title}

**Affected Locations:**
${locations}

**What's Wrong:**
${guide.problem}

**How to Fix:**

${guide.solution}

**After Fixing:**
${guide.verification}`;
}

interface VulnerabilityGuide {
	title: string;
	problem: string;
	solution: string;
	verification: string;
}

/**
 * Comprehensive fix guides for each vulnerability type
 */
function getVulnerabilityGuide(type: string): VulnerabilityGuide {
	const guides: Record<string, VulnerabilityGuide> = {
		'sql-injection': {
			title: '🔴 SQL Injection',
			problem: 'User input is being concatenated directly into SQL queries, allowing attackers to execute arbitrary database commands, steal data, or delete records.',
			solution: `Use parameterized queries (prepared statements) instead of string concatenation:

**JavaScript (pg/node-postgres):**
\`\`\`javascript
// ❌ VULNERABLE
const result = await db.query("SELECT * FROM users WHERE id = " + userId);
const result = await db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);

// ✅ FIXED
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
\`\`\`

**JavaScript (mysql2):**
\`\`\`javascript
// ❌ VULNERABLE
connection.query("SELECT * FROM users WHERE id = " + userId);

// ✅ FIXED
const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# ✅ FIXED
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
\`\`\`

**Using an ORM (Prisma, Sequelize, SQLAlchemy):**
\`\`\`javascript
// ❌ VULNERABLE - raw query with interpolation
prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE id = \${userId}\`)

// ✅ FIXED - use the ORM's built-in methods
const user = await prisma.user.findUnique({ where: { id: userId } });
// Or if raw SQL is needed:
const user = await prisma.$queryRaw(Prisma.sql\`SELECT * FROM users WHERE id = \${userId}\`);
\`\`\``,
			verification: `- Search for other SQL queries: \`grep -r "query.*\\$\\{" --include="*.js" --include="*.ts"\`
- Search for string concatenation in queries: \`grep -r "query.*+" --include="*.js"\`
- Test with a simple payload: Try entering \`' OR '1'='1\` in input fields
- Ensure no user input reaches SQL without parameterization`
		},

		'xss': {
			title: '🔴 Cross-Site Scripting (XSS)',
			problem: 'User input is rendered in the browser without sanitization, allowing attackers to inject malicious scripts that steal cookies, credentials, or perform actions as the user.',
			solution: `Never insert untrusted data directly into HTML. Use text content or sanitize:

**Vanilla JavaScript:**
\`\`\`javascript
// ❌ VULNERABLE
element.innerHTML = userInput;
document.write(userInput);

// ✅ FIXED - for text content
element.textContent = userInput;

// ✅ FIXED - if you MUST render HTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

**React:**
\`\`\`jsx
// ✅ SAFE by default - React escapes content
<div>{userInput}</div>

// ❌ VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ✅ FIXED - if you must render HTML
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
\`\`\`

**Vue:**
\`\`\`vue
<!-- ✅ SAFE by default -->
<div>{{ userInput }}</div>

<!-- ❌ VULNERABLE -->
<div v-html="userInput"></div>

<!-- ✅ FIXED -->
<div v-html="DOMPurify.sanitize(userInput)"></div>
\`\`\`

**Svelte:**
\`\`\`svelte
<!-- ✅ SAFE by default -->
<p>{userInput}</p>

<!-- ❌ VULNERABLE -->
{@html userInput}

<!-- ✅ FIXED -->
<script>
  import DOMPurify from 'dompurify';
  $: safeHtml = DOMPurify.sanitize(userInput);
</script>
{@html safeHtml}
\`\`\`

**Install DOMPurify:** \`npm install dompurify\``,
			verification: `- Search for innerHTML: \`grep -r "innerHTML" --include="*.js" --include="*.ts"\`
- Search for dangerous React: \`grep -r "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"\`
- Search for v-html: \`grep -r "v-html" --include="*.vue"\`
- Search for @html: \`grep -r "@html" --include="*.svelte"\`
- Test with: \`<script>alert('xss')</script>\` in input fields`
		},

		'command-injection': {
			title: '🔴 Command Injection',
			problem: 'User input is passed to shell commands, allowing attackers to execute arbitrary system commands on your server.',
			solution: `Never pass user input to shell commands. Use array arguments or avoid shell entirely:

**Node.js:**
\`\`\`javascript
// ❌ VULNERABLE - shell=true allows injection
const { exec } = require('child_process');
exec(\`convert \${userFilename} output.png\`);  // Attacker: "; rm -rf /"

// ✅ FIXED - use execFile with array arguments
const { execFile } = require('child_process');
execFile('convert', [userFilename, 'output.png'], (error, stdout) => {
  // handle result
});

// ✅ FIXED - or use spawn without shell
const { spawn } = require('child_process');
const child = spawn('convert', [userFilename, 'output.png']);
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
import os
os.system(f"convert {user_filename} output.png")

import subprocess
subprocess.call(f"convert {user_filename} output.png", shell=True)

# ✅ FIXED - use list arguments, shell=False
import subprocess
subprocess.run(["convert", user_filename, "output.png"], shell=False)
\`\`\`

**If you must use shell, validate strictly:**
\`\`\`javascript
// Allowlist approach
const ALLOWED_COMMANDS = ['convert', 'resize', 'compress'];
if (!ALLOWED_COMMANDS.includes(command)) {
  throw new Error('Invalid command');
}
// Also validate all arguments against expected patterns
if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
  throw new Error('Invalid filename');
}
\`\`\``,
			verification: `- Search for exec: \`grep -r "exec(" --include="*.js" --include="*.ts"\`
- Search for spawn with shell: \`grep -r "shell.*true" --include="*.js"\`
- Search for Python os.system: \`grep -r "os.system\\|subprocess.*shell=True" --include="*.py"\`
- Never trust user input in shell commands`
		},

		'hardcoded-secrets': {
			title: '🔴 Hardcoded Secrets',
			problem: 'API keys, passwords, or tokens are hardcoded in source code. Anyone with access to the code (including git history) can see these credentials.',
			solution: `Move all secrets to environment variables:

**Step 1: Create .env file (never commit this!):**
\`\`\`bash
# .env
DATABASE_URL=postgres://user:password@host/database
API_KEY=sk-your-api-key-here
JWT_SECRET=your-64-character-random-secret
STRIPE_SECRET_KEY=sk_live_...
\`\`\`

**Step 2: Add .env to .gitignore:**
\`\`\`bash
# .gitignore
.env
.env.local
.env*.local
\`\`\`

**Step 3: Update code to use environment variables:**
\`\`\`javascript
// ❌ VULNERABLE
const apiKey = "sk-1234567890abcdef";
const dbPassword = "supersecret123";

// ✅ FIXED - Node.js
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;

// ✅ FIXED - with validation
const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error('API_KEY environment variable is required');
}
\`\`\`

**For different frameworks:**
\`\`\`javascript
// Next.js (server-side)
const secret = process.env.JWT_SECRET;

// Next.js (client-side - only for non-sensitive values!)
const publicUrl = process.env.NEXT_PUBLIC_API_URL;

// Vite / SvelteKit
const apiKey = import.meta.env.VITE_API_KEY;
\`\`\`

**⚠️ CRITICAL: If secrets were already committed:**
1. The secret is exposed in git history FOREVER
2. You MUST rotate/regenerate all exposed secrets immediately
3. Consider using tools like \`git-filter-repo\` to remove from history
4. Notify your team and check for unauthorized access`,
			verification: `- Search for hardcoded strings: \`grep -r "sk-\\|api_key.*=.*['\\"]\\" --include="*.js" --include="*.ts"\`
- Check git history: \`git log -p | grep -i "password\\|secret\\|api_key"\`
- Use tools like gitleaks or trufflehog to scan for secrets
- Verify .env is in .gitignore: \`cat .gitignore | grep env\``
		},

		'path-traversal': {
			title: '🔴 Path Traversal',
			problem: 'User input is used to construct file paths, allowing attackers to access files outside the intended directory using "../" sequences.',
			solution: `Always validate that the resolved path stays within the allowed directory:

**Node.js:**
\`\`\`javascript
const path = require('path');
const fs = require('fs');

// ❌ VULNERABLE
app.get('/files/:filename', (req, res) => {
  const filePath = './uploads/' + req.params.filename;
  res.sendFile(filePath);  // Attacker: ../../../etc/passwd
});

// ✅ FIXED
const UPLOAD_DIR = path.resolve('./uploads');

app.get('/files/:filename', (req, res) => {
  // Get just the filename, removing any path components
  const filename = path.basename(req.params.filename);

  // Resolve the full path
  const filePath = path.resolve(UPLOAD_DIR, filename);

  // Verify the path is still within the allowed directory
  if (!filePath.startsWith(UPLOAD_DIR)) {
    return res.status(403).json({ error: 'Access denied' });
  }

  // Check file exists before sending
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.sendFile(filePath);
});
\`\`\`

**Python:**
\`\`\`python
import os

# ❌ VULNERABLE
def get_file(filename):
    return open(f"./uploads/{filename}").read()

# ✅ FIXED
UPLOAD_DIR = os.path.abspath("./uploads")

def get_file(filename):
    # Get just the filename
    safe_filename = os.path.basename(filename)

    # Resolve full path
    file_path = os.path.abspath(os.path.join(UPLOAD_DIR, safe_filename))

    # Verify path is within allowed directory
    if not file_path.startswith(UPLOAD_DIR):
        raise PermissionError("Access denied")

    return open(file_path).read()
\`\`\``,
			verification: `- Search for file operations with user input: \`grep -r "readFile.*req\\|sendFile.*req" --include="*.js"\`
- Test with: \`../../../etc/passwd\` or \`....//....//etc/passwd\`
- Verify path.basename() is used on all user-supplied filenames
- Check that startsWith() validation is present`
		},

		'ssrf': {
			title: '🔴 Server-Side Request Forgery (SSRF)',
			problem: 'User-controlled URLs are fetched by the server, allowing attackers to access internal services, cloud metadata, or perform port scanning.',
			solution: `Validate and restrict URLs before fetching:

\`\`\`javascript
const { URL } = require('url');

// ❌ VULNERABLE
app.get('/fetch', async (req, res) => {
  const response = await fetch(req.query.url);  // Attacker: http://169.254.169.254/metadata
  res.json(await response.json());
});

// ✅ FIXED
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

function isUrlSafe(urlString) {
  try {
    const url = new URL(urlString);

    // Must be HTTPS
    if (url.protocol !== 'https:') {
      return false;
    }

    // Check against allowlist
    if (!ALLOWED_HOSTS.includes(url.hostname)) {
      return false;
    }

    // Block private/internal IPs
    const blockedPatterns = [
      /^127\\./,           // Localhost
      /^10\\./,            // Private Class A
      /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./,  // Private Class B
      /^192\\.168\\./,     // Private Class C
      /^169\\.254\\./,     // Link-local
      /^0\\./,             // Current network
      /localhost/i,
      /internal/i,
    ];

    for (const pattern of blockedPatterns) {
      if (pattern.test(url.hostname)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

app.get('/fetch', async (req, res) => {
  if (!isUrlSafe(req.query.url)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const response = await fetch(req.query.url);
  res.json(await response.json());
});
\`\`\``,
			verification: `- Search for fetch/axios with user input: \`grep -r "fetch.*req\\|axios.*req" --include="*.js"\`
- Test with internal URLs: \`http://localhost\`, \`http://127.0.0.1\`, \`http://169.254.169.254\`
- Verify URL validation exists before all outbound requests
- Check that internal IPs are blocked`
		},

		'broken-auth': {
			title: '🔴 Broken Authentication',
			problem: 'Endpoints lack proper authentication, allowing unauthorized access to sensitive functionality or data.',
			solution: `Add authentication middleware to protected routes:

**Express.js:**
\`\`\`javascript
// ❌ VULNERABLE - no auth check
app.get('/api/user/profile', (req, res) => {
  res.json(getUserProfile(req.query.userId));
});

// ✅ FIXED - add auth middleware
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Apply to routes
app.get('/api/user/profile', requireAuth, (req, res) => {
  // Now req.user is available
  res.json(getUserProfile(req.user.id));
});

// Or apply to all /api routes
app.use('/api', requireAuth);
\`\`\`

**Next.js API Routes:**
\`\`\`typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('session')?.value;

  if (!token && request.nextUrl.pathname.startsWith('/api/protected')) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return NextResponse.next();
}
\`\`\`

**SvelteKit:**
\`\`\`typescript
// hooks.server.ts
export const handle = async ({ event, resolve }) => {
  const session = event.cookies.get('session');

  if (!session && event.url.pathname.startsWith('/api/protected')) {
    return new Response('Unauthorized', { status: 401 });
  }

  event.locals.user = await validateSession(session);
  return resolve(event);
};
\`\`\``,
			verification: `- List all API routes and verify each has auth middleware
- Test endpoints without auth headers - they should return 401
- Search for routes without middleware: \`grep -r "app.get\\|app.post" --include="*.js" -A2\`
- Verify sensitive operations check user identity, not just presence of token`
		},

		'broken-access-control': {
			title: '🔴 Broken Access Control (IDOR)',
			problem: 'Users can access or modify resources belonging to other users by changing IDs in requests.',
			solution: `Always verify the current user owns or has permission to access the requested resource:

\`\`\`javascript
// ❌ VULNERABLE - trusts user-supplied ID
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const document = await Document.findById(req.params.id);
  res.json(document);  // Anyone can access any document!
});

app.delete('/api/documents/:id', requireAuth, async (req, res) => {
  await Document.findByIdAndDelete(req.params.id);  // Anyone can delete!
  res.json({ success: true });
});

// ✅ FIXED - verify ownership
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const document = await Document.findById(req.params.id);

  if (!document) {
    return res.status(404).json({ error: 'Document not found' });
  }

  // Check ownership
  if (document.userId.toString() !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }

  res.json(document);
});

// ✅ BETTER - query with ownership built-in
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const document = await Document.findOne({
    _id: req.params.id,
    userId: req.user.id  // Only returns if user owns it
  });

  if (!document) {
    return res.status(404).json({ error: 'Document not found' });
  }

  res.json(document);
});

// For admin routes, check role
app.delete('/api/admin/users/:id', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  await User.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});
\`\`\``,
			verification: `- Test accessing other users' resources by changing IDs
- Search for findById without ownership check: \`grep -r "findById\\|findOne" --include="*.js" -A5\`
- Verify every data-modifying endpoint checks ownership
- Create two test accounts and try to access each other's data`
		},

		'csrf': {
			title: '🟠 Cross-Site Request Forgery (CSRF)',
			problem: 'State-changing requests can be triggered by malicious websites when users are authenticated.',
			solution: `Implement CSRF protection:

**Express.js with csurf:**
\`\`\`javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Apply to state-changing routes
app.post('/api/transfer', csrfProtection, (req, res) => {
  // req.csrfToken() generates the token to include in forms
});

// Include token in forms
app.get('/transfer', csrfProtection, (req, res) => {
  res.render('transfer', { csrfToken: req.csrfToken() });
});
\`\`\`

**Using SameSite cookies (modern approach):**
\`\`\`javascript
// Set SameSite=Strict on all auth cookies
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',  // Prevents CSRF in modern browsers
  maxAge: 24 * 60 * 60 * 1000
});
\`\`\`

**For SPAs with fetch:**
\`\`\`javascript
// Server: Generate and return CSRF token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Client: Include in headers
const csrfToken = await fetch('/api/csrf-token').then(r => r.json());

fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken.csrfToken
  },
  body: JSON.stringify(data)
});
\`\`\``,
			verification: `- Verify SameSite=Strict is set on session cookies
- Test state-changing endpoints from a different origin
- Check that CSRF tokens are validated on POST/PUT/DELETE
- Verify CORS doesn't allow all origins with credentials`
		},

		'cors': {
			title: '🟠 CORS Misconfiguration',
			problem: 'Overly permissive CORS settings allow malicious websites to make authenticated requests to your API.',
			solution: `Configure CORS with specific allowed origins:

\`\`\`javascript
const cors = require('cors');

// ❌ VULNERABLE - allows any origin
app.use(cors());

// ❌ VULNERABLE - wildcard with credentials
app.use(cors({
  origin: '*',
  credentials: true  // This combination is dangerous!
}));

// ✅ FIXED - specific origins
const allowedOrigins = [
  'https://myapp.com',
  'https://app.myapp.com',
  process.env.NODE_ENV === 'development' && 'http://localhost:3000'
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
\`\`\``,
			verification: `- Check current CORS config: \`grep -r "cors(" --include="*.js" -A10\`
- Verify origin is not '*' when credentials: true
- Test from unauthorized origin - should be blocked
- List all allowed origins and verify they're all trusted`
		},

		'jwt-issues': {
			title: '🟠 JWT Security Issues',
			problem: 'JWT implementation has weaknesses like missing algorithm validation, no expiration, or weak secrets.',
			solution: `Implement JWT securely:

\`\`\`javascript
const jwt = require('jsonwebtoken');

// ❌ VULNERABLE - no algorithm specified in verify
const decoded = jwt.verify(token, secret);  // Accepts 'none' algorithm!

// ❌ VULNERABLE - no expiration
const token = jwt.sign({ userId: user.id }, secret);

// ❌ VULNERABLE - weak secret
const secret = 'mysecret';

// ✅ FIXED - complete secure implementation
const JWT_SECRET = process.env.JWT_SECRET;  // At least 64 random bytes
const JWT_ALGORITHM = 'HS256';

// Generate strong secret (run once):
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

// Sign with expiration
function generateToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      algorithm: JWT_ALGORITHM,
      expiresIn: '15m',  // Short-lived access token
      issuer: 'myapp.com'
    }
  );
}

// Verify with algorithm specified
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: [JWT_ALGORITHM],  // CRITICAL: specify allowed algorithms
    issuer: 'myapp.com'
  });
}

// Implement refresh tokens for longer sessions
function generateRefreshToken(user) {
  return jwt.sign(
    { userId: user.id, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}
\`\`\``,
			verification: `- Search for jwt.verify without algorithms: \`grep -r "jwt.verify" --include="*.js" -A3\`
- Search for jwt.sign without expiresIn: \`grep -r "jwt.sign" --include="*.js" -A5\`
- Verify JWT_SECRET is from environment, not hardcoded
- Test with jwt.io - check algorithm and expiration exist`
		},

		'session-security': {
			title: '🟠 Session Security Issues',
			problem: 'Session configuration is insecure, making sessions vulnerable to hijacking, fixation, or theft.',
			solution: `Configure sessions securely:

\`\`\`javascript
const session = require('express-session');

// ❌ VULNERABLE
app.use(session({
  secret: 'keyboard cat',  // Weak secret
  cookie: {}  // No security flags
}));

// ✅ FIXED
app.use(session({
  secret: process.env.SESSION_SECRET,  // Strong random secret from env
  name: 'sessionId',  // Change from default 'connect.sid'
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,     // Prevents JavaScript access
    secure: true,       // HTTPS only (set false for dev)
    sameSite: 'strict', // CSRF protection
    maxAge: 24 * 60 * 60 * 1000  // 24 hours
  }
}));

// Regenerate session on login (prevents session fixation)
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body);

  if (user) {
    // Regenerate session ID after authentication
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });

      req.session.userId = user.id;
      res.json({ success: true });
    });
  }
});

// Destroy session properly on logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('sessionId');
    res.json({ success: true });
  });
});
\`\`\``,
			verification: `- Check session config: \`grep -r "session(" --include="*.js" -A15\`
- Verify cookie has httpOnly, secure, sameSite flags
- Verify session.regenerate() is called after login
- Verify session.destroy() is called on logout`
		},

		'cookie-security': {
			title: '🟠 Insecure Cookie Configuration',
			problem: 'Cookies lack security flags, making them vulnerable to theft via XSS or interception.',
			solution: `Set all security flags on cookies:

\`\`\`javascript
// ❌ VULNERABLE - no security flags
res.cookie('session', token);
res.cookie('auth', value, { httpOnly: true });  // Missing secure/sameSite

// ✅ FIXED - all security flags
res.cookie('session', token, {
  httpOnly: true,      // Cannot be accessed by JavaScript (XSS protection)
  secure: true,        // Only sent over HTTPS
  sameSite: 'strict',  // Not sent with cross-site requests (CSRF protection)
  maxAge: 24 * 60 * 60 * 1000,  // Expiration in milliseconds
  path: '/'            // Cookie scope
});

// For development (when not using HTTPS)
const isProduction = process.env.NODE_ENV === 'production';

res.cookie('session', token, {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'strict' : 'lax',
  maxAge: 24 * 60 * 60 * 1000
});
\`\`\``,
			verification: `- Search for res.cookie: \`grep -r "res.cookie\\|cookies.set" --include="*.js" -A5\`
- Verify all cookies have httpOnly, secure, sameSite
- Check in browser DevTools > Application > Cookies
- Test that cookies aren't sent over HTTP`
		},

		'weak-crypto': {
			title: '🟠 Weak Cryptography',
			problem: 'Using outdated or weak cryptographic algorithms that can be broken.',
			solution: `Use modern, strong cryptographic algorithms:

**For password hashing (ALWAYS use bcrypt or argon2):**
\`\`\`javascript
// ❌ VULNERABLE
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash = crypto.createHash('sha1').update(password).digest('hex');
const hash = crypto.createHash('sha256').update(password).digest('hex');  // Still wrong for passwords!

// ✅ FIXED - use bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;  // Minimum 12 for 2024

// Hashing
const hash = await bcrypt.hash(password, SALT_ROUNDS);

// Verifying
const isValid = await bcrypt.compare(inputPassword, storedHash);
\`\`\`

**For general hashing (data integrity, not passwords):**
\`\`\`javascript
// ❌ VULNERABLE
crypto.createHash('md5').update(data).digest('hex');
crypto.createHash('sha1').update(data).digest('hex');

// ✅ FIXED
crypto.createHash('sha256').update(data).digest('hex');
// Or SHA-3:
crypto.createHash('sha3-256').update(data).digest('hex');
\`\`\`

**For encryption:**
\`\`\`javascript
// ❌ VULNERABLE
crypto.createCipher('des', key);  // DES is broken
crypto.createCipher('aes-256-ecb', key);  // ECB mode is insecure
crypto.createCipher('aes-256-cbc', key);  // Deprecated API

// ✅ FIXED - use AES-256-GCM (authenticated encryption)
const crypto = require('crypto');

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);  // Random IV for each encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // Return IV + authTag + ciphertext (all needed for decryption)
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData, key) {
  const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
\`\`\``,
			verification: `- Search for weak hashes: \`grep -r "createHash.*md5\\|createHash.*sha1" --include="*.js"\`
- Search for deprecated cipher: \`grep -r "createCipher(" --include="*.js"\`
- Verify passwords use bcrypt/argon2, not SHA/MD5
- Check encryption uses AES-256-GCM with random IV`
		},

		'insecure-deserialization': {
			title: '🔴 Insecure Deserialization',
			problem: 'Deserializing untrusted data can lead to remote code execution.',
			solution: `Never deserialize untrusted data. Use JSON with schema validation:

**Node.js:**
\`\`\`javascript
// ❌ VULNERABLE - node-serialize has RCE vulnerability
const serialize = require('node-serialize');
const obj = serialize.unserialize(userInput);  // RCE possible!

// ❌ VULNERABLE - eval-based parsing
const obj = eval('(' + userInput + ')');

// ✅ FIXED - use JSON.parse with validation
const Joi = require('joi');

const schema = Joi.object({
  name: Joi.string().max(100).required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().min(0).max(150)
});

function parseUserData(input) {
  const data = JSON.parse(input);  // Safe parsing
  const { error, value } = schema.validate(data);  // Schema validation

  if (error) {
    throw new Error('Invalid data format');
  }

  return value;
}
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE - pickle with untrusted data
import pickle
obj = pickle.loads(user_input)  # RCE possible!

# ❌ VULNERABLE - yaml.load
import yaml
obj = yaml.load(user_input)  # RCE possible!

# ✅ FIXED - use JSON with validation
import json
from pydantic import BaseModel

class UserData(BaseModel):
    name: str
    email: str
    age: int

data = json.loads(user_input)
user = UserData(**data)  # Validates against schema
\`\`\``,
			verification: `- Search for dangerous deserializers: \`grep -r "unserialize\\|pickle.loads\\|yaml.load" --include="*.js" --include="*.py"\`
- Remove node-serialize package if present
- Verify all data parsing uses JSON.parse with validation
- Check that yaml uses safe_load, not load`
		},

		'xxe': {
			title: '🟠 XML External Entity (XXE) Injection',
			problem: 'XML parsers process external entities, allowing file disclosure or SSRF.',
			solution: `Disable external entity processing:

**Node.js:**
\`\`\`javascript
// ❌ VULNERABLE - default libxmljs settings
const libxmljs = require('libxmljs');
const doc = libxmljs.parseXml(userInput);

// ✅ FIXED - disable external entities
const doc = libxmljs.parseXml(userInput, {
  noent: false,      // Don't expand entities
  nonet: true,       // Don't allow network access
  noblanks: true,
  dtdload: false,    // Don't load external DTD
  dtdvalid: false    // Don't validate against DTD
});

// ✅ BETTER - use JSON instead of XML when possible
const data = JSON.parse(userInput);
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
from xml.etree import ElementTree as ET
tree = ET.parse(user_file)

# ✅ FIXED - use defusedxml
from defusedxml.ElementTree import parse
tree = parse(user_file)

# Or configure lxml safely
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)
tree = etree.parse(user_file, parser)
\`\`\`

**Java:**
\`\`\`java
// ✅ FIXED - disable DTDs and external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
\`\`\``,
			verification: `- Search for XML parsing: \`grep -r "parseXml\\|ElementTree\\|DocumentBuilder" --include="*.js" --include="*.py" --include="*.java"\`
- Verify external entities are disabled
- Test with XXE payload to confirm protection
- Consider replacing XML with JSON where possible`
		},

		'open-redirect': {
			title: '🟠 Open Redirect',
			problem: 'User-controlled redirect URLs can be used for phishing attacks.',
			solution: `Validate redirect URLs strictly:

\`\`\`javascript
// ❌ VULNERABLE
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);  // Attacker: ?url=https://evil.com
});

app.get('/login', (req, res) => {
  const returnUrl = req.query.returnUrl || '/dashboard';
  // After login...
  res.redirect(returnUrl);  // Attacker: ?returnUrl=https://phishing.com
});

// ✅ FIXED - validate redirect URL
function isValidRedirectUrl(url) {
  // Only allow relative paths
  if (!url.startsWith('/')) {
    return false;
  }

  // Block protocol-relative URLs
  if (url.startsWith('//')) {
    return false;
  }

  // Block javascript: URLs
  if (url.toLowerCase().includes('javascript:')) {
    return false;
  }

  return true;
}

app.get('/redirect', (req, res) => {
  const url = req.query.url || '/';

  if (!isValidRedirectUrl(url)) {
    return res.redirect('/');  // Safe default
  }

  res.redirect(url);
});

// ✅ ALTERNATIVE - use allowlist for external URLs
const ALLOWED_REDIRECT_HOSTS = ['myapp.com', 'auth.myapp.com'];

function isAllowedRedirect(urlString) {
  try {
    const url = new URL(urlString, 'https://myapp.com');  // Base URL for relative paths
    return ALLOWED_REDIRECT_HOSTS.includes(url.hostname);
  } catch {
    return false;
  }
}
\`\`\``,
			verification: `- Search for redirects: \`grep -r "res.redirect\\|location.*=" --include="*.js"\`
- Test with external URL: \`?returnUrl=https://evil.com\`
- Test with protocol-relative: \`?returnUrl=//evil.com\`
- Verify validation exists before all redirects`
		},

		'debug-exposure': {
			title: '🟠 Debug Mode / Verbose Errors Exposed',
			problem: 'Debug information or detailed error messages are exposed to users, revealing sensitive system information.',
			solution: `Disable debug mode and sanitize errors in production:

\`\`\`javascript
// ❌ VULNERABLE - stack traces exposed
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack  // Exposes internal paths and code
  });
});

// ❌ VULNERABLE - debug mode in production
app.listen(3000, () => {
  console.log('Debug mode enabled');
});

// ✅ FIXED - environment-aware error handling
const isProduction = process.env.NODE_ENV === 'production';

app.use((err, req, res, next) => {
  // Log full error server-side
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  // Return sanitized error to client
  res.status(err.status || 500).json({
    error: isProduction
      ? 'An unexpected error occurred'
      : err.message,
    ...(isProduction ? {} : { stack: err.stack })  // Only in dev
  });
});

// For Express, disable x-powered-by header
app.disable('x-powered-by');
\`\`\`

**Python Flask:**
\`\`\`python
# ❌ VULNERABLE
app.run(debug=True)  # In production!

# ✅ FIXED
app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
\`\`\`

**Django:**
\`\`\`python
# settings.py
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
\`\`\``,
			verification: `- Check for debug flags: \`grep -r "debug.*true\\|DEBUG.*True" --include="*.js" --include="*.py"\`
- Search for stack trace exposure: \`grep -r "err.stack\\|traceback" --include="*.js" --include="*.py"\`
- Test error responses in production mode
- Verify NODE_ENV=production is set in deployment`
		},

		'security-headers': {
			title: '🟠 Missing Security Headers',
			problem: 'Security headers are not set, leaving the application vulnerable to various attacks.',
			solution: `Add security headers using Helmet or manually:

\`\`\`javascript
// ✅ RECOMMENDED - use Helmet (Express)
const helmet = require('helmet');
app.use(helmet());

// Helmet sets these headers automatically:
// - X-Content-Type-Options: nosniff
// - X-Frame-Options: DENY
// - X-XSS-Protection: 0 (deprecated, CSP is better)
// - Strict-Transport-Security
// - And more...

// ✅ Custom CSP configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Customize as needed
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

// ✅ ALTERNATIVE - manual headers (any framework)
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Force HTTPS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // Basic CSP
  res.setHeader('Content-Security-Policy', "default-src 'self'");

  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  next();
});
\`\`\`

**Install:** \`npm install helmet\``,
			verification: `- Check for helmet: \`grep -r "helmet" --include="*.js"\`
- Test headers: \`curl -I https://yoursite.com\`
- Use securityheaders.com to scan your site
- Verify CSP is appropriate for your app`
		},

		'rate-limiting': {
			title: '🟠 Missing Rate Limiting',
			problem: 'No rate limiting allows brute force attacks, DoS, and abuse of resources.',
			solution: `Add rate limiting to sensitive endpoints:

\`\`\`javascript
// Install: npm install express-rate-limit
const rateLimit = require('express-rate-limit');

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // 100 requests per window
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// Strict limit for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // Only 5 attempts
  message: { error: 'Too many login attempts, please try again in 15 minutes' },
  skipSuccessfulRequests: true,  // Don't count successful logins
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/forgot-password', authLimiter);

// Even stricter for password reset
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 3,  // Only 3 attempts per hour
});

app.use('/api/reset-password', passwordResetLimiter);
\`\`\`

**For Redis-backed rate limiting (distributed systems):**
\`\`\`javascript
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

const redisClient = new Redis(process.env.REDIS_URL);

const limiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 100,
});
\`\`\``,
			verification: `- Check for rate limiting: \`grep -r "rateLimit\\|rate-limit" --include="*.js"\`
- Verify auth endpoints have strict limits (5-10 per 15 min)
- Test by sending many requests rapidly
- Monitor for brute force attempts in logs`
		},

		'vulnerable-dependency': {
			title: '🟠 Vulnerable Dependencies',
			problem: 'Project uses packages with known security vulnerabilities.',
			solution: `Update or replace vulnerable packages:

**Check and fix vulnerabilities:**
\`\`\`bash
# View vulnerabilities
npm audit

# Auto-fix what's possible
npm audit fix

# Force fix (may include breaking changes)
npm audit fix --force

# Update specific package
npm update lodash

# Update to latest major version
npm install lodash@latest
\`\`\`

**If no fix is available:**
\`\`\`bash
# Check if vulnerability applies to your usage
# Read the advisory to understand the attack vector

# Option 1: Find alternative package
npm uninstall vulnerable-package
npm install safer-alternative

# Option 2: Override nested dependency (package.json)
{
  "overrides": {
    "vulnerable-package": "^2.0.0"
  }
}

# Option 3: If low risk, document and accept
# Add to .nsprc or similar to ignore
\`\`\`

**For Python:**
\`\`\`bash
# Check vulnerabilities
pip-audit

# Or use safety
safety check

# Update package
pip install --upgrade package-name
\`\`\`

**Set up automated checks:**
\`\`\`yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm audit --audit-level=high
\`\`\``,
			verification: `- Run npm audit and address all high/critical issues
- Check if fixes break functionality
- Set up CI/CD to fail on new vulnerabilities
- Review CHANGELOG when updating major versions`
		},

		'logging-issues': {
			title: '🟠 Logging Security Issues',
			problem: 'Sensitive data is logged, or logs are vulnerable to injection.',
			solution: `Never log sensitive data and sanitize log input:

\`\`\`javascript
// ❌ VULNERABLE - logging sensitive data
console.log('User login:', { email, password });
logger.info(\`Payment processed: \${creditCardNumber}\`);
logger.debug('API response:', apiResponse);  // May contain tokens

// ❌ VULNERABLE - log injection
logger.info(\`User action: \${userInput}\`);  // Attacker injects newlines

// ✅ FIXED - redact sensitive fields
const redactSensitive = (obj) => {
  const sensitiveFields = ['password', 'token', 'secret', 'creditCard', 'ssn', 'apiKey'];
  const redacted = { ...obj };

  for (const field of sensitiveFields) {
    if (redacted[field]) {
      redacted[field] = '[REDACTED]';
    }
  }

  return redacted;
};

logger.info('User login:', redactSensitive({ email, password }));
// Output: User login: { email: 'user@example.com', password: '[REDACTED]' }

// ✅ FIXED - sanitize log input
const sanitizeForLog = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/[\\n\\r]/g, ' ')  // Remove newlines (prevent injection)
    .slice(0, 1000);           // Limit length
};

logger.info('User action:', sanitizeForLog(userInput));

// ✅ USE structured logging
const winston = require('winston');

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.File({ filename: 'app.log' })]
});

// Structured logs are harder to inject
logger.info('User action', {
  action: sanitizeForLog(userInput),
  userId: user.id,
  ip: req.ip
});
\`\`\``,
			verification: `- Search for logged secrets: \`grep -r "console.log.*password\\|logger.*token" --include="*.js"\`
- Verify user input is sanitized before logging
- Check logs don't contain PII or credentials
- Test log injection with newline characters`
		},

		'file-security': {
			title: '🟠 File Upload / File Handling Security',
			problem: 'File uploads lack proper validation, allowing malicious file uploads or path manipulation.',
			solution: `Validate file uploads thoroughly:

\`\`\`javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// ❌ VULNERABLE - no validation
const upload = multer({ dest: 'uploads/' });

// ✅ FIXED - comprehensive validation
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
const MAX_SIZE = 5 * 1024 * 1024;  // 5MB

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    // Generate random filename to prevent overwrites
    const uniqueName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, uniqueName + ext);
  }
});

const fileFilter = (req, file, cb) => {
  // Check MIME type
  if (!ALLOWED_TYPES.includes(file.mimetype)) {
    return cb(new Error('Invalid file type'), false);
  }

  // Check extension
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
  if (!allowedExts.includes(ext)) {
    return cb(new Error('Invalid file extension'), false);
  }

  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_SIZE,
    files: 1
  }
});

// Additional validation after upload - check magic bytes
const fileType = require('file-type');

app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // Verify actual file type by reading magic bytes
  const type = await fileType.fromFile(req.file.path);

  if (!type || !ALLOWED_TYPES.includes(type.mime)) {
    // Delete the uploaded file
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Invalid file content' });
  }

  res.json({ filename: req.file.filename });
});
\`\`\``,
			verification: `- Search for upload handling: \`grep -r "multer\\|upload\\|multipart" --include="*.js"\`
- Verify file type is checked by content, not just extension
- Test uploading a .php file renamed to .jpg
- Verify upload directory is outside webroot
- Check file size limits are enforced`
		},

		'nosql-injection': {
			title: '🔴 NoSQL Injection',
			problem: 'User input in NoSQL queries can manipulate query logic using operators like $gt, $ne.',
			solution: `Validate input types and sanitize MongoDB queries:

\`\`\`javascript
// ❌ VULNERABLE - user controls query operators
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    password: req.body.password  // Attacker sends { "$ne": "" }
  });
  // This matches ANY user with non-empty password!
});

// ✅ FIXED - validate input types
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Ensure inputs are strings, not objects
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  // Now safe to query
  const user = await User.findOne({ email });

  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Login successful...
});

// ✅ ALTERNATIVE - use mongo-sanitize
const mongoSanitize = require('express-mongo-sanitize');

// Apply to all requests
app.use(mongoSanitize());

// Or sanitize specific inputs
const sanitize = require('mongo-sanitize');
const cleanEmail = sanitize(req.body.email);
\`\`\`

**Install:** \`npm install express-mongo-sanitize\``,
			verification: `- Search for MongoDB queries with user input: \`grep -r "findOne.*req.body\\|find.*req.query" --include="*.js"\`
- Test with: \`{"email": {"$gt": ""}, "password": {"$gt": ""}}\`
- Verify input type validation exists
- Consider using mongo-sanitize middleware`
		},

		'template-injection': {
			title: '🔴 Server-Side Template Injection (SSTI)',
			problem: 'User input is passed into template rendering, allowing code execution on the server.',
			solution: `Never pass user input directly to template engines:

**Python (Flask/Jinja2):**
\`\`\`python
# ❌ VULNERABLE
from flask import render_template_string

@app.route('/hello')
def hello():
    template = request.args.get('template')
    return render_template_string(template)  # Attacker: {{config}}

# ✅ FIXED - use static templates with variables
from flask import render_template

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template('hello.html', name=name)
\`\`\`

**Node.js (EJS, Pug, etc.):**
\`\`\`javascript
// ❌ VULNERABLE
app.get('/page', (req, res) => {
  const template = req.query.template;
  res.render(template);  // Path traversal + SSTI
});

// ❌ VULNERABLE
const ejs = require('ejs');
const html = ejs.render(userInput);  // SSTI possible

// ✅ FIXED - only render static templates with user data as variables
app.get('/page', (req, res) => {
  res.render('page', {
    title: req.query.title,
    content: req.query.content
  });
});
\`\`\``,
			verification: `- Search for render_template_string: \`grep -r "render_template_string\\|ejs.render" --include="*.py" --include="*.js"\`
- Verify user input never controls template selection
- Test with template syntax: \`{{7*7}}\` or \`\${7*7}\`
- Use static templates with variables only`
		},

		'code-injection': {
			title: '🔴 Code Injection (eval)',
			problem: 'Using eval() or similar functions with user input allows arbitrary code execution.',
			solution: `Never use eval() with user input. Use safe alternatives:

\`\`\`javascript
// ❌ VULNERABLE
const result = eval(req.body.expression);  // RCE!
const fn = new Function(userInput);  // Also dangerous
setTimeout(userInput, 1000);  // If userInput is a string
setInterval(userInput, 1000);

// ✅ FIXED - for math expressions
const mathjs = require('mathjs');
const result = mathjs.evaluate(req.body.expression);  // Safe math only

// ✅ FIXED - for JSON parsing
const data = JSON.parse(req.body.data);  // Safe

// ✅ FIXED - for dynamic property access
const allowedProps = ['name', 'email', 'age'];
const prop = req.body.property;

if (allowedProps.includes(prop)) {
  const value = user[prop];  // Safe with allowlist
}

// ✅ FIXED - for setTimeout with user delay
const delay = parseInt(req.body.delay, 10);
if (isNaN(delay) || delay < 0 || delay > 60000) {
  throw new Error('Invalid delay');
}
setTimeout(() => doSomething(), delay);  // Function reference, not string
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
result = eval(user_input)
exec(user_input)

# ✅ FIXED - for math
import ast
result = ast.literal_eval(user_input)  # Only literals, no code

# Or use a safe math library
import simpleeval
result = simpleeval.simple_eval(user_input)
\`\`\``,
			verification: `- Search for eval: \`grep -r "eval(\\|new Function\\|exec(" --include="*.js" --include="*.py"\`
- Search for string-based setTimeout: \`grep -r "setTimeout.*req\\|setInterval.*req" --include="*.js"\`
- Remove or replace all eval usage
- Verify no user input reaches code execution functions`
		},

		'prototype-pollution': {
			title: '🟠 Prototype Pollution',
			problem: 'User input can modify Object.prototype, affecting all objects in the application.',
			solution: `Block dangerous keys and use safe merging:

\`\`\`javascript
// ❌ VULNERABLE - recursive merge without key filtering
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
merge({}, userInput);
// Now ALL objects have isAdmin === true!

// ✅ FIXED - block dangerous keys
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
  for (const key in source) {
    if (DANGEROUS_KEYS.includes(key)) {
      continue;  // Skip dangerous keys
    }

    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ✅ BETTER - use Map for user-keyed data
const userData = new Map();
userData.set(userKey, userValue);  // Safe - Map doesn't pollute prototype

// ✅ ALTERNATIVE - use Object.create(null)
const safeObj = Object.create(null);  // No prototype chain
safeObj[userKey] = userValue;  // Safe

// ✅ USE safe libraries
const _ = require('lodash');  // Updated versions are safe
_.merge(target, source);  // Lodash blocks __proto__
\`\`\``,
			verification: `- Search for recursive merge/extend: \`grep -r "merge\\|extend\\|deepCopy" --include="*.js"\`
- Test with: \`{"__proto__": {"polluted": true}}\`
- Check: \`({}).polluted\` should be undefined
- Use Object.create(null) or Map for user-keyed objects`
		},

		'regex-dos': {
			title: '🟠 Regular Expression DoS (ReDoS)',
			problem: 'Complex regex patterns with nested quantifiers can cause catastrophic backtracking.',
			solution: `Avoid vulnerable regex patterns and add input limits:

\`\`\`javascript
// ❌ VULNERABLE - nested quantifiers cause exponential backtracking
const emailRegex = /^([a-zA-Z0-9]+)+@/;  // (x+)+ is dangerous
const badRegex = /^(a+)+$/;
const overlapping = /^(a|a)+$/;

// These can hang with input like: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

// ✅ FIXED - use atomic groups / possessive quantifiers (where supported)
// Or simplify the regex
const safeEmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;

// ✅ FIXED - limit input length before regex
function validateEmail(input) {
  if (typeof input !== 'string' || input.length > 254) {
    return false;
  }
  return safeEmailRegex.test(input);
}

// ✅ FIXED - use regex timeout (Node.js 16+)
const { RE2 } = require('re2');  // Linear time regex engine

const safeRegex = new RE2('^([a-zA-Z0-9]+)+@');  // RE2 prevents backtracking

// ✅ FIXED - for user-provided regex patterns
function createSafeRegex(pattern, flags) {
  // Limit pattern length
  if (pattern.length > 100) {
    throw new Error('Pattern too long');
  }

  // Use RE2 for user patterns
  return new RE2(pattern, flags);
}
\`\`\`

**Test for vulnerable patterns:** Use [recheck](https://makenowjust-labs.github.io/recheck/)`,
			verification: `- Search for complex regex: \`grep -r "\\(.*+\\).*+" --include="*.js"\`
- Test suspicious patterns with long input
- Add input length limits before regex
- Consider RE2 library for user-provided patterns`
		},

		'weak-random': {
			title: '🟠 Weak Random Number Generation',
			problem: 'Math.random() is not cryptographically secure and can be predicted.',
			solution: `Use crypto module for security-sensitive random values:

\`\`\`javascript
// ❌ VULNERABLE - predictable
const token = Math.random().toString(36).substring(2);
const sessionId = Math.random().toString();

// ✅ FIXED - cryptographically secure
const crypto = require('crypto');

// For tokens/secrets (hex string)
const token = crypto.randomBytes(32).toString('hex');

// For URL-safe tokens
const urlSafeToken = crypto.randomBytes(32).toString('base64url');

// For session IDs
const sessionId = crypto.randomUUID();

// For numeric values in a range
function secureRandomInt(min, max) {
  const range = max - min;
  const randomBuffer = crypto.randomBytes(4);
  const randomValue = randomBuffer.readUInt32BE(0);
  return min + (randomValue % range);
}

// For selecting from an array
function secureRandomChoice(array) {
  const index = secureRandomInt(0, array.length);
  return array[index];
}
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
import random
token = ''.join(random.choices(string.ascii_letters, k=32))

# ✅ FIXED
import secrets

token = secrets.token_hex(32)
url_safe_token = secrets.token_urlsafe(32)
random_int = secrets.randbelow(100)
random_choice = secrets.choice(['a', 'b', 'c'])
\`\`\``,
			verification: `- Search for Math.random: \`grep -r "Math.random" --include="*.js"\`
- Search for Python random: \`grep -r "import random\\|from random" --include="*.py"\`
- Verify security-sensitive values use crypto/secrets module
- Check token generation for sessions, reset tokens, API keys`
		},

		'tls-issues': {
			title: '🟠 TLS/SSL Security Issues',
			problem: 'TLS certificate validation is disabled or weak protocols are allowed.',
			solution: `Never disable certificate validation in production:

**Node.js:**
\`\`\`javascript
// ❌ VULNERABLE
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const https = require('https');
https.get('https://example.com', { rejectUnauthorized: false });

const axios = require('axios');
axios.get('https://example.com', { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });

// ✅ FIXED - always validate certificates
// Remove NODE_TLS_REJECT_UNAUTHORIZED from env

const https = require('https');
https.get('https://example.com');  // Validates by default

// For self-signed certs in development only:
const agent = new https.Agent({
  rejectUnauthorized: process.env.NODE_ENV === 'production',
  // Or specify the CA:
  ca: fs.readFileSync('path/to/ca-cert.pem')
});
\`\`\`

**Python:**
\`\`\`python
# ❌ VULNERABLE
import requests
response = requests.get(url, verify=False)

import urllib3
urllib3.disable_warnings()

# ✅ FIXED
response = requests.get(url)  # verify=True is default

# For self-signed certs:
response = requests.get(url, verify='/path/to/ca-bundle.crt')
\`\`\``,
			verification: `- Search for disabled verification: \`grep -r "rejectUnauthorized.*false\\|verify.*False\\|NODE_TLS_REJECT" --include="*.js" --include="*.py"\`
- Remove all SSL verification bypasses
- For self-signed certs, specify the CA file instead of disabling`
		},

		'other-security': {
			title: '⚠️ Security Issue',
			problem: 'A security issue was detected that requires manual review.',
			solution: `Review the finding and apply appropriate security measures:

**General security principles to apply:**

1. **Input Validation**
   - Validate all input at system boundaries
   - Use allowlists over blocklists
   - Validate type, length, format, and range

2. **Output Encoding**
   - Encode output based on context (HTML, URL, JavaScript, SQL)
   - Use framework-provided escaping functions

3. **Authentication & Authorization**
   - Verify identity on every request
   - Check permissions before accessing resources
   - Use established authentication libraries

4. **Cryptography**
   - Use modern algorithms (AES-256-GCM, bcrypt, SHA-256+)
   - Never roll your own crypto
   - Generate strong random values with crypto module

5. **Error Handling**
   - Log errors server-side with details
   - Return generic messages to users
   - Never expose stack traces in production

6. **Dependencies**
   - Keep dependencies updated
   - Run npm audit regularly
   - Remove unused packages

**To fix this specific issue:**
1. Read the finding title and description carefully
2. Identify what type of vulnerability it represents
3. Apply the relevant security principle above
4. Test that the fix works and doesn't break functionality`,
			verification: `- Review the specific vulnerability type
- Apply appropriate security controls
- Test the fix thoroughly
- Search for similar patterns in the codebase`
		}
	};

	return guides[type] || guides['other-security'];
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

	// === setTimeout/setInterval with string ===
	if ((searchKey.includes('settimeout') || searchKey.includes('setinterval')) && searchKey.includes('string')) {
		return 'Pass function reference, not string: setTimeout(() => doSomething(), 1000) instead of setTimeout("doSomething()", 1000)';
	}

	// === document.write ===
	if (searchKey.includes('document.write') || searchKey.includes('document-write')) {
		return 'Replace document.write with DOM manipulation: element.textContent = text or element.appendChild(node). document.write is unsafe and blocks parsing';
	}

	// === insertAdjacentHTML / outerHTML ===
	if (searchKey.includes('insertadjacenthtml') || searchKey.includes('outerhtml')) {
		return 'Sanitize input before using: element.insertAdjacentHTML("beforeend", DOMPurify.sanitize(html)) or use DOM methods instead';
	}

	// === jQuery DOM XSS patterns ===
	if (searchKey.includes('jquery') && (searchKey.includes('html') || searchKey.includes('append') || searchKey.includes('prepend') || searchKey.includes('after') || searchKey.includes('before'))) {
		return 'Use .text() instead of .html() for user data: $(el).text(userInput). For HTML, sanitize: $(el).html(DOMPurify.sanitize(content))';
	}

	// === React href javascript: ===
	if (searchKey.includes('href') && searchKey.includes('javascript')) {
		return 'Never use javascript: in href. Use onClick handler: <button onClick={handleClick}> or validate URL starts with https://';
	}

	// === Vue compile dynamic ===
	if (searchKey.includes('vue') && searchKey.includes('compile')) {
		return 'Never compile user-provided templates. Use pre-compiled templates only. If dynamic rendering needed, use render functions with sanitized data';
	}

	// === Angular bypassSecurity ===
	if (searchKey.includes('angular') && searchKey.includes('bypass')) {
		return 'Avoid bypassSecurityTrust*() functions. Use Angular sanitization or pipe through DomSanitizer.sanitize() with appropriate SecurityContext';
	}

	// === Next.js specific ===
	if (searchKey.includes('nextjs') || searchKey.includes('next.js') || searchKey.includes('next-')) {
		if (searchKey.includes('getserverside') && searchKey.includes('html')) return 'Sanitize in getServerSideProps before passing to dangerouslySetInnerHTML: return { props: { html: DOMPurify.sanitize(data) } }';
		if (searchKey.includes('api') && searchKey.includes('sql')) return 'Use parameterized queries in Next.js API routes: await db.query("SELECT * FROM users WHERE id = $1", [req.query.id])';
		if (searchKey.includes('header')) return 'Set security headers in next.config.js: headers: [{ source: "/(.*)", headers: securityHeaders }]';
		if (searchKey.includes('middleware')) return 'Validate authorization in middleware.ts: if (!token) return NextResponse.redirect("/login")';
	}

	// === SvelteKit specific ===
	if (searchKey.includes('sveltekit') || searchKey.includes('svelte')) {
		if (searchKey.includes('@html') || searchKey.includes('html-inject')) return 'Avoid {@html}. Use text interpolation {variable} or sanitize: {@html DOMPurify.sanitize(content)}';
		if (searchKey.includes('load')) return 'Validate user data in load functions: if (!locals.user) throw redirect(303, "/login")';
		if (searchKey.includes('form') || searchKey.includes('action')) return 'Use SvelteKit form actions with CSRF protection built-in. Validate all form data server-side';
	}

	// === Node.js child_process ===
	if (searchKey.includes('child_process') || searchKey.includes('spawn') || searchKey.includes('execfile')) {
		if (searchKey.includes('spawn') && searchKey.includes('shell')) return 'Use spawn without shell: spawn("cmd", args, { shell: false }). shell: true enables injection';
		return 'Use execFile with array args: execFile("convert", [inputFile, outputFile]). Validate/sanitize all arguments';
	}

	// === Node.js fs path operations ===
	if (searchKey.includes('fs') && (searchKey.includes('readfile') || searchKey.includes('writefile') || searchKey.includes('unlink'))) {
		return 'Validate path: const safe = path.join(BASE_DIR, path.basename(input)); if (!safe.startsWith(BASE_DIR)) throw new Error("Path traversal")';
	}

	// === Express sendFile ===
	if (searchKey.includes('sendfile') || searchKey.includes('send-file')) {
		return 'Use root option and validate: res.sendFile(filename, { root: path.join(__dirname, "public") }). Never use absolute paths from user input';
	}

	// === node-serialize vulnerability ===
	if (searchKey.includes('node-serialize') || searchKey.includes('unserialize')) {
		return 'Remove node-serialize entirely - it has RCE vulnerability. Use JSON.parse() with schema validation (Zod/Joi)';
	}

	// === js-yaml unsafe load ===
	if (searchKey.includes('yaml') && searchKey.includes('load') && !searchKey.includes('safe')) {
		return 'Use yaml.load(data, { schema: yaml.SAFE_SCHEMA }) or yaml.safeLoad(). Never yaml.load() with untrusted YAML';
	}

	// === UUID v1 predictable ===
	if (searchKey.includes('uuid') && (searchKey.includes('v1') || searchKey.includes('predictable'))) {
		return 'Use UUIDv4 for unpredictable IDs: import { v4 as uuidv4 } from "uuid"; uuidv4(). UUIDv1 is time-based and predictable';
	}

	// === Express session hardcoded secret ===
	if (searchKey.includes('session') && searchKey.includes('hardcoded')) {
		return 'Move session secret to env: session({ secret: process.env.SESSION_SECRET }). Generate: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"';
	}

	// === Static IV / hardcoded IV ===
	if (searchKey.includes('static') && searchKey.includes('iv') || searchKey.includes('hardcoded') && searchKey.includes('iv')) {
		return 'Generate random IV per encryption: const iv = crypto.randomBytes(16). Store IV with ciphertext (it can be public)';
	}

	// === crypto.createCipher deprecated ===
	if (searchKey.includes('createcipher') && !searchKey.includes('iv')) {
		return 'Use createCipheriv with random IV: crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(16)). createCipher is deprecated';
	}

	// === MongoDB specific ===
	if (searchKey.includes('mongodb') || searchKey.includes('mongo')) {
		if (searchKey.includes('localhost') || searchKey.includes('no-auth')) return 'Enable MongoDB auth: use connection string with credentials and authSource. Never expose DB without authentication';
		if (searchKey.includes('findone') && searchKey.includes('unfiltered')) return 'Select only needed fields: User.findOne({ _id: id }, { password: 0, __v: 0 }). Never return full documents with sensitive fields';
		if (searchKey.includes('error') || searchKey.includes('disclosure')) return 'Catch and sanitize MongoDB errors: catch(e) { res.status(500).json({ error: "Database error" }) }. Never expose raw errors';
	}

	// === MySQL hardcoded credentials ===
	if (searchKey.includes('mysql') && searchKey.includes('hardcoded')) {
		return 'Use env vars for DB connection: mysql.createConnection({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASS })';
	}

	// === Cookie parser unsigned ===
	if (searchKey.includes('cookie') && searchKey.includes('parser') && searchKey.includes('unsigned')) {
		return 'Sign cookies: app.use(cookieParser(process.env.COOKIE_SECRET)). Set signed cookies: res.cookie("name", value, { signed: true })';
	}

	// === Credit card exposure ===
	if (searchKey.includes('credit') && searchKey.includes('card') || searchKey.includes('card') && searchKey.includes('number')) {
		return 'Never store full card numbers. Use tokenization (Stripe/Braintree). Mask display: **** **** **** 1234. Log only last 4 digits';
	}

	// === SSN exposure ===
	if (searchKey.includes('ssn') || searchKey.includes('social') && searchKey.includes('security')) {
		return 'Encrypt SSN at rest with AES-256-GCM. Mask in UI: ***-**-1234. Strict access controls and audit logging. Consider not storing if possible';
	}

	// === Password in console.log ===
	if (searchKey.includes('console') && (searchKey.includes('password') || searchKey.includes('secret') || searchKey.includes('token') || searchKey.includes('key'))) {
		return 'Remove sensitive data logging. Use structured logger with redaction: logger.info({ user: username, password: "[REDACTED]" })';
	}

	// === WebSocket insecure ===
	if (searchKey.includes('websocket') && (searchKey.includes('insecure') || searchKey.includes('ws://') || searchKey.includes('wss'))) {
		return 'Use wss:// (WebSocket Secure): new WebSocket("wss://example.com/socket"). Add authentication on connect';
	}

	// === HTTP password in URL ===
	if (searchKey.includes('password') && searchKey.includes('url')) {
		return 'Never put credentials in URLs - they appear in logs, history, referrer. Use Authorization header or POST body';
	}

	// === localStorage/sessionStorage for passwords ===
	if ((searchKey.includes('localstorage') || searchKey.includes('sessionstorage')) && (searchKey.includes('password') || searchKey.includes('token') || searchKey.includes('secret'))) {
		return 'Never store sensitive data in localStorage/sessionStorage - accessible to XSS. Use httpOnly cookies for tokens';
	}

	// === Loose comparison for passwords ===
	if (searchKey.includes('password') && searchKey.includes('loose') || searchKey.includes('==') && searchKey.includes('password')) {
		return 'Use bcrypt.compare() for password verification, never === or ==. bcrypt.compare handles timing attacks';
	}

	// === Empty string success check ===
	if (searchKey.includes('empty') && searchKey.includes('string') && searchKey.includes('success')) {
		return 'Check for explicit success condition, not absence of error: if (result.success === true) not if (!error)';
	}

	// === Missing error handler in AJAX ===
	if (searchKey.includes('ajax') && searchKey.includes('error')) {
		return 'Always handle errors: $.ajax({ url, success, error: (xhr, status, err) => { /* handle gracefully */ } })';
	}

	// === Regex injection ===
	if (searchKey.includes('regex') && searchKey.includes('inject')) {
		return 'Escape user input in regex: new RegExp(input.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")). Or use literal string search';
	}

	// === HTTP script src / no SRI ===
	if (searchKey.includes('script') && (searchKey.includes('http://') || searchKey.includes('integrity') || searchKey.includes('sri'))) {
		return 'Use HTTPS for scripts and add SRI: <script src="https://cdn.example/lib.js" integrity="sha384-..." crossorigin="anonymous">';
	}

	// === X-Powered-By header ===
	if (searchKey.includes('x-powered-by') || searchKey.includes('powered-by')) {
		return 'Disable X-Powered-By: app.disable("x-powered-by") or use helmet() which does this automatically';
	}

	// === Long session expiry ===
	if (searchKey.includes('session') && (searchKey.includes('expiry') || searchKey.includes('maxage') || searchKey.includes('long'))) {
		return 'Set reasonable session expiry: maxAge: 24 * 60 * 60 * 1000 (24h max). For sensitive apps, use 15-30 minutes';
	}

	// === Session no destroy on logout ===
	if (searchKey.includes('logout') && (searchKey.includes('destroy') || searchKey.includes('incomplete'))) {
		return 'Properly destroy session on logout: req.session.destroy((err) => { res.clearCookie("connect.sid"); res.redirect("/"); })';
	}

	// === Session no regenerate ===
	if (searchKey.includes('session') && searchKey.includes('regenerate')) {
		return 'Regenerate session after login: req.session.regenerate((err) => { req.session.userId = user.id; }). Prevents session fixation';
	}

	// === Test/default credentials in code ===
	if (searchKey.includes('test') && searchKey.includes('credential') || searchKey.includes('default') && searchKey.includes('password')) {
		return 'Remove test/default credentials from code. Use environment variables. Ensure CI/CD uses test-specific env files';
	}

	// === bodyParser deprecated ===
	if (searchKey.includes('bodyparser') && searchKey.includes('deprecated')) {
		return 'Use Express built-in: app.use(express.json()); app.use(express.urlencoded({ extended: true })); instead of body-parser';
	}

	// === returnUrl open redirect ===
	if (searchKey.includes('returnurl') || searchKey.includes('return_url') || searchKey.includes('redirect_uri')) {
		return 'Validate returnUrl is relative path or in allowlist: if (!returnUrl.startsWith("/") || returnUrl.startsWith("//")) returnUrl = "/"';
	}

	// === Error object to template ===
	if (searchKey.includes('error') && searchKey.includes('template')) {
		return 'Never pass error objects to templates: res.render("error", { message: "An error occurred" }) not { error: err }';
	}

	// === Hardcoded log path ===
	if (searchKey.includes('log') && searchKey.includes('path') && searchKey.includes('hardcoded')) {
		return 'Use environment variables for log paths: process.env.LOG_PATH || "/var/log/app". Ensure path is within allowed directory';
	}

	// === No log rotation ===
	if (searchKey.includes('log') && searchKey.includes('rotation')) {
		return 'Configure log rotation to prevent disk fill: winston with winston-daily-rotate-file or use logrotate system utility';
	}

	// === Python specific patterns ===
	if (isPython) {
		if (searchKey.includes('flask') && searchKey.includes('debug')) return 'Set debug=False in production: app.run(debug=False) or use FLASK_ENV=production';
		if (searchKey.includes('django') && searchKey.includes('debug')) return 'Set DEBUG=False in settings.py for production. Also set ALLOWED_HOSTS properly';
		if (searchKey.includes('request') && searchKey.includes('verify')) return 'Never disable SSL verification: requests.get(url, verify=True). For self-signed certs, use verify="/path/to/cert.pem"';
		if (searchKey.includes('random') && !searchKey.includes('secrets')) return 'Use secrets module: secrets.token_hex(32) for tokens, secrets.choice() for secure random. Never use random module for security';
		if (searchKey.includes('marshal')) return 'Never use marshal.loads() with untrusted data - RCE risk. Use json.loads() with validation';
		if (searchKey.includes('shelve')) return 'shelve uses pickle internally - RCE risk with untrusted data. Use JSON or SQLite instead';
		if (searchKey.includes('lxml')) return 'Disable external entities: parser = etree.XMLParser(resolve_entities=False, no_network=True)';
		if (searchKey.includes('fernet') && searchKey.includes('hardcoded')) return 'Store Fernet key in env var: key = os.environ["FERNET_KEY"]. Generate: Fernet.generate_key()';
		if (searchKey.includes('rsa') && searchKey.includes('weak')) return 'Use minimum 2048-bit RSA keys: rsa.generate_private_key(public_exponent=65537, key_size=2048)';
	}

	// === Java specific patterns ===
	if (isJava) {
		if (searchKey.includes('xml') && searchKey.includes('factory')) return 'Disable XXE: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)';
		if (searchKey.includes('objectinputstream')) return 'Never deserialize untrusted data. Use JSON with validation. If required, use look-ahead ObjectInputStream with class allowlist';
		if (searchKey.includes('spring') && searchKey.includes('csrf')) return 'Enable CSRF in Spring Security: http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())';
		if (searchKey.includes('preparedstatement')) return 'Always use PreparedStatement: PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);';
	}

	// === PHP specific patterns ===
	if (isPHP) {
		if (searchKey.includes('mysqli') && searchKey.includes('escape')) return 'Use prepared statements: $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $id);';
		if (searchKey.includes('eval') || searchKey.includes('preg_replace') && searchKey.includes('/e')) return 'Never use eval() or preg_replace with /e modifier. Use preg_replace_callback() instead';
		if (searchKey.includes('include') || searchKey.includes('require')) return 'Never include user input directly. Use allowlist: if (in_array($page, ["home", "about"])) include "$page.php";';
		if (searchKey.includes('unserialize')) return 'Never unserialize untrusted data - RCE risk. Use JSON: json_decode($data, true)';
		if (searchKey.includes('extract')) return 'Avoid extract() with user input - overwrites variables. Use explicit assignment: $name = $_POST["name"];';
	}

	// === Go specific patterns ===
	if (isGo) {
		if (searchKey.includes('sql') && searchKey.includes('sprintf')) return 'Use parameterized queries: db.Query("SELECT * FROM users WHERE id = $1", id). Never fmt.Sprintf for SQL';
		if (searchKey.includes('template') && searchKey.includes('html')) return 'Use html/template (auto-escapes) not text/template: template.HTMLEscapeString() for manual escaping';
		if (searchKey.includes('exec') && searchKey.includes('command')) return 'Use exec.Command with separate args: exec.Command("ls", "-la", path). Never shell with user input';
		if (searchKey.includes('tls') && searchKey.includes('insecure')) return 'Never InsecureSkipVerify in production: tls.Config{InsecureSkipVerify: false}';
	}

	// === Ruby specific patterns ===
	if (isRuby) {
		if (searchKey.includes('system') || searchKey.includes('backtick') || searchKey.includes('exec')) return 'Use array form: system("ls", "-la", user_input). Never interpolate in shell strings';
		if (searchKey.includes('erb') && searchKey.includes('raw')) return 'Use <%=h variable %> or ERB::Util.html_escape. raw() bypasses escaping - use only for pre-sanitized HTML';
		if (searchKey.includes('yaml') && searchKey.includes('load')) return 'Use YAML.safe_load(data, permitted_classes: []). Never YAML.load with untrusted data - RCE risk';
		if (searchKey.includes('mass') && searchKey.includes('assignment')) return 'Use strong parameters: params.require(:user).permit(:name, :email). Never params.permit!';
		if (searchKey.includes('send') || searchKey.includes('public_send')) return 'Validate method name before send(): ALLOWED_METHODS.include?(method_name) ? object.public_send(method_name) : raise';
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

	// === Fallback with category-based specific guidance ===
	// Extract vulnerability type from title/message for targeted advice
	const combinedText = `${title} ${message} ${ruleId}`;

	// Dependency vulnerabilities (Trivy/npm audit)
	if (searchKey.includes('cve-') || searchKey.includes('ghsa-') || searchKey.includes('vulnerable') && searchKey.includes('version')) {
		return `Update vulnerable package to patched version. Run: npm audit fix or npm update [package]. If no fix available, evaluate alternatives or apply workaround`;
	}

	// Authentication/Authorization patterns
	if (combinedText.includes('auth') || combinedText.includes('login') || combinedText.includes('permission') || combinedText.includes('access control')) {
		return 'Add authentication middleware and verify user permissions before processing. Use established auth libraries (passport, next-auth, lucia)';
	}

	// Input validation patterns
	if (combinedText.includes('input') || combinedText.includes('validation') || combinedText.includes('sanitiz') || combinedText.includes('untrusted')) {
		return 'Validate and sanitize all user input. Use schema validation (Zod, Joi, Yup) at API boundaries. Never trust client-side validation alone';
	}

	// Encryption/cryptography patterns
	if (combinedText.includes('encrypt') || combinedText.includes('crypto') || combinedText.includes('cipher') || combinedText.includes('hash')) {
		return 'Use modern cryptography: AES-256-GCM for encryption, bcrypt/argon2 for passwords, SHA-256+ for hashing. Never roll your own crypto';
	}

	// Network/API security patterns
	if (combinedText.includes('http') || combinedText.includes('request') || combinedText.includes('fetch') || combinedText.includes('api')) {
		return 'Use HTTPS only. Validate response data. Set appropriate timeouts. Never expose internal endpoints or sensitive headers';
	}

	// File system patterns
	if (combinedText.includes('file') || combinedText.includes('path') || combinedText.includes('directory') || combinedText.includes('read') || combinedText.includes('write')) {
		return 'Validate file paths stay within allowed directories. Use path.resolve() + startsWith() check. Never use user input directly in file operations';
	}

	// Database patterns
	if (combinedText.includes('database') || combinedText.includes('query') || combinedText.includes('sql') || combinedText.includes('mongo')) {
		return 'Use parameterized queries or ORM methods. Never concatenate user input into queries. Limit query results and use proper indexing';
	}

	// Configuration/environment patterns
	if (combinedText.includes('config') || combinedText.includes('environment') || combinedText.includes('setting') || combinedText.includes('production')) {
		return 'Use environment variables for sensitive config. Disable debug mode in production. Set secure defaults and validate all config values';
	}

	// Logging/error handling patterns
	if (combinedText.includes('log') || combinedText.includes('error') || combinedText.includes('exception') || combinedText.includes('stack')) {
		return 'Never log sensitive data (passwords, tokens, PII). Return generic error messages to users. Log details server-side only for debugging';
	}

	// Final fallback - still actionable
	const severity = finding.severity?.toLowerCase() || 'medium';
	if (severity === 'critical' || severity === 'high') {
		return `High-priority fix needed. Review the vulnerable code pattern, apply input validation, use secure library functions, and test the fix thoroughly`;
	}

	return `Review this code for security issues. Apply defense in depth: validate inputs, encode outputs, use least privilege, and prefer established security libraries`;
}
