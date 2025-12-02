export interface FixTemplate {
	id: string;
	title: string;
	description: string;
	estimatedTime: string;
	difficulty: 'easy' | 'medium' | 'hard';
	before: string;
	after: string;
	explanation: string;
	references?: string[];
}

export const fixTemplates: Record<string, FixTemplate> = {
	'sql-injection': {
		id: 'sql-injection',
		title: 'Use Parameterized Queries',
		description: 'Replace string concatenation with parameterized queries to prevent SQL injection.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `// Vulnerable: SQL Injection
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);`,
		after: `// Safe: Parameterized Query
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = $1";
db.query(query, [userId]);`,
		explanation: 'Parameterized queries separate SQL logic from data, preventing attackers from injecting malicious SQL commands.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html']
	},

	'sql-injection-prisma': {
		id: 'sql-injection-prisma',
		title: 'Use Prisma ORM Methods',
		description: 'Replace raw queries with type-safe Prisma methods.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `// Vulnerable: Raw query with user input
const user = await prisma.$queryRawUnsafe(
  \`SELECT * FROM users WHERE email = '\${email}'\`
);`,
		after: `// Safe: Use Prisma ORM
const user = await prisma.user.findUnique({
  where: { email }
});

// Or if raw SQL needed, use Prisma.sql
const user = await prisma.$queryRaw(
  Prisma.sql\`SELECT * FROM users WHERE email = \${email}\`
);`,
		explanation: 'Prisma ORM methods automatically escape values. If raw SQL is needed, use Prisma.sql template tag for safe interpolation.',
		references: ['https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access']
	},

	'xss-innerhtml': {
		id: 'xss-innerhtml',
		title: 'Use textContent or Sanitize HTML',
		description: 'Replace innerHTML with safe alternatives to prevent XSS attacks.',
		estimatedTime: '5-15 min',
		difficulty: 'easy',
		before: `// Vulnerable: XSS via innerHTML
element.innerHTML = userInput;

// React vulnerable pattern
<div dangerouslySetInnerHTML={{__html: userContent}} />`,
		after: `// Safe: Use textContent for plain text
element.textContent = userInput;

// If HTML is needed, sanitize with DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// React with sanitization
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(userContent)
}} />`,
		explanation: 'textContent treats content as plain text. When HTML is required, DOMPurify removes dangerous elements and attributes.',
		references: ['https://github.com/cure53/DOMPurify']
	},

	'xss-svelte': {
		id: 'xss-svelte',
		title: 'Sanitize HTML in Svelte',
		description: 'Sanitize user content before using {@html} directive.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `<!-- Vulnerable: Unsanitized HTML -->
{@html userContent}`,
		after: `<script>
  import DOMPurify from 'dompurify';

  $: sanitizedContent = DOMPurify.sanitize(userContent);
</script>

<!-- Safe: Sanitized HTML -->
{@html sanitizedContent}`,
		explanation: 'The {@html} directive renders raw HTML. Always sanitize user-provided content with DOMPurify before rendering.',
		references: ['https://svelte.dev/docs#template-syntax-html']
	},

	'hardcoded-secret': {
		id: 'hardcoded-secret',
		title: 'Move to Environment Variables',
		description: 'Replace hardcoded secrets with environment variables.',
		estimatedTime: '10-15 min',
		difficulty: 'easy',
		before: `// Vulnerable: Hardcoded API key
const API_KEY = "sk-abc123xyz789";
const client = new OpenAI({ apiKey: API_KEY });`,
		after: `// Safe: Environment variable
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// .env file (add to .gitignore!)
// OPENAI_API_KEY=sk-abc123xyz789

// For client-side (Next.js/Vite)
// Use NEXT_PUBLIC_ or VITE_ prefix only for non-sensitive keys`,
		explanation: 'Environment variables keep secrets out of source code. Rotate any exposed keys immediately.',
		references: ['https://12factor.net/config']
	},

	'hardcoded-jwt-secret': {
		id: 'hardcoded-jwt-secret',
		title: 'Use Environment Variable for JWT Secret',
		description: 'Move JWT signing secret to environment variables.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `// Vulnerable: Hardcoded JWT secret
const token = jwt.sign(payload, "my-super-secret-key");`,
		after: `// Safe: Environment variable
const token = jwt.sign(payload, process.env.JWT_SECRET, {
  expiresIn: '1h'
});

// Generate a strong secret:
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`,
		explanation: 'JWT secrets must be cryptographically random and stored securely. A compromised secret allows forging any token.',
		references: ['https://jwt.io/introduction']
	},

	'missing-auth': {
		id: 'missing-auth',
		title: 'Add Authentication Middleware',
		description: 'Protect API routes with authentication checks.',
		estimatedTime: '15-30 min',
		difficulty: 'medium',
		before: `// Vulnerable: No auth check
export async function GET(request) {
  const users = await db.users.findMany();
  return Response.json(users);
}`,
		after: `// Safe: With authentication
import { getServerSession } from 'next-auth';

export async function GET(request) {
  const session = await getServerSession();

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const users = await db.users.findMany();
  return Response.json(users);
}`,
		explanation: 'Every API endpoint handling sensitive data must verify the user is authenticated before processing.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html']
	},

	'missing-auth-sveltekit': {
		id: 'missing-auth-sveltekit',
		title: 'Add SvelteKit Auth Check',
		description: 'Protect SvelteKit server routes with authentication.',
		estimatedTime: '15-30 min',
		difficulty: 'medium',
		before: `// src/routes/api/users/+server.ts
// Vulnerable: No auth check
export async function GET() {
  const users = await db.users.findMany();
  return json(users);
}`,
		after: `// src/routes/api/users/+server.ts
import { error, json } from '@sveltejs/kit';

export async function GET({ locals }) {
  const session = await locals.getSession();

  if (!session) {
    throw error(401, 'Unauthorized');
  }

  const users = await db.users.findMany();
  return json(users);
}`,
		explanation: 'SvelteKit provides locals for session data. Use hooks.server.ts to populate session info for all routes.',
		references: ['https://kit.svelte.dev/docs/hooks']
	},

	'cors-allow-all': {
		id: 'cors-allow-all',
		title: 'Restrict CORS Origins',
		description: 'Replace wildcard CORS with specific allowed origins.',
		estimatedTime: '10-15 min',
		difficulty: 'easy',
		before: `// Vulnerable: Allows any origin
app.use(cors({ origin: '*' }));`,
		after: `// Safe: Whitelist specific origins
const allowedOrigins = [
  'https://yourapp.com',
  'https://staging.yourapp.com',
  process.env.NODE_ENV === 'development' && 'http://localhost:3000'
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
}));`,
		explanation: 'Wildcard CORS allows any website to make authenticated requests to your API, potentially stealing user data.',
		references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS']
	},

	'weak-password-hashing': {
		id: 'weak-password-hashing',
		title: 'Use bcrypt or Argon2',
		description: 'Replace weak hashing with modern password hashing algorithms.',
		estimatedTime: '15-20 min',
		difficulty: 'medium',
		before: `// Vulnerable: MD5/SHA1 is not suitable for passwords
const hash = crypto.createHash('md5').update(password).digest('hex');`,
		after: `// Safe: Use bcrypt
import bcrypt from 'bcrypt';

// Hashing (on registration)
const saltRounds = 12;
const hash = await bcrypt.hash(password, saltRounds);

// Verification (on login)
const isValid = await bcrypt.compare(password, storedHash);`,
		explanation: 'MD5/SHA1 are fast hashes designed for integrity, not passwords. bcrypt is intentionally slow and includes salting.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html']
	},

	'jwt-no-expiry': {
		id: 'jwt-no-expiry',
		title: 'Add JWT Expiration',
		description: 'Always set expiration time on JWT tokens.',
		estimatedTime: '5 min',
		difficulty: 'easy',
		before: `// Vulnerable: No expiration
const token = jwt.sign({ userId: user.id }, secret);`,
		after: `// Safe: With expiration
const token = jwt.sign(
  { userId: user.id },
  secret,
  { expiresIn: '1h' } // Access tokens: 15min-1h
);

// For refresh tokens
const refreshToken = jwt.sign(
  { userId: user.id, type: 'refresh' },
  secret,
  { expiresIn: '7d' }
);`,
		explanation: 'Tokens without expiration remain valid forever if stolen. Short-lived access tokens with refresh tokens balance security and UX.',
		references: ['https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/']
	},

	'command-injection': {
		id: 'command-injection',
		title: 'Avoid Shell Commands with User Input',
		description: 'Use safe alternatives to executing shell commands.',
		estimatedTime: '15-30 min',
		difficulty: 'medium',
		before: `// Vulnerable: Command injection
const { exec } = require('child_process');
exec(\`convert \${userFilename} output.png\`);`,
		after: `// Safe: Use execFile with array arguments
const { execFile } = require('child_process');

// Validate filename first
if (!/^[a-zA-Z0-9_-]+\\.[a-z]+$/.test(userFilename)) {
  throw new Error('Invalid filename');
}

execFile('convert', [userFilename, 'output.png'], (err, stdout) => {
  // handle result
});

// Or use a library that doesn't shell out
import sharp from 'sharp';
await sharp(userFilename).toFile('output.png');`,
		explanation: 'exec() runs commands through a shell, allowing injection. execFile() passes arguments directly without shell interpretation.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html']
	},

	'path-traversal': {
		id: 'path-traversal',
		title: 'Validate and Sanitize File Paths',
		description: 'Prevent directory traversal attacks when handling file paths.',
		estimatedTime: '10-15 min',
		difficulty: 'medium',
		before: `// Vulnerable: Path traversal
const filename = req.query.file;
const content = fs.readFileSync(\`./uploads/\${filename}\`);`,
		after: `import path from 'path';

const UPLOAD_DIR = path.resolve('./uploads');

function getSafePath(filename) {
  // Remove any path components
  const safeName = path.basename(filename);
  const fullPath = path.resolve(UPLOAD_DIR, safeName);

  // Ensure path is within upload directory
  if (!fullPath.startsWith(UPLOAD_DIR)) {
    throw new Error('Invalid path');
  }

  return fullPath;
}

const safePath = getSafePath(req.query.file);
const content = fs.readFileSync(safePath);`,
		explanation: 'Attackers use ../ sequences to access files outside intended directories. Always resolve and validate the full path.',
		references: ['https://owasp.org/www-community/attacks/Path_Traversal']
	},

	'ssrf': {
		id: 'ssrf',
		title: 'Validate and Whitelist URLs',
		description: 'Prevent SSRF by validating user-provided URLs.',
		estimatedTime: '15-20 min',
		difficulty: 'medium',
		before: `// Vulnerable: SSRF
const url = req.body.webhookUrl;
const response = await fetch(url);`,
		after: `import { URL } from 'url';

const ALLOWED_HOSTS = ['api.example.com', 'webhook.example.com'];

function validateUrl(urlString) {
  const url = new URL(urlString);

  // Block private IPs and localhost
  const blockedPatterns = [
    /^localhost$/i,
    /^127\\./,
    /^10\\./,
    /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./,
    /^192\\.168\\./,
    /^0\\./
  ];

  if (blockedPatterns.some(p => p.test(url.hostname))) {
    throw new Error('Invalid URL: private addresses not allowed');
  }

  // Optionally: whitelist specific hosts
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    throw new Error('Invalid URL: host not allowed');
  }

  return url.href;
}

const safeUrl = validateUrl(req.body.webhookUrl);
const response = await fetch(safeUrl);`,
		explanation: 'SSRF allows attackers to make your server request internal services. Validate URLs and block private IP ranges.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html']
	},

	'insecure-cookie': {
		id: 'insecure-cookie',
		title: 'Secure Cookie Configuration',
		description: 'Enable httpOnly, secure, and sameSite flags on cookies.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `// Vulnerable: Insecure cookie
res.cookie('session', token, {
  httpOnly: false,
  secure: false
});`,
		after: `// Safe: Secure cookie configuration
res.cookie('session', token, {
  httpOnly: true,    // Prevents JavaScript access
  secure: true,       // HTTPS only
  sameSite: 'strict', // Prevents CSRF
  maxAge: 3600000,    // 1 hour expiry
  path: '/'
});`,
		explanation: 'httpOnly prevents XSS from stealing cookies. secure ensures HTTPS-only. sameSite prevents CSRF attacks.',
		references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies']
	},

	'eval-usage': {
		id: 'eval-usage',
		title: 'Remove eval() Usage',
		description: 'Replace eval() with safe alternatives.',
		estimatedTime: '15-30 min',
		difficulty: 'medium',
		before: `// Vulnerable: Code injection via eval
const result = eval(userExpression);

// Also dangerous
const fn = new Function('return ' + userCode);`,
		after: `// Safe: Use JSON.parse for data
const data = JSON.parse(userJson);

// For math expressions, use a safe parser
import { evaluate } from 'mathjs';
const result = evaluate(userExpression); // Only allows math

// For config, use static mapping
const handlers = {
  'add': (a, b) => a + b,
  'subtract': (a, b) => a - b
};
const result = handlers[operation]?.(a, b);`,
		explanation: 'eval() executes arbitrary code with full access to your application. Use structured alternatives that limit what can be executed.',
		references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!']
	},

	'disabled-ssl-verification': {
		id: 'disabled-ssl-verification',
		title: 'Enable SSL Certificate Verification',
		description: 'Remove code that disables SSL verification.',
		estimatedTime: '5-10 min',
		difficulty: 'easy',
		before: `// Vulnerable: Disabled SSL verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Or in request options
const agent = new https.Agent({
  rejectUnauthorized: false
});`,
		after: `// Safe: Keep SSL verification enabled (default)
// Remove any rejectUnauthorized: false

// If you have certificate issues:
// 1. Fix the server certificate
// 2. Add the CA to your trust store
// 3. For self-signed certs in dev only:
const agent = new https.Agent({
  ca: fs.readFileSync('./dev-ca.pem')
});`,
		explanation: 'Disabling SSL verification allows man-in-the-middle attacks. Fix certificate issues properly instead.',
		references: ['https://nodejs.org/api/tls.html']
	},

	'open-redirect': {
		id: 'open-redirect',
		title: 'Validate Redirect URLs',
		description: 'Prevent open redirect vulnerabilities.',
		estimatedTime: '10-15 min',
		difficulty: 'easy',
		before: `// Vulnerable: Open redirect
const returnUrl = req.query.returnUrl;
res.redirect(returnUrl);`,
		after: `function getSafeRedirectUrl(url, allowedHosts) {
  try {
    const parsed = new URL(url, 'https://yourapp.com');

    // Only allow relative paths or whitelisted hosts
    if (parsed.origin === 'https://yourapp.com') {
      return parsed.pathname + parsed.search;
    }

    if (allowedHosts.includes(parsed.host)) {
      return url;
    }
  } catch {
    // Invalid URL
  }

  return '/'; // Default safe redirect
}

const safeUrl = getSafeRedirectUrl(
  req.query.returnUrl,
  ['auth.yourapp.com']
);
res.redirect(safeUrl);`,
		explanation: 'Open redirects are used in phishing attacks. Users trust URLs on your domain, so redirects should stay on your domain.',
		references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html']
	},

	'supabase-service-role': {
		id: 'supabase-service-role',
		title: 'Never Expose Service Role Key',
		description: 'Keep Supabase service role key server-side only.',
		estimatedTime: '15-30 min',
		difficulty: 'medium',
		before: `// Vulnerable: Service role key in client code
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY // WRONG!
);`,
		after: `// Client-side: Use anon key only
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

// Server-side (API routes, server actions): Service role OK
// src/lib/supabase-admin.ts
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // No NEXT_PUBLIC_ prefix
);`,
		explanation: 'Service role key bypasses Row Level Security. If exposed client-side, anyone can read/write all data.',
		references: ['https://supabase.com/docs/guides/auth/row-level-security']
	}
};

export function getFixTemplate(finding: any): FixTemplate | null {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const category = finding.category?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';

	if (ruleId.includes('sql') || title.includes('sql injection')) {
		if (ruleId.includes('prisma') || title.includes('prisma')) {
			return fixTemplates['sql-injection-prisma'];
		}
		return fixTemplates['sql-injection'];
	}

	if (ruleId.includes('xss') || title.includes('xss')) {
		if (ruleId.includes('svelte') || title.includes('svelte') || title.includes('@html')) {
			return fixTemplates['xss-svelte'];
		}
		return fixTemplates['xss-innerhtml'];
	}

	if (category === 'secrets' || ruleId.includes('secret') || ruleId.includes('hardcoded')) {
		if (ruleId.includes('jwt') || title.includes('jwt')) {
			return fixTemplates['hardcoded-jwt-secret'];
		}
		if (ruleId.includes('supabase') || title.includes('service role')) {
			return fixTemplates['supabase-service-role'];
		}
		return fixTemplates['hardcoded-secret'];
	}

	if (ruleId.includes('auth') || title.includes('authentication') || title.includes('missing auth')) {
		if (ruleId.includes('svelte') || title.includes('svelte')) {
			return fixTemplates['missing-auth-sveltekit'];
		}
		return fixTemplates['missing-auth'];
	}

	if (ruleId.includes('cors') || title.includes('cors')) {
		return fixTemplates['cors-allow-all'];
	}

	if (ruleId.includes('password') || ruleId.includes('hash') || title.includes('weak') && title.includes('hash')) {
		return fixTemplates['weak-password-hashing'];
	}

	if (ruleId.includes('jwt') && (ruleId.includes('expir') || title.includes('expir'))) {
		return fixTemplates['jwt-no-expiry'];
	}

	if (ruleId.includes('command') || ruleId.includes('exec') || title.includes('command injection')) {
		return fixTemplates['command-injection'];
	}

	if (ruleId.includes('path') || title.includes('path traversal')) {
		return fixTemplates['path-traversal'];
	}

	if (ruleId.includes('ssrf') || title.includes('ssrf')) {
		return fixTemplates['ssrf'];
	}

	if (ruleId.includes('cookie') || title.includes('cookie')) {
		return fixTemplates['insecure-cookie'];
	}

	if (ruleId.includes('eval') || title.includes('eval')) {
		return fixTemplates['eval-usage'];
	}

	if (ruleId.includes('ssl') || ruleId.includes('tls') || title.includes('ssl') || title.includes('certificate')) {
		return fixTemplates['disabled-ssl-verification'];
	}

	if (ruleId.includes('redirect') || title.includes('redirect')) {
		return fixTemplates['open-redirect'];
	}

	return null;
}
