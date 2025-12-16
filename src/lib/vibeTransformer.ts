/**
 * Vibe Transformer - Convert security scanner output to vibe-coder friendly format
 *
 * Philosophy: "Security scanners talk to security people. VibeShip Scanner talks to builders."
 *
 * This transforms technical security findings into actionable, copy-paste ready
 * output that works with Claude Code, Cursor, and other AI tools.
 */

import { getAIFixPrompt, generateMasterFixPrompt } from './aiFixPrompts';
import { getCWEFromRuleId, type CWEInfo } from './cweDatabase';

// ============================================================================
// Types
// ============================================================================

export type VibeUrgency = 'ship-blocker' | 'fix-this-week' | 'good-to-fix' | 'consider' | 'fyi';

export interface VibeOutput {
	// Plain English headline (no jargon)
	headline: string;

	// Urgency level with emoji
	urgency: VibeUrgency;
	urgencyLabel: string;
	urgencyEmoji: string;

	// Where is the problem?
	where: {
		file: string;
		line?: number;
		displayPath: string; // Shortened for display
	};

	// What's wrong in plain English?
	whatsWrong: string;

	// What could happen? (consequences)
	consequences: string[];

	// The vulnerable code snippet
	vulnerableCode?: {
		code: string;
		language: string;
	};

	// AI Fix Prompt - copy-paste ready
	aiFixPrompt: string;

	// Technical details (collapsed by default)
	technicalDetails: {
		cweId?: string;
		cweName?: string;
		cvssScore?: number;
		cvssLabel?: string;
		owaspCategory?: string;
		ruleId: string;
		severity: string;
	};

	// Original finding for reference
	originalFinding: any;
}

export interface TransformedResults {
	summary: {
		totalFindings: number;
		shipBlockers: number;
		fixThisWeek: number;
		goodToFix: number;
		consider: number;
		fyi: number;
	};
	findings: VibeOutput[];
	masterPrompt: string;
}

// ============================================================================
// Severity to Vibe Mapping
// ============================================================================

const severityToVibe: Record<string, { urgency: VibeUrgency; label: string; emoji: string }> = {
	critical: { urgency: 'ship-blocker', label: 'Fix Before You Ship', emoji: '🔴' },
	high: { urgency: 'fix-this-week', label: 'Fix This Week', emoji: '🟠' },
	medium: { urgency: 'good-to-fix', label: 'Good to Fix', emoji: '🟡' },
	low: { urgency: 'consider', label: 'Consider Fixing', emoji: '🔵' },
	info: { urgency: 'fyi', label: 'FYI', emoji: '⚪' },
	warning: { urgency: 'good-to-fix', label: 'Good to Fix', emoji: '🟡' },
	error: { urgency: 'fix-this-week', label: 'Fix This Week', emoji: '🟠' }
};

// ============================================================================
// Plain English Headlines
// ============================================================================

const headlineTemplates: Record<string, (ctx: { file: string }) => string> = {
	'sql-injection': ({ file }) => `User input goes straight into database query`,
	'sql_injection': ({ file }) => `User input goes straight into database query`,
	sqli: ({ file }) => `User input goes straight into database query`,
	xss: ({ file }) => `User input rendered without escaping`,
	'cross-site-scripting': ({ file }) => `User input rendered without escaping`,
	innerhtml: ({ file }) => `Using innerHTML with potentially unsafe content`,
	dangerously: ({ file }) => `Using dangerouslySetInnerHTML`,
	'hardcoded-secret': ({ file }) => `Secret value hardcoded in source code`,
	'hardcoded_secret': ({ file }) => `Secret value hardcoded in source code`,
	'api-key': ({ file }) => `API key exposed in code`,
	'api_key': ({ file }) => `API key exposed in code`,
	password: ({ file }) => `Password or credential in source code`,
	secret: ({ file }) => `Sensitive value hardcoded`,
	'command-injection': ({ file }) => `User input passed to shell command`,
	'command_injection': ({ file }) => `User input passed to shell command`,
	exec: ({ file }) => `Shell command with user-controlled input`,
	'path-traversal': ({ file }) => `File path includes user input`,
	'path_traversal': ({ file }) => `File path includes user input`,
	ssrf: ({ file }) => `Server fetches URL provided by user`,
	'missing-auth': ({ file }) => `Endpoint accessible without login`,
	'missing_auth': ({ file }) => `Endpoint accessible without login`,
	'no-auth': ({ file }) => `No authentication check`,
	'open-redirect': ({ file }) => `Redirect URL comes from user input`,
	redirect: ({ file }) => `Unvalidated redirect destination`,
	'insecure-cookie': ({ file }) => `Cookie missing security flags`,
	cookie: ({ file }) => `Session cookie not properly secured`,
	'weak-crypto': ({ file }) => `Using outdated cryptography`,
	'weak-hash': ({ file }) => `Using weak hashing algorithm`,
	md5: ({ file }) => `Using MD5 (broken and insecure)`,
	sha1: ({ file }) => `Using SHA1 (deprecated)`,
	eval: ({ file }) => `Using eval() with dynamic input`,
	'new-function': ({ file }) => `Using new Function() with dynamic code`,
	cors: ({ file }) => `CORS allows any website to access your API`,
	'prototype-pollution': ({ file }) => `Object properties can be manipulated`,
	jwt: ({ file }) => `JWT token missing security settings`,
	'nosql-injection': ({ file }) => `NoSQL query accepts unvalidated input`,
	mongodb: ({ file }) => `MongoDB query vulnerable to injection`,
	deserialization: ({ file }) => `Deserializing untrusted data`,
	csrf: ({ file }) => `Form submission not protected against forgery`,
	'information-disclosure': ({ file }) => `Sensitive information exposed`,
	'stack-trace': ({ file }) => `Error details visible to users`,
	xxe: ({ file }) => `XML parser processes external entities`,
	'rate-limit': ({ file }) => `No limit on request frequency`,
	'weak-random': ({ file }) => `Using Math.random() for security`,
	timing: ({ file }) => `Timing differences reveal information`
};

// ============================================================================
// Consequences (What could happen?)
// ============================================================================

const consequenceTemplates: Record<string, string[]> = {
	'sql-injection': [
		'Attackers could steal your entire database',
		'User passwords and personal data could be leaked',
		'Attackers could modify or delete any data',
		'Authentication could be bypassed entirely'
	],
	xss: [
		'Attackers could steal user sessions',
		'Fake content could be shown to users',
		'User actions could be performed without consent',
		'Credentials could be captured'
	],
	'hardcoded-secret': [
		'Anyone with code access has your credentials',
		'Secrets in git history are exposed forever',
		'Automated scrapers find these in public repos',
		'One leak compromises all environments'
	],
	'command-injection': [
		'Attackers could run ANY command on your server',
		'Your entire server could be compromised',
		'Data could be stolen or destroyed',
		'Crypto miners could be installed'
	],
	'path-traversal': [
		'Attackers could read any file on server',
		'Config files with secrets could be exposed',
		'Source code could be downloaded',
		'System files could be accessed'
	],
	ssrf: [
		'Internal services could be accessed',
		'Cloud metadata credentials could be stolen',
		'Internal network could be scanned',
		'Firewalls could be bypassed'
	],
	'missing-auth': [
		'Anyone could access this endpoint',
		'User data could be exposed',
		'Actions could be performed without permission',
		'Admin functions could be abused'
	],
	'open-redirect': [
		'Users could be sent to phishing sites',
		'Your domain legitimizes malicious links',
		'Credentials could be stolen via fake login pages'
	],
	'insecure-cookie': [
		'Sessions could be stolen over public WiFi',
		'XSS attacks could access session data',
		'Accounts could be hijacked'
	],
	'weak-crypto': [
		'Passwords could be cracked quickly',
		'Encrypted data could be decrypted',
		'User credentials could be exposed'
	],
	eval: [
		'Attackers could run arbitrary code',
		'Your application could be fully compromised',
		'Data could be stolen or modified'
	],
	cors: [
		'Any website could make requests to your API',
		'User data could be stolen cross-origin',
		'Actions could be performed on behalf of users'
	],
	'prototype-pollution': [
		'Application behavior could be modified',
		'Security checks could be bypassed',
		'Denial of service possible'
	],
	jwt: [
		'Tokens could be forged or modified',
		'Sessions could last indefinitely',
		'Authentication could be bypassed'
	],
	csrf: [
		'Users could be tricked into unwanted actions',
		'Account settings could be changed',
		'Purchases could be made without consent'
	],
	'information-disclosure': [
		'Attackers learn about your system',
		'Vulnerabilities become easier to exploit',
		'Sensitive data could be exposed'
	],
	default: [
		'Security vulnerability present',
		'Could be exploited by attackers',
		'Review and fix recommended'
	]
};

// ============================================================================
// Helper Functions
// ============================================================================

function shortenPath(fullPath: string): string {
	if (!fullPath) return 'Unknown file';

	const parts = fullPath.replace(/\\/g, '/').split('/');
	if (parts.length <= 3) return fullPath;

	// Show last 3 parts
	return '.../' + parts.slice(-3).join('/');
}

function detectLanguage(filename?: string): string {
	if (!filename) return 'javascript';
	const ext = filename.split('.').pop()?.toLowerCase();
	const langMap: Record<string, string> = {
		ts: 'typescript',
		tsx: 'typescript',
		js: 'javascript',
		jsx: 'javascript',
		py: 'python',
		rb: 'ruby',
		go: 'go',
		java: 'java',
		php: 'php',
		rs: 'rust',
		cs: 'csharp',
		cpp: 'cpp',
		c: 'c'
	};
	return langMap[ext || ''] || 'javascript';
}

function getHeadline(finding: any): string {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';
	const category = finding.category?.toLowerCase() || '';
	const searchKey = `${ruleId} ${title} ${category}`;
	const ctx = { file: finding.location?.file || 'this file' };

	for (const [key, generator] of Object.entries(headlineTemplates)) {
		if (searchKey.includes(key.toLowerCase())) {
			return generator(ctx);
		}
	}

	// If no match, clean up the original title
	return cleanTitle(finding.title || finding.category || 'Security issue found');
}

function cleanTitle(title: string): string {
	// Remove common prefixes and make more readable
	return title
		.replace(/^(vibeship[-_])?/i, '')
		.replace(/[-_]/g, ' ')
		.replace(/\b\w/g, (l) => l.toUpperCase())
		.trim();
}

function getConsequences(finding: any): string[] {
	const ruleId = finding.ruleId?.toLowerCase() || '';
	const title = finding.title?.toLowerCase() || '';
	const category = finding.category?.toLowerCase() || '';
	const searchKey = `${ruleId} ${title} ${category}`;

	for (const [key, consequences] of Object.entries(consequenceTemplates)) {
		if (searchKey.includes(key.toLowerCase())) {
			return consequences;
		}
	}

	// Use CWE info if available
	const cweInfo = getCWEFromRuleId(finding.ruleId || finding.title || '');
	if (cweInfo?.impact) {
		return cweInfo.impact.split(', ').map((s) => s.charAt(0).toUpperCase() + s.slice(1));
	}

	return consequenceTemplates.default;
}

function getCVSSLabel(score?: number): string {
	if (!score) return '';
	if (score >= 9.0) return 'Critical';
	if (score >= 7.0) return 'High';
	if (score >= 4.0) return 'Medium';
	if (score >= 0.1) return 'Low';
	return 'None';
}

function getOwaspCategory(cweInfo: CWEInfo | null): string | undefined {
	if (!cweInfo) return undefined;

	// Map CWE categories to OWASP Top 10 2021
	const categoryMap: Record<string, string> = {
		Injection: 'A03:2021 - Injection',
		'Credentials Management': 'A07:2021 - Identification and Authentication Failures',
		Authentication: 'A07:2021 - Identification and Authentication Failures',
		'Session Management': 'A07:2021 - Identification and Authentication Failures',
		Cryptography: 'A02:2021 - Cryptographic Failures',
		'Access Control': 'A01:2021 - Broken Access Control',
		'Input Validation': 'A03:2021 - Injection',
		'Information Disclosure': 'A01:2021 - Broken Access Control',
		'Data Processing': 'A08:2021 - Software and Data Integrity Failures',
		'File Handling': 'A01:2021 - Broken Access Control',
		'Request Handling': 'A10:2021 - Server-Side Request Forgery',
		'Object Handling': 'A08:2021 - Software and Data Integrity Failures',
		'Denial of Service': 'A05:2021 - Security Misconfiguration',
		'Resource Management': 'A05:2021 - Security Misconfiguration'
	};

	return categoryMap[cweInfo.category];
}

// ============================================================================
// Main Transform Function
// ============================================================================

export function transformFinding(finding: any): VibeOutput {
	const severity = (finding.severity || 'medium').toLowerCase();
	const vibeInfo = severityToVibe[severity] || severityToVibe.medium;

	const file = finding.location?.file || '';
	const line = finding.location?.line;
	const cweInfo = getCWEFromRuleId(finding.ruleId || finding.title || '');

	return {
		headline: getHeadline(finding),

		urgency: vibeInfo.urgency,
		urgencyLabel: vibeInfo.label,
		urgencyEmoji: vibeInfo.emoji,

		where: {
			file,
			line,
			displayPath: shortenPath(file) + (line ? `:${line}` : '')
		},

		whatsWrong: finding.description || finding.message || 'Security vulnerability detected',

		consequences: getConsequences(finding),

		vulnerableCode: finding.snippet?.code
			? {
					code: finding.snippet.code,
					language: detectLanguage(file)
				}
			: undefined,

		aiFixPrompt: getAIFixPrompt(finding),

		technicalDetails: {
			cweId: cweInfo?.id,
			cweName: cweInfo?.name,
			cvssScore: cweInfo?.cvssBase,
			cvssLabel: getCVSSLabel(cweInfo?.cvssBase),
			owaspCategory: getOwaspCategory(cweInfo),
			ruleId: finding.ruleId || finding.id || 'unknown',
			severity: finding.severity || 'medium'
		},

		originalFinding: finding
	};
}

export function transformResults(findings: any[]): TransformedResults {
	const transformed = findings.map(transformFinding);

	// Sort by urgency (most urgent first)
	const urgencyOrder: Record<VibeUrgency, number> = {
		'ship-blocker': 0,
		'fix-this-week': 1,
		'good-to-fix': 2,
		consider: 3,
		fyi: 4
	};

	transformed.sort((a, b) => urgencyOrder[a.urgency] - urgencyOrder[b.urgency]);

	const summary = {
		totalFindings: transformed.length,
		shipBlockers: transformed.filter((f) => f.urgency === 'ship-blocker').length,
		fixThisWeek: transformed.filter((f) => f.urgency === 'fix-this-week').length,
		goodToFix: transformed.filter((f) => f.urgency === 'good-to-fix').length,
		consider: transformed.filter((f) => f.urgency === 'consider').length,
		fyi: transformed.filter((f) => f.urgency === 'fyi').length
	};

	return {
		summary,
		findings: transformed,
		masterPrompt: generateMasterFixPrompt(findings)
	};
}

// ============================================================================
// Utility Exports
// ============================================================================

export function getUrgencyColor(urgency: VibeUrgency): string {
	const colors: Record<VibeUrgency, string> = {
		'ship-blocker': '#ef4444', // red-500
		'fix-this-week': '#f97316', // orange-500
		'good-to-fix': '#eab308', // yellow-500
		consider: '#3b82f6', // blue-500
		fyi: '#6b7280' // gray-500
	};
	return colors[urgency];
}

export function getUrgencyBgColor(urgency: VibeUrgency): string {
	const colors: Record<VibeUrgency, string> = {
		'ship-blocker': 'rgba(239, 68, 68, 0.15)',
		'fix-this-week': 'rgba(249, 115, 22, 0.15)',
		'good-to-fix': 'rgba(234, 179, 8, 0.15)',
		consider: 'rgba(59, 130, 246, 0.15)',
		fyi: 'rgba(107, 114, 128, 0.15)'
	};
	return colors[urgency];
}
