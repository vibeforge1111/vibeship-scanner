export interface CWEInfo {
	id: string;
	name: string;
	description: string;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	cvssBase?: number;
	exploitability: 'easy' | 'moderate' | 'difficult';
	impact: string;
	category: string;
	references: string[];
}

export const cweDatabase: Record<string, CWEInfo> = {
	'CWE-89': {
		id: 'CWE-89',
		name: 'SQL Injection',
		description: 'Improper neutralization of special elements used in an SQL command.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Complete database compromise, data theft, data modification, authentication bypass',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/89.html',
			'https://owasp.org/www-community/attacks/SQL_Injection'
		]
	},
	'CWE-79': {
		id: 'CWE-79',
		name: 'Cross-site Scripting (XSS)',
		description: 'Improper neutralization of input during web page generation.',
		severity: 'high',
		cvssBase: 6.1,
		exploitability: 'easy',
		impact: 'Session hijacking, account takeover, defacement, malware distribution',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/79.html',
			'https://owasp.org/www-community/attacks/xss/'
		]
	},
	'CWE-798': {
		id: 'CWE-798',
		name: 'Hardcoded Credentials',
		description: 'Use of hard-coded credentials for authentication or cryptographic operations.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Unauthorized access to systems and data, credential exposure in public repos',
		category: 'Credentials Management',
		references: [
			'https://cwe.mitre.org/data/definitions/798.html'
		]
	},
	'CWE-78': {
		id: 'CWE-78',
		name: 'OS Command Injection',
		description: 'Improper neutralization of special elements used in an OS command.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Complete server compromise, remote code execution, data exfiltration',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/78.html',
			'https://owasp.org/www-community/attacks/Command_Injection'
		]
	},
	'CWE-22': {
		id: 'CWE-22',
		name: 'Path Traversal',
		description: 'Improper limitation of a pathname to a restricted directory.',
		severity: 'high',
		cvssBase: 7.5,
		exploitability: 'easy',
		impact: 'Unauthorized file access, configuration file disclosure, source code exposure',
		category: 'File Handling',
		references: [
			'https://cwe.mitre.org/data/definitions/22.html',
			'https://owasp.org/www-community/attacks/Path_Traversal'
		]
	},
	'CWE-918': {
		id: 'CWE-918',
		name: 'Server-Side Request Forgery (SSRF)',
		description: 'Server makes requests to attacker-controlled URLs.',
		severity: 'high',
		cvssBase: 7.5,
		exploitability: 'moderate',
		impact: 'Internal network access, cloud metadata exposure, firewall bypass',
		category: 'Request Handling',
		references: [
			'https://cwe.mitre.org/data/definitions/918.html',
			'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
		]
	},
	'CWE-306': {
		id: 'CWE-306',
		name: 'Missing Authentication',
		description: 'Missing authentication for critical function.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Unauthorized access to sensitive functions and data',
		category: 'Authentication',
		references: [
			'https://cwe.mitre.org/data/definitions/306.html'
		]
	},
	'CWE-287': {
		id: 'CWE-287',
		name: 'Improper Authentication',
		description: 'Failure to properly authenticate users or systems.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'moderate',
		impact: 'Authentication bypass, account takeover',
		category: 'Authentication',
		references: [
			'https://cwe.mitre.org/data/definitions/287.html'
		]
	},
	'CWE-352': {
		id: 'CWE-352',
		name: 'Cross-Site Request Forgery (CSRF)',
		description: 'Web application does not verify requests were intentionally sent.',
		severity: 'medium',
		cvssBase: 6.5,
		exploitability: 'moderate',
		impact: 'Unauthorized actions on behalf of authenticated users',
		category: 'Session Management',
		references: [
			'https://cwe.mitre.org/data/definitions/352.html',
			'https://owasp.org/www-community/attacks/csrf'
		]
	},
	'CWE-94': {
		id: 'CWE-94',
		name: 'Code Injection',
		description: 'Improper control of code generation (eval, new Function).',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'moderate',
		impact: 'Remote code execution, complete application compromise',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/94.html'
		]
	},
	'CWE-95': {
		id: 'CWE-95',
		name: 'Eval Injection',
		description: 'Improper neutralization of directives in dynamically evaluated code.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Remote code execution, complete application compromise',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/95.html'
		]
	},
	'CWE-328': {
		id: 'CWE-328',
		name: 'Weak Hash',
		description: 'Use of weak hash (MD5, SHA1) for password storage.',
		severity: 'high',
		cvssBase: 7.5,
		exploitability: 'moderate',
		impact: 'Password cracking, credential compromise',
		category: 'Cryptography',
		references: [
			'https://cwe.mitre.org/data/definitions/328.html'
		]
	},
	'CWE-613': {
		id: 'CWE-613',
		name: 'Insufficient Session Expiration',
		description: 'Session or token does not expire or has excessive lifetime.',
		severity: 'medium',
		cvssBase: 5.4,
		exploitability: 'moderate',
		impact: 'Extended session hijacking window, persistent access after logout',
		category: 'Session Management',
		references: [
			'https://cwe.mitre.org/data/definitions/613.html'
		]
	},
	'CWE-614': {
		id: 'CWE-614',
		name: 'Sensitive Cookie Without Secure Flag',
		description: 'Session cookie sent over unencrypted channel.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'moderate',
		impact: 'Session hijacking via network sniffing',
		category: 'Session Management',
		references: [
			'https://cwe.mitre.org/data/definitions/614.html'
		]
	},
	'CWE-295': {
		id: 'CWE-295',
		name: 'Improper Certificate Validation',
		description: 'TLS certificate validation is disabled or improper.',
		severity: 'high',
		cvssBase: 7.4,
		exploitability: 'moderate',
		impact: 'Man-in-the-middle attacks, credential interception',
		category: 'Cryptography',
		references: [
			'https://cwe.mitre.org/data/definitions/295.html'
		]
	},
	'CWE-601': {
		id: 'CWE-601',
		name: 'Open Redirect',
		description: 'URL redirect to untrusted site without validation.',
		severity: 'medium',
		cvssBase: 6.1,
		exploitability: 'easy',
		impact: 'Phishing attacks, credential theft, malware distribution',
		category: 'Input Validation',
		references: [
			'https://cwe.mitre.org/data/definitions/601.html',
			'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect'
		]
	},
	'CWE-942': {
		id: 'CWE-942',
		name: 'Permissive CORS Policy',
		description: 'CORS policy allows requests from any origin.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'easy',
		impact: 'Cross-origin data theft, CSRF attacks',
		category: 'Access Control',
		references: [
			'https://cwe.mitre.org/data/definitions/942.html'
		]
	},
	'CWE-209': {
		id: 'CWE-209',
		name: 'Information Exposure Through Error Message',
		description: 'Detailed error messages reveal sensitive information.',
		severity: 'low',
		cvssBase: 4.3,
		exploitability: 'easy',
		impact: 'Information disclosure, attack surface mapping',
		category: 'Information Disclosure',
		references: [
			'https://cwe.mitre.org/data/definitions/209.html'
		]
	},
	'CWE-532': {
		id: 'CWE-532',
		name: 'Information Exposure Through Log Files',
		description: 'Sensitive information written to log files.',
		severity: 'medium',
		cvssBase: 5.5,
		exploitability: 'easy',
		impact: 'Credential exposure, sensitive data leakage',
		category: 'Information Disclosure',
		references: [
			'https://cwe.mitre.org/data/definitions/532.html'
		]
	},
	'CWE-502': {
		id: 'CWE-502',
		name: 'Deserialization of Untrusted Data',
		description: 'Deserialization of untrusted data without verification.',
		severity: 'high',
		cvssBase: 8.1,
		exploitability: 'moderate',
		impact: 'Remote code execution, denial of service',
		category: 'Data Processing',
		references: [
			'https://cwe.mitre.org/data/definitions/502.html'
		]
	},
	'CWE-20': {
		id: 'CWE-20',
		name: 'Improper Input Validation',
		description: 'Input is not properly validated before use.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'easy',
		impact: 'Various injection attacks, logic bypass',
		category: 'Input Validation',
		references: [
			'https://cwe.mitre.org/data/definitions/20.html'
		]
	},
	'CWE-943': {
		id: 'CWE-943',
		name: 'NoSQL Injection',
		description: 'Improper neutralization of special elements in NoSQL queries.',
		severity: 'critical',
		cvssBase: 9.8,
		exploitability: 'easy',
		impact: 'Database access bypass, data theft, authentication bypass',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/943.html'
		]
	},
	'CWE-611': {
		id: 'CWE-611',
		name: 'XML External Entity (XXE)',
		description: 'XML parser processes external entity references.',
		severity: 'high',
		cvssBase: 7.5,
		exploitability: 'moderate',
		impact: 'File disclosure, SSRF, denial of service',
		category: 'Injection',
		references: [
			'https://cwe.mitre.org/data/definitions/611.html',
			'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'
		]
	},
	'CWE-208': {
		id: 'CWE-208',
		name: 'Timing Attack',
		description: 'Observable timing differences reveal sensitive information.',
		severity: 'low',
		cvssBase: 3.7,
		exploitability: 'difficult',
		impact: 'Credential guessing, cryptographic key recovery',
		category: 'Cryptography',
		references: [
			'https://cwe.mitre.org/data/definitions/208.html'
		]
	},
	'CWE-1321': {
		id: 'CWE-1321',
		name: 'Prototype Pollution',
		description: 'Modification of Object prototype with user-controlled input.',
		severity: 'high',
		cvssBase: 7.3,
		exploitability: 'moderate',
		impact: 'Property injection, denial of service, remote code execution',
		category: 'Object Handling',
		references: [
			'https://cwe.mitre.org/data/definitions/1321.html'
		]
	},
	'CWE-1333': {
		id: 'CWE-1333',
		name: 'ReDoS',
		description: 'Regular expression denial of service via catastrophic backtracking.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'moderate',
		impact: 'Denial of service, resource exhaustion',
		category: 'Denial of Service',
		references: [
			'https://cwe.mitre.org/data/definitions/1333.html'
		]
	},
	'CWE-770': {
		id: 'CWE-770',
		name: 'Missing Rate Limiting',
		description: 'Allocation of resources without limits or throttling.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'easy',
		impact: 'Brute force attacks, denial of service, resource exhaustion',
		category: 'Resource Management',
		references: [
			'https://cwe.mitre.org/data/definitions/770.html'
		]
	},
	'CWE-338': {
		id: 'CWE-338',
		name: 'Weak Random',
		description: 'Use of cryptographically weak pseudo-random number generator.',
		severity: 'medium',
		cvssBase: 5.3,
		exploitability: 'moderate',
		impact: 'Predictable tokens, session hijacking, cryptographic weakness',
		category: 'Cryptography',
		references: [
			'https://cwe.mitre.org/data/definitions/338.html'
		]
	}
};

export function getCWEInfo(cweId: string): CWEInfo | null {
	const normalized = cweId.toUpperCase().replace('CWE-', '').trim();
	const key = `CWE-${normalized}`;
	return cweDatabase[key] || null;
}

export function getCWEFromRuleId(ruleId: string): CWEInfo | null {
	const lower = ruleId.toLowerCase();

	if (lower.includes('sql') && lower.includes('inject')) return cweDatabase['CWE-89'];
	if (lower.includes('nosql')) return cweDatabase['CWE-943'];
	if (lower.includes('xss') || lower.includes('innerhtml') || lower.includes('dangerously')) return cweDatabase['CWE-79'];
	if (lower.includes('secret') || lower.includes('hardcoded') || lower.includes('credential') || lower.includes('api-key') || lower.includes('password')) return cweDatabase['CWE-798'];
	if (lower.includes('command') || lower.includes('exec')) return cweDatabase['CWE-78'];
	if (lower.includes('path') && lower.includes('traversal')) return cweDatabase['CWE-22'];
	if (lower.includes('ssrf')) return cweDatabase['CWE-918'];
	if (lower.includes('auth') && (lower.includes('missing') || lower.includes('no-auth'))) return cweDatabase['CWE-306'];
	if (lower.includes('csrf')) return cweDatabase['CWE-352'];
	if (lower.includes('eval') || lower.includes('new-function')) return cweDatabase['CWE-95'];
	if (lower.includes('hash') || lower.includes('md5') || lower.includes('sha1')) return cweDatabase['CWE-328'];
	if (lower.includes('jwt') && lower.includes('expir')) return cweDatabase['CWE-613'];
	if (lower.includes('cookie') && lower.includes('secure')) return cweDatabase['CWE-614'];
	if (lower.includes('ssl') || lower.includes('tls') || lower.includes('certificate')) return cweDatabase['CWE-295'];
	if (lower.includes('redirect')) return cweDatabase['CWE-601'];
	if (lower.includes('cors')) return cweDatabase['CWE-942'];
	if (lower.includes('error') && lower.includes('verbose')) return cweDatabase['CWE-209'];
	if (lower.includes('log') && lower.includes('sensitive')) return cweDatabase['CWE-532'];
	if (lower.includes('deserializ')) return cweDatabase['CWE-502'];
	if (lower.includes('xxe') || lower.includes('xml')) return cweDatabase['CWE-611'];
	if (lower.includes('timing')) return cweDatabase['CWE-208'];
	if (lower.includes('prototype')) return cweDatabase['CWE-1321'];
	if (lower.includes('regex') || lower.includes('redos')) return cweDatabase['CWE-1333'];
	if (lower.includes('rate') && lower.includes('limit')) return cweDatabase['CWE-770'];
	if (lower.includes('random') && lower.includes('insecure')) return cweDatabase['CWE-338'];
	if (lower.includes('valid')) return cweDatabase['CWE-20'];

	return null;
}

export function getCVSSColor(score: number): string {
	if (score >= 9.0) return 'var(--red)';
	if (score >= 7.0) return '#f97316';
	if (score >= 4.0) return 'var(--orange)';
	if (score >= 0.1) return 'var(--blue)';
	return 'var(--text-secondary)';
}

export function getCVSSLabel(score: number): string {
	if (score >= 9.0) return 'Critical';
	if (score >= 7.0) return 'High';
	if (score >= 4.0) return 'Medium';
	if (score >= 0.1) return 'Low';
	return 'None';
}
