<script lang="ts">
	// Force rebuild: v2.2 - Added GitHub login for private repos in error state
	import { page } from '$app/stores';
	import { onMount, onDestroy } from 'svelte';
	import { supabase } from '$lib/supabase';
	import { explanationMode, type ExplanationMode } from '$lib/stores/preferences';
	import { getFixTemplate, type FixTemplate } from '$lib/fixTemplates';
	import { getCWEFromRuleId, getCVSSColor, getCVSSLabel, type CWEInfo } from '$lib/cweDatabase';
	import type { RealtimeChannel } from '@supabase/supabase-js';
	import { trackPageView, trackScanCompleted, trackScanResultsViewed } from '$lib/analytics';
	import { auth } from '$lib/stores/auth';

	let scanId = $derived($page.params.id);
	let status = $state<'queued' | 'scanning' | 'complete' | 'failed'>('queued');
	let progress = $state({
		step: 'init',
		stepNumber: 0,
		totalSteps: 5,
		message: 'Starting scan...',
		percent: 0
	});
	let results = $state<any>(null);
	let error = $state<string | null>(null);
	let repoUrl = $state<string | null>(null);
	let rescanning = $state(false);
	let scanDuration = $state<number | null>(null);
	let completedAt = $state<string | null>(null);
	let channel: RealtimeChannel | null = null;

	let displayScore = $state(0);
	let showResults = $state(false);
	let showConfetti = $state(false);
	let revealStage = $state(0);
	let confettiParticles = $state<Array<{id: number, x: number, delay: number, color: string, size: number}>>([]);
	let mode = $state<ExplanationMode>('founder');
	let expandedFindings = $state<Set<string>>(new Set());
	let copied = $state<string | null>(null);
	let showBadgeEmbed = $state(false);
	let generatingPdf = $state(false);
	let scanStartTime = $state<Date | null>(null);
	let timeoutCheckInterval: ReturnType<typeof setInterval> | null = null;
	let progressPollInterval: ReturnType<typeof setInterval> | null = null;
	const SCAN_TIMEOUT_MS = 15 * 60 * 1000;

	explanationMode.subscribe(value => {
		mode = value;
	});

	function getScanUrl(): string {
		if (typeof window !== 'undefined') {
			return window.location.href;
		}
		return '';
	}

	function copyToClipboard(text: string, type: string) {
		navigator.clipboard.writeText(text);
		copied = type;
		setTimeout(() => copied = null, 2000);
	}

	function shareTwitter() {
		const score = results?.score || 0;
		const grade = results?.grade || '?';
		const text = `My code just scored ${score}/100 (Grade ${grade}) on Vibeship Scanner! Check your repo's security:`;
		const url = getScanUrl();
		window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, '_blank');
	}

	function getBadgeMarkdown(): string {
		const grade = results?.grade || 'F';
		return `[![Vibeship Security Score](https://img.shields.io/badge/vibeship-${grade}-${getGradeColor(grade)})](${getScanUrl()})`;
	}

	function getBadgeHtml(): string {
		const grade = results?.grade || 'F';
		return `<a href="${getScanUrl()}"><img src="https://img.shields.io/badge/vibeship-${grade}-${getGradeColor(grade)}" alt="Vibeship Security Score"></a>`;
	}

	function formatDuration(ms: number | null): string {
		if (!ms) return '';
		if (ms < 1000) return `${ms}ms`;
		const seconds = Math.floor(ms / 1000);
		if (seconds < 60) return `${seconds}s`;
		const minutes = Math.floor(seconds / 60);
		const remainingSeconds = seconds % 60;
		return `${minutes}m ${remainingSeconds}s`;
	}

	function formatCompletedAt(dateStr: string | null): string {
		if (!dateStr) return '';
		const date = new Date(dateStr);
		return date.toLocaleString();
	}

	function isUnhelpfulSnippet(code: string): boolean {
		const trimmed = code.trim().toLowerCase();
		const unhelpfulPatterns = [
			'requires login',
			'login required',
			'authentication required',
			'please login',
			'please sign in',
			'sign in required',
			'access denied',
			'unauthorized',
			'forbidden'
		];
		return unhelpfulPatterns.some(pattern => trimmed === pattern || trimmed === pattern + '.');
	}

	function generateReportText(): string {
		if (!results) return '';

		const lines: string[] = [];
		lines.push('=' .repeat(60));
		lines.push('VIBESHIP SECURITY SCAN REPORT');
		lines.push('=' .repeat(60));
		lines.push('');
		lines.push(`Scan URL: ${getScanUrl()}`);
		if (repoUrl) {
			lines.push(`Repository: ${repoUrl}`);
		}
		lines.push(`Date: ${new Date().toLocaleString()}`);
		lines.push('');

		lines.push('-'.repeat(40));
		lines.push('SCORE SUMMARY');
		lines.push('-'.repeat(40));
		lines.push(`Score: ${results.score}/100`);
		lines.push(`Grade: ${results.grade}`);
		lines.push(`Status: ${getShipMessage(results.shipStatus)}`);
		lines.push('');

		if (results.stack?.languages?.length || results.stack?.frameworks?.length) {
			lines.push('-'.repeat(40));
			lines.push('DETECTED STACK');
			lines.push('-'.repeat(40));
			if (results.stack.languages?.length) {
				lines.push(`Languages: ${results.stack.languages.join(', ')}`);
			}
			if (results.stack.frameworks?.length) {
				lines.push(`Frameworks: ${results.stack.frameworks.join(', ')}`);
			}
			lines.push('');
		}

		lines.push('-'.repeat(40));
		lines.push('FINDING COUNTS');
		lines.push('-'.repeat(40));
		lines.push(`Critical: ${results.summary?.critical || 0}`);
		lines.push(`High: ${results.summary?.high || 0}`);
		lines.push(`Medium: ${results.summary?.medium || 0}`);
		lines.push(`Low: ${results.summary?.low || 0}`);
		lines.push(`Info: ${results.summary?.info || 0}`);
		lines.push('');

		if (results.findings?.length > 0) {
			lines.push('='.repeat(60));
			lines.push('DETAILED FINDINGS');
			lines.push('='.repeat(60));
			lines.push('');

			results.findings.forEach((finding: any, i: number) => {
				const cweInfo = getCWEFromRuleId(finding.ruleId || finding.title || '');

				lines.push(`[${i + 1}] ${finding.title}`);
				lines.push('-'.repeat(50));
				lines.push(`Severity: ${finding.severity.toUpperCase()}`);
				lines.push(`Category: ${finding.category}`);
				if (cweInfo) {
					lines.push(`CWE: ${cweInfo.id} - ${cweInfo.name}`);
					if (cweInfo.cvssBase) {
						lines.push(`CVSS: ${cweInfo.cvssBase} (${getCVSSLabel(cweInfo.cvssBase)})`);
					}
				}
				if (finding.location?.file) {
					lines.push(`Location: ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`);
				}
				lines.push('');
				lines.push('Risk & Fix:');
				lines.push(getExplanation(finding));

				if (finding.fix?.available && finding.fix?.template) {
					lines.push('');
					lines.push('Suggested Fix:');
					lines.push(finding.fix.template);
				}

				const fixTemplate = getFixTemplate(finding);
				if (fixTemplate) {
					lines.push('');
					lines.push(`Fix: ${fixTemplate.title}`);
					lines.push(`Estimated Time: ${fixTemplate.estimatedTime}`);
					lines.push(`Difficulty: ${fixTemplate.difficulty.toUpperCase()}`);
					lines.push('');
					lines.push('Before (Vulnerable):');
					lines.push(fixTemplate.before);
					lines.push('');
					lines.push('After (Safe):');
					lines.push(fixTemplate.after);
				}

				lines.push('');
				lines.push('');
			});
		}

		lines.push('='.repeat(60));
		lines.push('Generated by Vibeship Scanner');
		lines.push('https://vibeship.com');
		lines.push('='.repeat(60));

		return lines.join('\n');
	}

	function copyFullReport() {
		const report = generateReportText();
		navigator.clipboard.writeText(report);
		copied = 'report';
		setTimeout(() => copied = null, 2000);
	}

	async function downloadPdf() {
		generatingPdf = true;
		try {
			const report = generateReportText();
			const blob = new Blob([report], { type: 'text/plain' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `vibeship-scan-${scanId}.txt`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
		} finally {
			generatingPdf = false;
		}
	}

	function getGradeColor(grade: string): string {
		const colors: Record<string, string> = {
			A: '2ECC71',
			B: '84cc16',
			C: 'FFB020',
			D: 'f97316',
			F: 'FF4D4D'
		};
		return colors[grade] || 'gray';
	}

	const steps = [
		{ id: 'init', label: 'Initializing', icon: '⚡', details: 'Setting up secure scan environment' },
		{ id: 'clone', label: 'Cloning repository', icon: '📥', details: 'Fetching source code from GitHub' },
		{ id: 'detect', label: 'Detecting stack', icon: '🔍', details: 'Identifying languages and frameworks' },
		{ id: 'sast', label: 'Scanning code', icon: '🛡️', details: 'Running 1250+ security patterns' },
		{ id: 'deps', label: 'Checking dependencies', icon: '📦', details: 'Analyzing package vulnerabilities' },
		{ id: 'secrets', label: 'Scanning for secrets', icon: '🔐', details: 'Detecting exposed credentials' },
		{ id: 'score', label: 'Calculating score', icon: '📊', details: 'Generating security report' }
	];

	const securityFacts = [
		{ fact: 'Average cost of a data breach: $4.88 million in 2024, up 10% from last year', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Average breach lifecycle hit a 7-year low: 258 days to detect and contain', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: '70% of breached organizations reported significant business disruption', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Stolen credentials are the #1 initial attack vector at 16% of breaches', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'The human element was involved in 68% of all data breaches', source: 'Verizon DBIR 2024' },
		{ fact: 'Vulnerability exploitation as initial access tripled compared to last year', source: 'Verizon DBIR 2024' },
		{ fact: 'It takes 55 days to patch 50% of vulnerabilities after patches are released', source: 'Verizon DBIR 2024' },
		{ fact: '23.8 million secrets were leaked on public GitHub repos in 2024 (+25% YoY)', source: 'GitGuardian State of Secrets Sprawl 2025' },
		{ fact: '70% of secrets leaked in 2022 are still active today', source: 'GitGuardian State of Secrets Sprawl 2025' },
		{ fact: '35% of private repositories contain plaintext secrets', source: 'GitGuardian State of Secrets Sprawl 2025' },
		{ fact: '96% of leaked GitHub tokens had write access to repositories', source: 'GitGuardian State of Secrets Sprawl 2025' },
		{ fact: 'Copilot users have a 6.4% secret leakage rate in public repos', source: 'GitGuardian State of Secrets Sprawl 2025' },
		{ fact: '74% of commercial codebases contain high-risk open source vulnerabilities', source: 'Synopsys OSSRA 2024' },
		{ fact: '91% of codebases contain components 10+ versions out of date', source: 'Synopsys OSSRA 2024' },
		{ fact: '49% of codebases use components with no development activity in 2+ years', source: 'Synopsys OSSRA 2024' },
		{ fact: '77% of all code scanned traces back to open source projects', source: 'Synopsys OSSRA 2024' },
		{ fact: 'Average eCrime breakout time: just 62 minutes from initial compromise', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: 'Fastest recorded breakout time: only 2 minutes and 7 seconds', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: '75% of attacks are now malware-free, using stolen credentials instead', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: 'Cloud-related security breaches surged 75% year-over-year', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: 'Kerberoasting attacks increased 583% in 2023', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: 'Over 24,000 new vulnerabilities were discovered in 2024 alone', source: 'Snyk State of Open Source Security 2024' },
		{ fact: '80% believe AI generates more secure code — research shows otherwise', source: 'Snyk State of Open Source Security 2024' },
		{ fact: 'Security tool adoption dropped 11.3% despite increasing threats', source: 'Snyk State of Open Source Security 2024' },
		{ fact: 'SQL injection still affects 6.7% of open source and 10% of closed source projects', source: 'Aikido Security Research 2024' },
		{ fact: 'Over 20% of projects are vulnerable to SQL injection when first scanned', source: 'Aikido Security Research 2024' },
		{ fact: 'Injection is tested in 100% of applications — the most-tested category', source: 'OWASP Top 10 2025 RC1' },
		{ fact: 'Cross-site scripting has over 30,000 CVEs — highest of any vulnerability type', source: 'OWASP Top 10 2025 RC1' },
		{ fact: 'Security misconfiguration is the most common vulnerability across applications', source: 'OWASP Top 10 2025 RC1' },
		{ fact: 'Recommended time to fix critical vulnerabilities: 30 days or less', source: 'NIST SP 800-40 / CISA' },
		{ fact: 'Average time to remediate a vulnerability: 60-150 days', source: 'Infosec Institute' },
		{ fact: 'Malicious insider attacks cost $4.99 million on average — most expensive vector', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Ransomware victims saved $1 million on average by involving law enforcement', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: '63% of ransomware victims who involved law enforcement avoided paying ransom', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'U.S. entities face $9.36 million average breach costs — highest globally', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Multi-environment breaches (cloud + on-prem) cost over $5 million on average', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Security staffing shortages increase breach costs by $1.76 million', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: '42% of breaches are now detected internally vs 33% the year before', source: 'IBM Cost of Data Breach Report 2024' },
		{ fact: 'Median ransom demand: 1.34% of company revenue', source: 'Verizon DBIR 2024' },
		{ fact: '61% of hands-on attacks target North American organizations', source: 'CrowdStrike Global Threat Report 2024' },
		{ fact: 'Finding bugs in development is 100x cheaper than in production', source: 'IBM Systems Sciences Institute' },
		{ fact: 'XZ Utils backdoor nearly compromised millions of Linux systems in 2024', source: 'Snyk / Linux Foundation' },
		{ fact: '8 of top 10 vulnerabilities stem from improper input neutralization (CWE-707)', source: 'Synopsys OSSRA 2024' },
		{ fact: '53% of codebases have open source license conflicts', source: 'Synopsys OSSRA 2024' },
		{ fact: '34 new threat actor groups were identified in 2023 alone', source: 'CrowdStrike Global Threat Report 2024' }
	];

	let currentFactIndex = $state(0);
	let factInterval: ReturnType<typeof setInterval> | null = null;

	$effect(() => {
		if (status === 'scanning' || status === 'queued') {
			if (!factInterval) {
				factInterval = setInterval(() => {
					currentFactIndex = (currentFactIndex + 1) % securityFacts.length;
				}, 6000);
			}
		} else if (factInterval) {
			clearInterval(factInterval);
			factInterval = null;
		}
	});

	function getStepIndex(stepId: string): number {
		const index = steps.findIndex(s => s.id === stepId);
		return index >= 0 ? index : 0;
	}

	async function fetchScan() {
		const { data, error: fetchError } = await supabase
			.from('scans')
			.select('*')
			.eq('id', scanId)
			.single();

		if (fetchError) {
			error = 'Scan not found';
			return;
		}

		if (data) {
			status = data.status;
			repoUrl = data.repo_url || data.target_url || null;
			if (data.status === 'complete') {
				results = {
					score: data.score,
					grade: data.grade,
					shipStatus: data.ship_status,
					summary: data.finding_counts,
					stack: data.detected_stack,
					findings: data.findings || []
				};
				scanDuration = data.duration_ms;
				completedAt = data.completed_at;
			} else if (data.status === 'failed') {
				error = data.error || 'Scan failed';
			}
		}
	}

	async function fetchProgress() {
		const { data } = await supabase
			.from('scan_progress')
			.select('*')
			.eq('scan_id', scanId)
			.order('created_at', { ascending: false })
			.limit(1)
			.single();

		if (data) {
			progress = {
				step: data.step,
				stepNumber: getStepIndex(data.step),
				totalSteps: steps.length,
				message: data.message,
				percent: data.percent || 0
			};
		}
	}

	async function cancelScan() {
		try {
			await supabase
				.from('scans')
				.update({ status: 'failed', error_message: 'Scan cancelled by user' })
				.eq('id', scanId);
			status = 'failed';
			error = 'Scan cancelled';
		} catch (e) {
			console.error('Failed to cancel scan:', e);
		}
	}

	function checkScanTimeout() {
		if (scanStartTime && (status === 'queued' || status === 'scanning')) {
			const elapsed = Date.now() - scanStartTime.getTime();
			if (elapsed > SCAN_TIMEOUT_MS) {
				supabase
					.from('scans')
					.update({ status: 'failed', error_message: 'Scan timed out after 15 minutes' })
					.eq('id', scanId)
					.then(() => {
						status = 'failed';
						error = 'Scan timed out after 15 minutes';
					});
			}
		}
	}

	function saveToRecent(newScanId: string) {
		const stored = localStorage.getItem('vibeship-recent-scans');
		let ids: string[] = stored ? JSON.parse(stored) : [];
		ids = [newScanId, ...ids.filter(id => id !== newScanId)].slice(0, 10);
		localStorage.setItem('vibeship-recent-scans', JSON.stringify(ids));
	}

	async function rescanRepo() {
		if (!repoUrl) {
			console.error('Rescan failed: No repo URL available');
			return;
		}
		if (rescanning) return;

		rescanning = true;
		try {
			const response = await fetch('/api/scan', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ url: repoUrl })
			});
			const data = await response.json();
			if (data.scanId) {
				saveToRecent(data.scanId);
				window.location.href = `/scan/${data.scanId}`;
			} else {
				console.error('Rescan failed:', data);
				alert(`Rescan failed: ${data.message || 'Unknown error'}`);
				rescanning = false;
			}
		} catch (e) {
			console.error('Rescan error:', e);
			alert('Failed to start rescan. Please try again.');
			rescanning = false;
		}
	}

	onMount(async () => {
		trackPageView('Scan Results', { scan_id: scanId });
		await fetchScan();
		await fetchProgress();

		// Track scan results if already complete
		if (status === 'complete' && results) {
			trackScanResultsViewed(scanId, repoUrl || '', results.findings?.length || 0);
		}

		if (status === 'queued' || status === 'scanning') {
			scanStartTime = new Date();
			timeoutCheckInterval = setInterval(checkScanTimeout, 30000);
			// Poll for progress updates as fallback (in case realtime isn't working)
			progressPollInterval = setInterval(async () => {
				await fetchProgress();
				await fetchScan();
				// Stop polling if scan is done
				if (status === 'complete' || status === 'failed') {
					if (progressPollInterval) {
						clearInterval(progressPollInterval);
						progressPollInterval = null;
					}
				}
			}, 2000);
		}

		channel = supabase
			.channel(`scan-${scanId}`)
			.on(
				'postgres_changes',
				{
					event: 'UPDATE',
					schema: 'public',
					table: 'scans',
					filter: `id=eq.${scanId}`
				},
				async (payload) => {
					const data = payload.new;
					status = data.status;

					if (data.status === 'complete') {
						// Re-fetch scan data to get complete findings
						// Supabase realtime payloads may truncate large JSON fields
						await fetchScan();
						// Track scan completion
						if (results) {
							trackScanCompleted(repoUrl || '', {
								totalFindings: results.findings?.length || 0,
								criticalCount: results.summary?.critical || 0,
								highCount: results.summary?.high || 0,
								mediumCount: results.summary?.medium || 0,
								lowCount: results.summary?.low || 0
							});
							trackScanResultsViewed(scanId, repoUrl || '', results.findings?.length || 0);
						}
					} else if (data.status === 'failed') {
						error = data.error_message || data.error || 'Scan failed';
					}
				}
			)
			.on(
				'postgres_changes',
				{
					event: '*',
					schema: 'public',
					table: 'scan_progress',
					filter: `scan_id=eq.${scanId}`
				},
				(payload) => {
					const data = payload.new as any;
					if (data) {
						progress = {
							step: data.step,
							stepNumber: getStepIndex(data.step),
							totalSteps: steps.length,
							message: data.message,
							percent: data.percent || 0
						};
					}
				}
			)
			.subscribe();
	});

	onDestroy(() => {
		if (channel) {
			supabase.removeChannel(channel);
		}
		if (timeoutCheckInterval) {
			clearInterval(timeoutCheckInterval);
		}
		if (progressPollInterval) {
			clearInterval(progressPollInterval);
		}
		if (factInterval) {
			clearInterval(factInterval);
		}
	});

	function getSeverityClass(severity: string): string {
		const classes: Record<string, string> = {
			critical: 'severity-critical',
			high: 'severity-high',
			medium: 'severity-medium',
			low: 'severity-low',
			info: 'severity-info'
		};
		return classes[severity] || '';
	}

	function getGradeClass(grade: string): string {
		const classes: Record<string, string> = {
			A: 'grade-a',
			B: 'grade-b',
			C: 'grade-c',
			D: 'grade-d',
			F: 'grade-f'
		};
		return classes[grade] || '';
	}

	function getShipMessage(status: string): string {
		const messages: Record<string, string> = {
			ship: '🚀 Ship It!',
			review: '⚠️ Needs Review',
			fix: '🔧 Fix Required',
			danger: '🔧 Fix Required'
		};
		return messages[status] || '';
	}

	function copyFix(template: string) {
		navigator.clipboard.writeText(template);
		copied = 'fix';
		setTimeout(() => copied = null, 2000);
	}

	function getDifficultyColor(difficulty: string): string {
		const colors: Record<string, string> = {
			easy: 'var(--green)',
			medium: 'var(--orange)',
			hard: 'var(--red)'
		};
		return colors[difficulty] || 'var(--text-secondary)';
	}

	function toggleFinding(id: string) {
		if (expandedFindings.has(id)) {
			expandedFindings.delete(id);
			expandedFindings = new Set(expandedFindings);
		} else {
			expandedFindings.add(id);
			expandedFindings = new Set(expandedFindings);
		}
	}

	function getExplanation(finding: any): string {
		const explanations: Record<string, string> = {
			'sql-injection': `Attackers can manipulate database queries to steal, modify, or delete data. This is one of the most dangerous vulnerabilities - a single exploit can expose your entire database. Fix: Use parameterized queries instead of string concatenation.`,
			'sql_injection': `Attackers can manipulate database queries to steal, modify, or delete data. This is one of the most dangerous vulnerabilities - a single exploit can expose your entire database. Fix: Use parameterized queries instead of string concatenation.`,
			'nosql-injection': `Similar to SQL injection, but for NoSQL databases like MongoDB. Attackers can bypass authentication or access unauthorized data. Fix: Sanitize inputs and use query builders.`,
			'nosql_injection': `Similar to SQL injection, but for NoSQL databases like MongoDB. Attackers can bypass authentication or access unauthorized data. Fix: Sanitize inputs and use query builders.`,
			'xss': `Attackers can inject malicious scripts that run in your users' browsers, stealing sessions, credentials, or personal data. Fix: Sanitize all user input before rendering, use textContent instead of innerHTML.`,
			'cross-site': `Attackers can inject scripts that steal user data or hijack sessions. This affects all users who view the compromised content. Fix: Use output encoding and content security policies.`,
			'innerhtml': `Using innerHTML with user input allows attackers to inject malicious scripts. This can lead to account takeover and data theft. Fix: Use textContent for plain text, or sanitize with DOMPurify.`,
			'dangerously': `React's dangerouslySetInnerHTML can execute malicious scripts if given unsanitized user input. Fix: Always sanitize HTML content with DOMPurify before rendering.`,
			'hardcoded-secret': `Secrets in source code can be found by anyone with access to your repository or compiled app. Once exposed, attackers have direct access to your services. Fix: Move secrets to environment variables and rotate exposed keys immediately.`,
			'hardcoded_secret': `API keys and passwords in code are easily discovered and exploited. This is a common cause of data breaches. Fix: Use environment variables or a secrets manager like Vault.`,
			'hardcoded_credential': `Credentials in source code persist in git history forever. Even if deleted, they can be recovered. Fix: Use environment variables and rotate any exposed credentials.`,
			'api_key': `API keys in code can be extracted and misused, potentially costing you money or exposing user data. Fix: Move to environment variables, never commit keys to git.`,
			'secret': `Sensitive values in source code can be discovered through code leaks, decompilation, or git history. Fix: Store secrets in environment variables or a secrets manager.`,
			'password': `Passwords in code are a severe security risk. Anyone with code access can authenticate as that user/service. Fix: Remove immediately, use environment variables, rotate the password.`,
			'insecure-dependency': `This package has known security vulnerabilities that attackers actively exploit. Fix: Update to the latest patched version using npm update or pip install --upgrade.`,
			'vulnerable_dependency': `Known vulnerability in this dependency. Attackers scan for apps using vulnerable packages. Fix: Update to the patched version or find an alternative package.`,
			'missing-auth': `This endpoint can be accessed without authentication, potentially exposing sensitive data or actions to anyone. Fix: Add authentication middleware to verify user identity.`,
			'missing_auth': `Unprotected endpoints allow unauthorized access to your app's functionality. Fix: Implement session or token-based authentication checks.`,
			'path-traversal': `Attackers can use ../ sequences to access files outside the intended directory, potentially reading config files or source code. Fix: Use path.basename() and validate paths stay within allowed directories.`,
			'path_traversal': `File path manipulation can expose sensitive files like /etc/passwd or config files. Fix: Sanitize file paths and validate they stay within allowed directories.`,
			'directory_traversal': `User input in file paths can escape to parent directories. This can expose sensitive system files. Fix: Use path.resolve() and verify the final path is within allowed bounds.`,
			'open-redirect': `Attackers use your domain's reputation for phishing by redirecting users to malicious sites. Fix: Validate redirect URLs against a whitelist of allowed domains.`,
			'open_redirect': `Your trusted domain can be weaponized to redirect users to phishing sites that steal credentials. Fix: Only allow redirects to relative paths or whitelisted domains.`,
			'redirect': `Unvalidated redirects enable phishing attacks that abuse your domain's trust. Fix: Check the redirect destination against allowed domains before redirecting.`,
			'command-injection': `Attackers can execute arbitrary system commands on your server, potentially taking complete control. Fix: Avoid shell commands with user input, use execFile() with argument arrays.`,
			'command_injection': `User input in shell commands allows full system compromise. This is as dangerous as giving attackers SSH access. Fix: Use safe alternatives to exec() or sanitize input strictly.`,
			'exec': `The exec() function runs commands through a shell, allowing injection. An attacker could run any command on your server. Fix: Use execFile() or spawn() with separate arguments.`,
			'ssrf': `Server-Side Request Forgery allows attackers to make your server fetch internal resources, potentially accessing private APIs or cloud metadata. Fix: Validate URLs and block private IP ranges.`,
			'server_side_request': `SSRF can expose internal services, cloud credentials (via metadata endpoints), or scan your internal network. Fix: Whitelist allowed hosts and block private IP ranges.`,
			'prototype-pollution': `Attackers can modify JavaScript object prototypes, potentially leading to code execution or bypassing security checks. Fix: Validate object keys and avoid using user input as property names.`,
			'prototype_pollution': `Polluting Object.prototype can affect all objects in your application, leading to unexpected behavior or security bypasses. Fix: Use Object.create(null) or Map for user-controlled keys.`,
			'eval': `eval() executes arbitrary code, giving attackers complete control if they can influence the input. Fix: Use JSON.parse() for data, avoid eval entirely.`,
			'code_injection': `User input executed as code allows complete application takeover. Fix: Never use eval(), Function(), or setTimeout() with user-controlled strings.`,
			'deserialization': `Deserializing untrusted data can execute arbitrary code. Many major breaches started with insecure deserialization. Fix: Use JSON instead of native serialization, validate all input.`,
			'unsafe_deserialize': `Unsafe deserialization has caused major security incidents. Attackers craft payloads that execute code when deserialized. Fix: Use JSON.parse() for untrusted data.`,
			'xxe': `XML External Entity attacks can read local files, make server requests, or cause denial of service. Fix: Disable DTD and external entity processing in your XML parser.`,
			'xml': `XML parsers with external entity processing enabled can be exploited to read files or access internal services. Fix: Disable external entities in parser configuration.`,
			'cors': `Permissive CORS (Access-Control-Allow-Origin: *) lets any website make authenticated requests to your API. Fix: Specify exact allowed origins instead of using wildcards.`,
			'cross-origin': `Misconfigured CORS can allow malicious websites to access your users' data. Fix: Whitelist specific trusted origins, avoid using * with credentials.`,
			'jwt': `JWT issues can allow attackers to forge tokens or maintain access indefinitely. Fix: Use strong secrets, set expiration, validate tokens properly.`,
			'weak_hash': `MD5 and SHA1 are broken for security purposes - attackers can find collisions or crack passwords quickly. Fix: Use bcrypt, Argon2, or scrypt for passwords.`,
			'weak_crypto': `Weak cryptographic algorithms can be broken with modern computing power. Fix: Use AES-256, RSA-2048+, or modern alternatives like ChaCha20.`,
			'md5': `MD5 has known vulnerabilities and can be cracked quickly. Never use for passwords or security-critical hashing. Fix: Use SHA-256 for hashing, bcrypt for passwords.`,
			'sha1': `SHA1 has demonstrated collision attacks. It's no longer considered secure. Fix: Use SHA-256 or SHA-3 for cryptographic purposes.`,
			'cookie': `Cookies without proper security flags can be stolen via XSS or sent over insecure connections. Fix: Enable httpOnly, secure, and sameSite attributes.`,
			'session': `Insecure session handling can lead to session hijacking or fixation attacks. Fix: Use secure cookies, regenerate session IDs on login.`,
			'ssl': `Disabling SSL verification allows man-in-the-middle attacks where attackers can intercept all traffic. Fix: Enable certificate verification, fix certificate issues properly.`,
			'certificate': `Bypassing certificate validation lets attackers intercept HTTPS traffic. Fix: Never disable verification in production, add trusted CAs if needed.`,
			'idor': `Insecure Direct Object References let users access other users' data by changing IDs in URLs or requests. Fix: Always verify the user has permission to access the requested resource.`,
			'authorization': `Missing authorization checks let users perform actions they shouldn't be allowed to. Fix: Verify permissions before every sensitive operation.`,
			'access_control': `Broken access control is consistently in OWASP Top 10. Users can access unauthorized functions or data. Fix: Implement proper permission checks.`,
			'regex': `Complex regular expressions can cause catastrophic backtracking, freezing your application (ReDoS). Fix: Simplify patterns, avoid nested quantifiers, add timeouts.`,
			'redos': `Regular Expression Denial of Service can freeze your app with crafted input. Fix: Test regex with pathological inputs, limit input length.`,
			'file_upload': `Unrestricted file uploads can lead to code execution if attackers upload malicious files. Fix: Validate file types by content (not just extension), store outside webroot.`,
			'upload': `File uploads are a common attack vector. Attackers upload web shells or malicious files. Fix: Check MIME types, limit file sizes, use random filenames.`,
			'csrf': `Cross-Site Request Forgery tricks authenticated users into performing unwanted actions. Fix: Implement CSRF tokens for all state-changing operations.`,
			'clickjacking': `Attackers can embed your site in an iframe and trick users into clicking hidden elements. Fix: Add X-Frame-Options header or frame-ancestors CSP directive.`,
			'log_injection': `Attackers can inject fake log entries to cover their tracks or exploit log viewers. Fix: Sanitize user input before logging, use structured logging.`,
			'information_disclosure': `Exposing internal details helps attackers understand your system and find vulnerabilities. Fix: Remove stack traces and debug info from production responses.`,
			'error_handling': `Detailed error messages reveal system information useful for attacks. Fix: Show generic errors to users, log details server-side only.`,
			'race_condition': `Race conditions can lead to duplicate transactions, bypassed limits, or corrupted data. Fix: Use transactions, locks, or atomic operations.`,
			'timing_attack': `Timing differences can reveal information about secrets or bypass authentication. Fix: Use constant-time comparison for sensitive values.`,
			'mass_assignment': `Attackers can modify unintended fields by adding extra parameters. Fix: Explicitly whitelist allowed fields, never bind all input to models.`,
			'buffer': `Buffer overflows can crash applications or enable code execution. Fix: Validate input lengths, use safe memory functions.`,
			'memory': `Memory safety issues can lead to crashes, data corruption, or code execution. Fix: Validate array bounds, use safe memory operations.`,
			'integer_overflow': `Integer overflow can bypass size checks or cause unexpected behavior. Fix: Validate numeric ranges, check for overflow before operations.`,
			'template_injection': `Server-side template injection can lead to remote code execution. Fix: Never pass user input directly to template engines.`,
			'ssti': `Template injection is as dangerous as code injection - attackers can execute arbitrary code. Fix: Escape or sanitize all user input in templates.`,
			'ldap_injection': `LDAP injection can bypass authentication or expose directory data. Fix: Use parameterized LDAP queries, escape special characters.`,
			'xpath_injection': `XPath injection can extract unauthorized data from XML documents. Fix: Use parameterized queries or strictly validate input.`,
			'header_injection': `HTTP header injection can lead to response splitting, XSS, or cache poisoning. Fix: Validate and sanitize values used in headers.`,
			'crlf': `CRLF injection can split HTTP responses, enabling XSS or cache poisoning. Fix: Strip carriage return and line feed characters from user input.`,
			'insecure_random': `Predictable random values can be guessed by attackers for session tokens, passwords, etc. Fix: Use crypto.randomBytes() for security-sensitive values.`,
			'weak_random': `Math.random() is not cryptographically secure and can be predicted. Fix: Use the crypto module for generating tokens, secrets, or IDs.`
		};
		const key = finding.ruleId?.toLowerCase() || finding.category?.toLowerCase() || '';
		const title = finding.title?.toLowerCase() || '';
		const searchKeys = [key, title].join(' ');
		for (const [k, v] of Object.entries(explanations)) {
			if (searchKeys.includes(k.replace(/_/g, '-')) || searchKeys.includes(k.replace(/-/g, '_')) || searchKeys.includes(k)) return v;
		}
		const cweInfo = getCWEFromRuleId(finding.ruleId || '');
		if (cweInfo) {
			return `${cweInfo.name}: ${cweInfo.impact}. Review the code at this location and apply the recommended fix pattern.`;
		}
		return `This pattern was flagged as a potential security issue. Review the code context and apply the recommended fix to prevent exploitation.`;
	}

	function animateScore(targetScore: number) {
		const duration = 1500;
		const startTime = performance.now();
		const easeOutQuart = (t: number) => 1 - Math.pow(1 - t, 4);

		function update() {
			const elapsed = performance.now() - startTime;
			const progress = Math.min(elapsed / duration, 1);
			const easedProgress = easeOutQuart(progress);
			displayScore = Math.round(easedProgress * targetScore);

			if (progress < 1) {
				requestAnimationFrame(update);
			} else {
				displayScore = targetScore;
				if (targetScore >= 80) {
					triggerConfetti();
				}
				startCascadeReveal();
			}
		}
		requestAnimationFrame(update);
	}

	function triggerConfetti() {
		showConfetti = true;
		const colors = ['#00C49A', '#2ECC71', '#FFB020', '#3399FF', '#9D8CFF'];
		const particles: typeof confettiParticles = [];

		for (let i = 0; i < 50; i++) {
			particles.push({
				id: i,
				x: Math.random() * 100,
				delay: Math.random() * 0.5,
				color: colors[Math.floor(Math.random() * colors.length)],
				size: Math.random() * 8 + 4
			});
		}
		confettiParticles = particles;

		setTimeout(() => {
			showConfetti = false;
		}, 3000);
	}

	function startCascadeReveal() {
		const stages = [1, 2, 3, 4];
		stages.forEach((stage, i) => {
			setTimeout(() => {
				revealStage = stage;
			}, i * 200);
		});
	}

	$effect(() => {
		if (status === 'complete' && results && !showResults) {
			showResults = true;
			setTimeout(() => {
				animateScore(results.score || 0);
			}, 300);
		}
	});
</script>

<div class="scan-page">
	{#if error}
		<div class="error-container">
			<h1>Scan Error</h1>
			{#if error.toLowerCase().includes('clone') || error.toLowerCase().includes('repository') || error.toLowerCase().includes('not found')}
				<p>This repository couldn't be scanned. It may be private or doesn't exist.</p>
				{#if $auth.user}
					<p class="error-note">You're signed in but this repo may require additional permissions, or doesn't exist.</p>
				{:else}
					<p class="error-note">Sign in with GitHub in the header above to scan private repositories.</p>
				{/if}
			{:else if error.toLowerCase().includes('timeout') || error.toLowerCase().includes('timed out')}
				<p>This scan took too long and was stopped.</p>
				<p class="error-note">Large repositories may need more time. Try again - our scanner is getting faster!</p>
			{:else}
				<p>{error}</p>
			{/if}

			<div class="error-actions">
				{#if repoUrl}
					<button class="btn btn-primary" onclick={rescanRepo} disabled={rescanning}>
						{rescanning ? 'Starting new scan...' : 'Rescan This Repo'}
					</button>
				{/if}
				<a href="/" class="btn btn-secondary">Scan Different Repo</a>
			</div>

			<div class="dev-notice">
				<div class="dev-notice-icon">🚀</div>
				<div class="dev-notice-content">
					<strong>We're actively improving the scanner!</strong>
					<p>We push updates frequently to add new vulnerability detection rules and improve performance. Occasionally, in-progress scans may be interrupted during deployments. Just hit rescan and you're good to go!</p>
				</div>
			</div>
		</div>

	{:else if status === 'queued' || status === 'scanning'}
		<div class="progress-container">
			<h1>Scanning your repository...</h1>
	
			<div class="progress-steps">
				{#each steps as step, i}
					<div class="step" class:active={i === progress.stepNumber} class:complete={i < progress.stepNumber}>
						<span class="step-icon">{step.icon}</span>
						<div class="step-content">
							<span class="step-label">{step.label}</span>
							{#if i === progress.stepNumber}
								<span class="step-detail">{step.details}</span>
							{/if}
						</div>
						{#if i < progress.stepNumber}
							<span class="step-check">✓</span>
						{:else if i === progress.stepNumber}
							<span class="step-spinner"></span>
						{/if}
					</div>
				{/each}
			</div>

			<div class="security-fact">
				<span class="fact-text">{securityFacts[currentFactIndex].fact}</span>
				<span class="fact-source">Source: {securityFacts[currentFactIndex].source}</span>
			</div>

			<div class="progress-bar">
				<div class="progress-fill" style="width: {progress.percent}%"></div>
			</div>

			<p class="progress-message">{progress.message}</p>

			<button class="btn btn-cancel" onclick={cancelScan}>
				Cancel Scan
			</button>
		</div>

	{:else if status === 'complete' && results}
		<div class="results-container">
			{#if showConfetti}
				<div class="confetti-container">
					{#each confettiParticles as particle (particle.id)}
						<div
							class="confetti-particle"
							style="
								left: {particle.x}%;
								animation-delay: {particle.delay}s;
								background: {particle.color};
								width: {particle.size}px;
								height: {particle.size}px;
							"
						></div>
					{/each}
				</div>
			{/if}

			<div class="results-header">
				<div class="score-section" class:revealed={showResults}>
					<div class="score-circle {getGradeClass(results.grade)}">
						<span class="score-number">{displayScore}</span>
						<span class="score-label">out of 100</span>
					</div>
					<p class="ship-status" class:fade-in={revealStage >= 1}>{getShipMessage(results.shipStatus)}</p>
					{#if repoUrl}
						<a href={repoUrl} target="_blank" rel="noopener noreferrer" class="repo-link">
							<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
								<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
							</svg>
							{repoUrl.replace('https://github.com/', '')}
						</a>
						<div class="repo-actions" class:revealed={showResults}>
							<button class="action-btn" onclick={rescanRepo} disabled={rescanning || !repoUrl}>
								<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<path d="M23 4v6h-6"/>
									<path d="M1 20v-6h6"/>
									<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
								</svg>
								{rescanning ? 'Starting...' : 'Rescan'}
							</button>
							<button class="action-btn" onclick={shareTwitter}>
								Share on
								<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
									<path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
								</svg>
							</button>
						</div>
					{/if}
				</div>

				<div class="summary-section" class:revealed={revealStage >= 3}>
					<div class="summary-counts">
						{#if results.summary?.critical > 0}
							<span class="count severity-critical">{results.summary.critical} Critical</span>
						{/if}
						{#if results.summary?.high > 0}
							<span class="count severity-high">{results.summary.high} High</span>
						{/if}
						{#if results.summary?.medium > 0}
							<span class="count severity-medium">{results.summary.medium} Medium</span>
						{/if}
						{#if results.summary?.low > 0}
							<span class="count severity-low">{results.summary.low} Low</span>
						{/if}
						{#if results.summary?.info > 0}
							<span class="count severity-info">{results.summary.info} Info</span>
						{/if}
						{#if !results.summary?.critical && !results.summary?.high && !results.summary?.medium && !results.summary?.low && !results.summary?.info}
							<span class="count severity-info">No issues found</span>
						{/if}
					</div>
					{#if results.stack?.frameworks?.length > 0}
						<div class="stack-info">
							<span class="stack-label">Stack detected:</span>
							<span class="stack-value">{results.stack.frameworks.join(', ')}</span>
						</div>
					{/if}
					{#if results.stack?.languages?.length > 0}
						<div class="stack-info">
							<span class="stack-label">Languages:</span>
							<span class="stack-value">{results.stack.languages.join(', ')}</span>
						</div>
					{/if}
				</div>
			</div>

			{#if results.findings?.length > 0}
				<div class="findings-section" class:revealed={revealStage >= 4}>
					<div class="findings-header">
						<h2>Findings ({results.findings.length})</h2>
						<div class="findings-actions">
							<button class="export-btn" onclick={copyFullReport}>
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
									<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
								</svg>
								{copied === 'report' ? 'Copied!' : 'Copy Report'}
							</button>
							<button class="export-btn" onclick={downloadPdf} disabled={generatingPdf}>
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
									<polyline points="7 10 12 15 17 10"/>
									<line x1="12" y1="15" x2="12" y2="3"/>
								</svg>
								{generatingPdf ? 'Generating...' : 'Download Report'}
							</button>
						</div>
					</div>
					<div class="findings-list">
						{#each results.findings as finding, i}
							{@const findingId = finding.id || `finding-${i}`}
							{@const isExpanded = expandedFindings.has(findingId)}
							{@const cweInfo = getCWEFromRuleId(finding.ruleId || finding.title || '')}
							<div class="finding-card" class:expanded={isExpanded}>
								<button class="finding-toggle" onclick={() => toggleFinding(findingId)}>
									<div class="finding-header">
										<span class="severity-badge {getSeverityClass(finding.severity)}">
											{finding.severity.toUpperCase()}
										</span>
										<span class="finding-category">{finding.category}</span>
										{#if cweInfo}
											<span class="finding-cwe">{cweInfo.id}</span>
										{/if}
										<span class="finding-chevron" class:rotated={isExpanded}>▼</span>
									</div>
									<h3 class="finding-title">{finding.title}</h3>
								</button>

								{#if isExpanded}
									<div class="finding-details">
										<p class="finding-explanation">{getExplanation(finding)}</p>

										{#if finding.location?.file}
											<div class="finding-location">
												<code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
											</div>
										{/if}

										{#if finding.snippet?.code && finding.snippet.code.trim() && finding.snippet.code.length > 10 && !isUnhelpfulSnippet(finding.snippet.code)}
											<pre class="finding-code"><code>{finding.snippet.code}</code></pre>
										{/if}

										{#if getFixTemplate(finding)}
											{@const fixTemplate = getFixTemplate(finding)}
											<details class="fix-details">
												<summary class="fix-summary">
													<span>How to fix</span>
												</summary>
												<div class="fix-content">
													<div class="fix-comparison">
														<div class="fix-before">
															<span class="fix-label-bad">Before</span>
															<pre><code>{fixTemplate.before}</code></pre>
														</div>
														<div class="fix-after">
															<span class="fix-label-good">After</span>
															<button class="btn-copy-sm" onclick={() => copyFix(fixTemplate.after)}>
																{copied === 'fix' ? '✓' : 'Copy'}
															</button>
															<pre><code>{fixTemplate.after}</code></pre>
														</div>
													</div>
													{#if cweInfo?.references?.[0]}
														<a href={cweInfo.references[0]} target="_blank" rel="noopener noreferrer" class="fix-learn-more">
															Learn more →
														</a>
													{/if}
												</div>
											</details>
										{:else if finding.fix?.available && finding.fix?.template}
											<details class="fix-details">
												<summary class="fix-summary">
													<span>Suggested fix</span>
												</summary>
												<div class="fix-content">
													<pre><code>{finding.fix.template}</code></pre>
													<button class="btn-copy-sm" onclick={() => copyFix(finding.fix.template)}>
														{copied === 'fix' ? '✓' : 'Copy'}
													</button>
												</div>
											</details>
										{/if}
									</div>
								{/if}
							</div>
						{/each}
					</div>
				</div>
			{:else}
				<div class="no-findings">
					<h2>No Security Issues Found</h2>
					<p>Your code looks clean! Consider running deeper analysis with Vibeship Pro.</p>
				</div>
			{/if}

			<div class="scan-disclaimer">
				<p><strong>Disclaimer:</strong> Vibeship Scanner uses industry-standard security tools to identify potential vulnerabilities in your codebase. While we strive to detect as many security issues as possible, this scan is not a guarantee of complete security coverage. False positives and false negatives may occur. Recommendations provided may not be applicable to your specific use case. This tool is not a substitute for professional security audits or penetration testing. By using this service, you agree to our <a href="/terms">Terms of Service</a> and <a href="/privacy">Privacy Policy</a>.</p>
			</div>
		</div>

	{:else if status === 'failed'}
		<div class="error-container">
			<h1>Scan Failed</h1>
			<p>{error || 'Something went wrong during the scan.'}</p>
			<a href="/" class="btn">Try Again</a>
		</div>
	{/if}
</div>

<style>
	.scan-page {
		padding: 8rem 2rem 4rem;
		max-width: 1000px;
		margin: 0 auto;
		min-height: calc(100vh - 80px);
	}

	.error-container {
		text-align: center;
		padding: 4rem 0;
	}

	.error-container h1 {
		font-family: 'Inter', sans-serif;
		font-size: 2rem;
		margin-bottom: 1rem;
		color: var(--red);
	}

	.error-container p {
		color: var(--text-secondary);
		margin-bottom: 1rem;
	}

	.error-container .error-note {
		font-size: 0.85rem;
		color: var(--text-tertiary);
		margin-bottom: 1.5rem;
	}

	.error-actions {
		display: flex;
		gap: 1rem;
		justify-content: center;
		margin-bottom: 2rem;
	}

	.error-actions .btn-primary {
		background: var(--purple);
		color: white;
		border: none;
		padding: 0.75rem 1.5rem;
		cursor: pointer;
		font-weight: 500;
		transition: all 0.15s;
	}

	.error-actions .btn-primary:hover:not(:disabled) {
		background: var(--purple-light);
	}

	.error-actions .btn-primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.error-actions .btn-secondary {
		background: var(--bg-tertiary);
		color: var(--text-primary);
		border: 1px solid var(--border);
		padding: 0.75rem 1.5rem;
		text-decoration: none;
		font-weight: 500;
		transition: all 0.15s;
	}

	.error-actions .btn-secondary:hover {
		border-color: var(--text-primary);
	}

	.dev-notice {
		max-width: 500px;
		margin: 0 auto;
		padding: 1.25rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		border-left: 3px solid var(--purple);
		text-align: left;
		display: flex;
		gap: 1rem;
	}

	.dev-notice-icon {
		font-size: 1.5rem;
		flex-shrink: 0;
	}

	.dev-notice-content strong {
		display: block;
		color: var(--text-primary);
		margin-bottom: 0.5rem;
	}

	.dev-notice-content p {
		font-size: 0.85rem;
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	.progress-container {
		text-align: center;
		padding: 4rem 0;
	}

	.progress-container h1 {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1.5rem;
		font-weight: 500;
		margin-bottom: 0.5rem;
	}

	.progress-steps {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 400px;
		margin: 2rem auto 3rem;
		text-align: left;
	}

	.step {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 1rem;
		border: 1px solid var(--border);
		background: var(--bg-primary);
		opacity: 0.5;
		transition: all 0.3s;
	}

	.step.active {
		opacity: 1;
		border-color: var(--green-dim);
		background: var(--bg-secondary);
	}

	.step.complete {
		opacity: 1;
	}

	.step-icon {
		font-size: 1.25rem;
	}

	.step-content {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.step-label {
		font-size: 0.9rem;
	}

	.step-detail {
		font-size: 0.75rem;
		color: var(--green-dim);
		opacity: 0.8;
	}

	.step-check {
		color: var(--green);
	}

	.step-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid var(--border);
		border-top-color: var(--green-dim);
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.progress-bar {
		max-width: 400px;
		margin: 0 auto 1rem;
		height: 4px;
		background: var(--border);
	}

	.progress-fill {
		height: 100%;
		background: var(--green-dim);
		transition: width 0.5s ease;
	}

	.progress-message {
		font-size: 0.9rem;
		color: var(--text-secondary);
	}

	.security-fact {
		margin: 2rem auto;
		max-width: 700px;
		padding: 1.5rem 2rem;
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		animation: factFade 0.5s ease;
		text-align: center;
		min-height: 80px;
	}

	.fact-text {
		font-size: 1.1rem;
		color: var(--text-primary);
		white-space: normal;
		line-height: 1.6;
		font-weight: 500;
	}

	.fact-source {
		font-size: 0.85rem;
		color: var(--text-muted, #666);
		opacity: 0.7;
		font-style: italic;
	}

	@keyframes factFade {
		from {
			opacity: 0;
			transform: translateY(5px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.btn-cancel {
		margin-top: 2rem;
		background: transparent;
		border: 1px solid var(--red);
		color: var(--red);
		padding: 0.5rem 1.5rem;
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-cancel:hover {
		background: var(--red);
		color: white;
	}

	.results-container {
		animation: fadeUp 0.5s ease;
	}

	.results-header {
		position: relative;
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 4rem;
		margin-bottom: 4rem;
		padding-bottom: 2rem;
		border-bottom: 1px solid var(--border);
	}

	.repo-actions {
		display: flex;
		justify-content: center;
		gap: 0.5rem;
		margin-top: 0.75rem;
		opacity: 0;
		transform: translateY(-10px);
		transition: opacity 0.3s ease, transform 0.3s ease;
		pointer-events: none;
	}

	.repo-actions.revealed {
		opacity: 1;
		transform: translateY(0);
		pointer-events: auto;
	}

	.action-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		background: transparent;
		border: 1px solid var(--border);
		border-radius: 0;
		color: var(--text-primary);
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.action-btn:hover {
		background: var(--bg-secondary);
		border-color: var(--text-primary);
	}

	.action-btn svg {
		flex-shrink: 0;
	}

	.action-btn-primary {
		background: #000;
		border-color: #333;
		color: #fff;
	}

	.action-btn-primary:hover {
		background: #1a1a1a;
		border-color: #444;
	}

	.action-btn-primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.top-badge-embed {
		position: absolute;
		top: 50px;
		right: 0;
		z-index: 10;
		width: 400px;
		max-width: calc(100vw - 2rem);
	}

	.score-section {
		text-align: center;
	}

	.score-circle {
		width: 150px;
		height: 150px;
		border-radius: 50%;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		margin-bottom: 1rem;
		border: 3px solid;
	}

	.score-circle.grade-a { border-color: var(--green); }
	.score-circle.grade-b { border-color: #84cc16; }
	.score-circle.grade-c { border-color: var(--orange); }
	.score-circle.grade-d { border-color: #f97316; }
	.score-circle.grade-f { border-color: var(--red); }

	.score-number {
		font-size: 3rem;
		font-weight: 600;
		line-height: 1;
	}

	.score-label {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.grade-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 48px;
		height: 48px;
		font-size: 1.5rem;
		font-weight: 600;
		margin-bottom: 0.5rem;
	}

	.grade-badge.grade-a { background: var(--green); color: white; }
	.grade-badge.grade-b { background: #84cc16; color: white; }
	.grade-badge.grade-c { background: var(--orange); color: var(--bg-inverse); }
	.grade-badge.grade-d { background: #f97316; color: white; }
	.grade-badge.grade-f { background: var(--red); color: white; }

	.ship-status {
		font-size: 1rem;
		font-weight: 500;
	}

	.repo-link {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.75rem;
		margin-top: 1rem;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		text-decoration: none;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		transition: all 0.15s;
	}

	.repo-link:hover {
		border-color: var(--text-primary);
		background: var(--bg-secondary);
	}

	.repo-link svg {
		flex-shrink: 0;
	}

	.scan-meta {
		display: flex;
		align-items: center;
		gap: 1rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
		color: var(--text-secondary);
	}

	.scan-duration {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.3rem 0.6rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		border-radius: 4px;
	}

	.scan-duration svg {
		opacity: 0.7;
	}

	.scan-completed {
		opacity: 0.7;
	}

	.summary-section h2 {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1rem;
		font-weight: 500;
		margin-bottom: 1.5rem;
	}

	.summary-counts {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
		margin-bottom: 1.5rem;
	}

	.count {
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
		font-weight: 500;
		border: 1px solid;
	}

	.severity-critical { border-color: var(--red); color: var(--red); }
	.severity-high { border-color: #f97316; color: #f97316; }
	.severity-medium { border-color: var(--orange); color: var(--orange); }
	.severity-low { border-color: var(--blue); color: var(--blue); }
	.severity-info { border-color: var(--text-tertiary); color: var(--text-tertiary); }

	.stack-info {
		font-size: 0.85rem;
		margin-bottom: 0.5rem;
	}

	.stack-label {
		color: var(--text-secondary);
	}

	.stack-value {
		color: var(--text-primary);
	}

	.findings-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1.5rem;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.findings-actions {
		display: flex;
		gap: 0.5rem;
	}

	.findings-actions .export-btn {
		font-size: 0.75rem;
		padding: 0.4rem 0.75rem;
	}

	.findings-section h2,
	.no-findings h2 {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1.125rem;
		font-weight: 500;
		margin-bottom: 0;
	}

	.mode-toggle {
		display: flex;
		border: 1px solid var(--border);
	}

	.mode-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: transparent;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.mode-btn:first-child {
		border-right: 1px solid var(--border);
	}

	.mode-btn:hover {
		color: var(--text-primary);
		background: var(--bg-secondary);
	}

	.mode-btn.active {
		color: var(--green-dim);
		background: var(--bg-secondary);
	}

	.mode-icon {
		font-size: 0.9rem;
	}

	.no-findings {
		text-align: center;
		padding: 3rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
	}

	.no-findings p {
		color: var(--text-secondary);
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.finding-card {
		border: 1px solid var(--border);
		background: var(--bg-primary);
		transition: border-color 0.15s;
	}

	.finding-card:hover {
		border-color: var(--border-strong);
	}

	.finding-card.expanded {
		border-color: var(--green-dim);
	}

	.finding-toggle {
		width: 100%;
		padding: 1.5rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
	}

	.finding-header {
		display: flex;
		gap: 1rem;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.finding-chevron {
		margin-left: auto;
		font-size: 0.7rem;
		color: var(--text-tertiary);
		transition: transform 0.2s;
	}

	.finding-chevron.rotated {
		transform: rotate(180deg);
	}

	.finding-details {
		padding: 1rem 1.5rem 1.5rem;
		border-top: 1px solid var(--border);
		animation: slideDown 0.15s ease;
	}

	@keyframes slideDown {
		from { opacity: 0; transform: translateY(-5px); }
		to { opacity: 1; transform: translateY(0); }
	}

	.finding-explanation {
		font-size: 0.9rem;
		line-height: 1.6;
		color: var(--text-secondary);
		margin: 0 0 1rem 0;
	}

	.finding-location {
		margin: 0.75rem 0;
	}

	.finding-location code {
		font-size: 0.8rem;
		background: var(--bg-tertiary);
		padding: 0.25rem 0.5rem;
		color: var(--text-secondary);
	}

	.finding-code {
		margin: 0.75rem 0;
		padding: 0.75rem 1rem;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		font-size: 0.8rem;
		line-height: 1.5;
		overflow-x: auto;
		border-left: 3px solid var(--red);
	}

	.finding-code code {
		background: transparent;
		padding: 0;
	}

	.fix-details {
		margin-top: 1rem;
		border: 1px solid var(--border);
	}

	.fix-summary {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem 1rem;
		background: var(--bg-tertiary);
		cursor: pointer;
		font-size: 0.85rem;
		font-weight: 500;
		color: var(--green-dim);
		list-style: none;
	}

	.fix-summary::-webkit-details-marker {
		display: none;
	}

	.fix-summary::before {
		content: '▶';
		font-size: 0.6rem;
		margin-right: 0.5rem;
		transition: transform 0.15s;
	}

	.fix-details[open] .fix-summary::before {
		transform: rotate(90deg);
	}

	.fix-summary:hover {
		background: var(--bg-secondary);
	}

	.fix-meta {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		color: var(--text-tertiary);
	}

	.fix-content {
		padding: 1rem;
		background: var(--bg-secondary);
	}

	.fix-comparison {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.5rem;
	}

	@media (max-width: 700px) {
		.fix-comparison {
			grid-template-columns: 1fr;
		}
	}

	.fix-before, .fix-after {
		position: relative;
	}

	.fix-label-bad, .fix-label-good {
		display: block;
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.25rem;
	}

	.fix-label-bad { color: var(--red); }
	.fix-label-good { color: var(--green); }

	.fix-before pre, .fix-after pre {
		margin: 0;
		padding: 0.75rem;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		font-size: 0.75rem;
		line-height: 1.4;
		overflow-x: auto;
		max-height: 200px;
	}

	.fix-before pre { border-left: 2px solid var(--red); }
	.fix-after pre { border-left: 2px solid var(--green); }

	.fix-before pre code, .fix-after pre code {
		background: transparent;
		padding: 0;
	}

	.btn-copy-sm {
		position: absolute;
		top: -0.25rem;
		right: 0;
		padding: 0.25rem 0.5rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.6rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		color: var(--text-secondary);
		cursor: pointer;
	}

	.btn-copy-sm:hover {
		background: var(--bg-secondary);
		color: var(--text-primary);
	}

	.fix-learn-more {
		display: inline-block;
		margin-top: 0.75rem;
		font-size: 0.8rem;
		color: var(--blue);
		text-decoration: none;
	}

	.fix-learn-more:hover {
		text-decoration: underline;
	}

	.code-snippet {
		margin: 1rem 0;
		border: 1px solid var(--border);
		overflow: hidden;
	}

	.snippet-header {
		padding: 0.5rem 1rem;
		background: var(--bg-tertiary);
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.code-snippet pre {
		padding: 1rem;
		margin: 0;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		overflow-x: auto;
		font-size: 0.8rem;
		line-height: 1.5;
	}

	.code-snippet code {
		background: transparent;
		padding: 0;
	}

	.severity-badge {
		padding: 0.25rem 0.5rem;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.severity-badge.severity-critical { background: var(--red); color: white; }
	.severity-badge.severity-high { background: #f97316; color: white; }
	.severity-badge.severity-medium { background: var(--orange); color: var(--bg-inverse); }
	.severity-badge.severity-low { background: var(--blue); color: white; }

	.finding-category {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.finding-title {
		font-family: 'Inter', sans-serif;
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
	}

	.finding-location {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin: 1rem 0;
	}

	.location-label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.finding-location code {
		font-size: 0.8rem;
		background: var(--bg-tertiary);
		padding: 0.25rem 0.5rem;
	}

	.finding-fix {
		margin-top: 1rem;
		border: 1px solid var(--border);
		overflow: hidden;
	}

	.fix-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 1rem;
		background: var(--bg-tertiary);
	}

	.fix-label {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--green-dim);
	}

	pre.fix-code {
		padding: 1rem;
		margin: 0;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		overflow-x: auto;
		font-size: 0.8rem;
		line-height: 1.5;
	}

	pre.fix-code code {
		background: transparent;
		padding: 0;
	}

	.btn-copy {
		padding: 0.5rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		text-transform: uppercase;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-copy:hover {
		border-color: var(--text-primary);
	}

	.finding-cwe {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.7rem;
		padding: 0.2rem 0.5rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		color: var(--text-secondary);
	}

	.cwe-info-box {
		margin: 1rem 0;
		padding: 1rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		border-left: 3px solid var(--blue);
	}

	.cwe-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.cwe-title {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.cwe-link {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--blue);
		text-decoration: none;
	}

	.cwe-link:hover {
		text-decoration: underline;
	}

	.cwe-name {
		font-weight: 600;
		color: var(--text-primary);
	}

	.cvss-badge {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.3rem 0.6rem;
		border-radius: 2px;
		color: white;
		font-size: 0.75rem;
		font-weight: 600;
	}

	.cvss-score {
		font-family: 'JetBrains Mono', monospace;
	}

	.cvss-label {
		text-transform: uppercase;
		font-size: 0.65rem;
		letter-spacing: 0.05em;
	}

	.cwe-details {
		display: flex;
		gap: 2rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.cwe-detail {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.cwe-detail-label {
		font-size: 0.65rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-tertiary);
	}

	.cwe-detail-value {
		font-size: 0.85rem;
		color: var(--text-primary);
	}

	.cwe-detail-value.exploit-easy {
		color: var(--red);
	}

	.cwe-detail-value.exploit-moderate {
		color: var(--orange);
	}

	.cwe-detail-value.exploit-difficult {
		color: var(--green);
	}

	.cwe-impact {
		font-size: 0.85rem;
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	.cwe-impact strong {
		color: var(--text-primary);
	}

	.fix-template {
		margin-top: 1.5rem;
		border: 1px solid var(--green-dim);
		background: var(--bg-secondary);
	}

	.fix-template-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem;
		border-bottom: 1px solid var(--border);
		background: var(--bg-tertiary);
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.fix-template-title {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-weight: 600;
		color: var(--green-dim);
	}

	.fix-icon {
		font-size: 1rem;
	}

	.fix-meta {
		display: flex;
		gap: 1rem;
		font-size: 0.75rem;
		font-family: 'JetBrains Mono', monospace;
	}

	.fix-time {
		color: var(--text-secondary);
	}

	.fix-difficulty {
		font-weight: 600;
		text-transform: uppercase;
	}

	.fix-description {
		padding: 1rem;
		margin: 0;
		font-size: 0.9rem;
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border);
	}

	.code-comparison {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1px;
		background: var(--border);
	}

	@media (max-width: 900px) {
		.code-comparison {
			grid-template-columns: 1fr;
		}
	}

	.code-block {
		background: var(--bg-primary);
		overflow: hidden;
	}

	.code-block-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0.75rem;
		background: var(--bg-tertiary);
		border-bottom: 1px solid var(--border);
	}

	.code-label-bad {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--red);
	}

	.code-label-good {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--green);
	}

	.code-block pre {
		margin: 0;
		padding: 1rem;
		background: var(--bg-inverse);
		color: var(--text-inverse);
		overflow-x: auto;
		font-size: 0.75rem;
		line-height: 1.5;
		max-height: 250px;
	}

	.code-block pre code {
		background: transparent;
		padding: 0;
	}

	.code-block.before {
		border-left: 3px solid var(--red);
	}

	.code-block.after {
		border-left: 3px solid var(--green);
	}

	.fix-explanation {
		padding: 1rem;
		margin: 0;
		font-size: 0.85rem;
		line-height: 1.6;
		color: var(--text-primary);
		background: var(--bg-primary);
		border-top: 1px solid var(--border);
	}

	.fix-references {
		padding: 0.75rem 1rem;
		background: var(--bg-tertiary);
		display: flex;
		align-items: center;
		gap: 0.75rem;
		flex-wrap: wrap;
		font-size: 0.75rem;
	}

	.ref-label {
		color: var(--text-secondary);
	}

	.fix-references a {
		color: var(--blue);
		text-decoration: none;
	}

	.fix-references a:hover {
		text-decoration: underline;
	}

	.finding-actions {
		margin-top: 1.5rem;
		padding-top: 1.5rem;
		border-top: 1px solid var(--border);
		display: flex;
		gap: 1rem;
	}

	.btn-sm {
		padding: 0.5rem 1rem;
		font-size: 0.75rem;
	}

	.results-footer {
		margin-top: 4rem;
		padding-top: 2rem;
		border-top: 1px solid var(--border);
		display: flex;
		gap: 1rem;
		justify-content: center;
		flex-wrap: wrap;
	}

	.scan-disclaimer {
		margin-top: 3rem;
		padding: 1.5rem;
		background: var(--bg-secondary);
		border: 1px solid var(--border);
	}

	.scan-disclaimer p {
		font-size: 0.75rem;
		color: var(--text-tertiary);
		line-height: 1.7;
		margin: 0;
	}

	.scan-disclaimer strong {
		color: var(--text-secondary);
	}

	.scan-disclaimer a {
		color: var(--green-dim);
		text-decoration: underline;
	}

	.scan-disclaimer a:hover {
		color: var(--text-primary);
	}

	.btn-rescan {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: var(--blue);
		border: 1px solid var(--blue);
		color: white;
		cursor: pointer;
		text-decoration: none;
		transition: all 0.15s;
	}

	.btn-rescan:hover:not(:disabled) {
		background: #2980d9;
		border-color: #2980d9;
	}

	.btn-rescan:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	@keyframes fadeUp {
		from {
			opacity: 0;
			transform: translateY(20px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.confetti-container {
		position: fixed;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		pointer-events: none;
		z-index: 1000;
		overflow: hidden;
	}

	.confetti-particle {
		position: absolute;
		top: -20px;
		animation: confetti-fall 3s ease-out forwards;
	}

	@keyframes confetti-fall {
		0% {
			transform: translateY(0) rotate(0deg);
			opacity: 1;
		}
		100% {
			transform: translateY(100vh) rotate(720deg);
			opacity: 0;
		}
	}

	.score-section {
		opacity: 0;
		transform: scale(0.8);
		transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
	}

	.score-section.revealed {
		opacity: 1;
		transform: scale(1);
	}

	.grade-badge {
		opacity: 0;
		transform: scale(0);
		transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
	}

	.grade-badge.pop {
		opacity: 1;
		transform: scale(1);
	}

	.ship-status {
		opacity: 0;
		transition: opacity 0.4s ease;
	}

	.ship-status.fade-in {
		opacity: 1;
	}

	.summary-section {
		opacity: 0;
		transform: translateX(20px);
		transition: all 0.5s ease;
	}

	.summary-section.revealed {
		opacity: 1;
		transform: translateX(0);
	}

	.findings-section {
		opacity: 0;
		transform: translateY(20px);
		transition: all 0.5s ease;
	}

	.findings-section.revealed {
		opacity: 1;
		transform: translateY(0);
	}

	.export-section {
		margin-bottom: 1.5rem;
		padding: 1.5rem;
		border: 1px solid var(--green-dim);
		background: var(--bg-secondary);
		opacity: 0;
		transform: translateY(10px);
		transition: all 0.4s ease;
	}

	.export-section.revealed {
		opacity: 1;
		transform: translateY(0);
	}

	.export-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.export-header h3 {
		font-family: 'JetBrains Mono', monospace;
		font-size: 1rem;
		font-weight: 500;
		margin: 0;
		color: var(--green-dim);
	}

	.export-actions {
		display: flex;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.export-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.6rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: var(--green-dim);
		border: 1px solid var(--green-dim);
		color: var(--bg-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.export-btn:hover {
		background: var(--green);
		border-color: var(--green);
	}

	.export-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.export-btn svg {
		width: 14px;
		height: 14px;
	}

	.share-section {
		margin-bottom: 3rem;
		padding: 1.5rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		opacity: 0;
		transform: translateY(10px);
		transition: all 0.4s ease;
	}

	.share-section.revealed {
		opacity: 1;
		transform: translateY(0);
	}

	.share-actions {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.share-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.6rem 1rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.share-btn:hover {
		border-color: var(--text-primary);
		background: var(--bg-primary);
	}

	.share-btn svg {
		width: 14px;
		height: 14px;
	}

	.badge-embed {
		margin-top: 1.5rem;
		padding-top: 1.5rem;
		border-top: 1px solid var(--border);
		animation: slideDown 0.2s ease;
	}

	.badge-preview {
		margin-bottom: 1rem;
	}

	.badge-preview img {
		height: 24px;
	}

	.badge-codes {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.badge-code-block {
		border: 1px solid var(--border);
		background: var(--bg-primary);
	}

	.badge-code-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0.75rem;
		border-bottom: 1px solid var(--border);
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}

	.badge-code-block code {
		display: block;
		padding: 0.75rem;
		font-size: 0.75rem;
		word-break: break-all;
		background: transparent;
	}

	.btn-copy-sm {
		padding: 0.25rem 0.5rem;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.65rem;
		text-transform: uppercase;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		cursor: pointer;
		transition: all 0.15s;
	}

	.btn-copy-sm:hover {
		border-color: var(--text-primary);
		color: var(--text-primary);
	}

	.score-number {
		font-family: 'JetBrains Mono', monospace;
	}

	@media (max-width: 768px) {
		.results-header {
			grid-template-columns: 1fr;
			gap: 2rem;
			padding-top: 3rem;
		}

		.repo-actions {
			flex-wrap: wrap;
		}

		.action-btn {
			font-size: 0.8rem;
			padding: 0.4rem 0.75rem;
		}

		.top-badge-embed {
			position: relative;
			top: auto;
			right: auto;
			width: 100%;
			margin-bottom: 1rem;
		}

		.score-section {
			display: flex;
			flex-direction: column;
			align-items: center;
		}
	}
</style>
