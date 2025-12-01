import { spawn } from 'child_process';
import { supabase } from '$lib/supabase';
import { SUPABASE_SERVICE_ROLE_KEY } from '$env/static/private';
import { PUBLIC_SUPABASE_URL } from '$env/static/public';
import { createClient } from '@supabase/supabase-js';

const adminSupabase = createClient(PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function updateProgress(scanId: string, step: string, message: string, percent: number) {
	await adminSupabase.from('scan_progress').insert({
		scan_id: scanId,
		step,
		message,
		percent
	});
}

async function updateScan(scanId: string, data: Record<string, unknown>) {
	await adminSupabase.from('scans').update(data).eq('id', scanId);
}

function runCommand(command: string, args: string[]): Promise<string> {
	return new Promise((resolve, reject) => {
		const proc = spawn(command, args);
		let stdout = '';
		let stderr = '';

		proc.stdout.on('data', (data) => { stdout += data; });
		proc.stderr.on('data', (data) => { stderr += data; });

		proc.on('close', (code) => {
			resolve(stdout);
		});

		proc.on('error', (err) => {
			reject(err);
		});

		setTimeout(() => {
			proc.kill();
			resolve(stdout);
		}, 120000);
	});
}

export async function runScan(scanId: string, repoUrl: string, branch: string) {
	const startTime = Date.now();

	try {
		await updateScan(scanId, { status: 'scanning', started_at: new Date().toISOString() });
		await updateProgress(scanId, 'init', 'Initializing scan...', 5);

		const tempDir = `/tmp/scan-${scanId}`;

		await updateProgress(scanId, 'clone', 'Cloning repository...', 15);
		await runCommand('git', ['clone', '--depth', '1', '--branch', branch, repoUrl, tempDir]).catch(() =>
			runCommand('git', ['clone', '--depth', '1', repoUrl, tempDir])
		);

		await updateProgress(scanId, 'sast', 'Running code analysis...', 35);
		const semgrepOutput = await runCommand('semgrep', ['scan', '--config', 'auto', '--json', tempDir]);

		await updateProgress(scanId, 'deps', 'Checking dependencies...', 55);
		const trivyOutput = await runCommand('trivy', ['fs', '--format', 'json', '--scanners', 'vuln', tempDir]);

		await updateProgress(scanId, 'secrets', 'Scanning for secrets...', 75);
		const gitleaksOutput = await runCommand('gitleaks', ['detect', '--source', tempDir, '--report-format', 'json', '--report-path', '/dev/stdout', '--no-git']);

		await updateProgress(scanId, 'score', 'Calculating score...', 90);

		const findings: any[] = [];

		try {
			const semgrep = JSON.parse(semgrepOutput);
			for (const item of semgrep.results || []) {
				findings.push({
					id: item.check_id?.slice(0, 12) || 'unknown',
					ruleId: item.check_id || 'unknown',
					severity: mapSeverity(item.extra?.severity),
					category: 'code',
					title: item.extra?.message || 'Security Issue',
					description: item.extra?.metadata?.message || '',
					location: {
						file: item.path?.replace(tempDir + '/', '') || '',
						line: item.start?.line || 0
					},
					fix: {
						available: !!item.extra?.fix,
						template: item.extra?.fix
					}
				});
			}
		} catch {}

		try {
			const trivy = JSON.parse(trivyOutput);
			for (const target of trivy.Results || []) {
				for (const vuln of target.Vulnerabilities || []) {
					findings.push({
						id: vuln.VulnerabilityID || 'unknown',
						ruleId: `trivy-${vuln.VulnerabilityID}`,
						severity: mapSeverity(vuln.Severity),
						category: 'dependencies',
						title: `${vuln.PkgName}: ${vuln.Title || vuln.VulnerabilityID}`,
						description: vuln.Description || '',
						location: {
							file: target.Target?.replace(tempDir + '/', '') || '',
							line: 0
						},
						fix: {
							available: !!vuln.FixedVersion,
							template: vuln.FixedVersion ? `Update to ${vuln.FixedVersion}` : null
						}
					});
				}
			}
		} catch {}

		try {
			const gitleaks = JSON.parse(gitleaksOutput);
			for (const item of gitleaks || []) {
				findings.push({
					id: item.RuleID?.slice(0, 12) || 'secret',
					ruleId: `gitleaks-${item.RuleID}`,
					severity: 'critical',
					category: 'secrets',
					title: `Exposed Secret: ${item.Description || item.RuleID}`,
					description: `Found ${item.RuleID} in source code`,
					location: {
						file: item.File?.replace(tempDir + '/', '') || '',
						line: item.StartLine || 0
					},
					fix: {
						available: true,
						template: 'Move to environment variable and rotate immediately'
					}
				});
			}
		} catch {}

		const score = calculateScore(findings);
		const grade = calculateGrade(score);
		const shipStatus = calculateShipStatus(score);

		const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
		for (const f of findings) {
			counts[f.severity as keyof typeof counts] = (counts[f.severity as keyof typeof counts] || 0) + 1;
		}

		const durationMs = Date.now() - startTime;

		await updateScan(scanId, {
			status: 'complete',
			score,
			grade,
			ship_status: shipStatus,
			findings,
			finding_counts: counts,
			duration_ms: durationMs,
			completed_at: new Date().toISOString()
		});

		await updateProgress(scanId, 'complete', 'Scan complete!', 100);

		await runCommand('rm', ['-rf', tempDir]);

	} catch (error) {
		console.error('Scan error:', error);
		await updateScan(scanId, {
			status: 'failed',
			error_message: error instanceof Error ? error.message : 'Unknown error'
		});
	}
}

function mapSeverity(sev: string | undefined): string {
	const map: Record<string, string> = {
		'CRITICAL': 'critical',
		'HIGH': 'high',
		'MEDIUM': 'medium',
		'LOW': 'low',
		'INFO': 'info',
		'WARNING': 'medium',
		'ERROR': 'high'
	};
	return map[sev?.toUpperCase() || ''] || 'info';
}

function calculateScore(findings: any[]): number {
	let score = 100;
	const deductions: Record<string, number> = { critical: 25, high: 10, medium: 5, low: 2, info: 0 };
	const maxDeductions: Record<string, number> = { critical: 100, high: 50, medium: 50, low: 20, info: 0 };

	const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of findings) {
		counts[f.severity] = (counts[f.severity] || 0) + 1;
	}

	for (const sev of ['critical', 'high', 'medium', 'low']) {
		const deduction = Math.min(counts[sev] * deductions[sev], maxDeductions[sev]);
		score -= deduction;
	}

	return Math.max(0, Math.min(100, score));
}

function calculateGrade(score: number): string {
	if (score >= 90) return 'A';
	if (score >= 80) return 'B';
	if (score >= 70) return 'C';
	if (score >= 60) return 'D';
	return 'F';
}

function calculateShipStatus(score: number): string {
	if (score >= 90) return 'ship';
	if (score >= 70) return 'review';
	if (score >= 50) return 'fix';
	return 'danger';
}
