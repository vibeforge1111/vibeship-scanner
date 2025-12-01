import { createHash } from 'crypto';
import type { ScanInsert, Finding, Severity } from '$lib/types/database';

export function hashUrl(url: string): string {
	return createHash('sha256').update(url).digest('hex').slice(0, 16);
}

export function parseRepoUrl(url: string): { type: 'github' | 'gitlab'; owner: string; repo: string } | null {
	const githubMatch = url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
	if (githubMatch) {
		return { type: 'github', owner: githubMatch[1], repo: githubMatch[2].replace(/\.git$/, '') };
	}

	const gitlabMatch = url.match(/gitlab\.com\/([^\/]+)\/([^\/]+)/);
	if (gitlabMatch) {
		return { type: 'gitlab', owner: gitlabMatch[1], repo: gitlabMatch[2].replace(/\.git$/, '') };
	}

	return null;
}

export function calculateScore(findings: Finding[]): number {
	let score = 100;

	const deductions: Record<Severity, number> = {
		critical: 25,
		high: 10,
		medium: 5,
		low: 2,
		info: 0
	};

	const maxDeductions: Record<Severity, number> = {
		critical: 100,
		high: 50,
		medium: 50,
		low: 20,
		info: 0
	};

	const counts: Record<Severity, number> = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0
	};

	for (const finding of findings) {
		counts[finding.severity]++;
	}

	for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
		const deduction = Math.min(
			counts[severity] * deductions[severity],
			maxDeductions[severity]
		);
		score -= deduction;
	}

	return Math.max(0, Math.min(100, score));
}

export function calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
	if (score >= 90) return 'A';
	if (score >= 80) return 'B';
	if (score >= 70) return 'C';
	if (score >= 60) return 'D';
	return 'F';
}

export function calculateShipStatus(score: number): 'ship' | 'review' | 'fix' | 'danger' {
	if (score >= 90) return 'ship';
	if (score >= 70) return 'review';
	if (score >= 50) return 'fix';
	return 'danger';
}

export function countFindings(findings: Finding[]): Record<Severity, number> {
	const counts: Record<Severity, number> = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0
	};

	for (const finding of findings) {
		counts[finding.severity]++;
	}

	return counts;
}

export function detectStackFromFiles(files: string[]): { languages: string[]; frameworks: string[]; signature: string } {
	const languages: Set<string> = new Set();
	const frameworks: Set<string> = new Set();

	for (const file of files) {
		if (file === 'package.json') {
			languages.add('JavaScript');
			languages.add('TypeScript');
		}
		if (file === 'requirements.txt' || file === 'pyproject.toml') {
			languages.add('Python');
		}
		if (file === 'go.mod') {
			languages.add('Go');
		}
		if (file === 'Cargo.toml') {
			languages.add('Rust');
		}
		if (file === 'Gemfile') {
			languages.add('Ruby');
		}

		if (file === 'next.config.js' || file === 'next.config.ts' || file === 'next.config.mjs') {
			frameworks.add('Next.js');
		}
		if (file === 'svelte.config.js') {
			frameworks.add('SvelteKit');
		}
		if (file === 'nuxt.config.ts' || file === 'nuxt.config.js') {
			frameworks.add('Nuxt');
		}
		if (file === 'vite.config.ts' || file === 'vite.config.js') {
			frameworks.add('Vite');
		}
		if (file === 'angular.json') {
			frameworks.add('Angular');
		}
	}

	const languageArr = Array.from(languages).sort();
	const frameworkArr = Array.from(frameworks).sort();
	const signature = [...languageArr, ...frameworkArr].join(',').toLowerCase();

	return {
		languages: languageArr,
		frameworks: frameworkArr,
		signature
	};
}

export function createScanRecord(url: string, sessionId?: string, userId?: string): ScanInsert {
	const parsed = parseRepoUrl(url);

	return {
		target_type: parsed?.type || 'github',
		target_url: url,
		target_url_hash: hashUrl(url),
		target_branch: 'main',
		is_private: false,
		status: 'pending',
		session_id: sessionId,
		user_id: userId,
		is_public: true
	};
}
