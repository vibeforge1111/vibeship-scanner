#!/usr/bin/env python3
"""
Vibeship Scanner - Security scanning orchestrator
Runs Semgrep, Trivy, and Gitleaks on a repository
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

SEVERITY_MAP = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'INFO': 'info',
    'WARNING': 'medium',
    'ERROR': 'high',
}

SCRIPT_DIR = Path(__file__).parent
RULES_DIR = SCRIPT_DIR / 'rules'
GITLEAKS_CONFIG = SCRIPT_DIR / 'gitleaks.toml'

TEST_FILE_PATTERNS = [
    r'\.test\.(js|ts|jsx|tsx)$',
    r'\.spec\.(js|ts|jsx|tsx)$',
    r'__tests__/',
    r'__mocks__/',
    r'/test/',
    r'/tests/',
]

EXAMPLE_FILE_PATTERNS = [
    r'/examples?/',
    r'/samples?/',
    r'/demos?/',
    r'\.example\.',
    r'\.sample\.',
]

CLIENT_BUNDLE_PATTERNS = [
    r'^src/',
    r'^app/',
    r'^pages/',
    r'^components/',
    r'^lib/',
    r'^public/',
]

import re

def is_test_file(filepath: str) -> bool:
    for pattern in TEST_FILE_PATTERNS:
        if re.search(pattern, filepath, re.IGNORECASE):
            return True
    return False

def is_example_file(filepath: str) -> bool:
    for pattern in EXAMPLE_FILE_PATTERNS:
        if re.search(pattern, filepath, re.IGNORECASE):
            return True
    return False

def is_client_bundle(filepath: str) -> bool:
    for pattern in CLIENT_BUNDLE_PATTERNS:
        if re.search(pattern, filepath, re.IGNORECASE):
            return True
    return False

def downgrade_severity(severity: str) -> str:
    downgrade_map = {
        'critical': 'high',
        'high': 'medium',
        'medium': 'low',
        'low': 'info',
        'info': 'info'
    }
    return downgrade_map.get(severity, severity)

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings from different tools finding the same issue"""
    seen = {}

    for finding in findings:
        file_path = finding.get('location', {}).get('file', '')
        line = finding.get('location', {}).get('line', 0)
        category = finding.get('category', '')

        key = f"{file_path}:{line}:{category}"

        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            existing_severity = existing.get('severity', 'info')
            new_severity = finding.get('severity', 'info')

            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            if severity_order.get(new_severity, 0) > severity_order.get(existing_severity, 0):
                seen[key] = finding
            elif finding.get('ruleId', '').startswith('semgrep'):
                seen[key] = finding

    return list(seen.values())

def apply_context_scoring(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Apply context-aware severity adjustments based on file location"""
    filepath = finding.get('location', {}).get('file', '')
    original_severity = finding.get('severity', 'info')
    context_note = None
    new_severity = original_severity

    if is_test_file(filepath):
        new_severity = downgrade_severity(original_severity)
        context_note = 'Found in test file - lower production risk'
    elif is_example_file(filepath):
        new_severity = downgrade_severity(original_severity)
        context_note = 'Found in example file - may be intentional for demonstration'
    elif is_client_bundle(filepath) and finding.get('category') == 'secrets':
        new_severity = 'critical'
        context_note = 'Secret exposed in client-side code - highest risk'

    if context_note:
        finding['severity'] = new_severity
        finding['contextNote'] = context_note
        finding['originalSeverity'] = original_severity

    return finding

def clone_repo(url: str, target_dir: str, branch: str = 'main') -> bool:
    """Clone a git repository (shallow clone for speed)"""
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--branch', branch, url, target_dir],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', url, target_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("Clone timeout", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Clone error: {e}", file=sys.stderr)
        return False

def detect_stack(repo_dir: str) -> Dict[str, Any]:
    """Detect the tech stack from repository files"""
    languages = set()
    frameworks = set()

    files = os.listdir(repo_dir)

    if 'package.json' in files:
        languages.add('JavaScript')
        languages.add('TypeScript')
        try:
            with open(os.path.join(repo_dir, 'package.json')) as f:
                pkg = json.load(f)
                deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
                if 'next' in deps:
                    frameworks.add('Next.js')
                if 'svelte' in deps or '@sveltejs/kit' in deps:
                    frameworks.add('SvelteKit')
                if 'vue' in deps or 'nuxt' in deps:
                    frameworks.add('Vue')
                if 'react' in deps:
                    frameworks.add('React')
                if 'express' in deps:
                    frameworks.add('Express')
                if '@supabase/supabase-js' in deps:
                    frameworks.add('Supabase')
        except:
            pass

    if 'requirements.txt' in files or 'pyproject.toml' in files:
        languages.add('Python')
        if 'manage.py' in files:
            frameworks.add('Django')

    if 'go.mod' in files:
        languages.add('Go')

    if 'Cargo.toml' in files:
        languages.add('Rust')

    lang_list = sorted(list(languages))
    framework_list = sorted(list(frameworks))
    signature = ','.join(lang_list + framework_list).lower()

    return {
        'languages': lang_list,
        'frameworks': framework_list,
        'signature': signature
    }

def run_semgrep(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Semgrep SAST scanner with custom rules"""
    findings = []

    cmd = ['semgrep', 'scan', '--json', repo_dir]

    vibeship_rules = RULES_DIR / 'vibeship.yaml'
    if vibeship_rules.exists():
        cmd.extend(['--config', str(vibeship_rules)])

    cmd.extend(['--config', 'auto'])
    cmd.extend(['--config', 'p/javascript'])
    cmd.extend(['--config', 'p/nodejs'])
    cmd.extend(['--config', 'p/express'])
    cmd.extend(['--config', 'p/security-audit'])
    cmd.extend(['--config', 'p/owasp-top-ten'])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.stdout:
            data = json.loads(result.stdout)
            for item in data.get('results', []):
                severity = SEVERITY_MAP.get(item.get('extra', {}).get('severity', 'INFO'), 'info')
                findings.append({
                    'id': hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()[:12],
                    'ruleId': item.get('check_id', 'unknown'),
                    'severity': severity,
                    'category': 'code',
                    'title': item.get('extra', {}).get('message', 'Security Issue'),
                    'description': item.get('extra', {}).get('metadata', {}).get('message', ''),
                    'location': {
                        'file': item.get('path', '').replace(repo_dir + '/', ''),
                        'line': item.get('start', {}).get('line', 0),
                        'column': item.get('start', {}).get('col', 0)
                    },
                    'snippet': {
                        'code': item.get('extra', {}).get('lines', ''),
                        'highlightLines': [item.get('start', {}).get('line', 0)]
                    },
                    'fix': {
                        'available': bool(item.get('extra', {}).get('fix')),
                        'template': item.get('extra', {}).get('fix')
                    },
                    'references': item.get('extra', {}).get('metadata', {}).get('references', [])
                })
    except subprocess.TimeoutExpired:
        print("Semgrep timeout", file=sys.stderr)
    except Exception as e:
        print(f"Semgrep error: {e}", file=sys.stderr)

    return findings

def run_trivy(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Trivy dependency scanner"""
    findings = []

    try:
        result = subprocess.run(
            ['trivy', 'fs', '--format', 'json', '--scanners', 'vuln', '--skip-db-update', '--offline-scan', repo_dir],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.stdout:
            data = json.loads(result.stdout)
            for target in data.get('Results', []):
                target_file = target.get('Target', '')
                for vuln in target.get('Vulnerabilities', []):
                    severity = SEVERITY_MAP.get(vuln.get('Severity', 'UNKNOWN'), 'info')
                    findings.append({
                        'id': vuln.get('VulnerabilityID', hashlib.md5(str(vuln).encode()).hexdigest()[:12]),
                        'ruleId': f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                        'severity': severity,
                        'category': 'dependencies',
                        'title': f"{vuln.get('PkgName', 'Unknown')}: {vuln.get('Title', vuln.get('VulnerabilityID', 'Vulnerability'))}",
                        'description': vuln.get('Description', ''),
                        'location': {
                            'file': target_file.replace(repo_dir + '/', ''),
                            'line': 0
                        },
                        'fix': {
                            'available': bool(vuln.get('FixedVersion')),
                            'template': f"Update {vuln.get('PkgName')} to {vuln.get('FixedVersion')}" if vuln.get('FixedVersion') else None
                        },
                        'references': vuln.get('References', [])[:3]
                    })
    except subprocess.TimeoutExpired:
        print("Trivy timeout", file=sys.stderr)
    except Exception as e:
        print(f"Trivy error: {e}", file=sys.stderr)

    return findings

def run_gitleaks(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Gitleaks secret scanner with custom rules"""
    findings = []

    cmd = ['gitleaks', 'detect', '--source', repo_dir, '--report-format', 'json', '--report-path', '/dev/stdout', '--no-git']

    if GITLEAKS_CONFIG.exists():
        cmd.extend(['--config', str(GITLEAKS_CONFIG)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for item in data:
                    findings.append({
                        'id': hashlib.md5(str(item).encode()).hexdigest()[:12],
                        'ruleId': f"gitleaks-{item.get('RuleID', 'secret')}",
                        'severity': 'critical',
                        'category': 'secrets',
                        'title': f"Exposed Secret: {item.get('Description', item.get('RuleID', 'Secret'))}",
                        'description': f"Found {item.get('RuleID', 'secret')} in source code",
                        'location': {
                            'file': item.get('File', '').replace(repo_dir + '/', ''),
                            'line': item.get('StartLine', 0)
                        },
                        'snippet': {
                            'code': item.get('Match', '')[:50] + '...' if len(item.get('Match', '')) > 50 else item.get('Match', ''),
                            'highlightLines': [item.get('StartLine', 0)]
                        },
                        'fix': {
                            'available': True,
                            'template': 'Move to environment variable and rotate the exposed secret immediately'
                        }
                    })
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        print("Gitleaks timeout", file=sys.stderr)
    except Exception as e:
        print(f"Gitleaks error: {e}", file=sys.stderr)

    return findings

def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate security score from findings"""
    score = 100

    deductions = {
        'critical': 25,
        'high': 10,
        'medium': 5,
        'low': 2,
        'info': 0
    }

    max_deductions = {
        'critical': 100,
        'high': 50,
        'medium': 50,
        'low': 20,
        'info': 0
    }

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1

    for sev in ['critical', 'high', 'medium', 'low']:
        deduction = min(counts[sev] * deductions[sev], max_deductions[sev])
        score -= deduction

    return max(0, min(100, score))

def calculate_grade(score: int) -> str:
    """Calculate letter grade from score"""
    if score >= 90: return 'A'
    if score >= 80: return 'B'
    if score >= 70: return 'C'
    if score >= 60: return 'D'
    return 'F'

def calculate_ship_status(score: int) -> str:
    """Calculate ship status from score"""
    if score >= 90: return 'ship'
    if score >= 70: return 'review'
    if score >= 50: return 'fix'
    return 'danger'

def main():
    if len(sys.argv) < 2:
        print("Usage: scan.py <repo_url> [branch]", file=sys.stderr)
        sys.exit(1)

    repo_url = sys.argv[1]
    branch = sys.argv[2] if len(sys.argv) > 2 else 'main'

    start_time = datetime.now()

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, 'repo')

        print(json.dumps({'step': 'clone', 'message': 'Cloning repository...'}), flush=True)
        if not clone_repo(repo_url, repo_dir, branch):
            print(json.dumps({'error': 'Failed to clone repository'}))
            sys.exit(1)

        print(json.dumps({'step': 'detect', 'message': 'Detecting stack...'}), flush=True)
        stack = detect_stack(repo_dir)

        print(json.dumps({'step': 'sast', 'message': 'Running code analysis...'}), flush=True)
        semgrep_findings = run_semgrep(repo_dir)

        print(json.dumps({'step': 'deps', 'message': 'Checking dependencies...'}), flush=True)
        trivy_findings = run_trivy(repo_dir)

        print(json.dumps({'step': 'secrets', 'message': 'Scanning for secrets...'}), flush=True)
        gitleaks_findings = run_gitleaks(repo_dir)

        all_findings = semgrep_findings + trivy_findings + gitleaks_findings

        all_findings = deduplicate_findings(all_findings)

        all_findings = [apply_context_scoring(f) for f in all_findings]

        print(json.dumps({'step': 'score', 'message': 'Calculating score...'}), flush=True)
        score = calculate_score(all_findings)
        grade = calculate_grade(score)
        ship_status = calculate_ship_status(score)

        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info')
            counts[sev] = counts.get(sev, 0) + 1

        result = {
            'status': 'complete',
            'score': score,
            'grade': grade,
            'shipStatus': ship_status,
            'summary': counts,
            'stack': stack,
            'findings': all_findings,
            'duration': duration_ms
        }

        print(json.dumps({'step': 'complete', 'result': result}), flush=True)

if __name__ == '__main__':
    main()
