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


def clone_repo(url: str, target_dir: str, branch: str = 'main') -> bool:
    """Clone a git repository (shallow clone for speed)"""
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--branch', branch, url, target_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            print(f"Clone with branch failed, trying default: {result.stderr}", file=sys.stderr)
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', url, target_dir],
                capture_output=True,
                text=True,
                timeout=120
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

    try:
        files = os.listdir(repo_dir)
    except:
        files = []

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
                if 'mongoose' in deps or 'mongodb' in deps:
                    frameworks.add('MongoDB')
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


def run_opengrep(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Opengrep SAST scanner with local rules only (LGPL fork of Semgrep)"""
    findings = []

    # Use only local rules - no registry dependencies
    core_rules = RULES_DIR / 'core.yaml'
    vibeship_rules = RULES_DIR / 'vibeship.yaml'

    configs = []
    if core_rules.exists():
        configs.extend(['-f', str(core_rules)])
    if vibeship_rules.exists():
        configs.extend(['-f', str(vibeship_rules)])

    if not configs:
        print("ERROR: No rule files found!", file=sys.stderr)
        return findings

    # Opengrep uses similar syntax: opengrep scan -f rules --json target
    cmd = ['opengrep', 'scan', '--json'] + configs + [repo_dir]

    try:
        print(f"Running Opengrep: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"Opengrep exit code: {result.returncode}", file=sys.stderr)

        if result.stderr:
            print(f"Opengrep stderr (first 2000 chars): {result.stderr[:2000]}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                results = data.get('results', [])
                print(f"Opengrep raw results: {len(results)}", file=sys.stderr)

                for item in results:
                    severity = SEVERITY_MAP.get(
                        item.get('extra', {}).get('severity', 'INFO').upper(),
                        'info'
                    )
                    findings.append({
                        'id': hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()[:12],
                        'ruleId': item.get('check_id', 'unknown'),
                        'severity': severity,
                        'category': 'code',
                        'title': item.get('extra', {}).get('message', 'Security Issue'),
                        'description': item.get('extra', {}).get('metadata', {}).get('message', ''),
                        'location': {
                            'file': item.get('path', '').replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
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
            except json.JSONDecodeError as e:
                print(f"Semgrep JSON parse error: {e}", file=sys.stderr)
                print(f"Stdout preview: {result.stdout[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Semgrep timeout after 300s", file=sys.stderr)
    except Exception as e:
        print(f"Semgrep error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Semgrep found {len(findings)} findings", file=sys.stderr)
    return findings


def run_trivy(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Trivy dependency and secret scanner"""
    findings = []

    cmd = [
        'trivy', 'fs',
        '--format', 'json',
        '--scanners', 'vuln,secret',
        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
        repo_dir
    ]

    try:
        print(f"Running Trivy: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"Trivy exit code: {result.returncode}", file=sys.stderr)

        if result.stderr:
            errors = [l for l in result.stderr.split('\n') if 'error' in l.lower()][:3]
            if errors:
                print(f"Trivy errors: {errors}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                # Process vulnerability results
                for target in data.get('Results', []):
                    target_file = target.get('Target', '')

                    # Vulnerabilities
                    for vuln in target.get('Vulnerabilities', []) or []:
                        severity = SEVERITY_MAP.get(vuln.get('Severity', 'UNKNOWN').upper(), 'info')
                        findings.append({
                            'id': vuln.get('VulnerabilityID', hashlib.md5(str(vuln).encode()).hexdigest()[:12]),
                            'ruleId': f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                            'severity': severity,
                            'category': 'dependencies',
                            'title': f"{vuln.get('PkgName', 'Unknown')}: {vuln.get('Title', vuln.get('VulnerabilityID', 'Vulnerability'))}",
                            'description': vuln.get('Description', ''),
                            'location': {
                                'file': target_file.replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': 0
                            },
                            'fix': {
                                'available': bool(vuln.get('FixedVersion')),
                                'template': f"Update {vuln.get('PkgName')} to {vuln.get('FixedVersion')}" if vuln.get('FixedVersion') else None
                            },
                            'references': vuln.get('References', [])[:3]
                        })

                    # Secrets
                    for secret in target.get('Secrets', []) or []:
                        findings.append({
                            'id': hashlib.md5(str(secret).encode()).hexdigest()[:12],
                            'ruleId': f"trivy-secret-{secret.get('RuleID', 'unknown')}",
                            'severity': 'critical',
                            'category': 'secrets',
                            'title': f"Secret Detected: {secret.get('Title', secret.get('RuleID', 'Secret'))}",
                            'description': secret.get('Match', ''),
                            'location': {
                                'file': target_file.replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': secret.get('StartLine', 0)
                            },
                            'fix': {
                                'available': True,
                                'template': 'Remove secret and rotate credentials immediately'
                            }
                        })

            except json.JSONDecodeError as e:
                print(f"Trivy JSON parse error: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Trivy timeout after 300s", file=sys.stderr)
    except Exception as e:
        print(f"Trivy error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Trivy found {len(findings)} findings", file=sys.stderr)
    return findings


def run_gitleaks(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Gitleaks secret scanner"""
    findings = []

    cmd = [
        'gitleaks', 'detect',
        '--source', repo_dir,
        '--report-format', 'json',
        '--report-path', '/dev/stdout',
        '--no-git'
    ]

    if GITLEAKS_CONFIG.exists():
        cmd.extend(['--config', str(GITLEAKS_CONFIG)])

    try:
        print(f"Running Gitleaks: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        # Gitleaks returns 1 when secrets are found, 0 when clean
        print(f"Gitleaks exit code: {result.returncode}", file=sys.stderr)

        if result.stdout and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    for item in data:
                        match_text = item.get('Match', item.get('Secret', ''))
                        if len(match_text) > 50:
                            match_text = match_text[:50] + '...'

                        findings.append({
                            'id': hashlib.md5(str(item).encode()).hexdigest()[:12],
                            'ruleId': f"gitleaks-{item.get('RuleID', 'secret')}",
                            'severity': 'critical',
                            'category': 'secrets',
                            'title': f"Exposed Secret: {item.get('Description', item.get('RuleID', 'Secret'))}",
                            'description': f"Found {item.get('RuleID', 'secret')} in source code",
                            'location': {
                                'file': item.get('File', '').replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': item.get('StartLine', 0)
                            },
                            'snippet': {
                                'code': match_text,
                                'highlightLines': [item.get('StartLine', 0)]
                            },
                            'fix': {
                                'available': True,
                                'template': 'Move to environment variable and rotate the exposed secret immediately'
                            }
                        })
            except json.JSONDecodeError:
                # Empty or no results
                pass

    except subprocess.TimeoutExpired:
        print("Gitleaks timeout after 120s", file=sys.stderr)
    except Exception as e:
        print(f"Gitleaks error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Gitleaks found {len(findings)} findings", file=sys.stderr)
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
        'medium': 30,
        'low': 15,
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
    print(f"Starting scan of {repo_url}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, 'repo')

        print(json.dumps({'step': 'clone', 'message': 'Cloning repository...'}), flush=True)
        if not clone_repo(repo_url, repo_dir, branch):
            print(json.dumps({'error': 'Failed to clone repository'}))
            sys.exit(1)

        print(json.dumps({'step': 'detect', 'message': 'Detecting stack...'}), flush=True)
        stack = detect_stack(repo_dir)
        print(f"Detected stack: {stack}", file=sys.stderr)

        print(json.dumps({'step': 'sast', 'message': 'Running code analysis...'}), flush=True)
        opengrep_findings = run_opengrep(repo_dir)

        print(json.dumps({'step': 'deps', 'message': 'Checking dependencies...'}), flush=True)
        trivy_findings = run_trivy(repo_dir)

        print(json.dumps({'step': 'secrets', 'message': 'Scanning for secrets...'}), flush=True)
        gitleaks_findings = run_gitleaks(repo_dir)

        all_findings = opengrep_findings + trivy_findings + gitleaks_findings
        print(f"Total findings: {len(all_findings)}", file=sys.stderr)

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
