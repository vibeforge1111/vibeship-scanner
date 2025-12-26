#!/usr/bin/env python3
"""
Vibeship Scanner API Server
Receives scan requests and updates Supabase with results
"""

import os
import json
import tempfile
import threading
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

from scan import (
    clone_repo, detect_stack, run_opengrep, run_trivy, run_gitleaks, run_retirejs,
    calculate_score, calculate_grade, calculate_ship_status, deduplicate_findings
)

from mcp_endpoint import mcp_bp

app = Flask(__name__)
app.register_blueprint(mcp_bp)
CORS(app, origins=['https://scanner.vibeship.co', 'https://vibeship.co', 'https://www.vibeship.co', 'http://localhost:5173', 'http://localhost:3000'])

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

STEP_MAP = {
    'init': 0,
    'clone': 1,
    'detect': 2,
    'sast': 3,
    'deps': 4,
    'secrets': 5,
    'score': 6,
    'complete': 7
}

def update_progress(supabase: Client, scan_id: str, step: str, message: str, percent: int):
    step_number = STEP_MAP.get(step, 0)
    supabase.table('scan_progress').insert({
        'scan_id': scan_id,
        'step': step,
        'step_number': step_number,
        'total_steps': 7,
        'percent': percent,
        'message': message
    }).execute()

def update_scan(supabase: Client, scan_id: str, data: dict):
    supabase.table('scans').update(data).eq('id', scan_id).execute()

def save_findings_in_batches(supabase: Client, scan_id: str, findings: list, batch_size: int = 500) -> bool:
    """
    Save findings in batches to handle large result sets.
    For repos like LoopFi with 55,000+ findings, saving all at once can fail.

    Strategy:
    1. If findings < batch_size, save normally
    2. If larger, save in batches with retries
    3. Each batch updates the findings array incrementally

    Tuned for Supabase reliability:
    - batch_size=500 (reduced from 5000 to avoid timeouts)
    - 5 retries with exponential backoff + jitter
    - Inter-batch delay to avoid overwhelming the database
    """
    import time
    import random

    total = len(findings)
    max_retries = 5
    base_delay = 2  # seconds
    inter_batch_delay = 0.5  # seconds between successful batches

    if total <= batch_size:
        # Small enough to save in one go
        for retry in range(max_retries):
            try:
                supabase.table('scans').update({'findings': findings}).eq('id', scan_id).execute()
                return True
            except Exception as e:
                wait_time = base_delay * (2 ** retry) + random.uniform(0, 1)
                print(f"[Scan] Failed to save {total} findings (attempt {retry + 1}/{max_retries}): {e}", flush=True)
                if retry < max_retries - 1:
                    print(f"[Scan] Retrying in {wait_time:.1f}s...", flush=True)
                    time.sleep(wait_time)
        # Fall through to batched approach after all retries failed

    print(f"[Scan] Large finding set ({total}), saving in batches of {batch_size}...", flush=True)

    # Sort by severity for priority (critical first)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'info'), 5))

    saved_count = 0
    batch_num = 0
    total_batches = (total + batch_size - 1) // batch_size

    # Save in batches
    for i in range(0, total, batch_size):
        batch = sorted_findings[i:i + batch_size]
        batch_num += 1

        for retry in range(max_retries):
            try:
                # Cumulative replace strategy: save all findings up to this point
                # This avoids reading existing findings (which times out on large sets)
                cumulative_findings = sorted_findings[:i + len(batch)]
                supabase.table('scans').update({'findings': cumulative_findings}).eq('id', scan_id).execute()

                saved_count += len(batch)
                print(f"[Scan] Saved batch {batch_num}/{total_batches}: {saved_count}/{total} findings", flush=True)

                # Inter-batch delay to avoid overwhelming Supabase
                if i + batch_size < total:
                    time.sleep(inter_batch_delay)
                break  # Success, move to next batch

            except Exception as e:
                # Exponential backoff with jitter
                wait_time = base_delay * (2 ** retry) + random.uniform(0, 2)
                print(f"[Scan] Batch {batch_num} attempt {retry + 1}/{max_retries} failed: {e}", flush=True)
                if retry < max_retries - 1:
                    print(f"[Scan] Retrying in {wait_time:.1f}s...", flush=True)
                    time.sleep(wait_time)
                else:
                    print(f"[Scan] Failed to save batch {batch_num} after {max_retries} retries", flush=True)
                    # Continue with remaining batches

    print(f"[Scan] Batch save complete: {saved_count}/{total} findings saved", flush=True)
    return saved_count > 0

def run_scan(scan_id: str, repo_url: str, branch: str, github_token: str = None):
    """Run the full scan pipeline"""
    supabase = get_supabase()
    start_time = datetime.now()

    try:
        # Create scan row if it doesn't exist (upsert)
        target_url_hash = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
        supabase.table('scans').upsert({
            'id': scan_id,
            'target_url': repo_url,
            'target_url_hash': target_url_hash,
            'target_branch': branch or 'main',
            'target_type': 'github',
            'status': 'scanning',
            'started_at': start_time.isoformat()
        }, on_conflict='id').execute()

        update_progress(supabase, scan_id, 'init', 'Initializing scan...', 5)

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = os.path.join(temp_dir, 'repo')

            update_progress(supabase, scan_id, 'clone', 'Cloning repository...', 15)
            if not clone_repo(repo_url, repo_dir, branch, github_token):
                update_scan(supabase, scan_id, {
                    'status': 'failed',
                    'error_message': 'Failed to clone repository'
                })
                return

            update_progress(supabase, scan_id, 'detect', 'Detecting stack...', 25)
            stack = detect_stack(repo_dir)

            # Run all scanners in parallel for faster execution
            update_progress(supabase, scan_id, 'sast', 'Running security scanners in parallel...', 40)

            opengrep_findings = []
            trivy_findings = []
            gitleaks_findings = []
            retirejs_findings = []

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(run_opengrep, repo_dir, stack.get('languages', [])): 'opengrep',
                    executor.submit(run_trivy, repo_dir): 'trivy',
                    executor.submit(run_gitleaks, repo_dir): 'gitleaks',
                    executor.submit(run_retirejs, repo_dir): 'retirejs',
                }

                completed = 0
                for future in as_completed(futures):
                    scanner_name = futures[future]
                    completed += 1
                    try:
                        results = future.result()
                        if scanner_name == 'opengrep':
                            opengrep_findings = results
                        elif scanner_name == 'trivy':
                            trivy_findings = results
                        elif scanner_name == 'gitleaks':
                            gitleaks_findings = results
                        elif scanner_name == 'retirejs':
                            retirejs_findings = results

                        # Update progress as each scanner completes
                        percent = 40 + (completed * 12)  # 40, 52, 64, 76
                        update_progress(supabase, scan_id, 'sast', f'{scanner_name} complete ({completed}/4)...', percent)
                    except Exception as e:
                        print(f"Scanner {scanner_name} error: {e}", flush=True)

            print(f"[Scan] All scanners complete. Combining findings...", flush=True)
            print(f"[Scan] Opengrep: {len(opengrep_findings)}, Trivy: {len(trivy_findings)}, Gitleaks: {len(gitleaks_findings)}, RetireJS: {len(retirejs_findings)}", flush=True)

            all_findings = opengrep_findings + trivy_findings + gitleaks_findings + retirejs_findings
            print(f"[Scan] Total raw findings: {len(all_findings)}", flush=True)

            all_findings = deduplicate_findings(all_findings)
            print(f"[Scan] After dedup: {len(all_findings)}", flush=True)

            update_progress(supabase, scan_id, 'score', 'Calculating score...', 95)
            print(f"[Scan] Calculating score...", flush=True)
            score = calculate_score(all_findings)
            grade = calculate_grade(score)
            ship_status = calculate_ship_status(score)

            end_time = datetime.now()
            duration_ms = int((end_time - start_time).total_seconds() * 1000)

            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in all_findings:
                sev = f.get('severity', 'info')
                counts[sev] = counts.get(sev, 0) + 1

            print(f"[Scan] Score={score}, Grade={grade}, Duration={duration_ms}ms, Findings={len(all_findings)}", flush=True)
            print(f"[Scan] Counts: {counts}", flush=True)
            print(f"[Scan] Updating database with final results...", flush=True)

            # First save metadata (without findings)
            update_scan(supabase, scan_id, {
                'status': 'scanning',  # Keep as scanning while saving findings
                'score': score,
                'grade': grade,
                'ship_status': ship_status,
                'finding_counts': counts,
                'detected_stack': stack,
                'stack_signature': stack.get('signature', ''),
                'duration_ms': duration_ms,
                'completed_at': end_time.isoformat()
            })

            # Save findings in batches (handles large result sets like LoopFi)
            # Uses batch_size=500 by default with exponential backoff for Supabase reliability
            save_findings_in_batches(supabase, scan_id, all_findings)

            # Mark as complete
            update_scan(supabase, scan_id, {'status': 'complete'})

            print(f"[Scan] Database updated successfully!", flush=True)

            update_progress(supabase, scan_id, 'complete', 'Scan complete!', 100)
            print(f"[Scan] SCAN COMPLETE for {scan_id}", flush=True)

    except Exception as e:
        import traceback
        print(f"Scan error: {e}", flush=True)
        print(f"Traceback: {traceback.format_exc()}", flush=True)
        try:
            update_scan(supabase, scan_id, {
                'status': 'failed',
                'error_message': str(e)
            })
        except Exception as e2:
            print(f"Failed to update scan status: {e2}", flush=True)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/test-token', methods=['POST'])
def test_token():
    """Test if a GitHub token can access a repo"""
    import requests
    data = request.json or {}
    token = data.get('token')
    repo = data.get('repo', 'vibeforge1111/test')  # default test repo

    if not token:
        return jsonify({'error': 'No token provided'}), 400

    # Test the token by calling GitHub API
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    # First, check what scopes the token has
    user_resp = requests.get('https://api.github.com/user', headers=headers)
    scopes = user_resp.headers.get('X-OAuth-Scopes', 'none')

    # Try to access the repo
    repo_resp = requests.get(f'https://api.github.com/repos/{repo}', headers=headers)

    return jsonify({
        'token_valid': user_resp.status_code == 200,
        'token_scopes': scopes,
        'user': user_resp.json().get('login') if user_resp.status_code == 200 else None,
        'repo_accessible': repo_resp.status_code == 200,
        'repo_status': repo_resp.status_code,
        'repo_message': repo_resp.json().get('message') if repo_resp.status_code != 200 else 'OK'
    })

@app.route('/test-scan', methods=['POST'])
def test_scan():
    """Test endpoint - runs scan without database, returns results directly"""
    import tempfile
    data = request.json
    repo_url = data.get('repoUrl')
    branch = data.get('branch', 'main')

    if not repo_url:
        return jsonify({'error': 'Missing repoUrl'}), 400

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = os.path.join(temp_dir, 'repo')

            if not clone_repo(repo_url, repo_dir, branch):
                return jsonify({'error': 'Failed to clone repository'}), 400

            stack = detect_stack(repo_dir)

            # Run all scanners in parallel
            opengrep_findings = []
            trivy_findings = []
            gitleaks_findings = []
            retirejs_findings = []

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(run_opengrep, repo_dir, stack.get('languages', [])): 'opengrep',
                    executor.submit(run_trivy, repo_dir): 'trivy',
                    executor.submit(run_gitleaks, repo_dir): 'gitleaks',
                    executor.submit(run_retirejs, repo_dir): 'retirejs',
                }

                for future in as_completed(futures):
                    scanner_name = futures[future]
                    try:
                        results = future.result()
                        if scanner_name == 'opengrep':
                            opengrep_findings = results
                        elif scanner_name == 'trivy':
                            trivy_findings = results
                        elif scanner_name == 'gitleaks':
                            gitleaks_findings = results
                        elif scanner_name == 'retirejs':
                            retirejs_findings = results
                    except Exception as e:
                        print(f"Scanner {scanner_name} error: {e}")

            all_findings = opengrep_findings + trivy_findings + gitleaks_findings + retirejs_findings
            all_findings = deduplicate_findings(all_findings)

            score = calculate_score(all_findings)
            grade = calculate_grade(score)
            ship_status = calculate_ship_status(score)

            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in all_findings:
                sev = f.get('severity', 'info')
                counts[sev] = counts.get(sev, 0) + 1

            return jsonify({
                'status': 'complete',
                'score': score,
                'grade': grade,
                'ship_status': ship_status,
                'finding_counts': counts,
                'total_findings': len(all_findings),
                'detected_stack': stack,
                'findings_preview': all_findings[:20]  # First 20 findings for preview
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    scan_id = data.get('scanId')
    repo_url = data.get('repoUrl')
    branch = data.get('branch', 'main')
    github_token = data.get('githubToken')

    print(f"[Scanner] Received scan request: scanId={scan_id}, repo={repo_url}, hasToken={bool(github_token)}", flush=True)

    if not scan_id or not repo_url:
        return jsonify({'error': 'Missing scanId or repoUrl'}), 400

    thread = threading.Thread(target=run_scan, args=(scan_id, repo_url, branch, github_token))
    thread.start()

    return jsonify({'status': 'started', 'scanId': scan_id})


# ============================================
# BENCHMARK ENDPOINT (Hidden - requires secret key)
# ============================================

BENCHMARK_SECRET = os.environ.get('BENCHMARK_SECRET', 'vibeship-benchmark-2024')

@app.route('/benchmark', methods=['POST'])
def run_benchmark():
    """
    Run the benchmark suite against known vulnerable repos.
    Requires secret key for access.

    POST /benchmark
    Headers: X-Benchmark-Key: <secret>
    Body: { "repos": ["owner/repo", ...], "target_coverage": 0.90 }
    """
    # Check secret key
    provided_key = request.headers.get('X-Benchmark-Key', '')
    if provided_key != BENCHMARK_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    repos = data.get('repos')  # None means all repos
    target_coverage = data.get('target_coverage', 0.90)

    try:
        # Import benchmark module
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'benchmark'))
        from benchmark import BenchmarkRunner

        runner = BenchmarkRunner(target_coverage=target_coverage)
        results = runner.run_full_benchmark(repos=repos)

        # Generate gap report
        gap_report = runner.generate_gap_report(results)

        return jsonify({
            'status': 'complete',
            'overall_coverage': results['overall_coverage'],
            'total_detected': results['total_detected'],
            'total_missed': results['total_missed'],
            'target_coverage': target_coverage,
            'target_met': results['overall_coverage'] >= target_coverage,
            'repos': {
                repo: {
                    'coverage': data.get('coverage', 0),
                    'detected': data.get('detected_count', 0),
                    'missed': data.get('missed_count', 0),
                    'gaps': [g['id'] for g in data.get('missed', [])]
                }
                for repo, data in results.get('repos', {}).items()
                if 'error' not in data
            },
            'all_gaps': results.get('all_gaps', []),
            'gap_report': gap_report
        })

    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/benchmark/repos', methods=['GET'])
def list_benchmark_repos():
    """List all available benchmark repos (no auth required)"""
    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'benchmark'))
        from known_vulns import KNOWN_VULNERABILITIES

        repos = []
        for repo_name, repo_data in KNOWN_VULNERABILITIES.items():
            repos.append({
                'repo': repo_name,
                'name': repo_data.get('name', repo_name),
                'language': repo_data.get('language', 'unknown'),
                'vuln_count': len(repo_data.get('vulns', []))
            })

        return jsonify({'repos': repos})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/benchmark/scan-single', methods=['POST'])
def benchmark_single():
    """
    Benchmark a single repo and return detailed results.
    Requires secret key for access.

    POST /benchmark/scan-single
    Headers: X-Benchmark-Key: <secret>
    Body: { "repo": "owner/repo" }
    """
    # Check secret key
    provided_key = request.headers.get('X-Benchmark-Key', '')
    if provided_key != BENCHMARK_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    repo = data.get('repo')

    if not repo:
        return jsonify({'error': 'Missing repo parameter'}), 400

    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'benchmark'))
        from benchmark import BenchmarkRunner

        runner = BenchmarkRunner()
        result = runner.run_single_repo(repo)

        return jsonify({
            'status': 'complete',
            'result': result
        })

    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


# Store for background jobs
benchmark_jobs = {}

@app.route('/benchmark/auto-improve', methods=['POST'])
def start_auto_improve():
    """
    Start the auto-improve loop in the background.
    Returns a job ID to check progress.

    POST /benchmark/auto-improve
    Headers: X-Benchmark-Key: <secret>
    Body: { "target_coverage": 0.95, "max_iterations": 5 }
    """
    provided_key = request.headers.get('X-Benchmark-Key', '')
    if provided_key != BENCHMARK_SECRET:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    target = data.get('target_coverage', 0.95)
    max_iter = data.get('max_iterations', 5)

    import uuid
    job_id = str(uuid.uuid4())[:8]

    def run_auto_improve(job_id, target, max_iter):
        try:
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'benchmark'))
            from auto_improve import AutoImprover

            benchmark_jobs[job_id] = {
                'status': 'running',
                'started_at': datetime.now().isoformat(),
                'progress': 'Starting...'
            }

            improver = AutoImprover(target_coverage=target, max_iterations=max_iter)
            result = improver.run_until_target()

            benchmark_jobs[job_id] = {
                'status': 'complete',
                'completed_at': datetime.now().isoformat(),
                'result': result
            }

        except Exception as e:
            import traceback
            benchmark_jobs[job_id] = {
                'status': 'failed',
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    thread = threading.Thread(target=run_auto_improve, args=(job_id, target, max_iter))
    thread.start()

    return jsonify({
        'status': 'started',
        'job_id': job_id,
        'message': 'Auto-improve loop started. Check /benchmark/job/<job_id> for progress.'
    })


@app.route('/benchmark/job/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """Get status of a benchmark job"""
    if job_id not in benchmark_jobs:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify(benchmark_jobs[job_id])


# ============================================
# FALSE POSITIVE FEEDBACK SYSTEM
# Privacy-preserving feedback collection
# ============================================

@app.route('/feedback/report', methods=['POST'])
def report_false_positive():
    """
    Submit a false positive report (privacy-preserving).

    POST /feedback/report
    Body: {
        "rule_id": "sol-unchecked-call-return",
        "rule_message": "Low-level call return value not checked",
        "severity": "ERROR",
        "language": "solidity",
        "code_snippet": "...",
        "context": "...",
        "repo_url": "...",  # Only used for hashing at Level 3
        "reason_category": "safe_pattern",
        "reason_detail": "...",
        "ai_analysis": "...",
        "consent_level": 1  # 1=anonymous, 2=with_context, 3=full
    }
    """
    try:
        from feedback import sanitize_for_feedback

        data = request.json or {}

        # Validate required fields
        required = ['rule_id', 'language', 'code_snippet', 'reason_category', 'consent_level']
        for field in required:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Validate consent level
        consent_level = data.get('consent_level', 1)
        if consent_level not in [1, 2, 3]:
            return jsonify({'error': 'consent_level must be 1, 2, or 3'}), 400

        # Validate reason category
        valid_reasons = ['safe_pattern', 'framework_handled', 'test_code', 'intentional', 'wrong_context', 'other']
        if data.get('reason_category') not in valid_reasons:
            return jsonify({'error': f'reason_category must be one of: {valid_reasons}'}), 400

        # Sanitize the report
        sanitized = sanitize_for_feedback(
            code_snippet=data.get('code_snippet', ''),
            context=data.get('context'),
            repo_url=data.get('repo_url'),
            language=data.get('language'),
            consent_level=consent_level,
            rule_id=data.get('rule_id'),
            rule_message=data.get('rule_message', ''),
            severity=data.get('severity', 'WARNING'),
            reason_category=data.get('reason_category'),
            reason_detail=data.get('reason_detail', ''),
            ai_analysis=data.get('ai_analysis', '')
        )

        # Submit to Supabase
        supabase = get_supabase()

        # Use the upsert function for deduplication
        result = supabase.rpc('feedback.upsert_false_positive', {
            'p_rule_id': sanitized['rule_id'],
            'p_rule_message': sanitized['rule_message'],
            'p_severity': sanitized['severity'],
            'p_language': sanitized['language'],
            'p_sanitized_pattern': sanitized['sanitized_pattern'],
            'p_pattern_hash': sanitized['pattern_hash'],
            'p_pattern_structure': sanitized['pattern_structure'],
            'p_surrounding_context': sanitized['surrounding_context'],
            'p_framework_hints': sanitized['framework_hints'],
            'p_reason_category': sanitized['reason_category'],
            'p_reason_detail': sanitized['reason_detail'],
            'p_ai_analysis': sanitized['ai_analysis'],
            'p_consent_level': sanitized['consent_level'],
            'p_anonymized_repo_hash': sanitized['anonymized_repo_hash']
        }).execute()

        report_id = result.data if result.data else 'submitted'

        # Check if this is a known issue
        known_check = supabase.table('feedback.false_positive_reports').select('status, report_count').eq(
            'pattern_hash', sanitized['pattern_hash']
        ).eq('rule_id', sanitized['rule_id']).limit(1).execute()

        known_issue = False
        if known_check.data and len(known_check.data) > 0:
            status = known_check.data[0].get('status')
            if status in ['confirmed', 'fixed', 'reviewing']:
                known_issue = True

        print(f"[Feedback] Received report for rule {sanitized['rule_id']}, pattern_hash={sanitized['pattern_hash'][:8]}...", flush=True)

        return jsonify({
            'status': 'submitted',
            'report_id': str(report_id),
            'pattern_hash': sanitized['pattern_hash'][:8],
            'known_issue': known_issue,
            'message': 'Thank you for helping improve the scanner!'
        })

    except Exception as e:
        import traceback
        print(f"[Feedback] Error: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        return jsonify({'error': 'Failed to submit feedback'}), 500


@app.route('/feedback/bulk-report', methods=['POST'])
def bulk_report_false_positives():
    """
    Submit multiple false positive reports at once.

    POST /feedback/bulk-report
    Body: {
        "consent_level": 1,
        "reports": [
            {
                "rule_id": "...",
                "code_snippet": "...",
                "reason_category": "...",
                "reason_detail": "...",
                ...
            },
            ...
        ]
    }
    """
    try:
        from feedback import sanitize_for_feedback

        data = request.json or {}
        reports = data.get('reports', [])
        consent_level = data.get('consent_level', 1)

        if not reports:
            return jsonify({'error': 'No reports provided'}), 400

        if len(reports) > 50:
            return jsonify({'error': 'Maximum 50 reports per request'}), 400

        submitted = 0
        duplicates = 0
        errors = []

        supabase = get_supabase()

        for i, report in enumerate(reports):
            try:
                # Sanitize each report
                sanitized = sanitize_for_feedback(
                    code_snippet=report.get('code_snippet', ''),
                    context=report.get('context'),
                    repo_url=report.get('repo_url'),
                    language=report.get('language', 'unknown'),
                    consent_level=consent_level,
                    rule_id=report.get('rule_id', 'unknown'),
                    rule_message=report.get('rule_message', ''),
                    severity=report.get('severity', 'WARNING'),
                    reason_category=report.get('reason_category', 'other'),
                    reason_detail=report.get('reason_detail', ''),
                    ai_analysis=report.get('ai_analysis', '')
                )

                # Check if duplicate
                existing = supabase.table('feedback.false_positive_reports').select('id').eq(
                    'pattern_hash', sanitized['pattern_hash']
                ).eq('rule_id', sanitized['rule_id']).limit(1).execute()

                if existing.data and len(existing.data) > 0:
                    # Update count on existing
                    supabase.table('feedback.false_positive_reports').update({
                        'report_count': existing.data[0].get('report_count', 1) + 1
                    }).eq('id', existing.data[0]['id']).execute()
                    duplicates += 1
                else:
                    # Insert new
                    supabase.table('feedback.false_positive_reports').insert({
                        'rule_id': sanitized['rule_id'],
                        'rule_message': sanitized['rule_message'],
                        'severity': sanitized['severity'],
                        'language': sanitized['language'],
                        'sanitized_pattern': sanitized['sanitized_pattern'],
                        'pattern_hash': sanitized['pattern_hash'],
                        'pattern_structure': sanitized['pattern_structure'],
                        'surrounding_context': sanitized['surrounding_context'],
                        'framework_hints': sanitized['framework_hints'],
                        'reason_category': sanitized['reason_category'],
                        'reason_detail': sanitized['reason_detail'],
                        'ai_analysis': sanitized['ai_analysis'],
                        'consent_level': sanitized['consent_level'],
                        'anonymized_repo_hash': sanitized['anonymized_repo_hash']
                    }).execute()
                    submitted += 1

            except Exception as e:
                errors.append({'index': i, 'error': str(e)})

        print(f"[Feedback] Bulk report: {submitted} new, {duplicates} duplicates, {len(errors)} errors", flush=True)

        return jsonify({
            'status': 'complete',
            'submitted': submitted,
            'duplicates': duplicates,
            'errors': len(errors),
            'message': f'Processed {submitted + duplicates} reports. Thank you!'
        })

    except Exception as e:
        import traceback
        print(f"[Feedback] Bulk error: {e}", flush=True)
        return jsonify({'error': 'Failed to process bulk feedback'}), 500


@app.route('/feedback/check-known/<rule_id>', methods=['GET'])
def check_known_false_positives(rule_id):
    """
    Check if a rule has known false positive patterns.

    GET /feedback/check-known/sol-unchecked-call-return

    Returns known patterns and their status (so users don't report duplicates).
    """
    try:
        supabase = get_supabase()

        # Get confirmed/reviewing false positives for this rule
        result = supabase.table('feedback.false_positive_reports').select(
            'pattern_structure, reason_category, status, report_count, framework_hints'
        ).eq('rule_id', rule_id).in_('status', ['confirmed', 'reviewing', 'fixed']).execute()

        patterns = []
        for row in (result.data or []):
            patterns.append({
                'pattern': row.get('pattern_structure'),
                'reason': row.get('reason_category'),
                'status': row.get('status'),
                'reports': row.get('report_count', 1),
                'frameworks': row.get('framework_hints', [])
            })

        # Get summary stats
        total_reports = supabase.table('feedback.false_positive_reports').select(
            'id', count='exact'
        ).eq('rule_id', rule_id).execute()

        return jsonify({
            'rule_id': rule_id,
            'known_patterns': patterns,
            'total_reports': total_reports.count or 0,
            'has_known_issues': len(patterns) > 0
        })

    except Exception as e:
        print(f"[Feedback] Check error: {e}", flush=True)
        return jsonify({
            'rule_id': rule_id,
            'known_patterns': [],
            'total_reports': 0,
            'has_known_issues': False
        })


@app.route('/feedback/stats', methods=['GET'])
def feedback_stats():
    """
    Get public stats about feedback (no sensitive data).

    GET /feedback/stats

    Returns aggregate statistics about false positive reports.
    """
    try:
        supabase = get_supabase()

        # Total reports
        total = supabase.table('feedback.false_positive_reports').select(
            'id', count='exact'
        ).execute()

        # Reports by status
        confirmed = supabase.table('feedback.false_positive_reports').select(
            'id', count='exact'
        ).eq('status', 'confirmed').execute()

        fixed = supabase.table('feedback.false_positive_reports').select(
            'id', count='exact'
        ).eq('status', 'fixed').execute()

        # Top rules with reports
        top_rules = supabase.table('feedback.rule_summary').select(
            'rule_id, total_reports, confirmed_fps'
        ).order('total_reports', desc=True).limit(10).execute()

        return jsonify({
            'total_reports': total.count or 0,
            'confirmed_false_positives': confirmed.count or 0,
            'rules_improved': fixed.count or 0,
            'top_reported_rules': top_rules.data or [],
            'message': 'Thank you to all contributors helping improve the scanner!'
        })

    except Exception as e:
        print(f"[Feedback] Stats error: {e}", flush=True)
        return jsonify({
            'total_reports': 0,
            'confirmed_false_positives': 0,
            'rules_improved': 0,
            'top_reported_rules': [],
            'error': 'Could not fetch stats'
        })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
