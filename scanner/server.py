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
from flask import Flask, request, jsonify
from supabase import create_client, Client

from scan import (
    clone_repo, detect_stack, run_opengrep, run_trivy, run_gitleaks,
    calculate_score, calculate_grade, calculate_ship_status, deduplicate_findings
)

app = Flask(__name__)

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

def run_scan(scan_id: str, repo_url: str, branch: str):
    """Run the full scan pipeline"""
    supabase = get_supabase()
    start_time = datetime.now()

    try:
        update_scan(supabase, scan_id, {'status': 'scanning', 'started_at': start_time.isoformat()})
        update_progress(supabase, scan_id, 'init', 'Initializing scan...', 5)

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = os.path.join(temp_dir, 'repo')

            update_progress(supabase, scan_id, 'clone', 'Cloning repository...', 15)
            if not clone_repo(repo_url, repo_dir, branch):
                update_scan(supabase, scan_id, {
                    'status': 'failed',
                    'error_message': 'Failed to clone repository'
                })
                return

            update_progress(supabase, scan_id, 'detect', 'Detecting stack...', 25)
            stack = detect_stack(repo_dir)

            update_progress(supabase, scan_id, 'sast', 'Running code analysis...', 40)
            opengrep_findings = run_opengrep(repo_dir, stack.get('languages', []))

            update_progress(supabase, scan_id, 'deps', 'Checking dependencies...', 60)
            trivy_findings = run_trivy(repo_dir)

            update_progress(supabase, scan_id, 'secrets', 'Scanning for secrets...', 80)
            gitleaks_findings = run_gitleaks(repo_dir)

            all_findings = opengrep_findings + trivy_findings + gitleaks_findings
            all_findings = deduplicate_findings(all_findings)

            update_progress(supabase, scan_id, 'score', 'Calculating score...', 95)
            score = calculate_score(all_findings)
            grade = calculate_grade(score)
            ship_status = calculate_ship_status(score)

            end_time = datetime.now()
            duration_ms = int((end_time - start_time).total_seconds() * 1000)

            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in all_findings:
                sev = f.get('severity', 'info')
                counts[sev] = counts.get(sev, 0) + 1

            update_scan(supabase, scan_id, {
                'status': 'complete',
                'score': score,
                'grade': grade,
                'ship_status': ship_status,
                'findings': all_findings,
                'finding_counts': counts,
                'detected_stack': stack,
                'stack_signature': stack.get('signature', ''),
                'duration_ms': duration_ms,
                'completed_at': end_time.isoformat()
            })

            update_progress(supabase, scan_id, 'complete', 'Scan complete!', 100)

    except Exception as e:
        print(f"Scan error: {e}")
        update_scan(supabase, scan_id, {
            'status': 'failed',
            'error_message': str(e)
        })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

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
            opengrep_findings = run_opengrep(repo_dir, stack.get('languages', []))
            trivy_findings = run_trivy(repo_dir)
            gitleaks_findings = run_gitleaks(repo_dir)

            all_findings = opengrep_findings + trivy_findings + gitleaks_findings
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

    if not scan_id or not repo_url:
        return jsonify({'error': 'Missing scanId or repoUrl'}), 400

    thread = threading.Thread(target=run_scan, args=(scan_id, repo_url, branch))
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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
