#!/usr/bin/env python3
"""
Auto-Improve Loop - Runs until scanner achieves target coverage

This script:
1. Scans all benchmark repos
2. Measures coverage against known vulnerabilities
3. For gaps, fetches vulnerable code and generates new rules
4. Adds rules to the appropriate yaml files
5. Re-scans to verify improvement
6. Loops until target coverage is met
7. Outputs a final report

Run with: python auto_improve.py
Or deploy as a Fly.io machine for full automation.
"""

import os
import sys
import json
import time
import re
import yaml
import subprocess
import urllib.request
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan import (
    clone_repo, detect_stack, run_opengrep, run_trivy, run_gitleaks,
    deduplicate_findings, calculate_score
)

# Import from same directory
from known_vulns import KNOWN_VULNERABILITIES, get_repo_vulns, get_all_repos


class AutoImprover:
    def __init__(
        self,
        target_coverage: float = 0.95,
        max_iterations: int = 5,
        webhook_url: str = None
    ):
        self.target_coverage = target_coverage
        self.max_iterations = max_iterations
        self.webhook_url = webhook_url or os.environ.get('BENCHMARK_WEBHOOK')

        self.rules_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "rules"
        )
        self.results_dir = os.path.join(os.path.dirname(__file__), "results")
        os.makedirs(self.results_dir, exist_ok=True)

        self.iteration = 0
        self.history = []

    def log(self, msg: str):
        """Print with timestamp"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {msg}")

    def scan_repo(self, repo_name: str) -> Dict:
        """Scan a single repo"""
        import tempfile
        repo_url = f"https://github.com/{repo_name}"

        self.log(f"  Scanning {repo_name}...")

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                clone_path = os.path.join(temp_dir, "repo")

                if not clone_repo(repo_url, clone_path):
                    return {"findings": [], "error": "Clone failed"}

                stack = detect_stack(clone_path)
                languages = stack.get('languages', [])

                opengrep = run_opengrep(clone_path, languages)
                trivy = run_trivy(clone_path)
                gitleaks = run_gitleaks(clone_path)

                all_findings = deduplicate_findings(opengrep + trivy + gitleaks)

                return {
                    "findings": all_findings,
                    "count": len(all_findings),
                    "stack": stack
                }

        except Exception as e:
            self.log(f"  Error: {e}")
            return {"findings": [], "error": str(e)}

    def match_finding(self, finding: Dict, vuln: Dict) -> bool:
        """Check if finding matches known vulnerability"""
        pattern = vuln.get("pattern", "")
        if not pattern:
            return False

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except:
            return False

        # Check various fields
        fields_to_check = [
            str(finding.get("message", "")),
            str(finding.get("location", "")),
            str(finding.get("rule_id", "")),
            str(finding.get("id", ""))
        ]

        for field in fields_to_check:
            if regex.search(field):
                return True
        return False

    def calculate_coverage(self, repo_name: str, findings: List[Dict]) -> Tuple[float, List, List]:
        """Calculate what % of known vulns were detected"""
        repo_data = get_repo_vulns(repo_name)
        if not repo_data:
            return 1.0, [], []

        vulns = repo_data.get("vulns", [])
        if not vulns:
            return 1.0, [], []

        detected = []
        missed = []

        for vuln in vulns:
            found = any(self.match_finding(f, vuln) for f in findings)
            if found:
                detected.append(vuln)
            else:
                missed.append(vuln)

        coverage = len(detected) / len(vulns)
        return coverage, detected, missed

    def fetch_vuln_code(self, repo_name: str, file_path: str) -> Optional[str]:
        """Fetch vulnerable code from GitHub"""
        if not file_path:
            return None

        for branch in ['main', 'master']:
            try:
                url = f"https://raw.githubusercontent.com/{repo_name}/{branch}/{file_path}"
                with urllib.request.urlopen(url, timeout=10) as resp:
                    return resp.read().decode('utf-8')
            except:
                continue
        return None

    def generate_rule(self, vuln: Dict, code: str, language: str) -> Optional[Dict]:
        """Generate a Semgrep rule for a missed vulnerability"""
        vuln_type = vuln.get("type", "unknown")
        vuln_id = vuln.get("id", "unknown").replace("-", "_")
        description = vuln.get("description", "Security vulnerability")

        # Language mapping
        lang_map = {
            "javascript": ["javascript", "typescript"],
            "python": ["python"],
            "php": ["php"],
            "java": ["java"]
        }

        # Generate pattern based on vulnerability type and code analysis
        pattern = self._analyze_and_generate_pattern(vuln_type, code, language)
        if not pattern:
            return None

        rule = {
            "id": f"auto-{vuln_id}",
            "message": f"{description} - auto-generated rule",
            "languages": lang_map.get(language, [language]),
            "severity": "ERROR" if vuln.get("severity") in ["critical", "high"] else "WARNING",
            "metadata": {
                "tags": ["auto-generated", vuln_type]
            }
        }

        # Add pattern (regex or semgrep pattern)
        if pattern.startswith("REGEX:"):
            rule["pattern-regex"] = pattern[6:]
        else:
            rule["pattern"] = pattern

        return rule

    def _analyze_and_generate_pattern(self, vuln_type: str, code: str, language: str) -> Optional[str]:
        """Analyze code and generate detection pattern"""
        if not code:
            return None

        # Common patterns by vulnerability type
        patterns = {
            "sql-injection": {
                "javascript": [
                    (r'`SELECT[^`]*\$\{', 'REGEX:`SELECT[^`]*\\$\\{'),
                    (r'query\s*\(\s*["\']SELECT', 'REGEX:query\\s*\\(\\s*["\']SELECT[^"\']*\\+'),
                ],
                "python": [
                    (r'execute\s*\(\s*f["\']', 'REGEX:execute\\s*\\(\\s*f["\']'),
                    (r'execute\s*\([^)]*%', 'REGEX:execute\\s*\\([^)]*%'),
                ]
            },
            "xss": {
                "javascript": [
                    (r'res\.send\s*\(\s*`', 'REGEX:res\\.send\\s*\\(\\s*`[^`]*\\$\\{'),
                    (r'innerHTML\s*=', 'REGEX:innerHTML\\s*=\\s*[^;]*req\\.'),
                ]
            },
            "command-injection": {
                "javascript": [
                    (r'exec\s*\(', 'REGEX:exec\\s*\\([^)]*req\\.'),
                    (r'spawn\s*\(', 'REGEX:spawn\\s*\\([^)]*req\\.'),
                ],
                "python": [
                    (r'os\.system\s*\(', 'REGEX:os\\.system\\s*\\([^)]*\\+'),
                    (r'subprocess', 'REGEX:subprocess\\.(call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True'),
                ]
            },
            "nosql-injection": {
                "javascript": [
                    (r'\$where', 'REGEX:\\$where\\s*:'),
                    (r'find\s*\(\s*\{[^}]*req\.', 'REGEX:find\\s*\\(\\s*\\{[^}]*req\\.'),
                ]
            }
        }

        type_patterns = patterns.get(vuln_type, {}).get(language, [])

        for check_pattern, gen_pattern in type_patterns:
            if re.search(check_pattern, code, re.IGNORECASE):
                return gen_pattern

        return None

    def add_rule_to_file(self, rule: Dict, language: str) -> bool:
        """Add generated rule to the appropriate yaml file"""
        file_map = {
            "javascript": "javascript.yaml",
            "typescript": "javascript.yaml",
            "python": "python.yaml",
            "php": "php.yaml",
            "java": "java.yaml"
        }

        filename = file_map.get(language, "core.yaml")
        filepath = os.path.join(self.rules_dir, filename)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)

            if not content or 'rules' not in content:
                self.log(f"  Warning: {filename} has unexpected structure")
                return False

            # Check if rule already exists
            existing_ids = [r.get('id') for r in content['rules']]
            if rule['id'] in existing_ids:
                self.log(f"  Rule {rule['id']} already exists")
                return False

            # Add at the end
            content['rules'].append(rule)

            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(content, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

            self.log(f"  Added rule {rule['id']} to {filename}")
            return True

        except Exception as e:
            self.log(f"  Error adding rule: {e}")
            return False

    def run_iteration(self, repos: List[str] = None) -> Dict:
        """Run one iteration of scan + improve"""
        if repos is None:
            repos = get_all_repos()

        self.iteration += 1
        self.log(f"\n{'='*60}")
        self.log(f"ITERATION {self.iteration}")
        self.log(f"{'='*60}")

        results = {
            "iteration": self.iteration,
            "timestamp": datetime.now().isoformat(),
            "repos": {},
            "rules_added": 0,
            "total_detected": 0,
            "total_known": 0
        }

        for repo_name in repos:
            repo_data = get_repo_vulns(repo_name)
            if not repo_data:
                continue

            language = repo_data.get("language", "javascript")

            # Scan
            scan_result = self.scan_repo(repo_name)
            findings = scan_result.get("findings", [])

            # Calculate coverage
            coverage, detected, missed = self.calculate_coverage(repo_name, findings)

            self.log(f"  {repo_name}: {coverage*100:.0f}% coverage ({len(detected)}/{len(detected)+len(missed)})")

            results["repos"][repo_name] = {
                "coverage": coverage,
                "detected": len(detected),
                "missed": len(missed),
                "findings": len(findings)
            }

            results["total_detected"] += len(detected)
            results["total_known"] += len(detected) + len(missed)

            # For missed vulns, try to generate rules
            for vuln in missed:
                file_path = vuln.get("file", "")
                code = self.fetch_vuln_code(repo_name, file_path) if file_path else None

                rule = self.generate_rule(vuln, code, language)
                if rule:
                    if self.add_rule_to_file(rule, language):
                        results["rules_added"] += 1

        # Calculate overall coverage
        if results["total_known"] > 0:
            results["overall_coverage"] = results["total_detected"] / results["total_known"]
        else:
            results["overall_coverage"] = 1.0

        self.history.append(results)
        return results

    def run_until_target(self, repos: List[str] = None) -> Dict:
        """Run iterations until target coverage is met"""
        self.log(f"\n{'#'*60}")
        self.log(f"AUTO-IMPROVE LOOP")
        self.log(f"Target: {self.target_coverage*100:.0f}% coverage")
        self.log(f"Max iterations: {self.max_iterations}")
        self.log(f"{'#'*60}")

        start_time = datetime.now()

        while self.iteration < self.max_iterations:
            result = self.run_iteration(repos)

            coverage = result["overall_coverage"]
            self.log(f"\nOverall coverage: {coverage*100:.1f}%")
            self.log(f"Rules added this iteration: {result['rules_added']}")

            if coverage >= self.target_coverage:
                self.log(f"\n🎉 TARGET ACHIEVED! {coverage*100:.1f}% >= {self.target_coverage*100:.0f}%")
                break

            if result["rules_added"] == 0:
                self.log(f"\n⚠️ No new rules generated. Stopping.")
                break

            self.log(f"\nContinuing to next iteration...")
            time.sleep(2)  # Brief pause between iterations

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Final report
        final_result = {
            "status": "complete",
            "target_coverage": self.target_coverage,
            "final_coverage": self.history[-1]["overall_coverage"] if self.history else 0,
            "target_met": self.history[-1]["overall_coverage"] >= self.target_coverage if self.history else False,
            "iterations": self.iteration,
            "duration_seconds": duration,
            "history": self.history,
            "per_repo": self.history[-1]["repos"] if self.history else {}
        }

        # Save report
        report_file = os.path.join(
            self.results_dir,
            f"auto_improve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_file, 'w') as f:
            json.dump(final_result, f, indent=2)

        self.log(f"\nReport saved to: {report_file}")

        # Send webhook if configured
        if self.webhook_url:
            self._send_webhook(final_result)

        # Print summary
        self.log(f"\n{'='*60}")
        self.log("FINAL SUMMARY")
        self.log(f"{'='*60}")
        self.log(f"Coverage: {final_result['final_coverage']*100:.1f}%")
        self.log(f"Target met: {'Yes ✓' if final_result['target_met'] else 'No ✗'}")
        self.log(f"Iterations: {final_result['iterations']}")
        self.log(f"Duration: {duration:.0f}s")

        return final_result

    def _send_webhook(self, result: Dict):
        """Send result to webhook"""
        try:
            import json
            data = json.dumps(result).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=10)
            self.log("Webhook sent successfully")
        except Exception as e:
            self.log(f"Webhook error: {e}")


def main():
    """Main entry point"""
    target = float(os.environ.get('TARGET_COVERAGE', '0.95'))
    max_iter = int(os.environ.get('MAX_ITERATIONS', '5'))

    improver = AutoImprover(
        target_coverage=target,
        max_iterations=max_iter
    )

    result = improver.run_until_target()

    # Exit with appropriate code
    sys.exit(0 if result.get('target_met') else 1)


if __name__ == "__main__":
    main()
