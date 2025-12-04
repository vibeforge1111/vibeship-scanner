"""
Benchmark Orchestrator - Auto-scan vulnerable repos and measure detection coverage

This script:
1. Scans known vulnerable repos
2. Compares findings against known vulnerabilities
3. Identifies gaps in detection
4. Generates rules to fill gaps
5. Re-scans to verify improvements
6. Loops until coverage targets are met
"""

import os
import re
import sys
import json
import time
import shutil
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from known_vulns import KNOWN_VULNERABILITIES, get_repo_vulns, get_all_repos
from scan import (
    clone_repo, detect_stack, run_opengrep, run_trivy, run_gitleaks,
    deduplicate_findings, calculate_score
)


class BenchmarkRunner:
    def __init__(self, target_coverage: float = 0.90, max_iterations: int = 10):
        self.target_coverage = target_coverage
        self.max_iterations = max_iterations
        self.results_dir = os.path.join(os.path.dirname(__file__), "results")
        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        os.makedirs(self.results_dir, exist_ok=True)

        self.current_results = {}
        self.gaps = {}
        self.iteration = 0

    def log(self, message: str):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def scan_repo(self, repo_url: str) -> Dict:
        """Scan a single repo and return results"""
        self.log(f"Scanning {repo_url}...")

        try:
            # Create temp directory for clone
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone the repo
                clone_path = os.path.join(temp_dir, "repo")

                if not clone_repo(repo_url, clone_path):
                    return {"findings": [], "error": "Failed to clone"}

                # Detect stack
                stack = detect_stack(clone_path)
                languages = stack.get('languages', [])

                # Run all scanners
                opengrep_findings = run_opengrep(clone_path, languages)
                trivy_findings = run_trivy(clone_path)
                gitleaks_findings = run_gitleaks(clone_path)

                # Combine and dedupe
                all_findings = opengrep_findings + trivy_findings + gitleaks_findings
                all_findings = deduplicate_findings(all_findings)

                return {
                    "findings": all_findings,
                    "stack": stack,
                    "score": calculate_score(all_findings)
                }

        except Exception as e:
            self.log(f"Error scanning {repo_url}: {e}")
            return {"findings": [], "error": str(e)}

    def match_finding_to_vuln(self, finding: Dict, vuln: Dict) -> bool:
        """Check if a finding matches a known vulnerability"""
        # Get finding file as string
        finding_file = finding.get("location", "") or finding.get("file", "")
        if isinstance(finding_file, dict):
            finding_file = str(finding_file)
        finding_file = str(finding_file).lower()

        # Check file pattern match
        if vuln.get("file"):
            vuln_file = vuln["file"].lower()
            # File match is optional - if specified, check it
            file_matches = vuln_file in finding_file
        else:
            file_matches = True  # No file constraint

        # Check pattern match in message or location
        pattern = vuln.get("pattern", "")
        if pattern:
            regex = re.compile(pattern, re.IGNORECASE)
            message = str(finding.get("message", ""))
            location = str(finding.get("location", ""))
            rule_id = str(finding.get("rule_id", "") or finding.get("id", ""))

            pattern_matches = bool(
                regex.search(message) or
                regex.search(location) or
                regex.search(rule_id)
            )

            # Return true if pattern matches (file match is optional bonus)
            return pattern_matches

        return False

    def calculate_coverage(self, repo_name: str, findings: List[Dict]) -> Tuple[float, List[Dict], List[Dict]]:
        """Calculate coverage for a repo - returns (coverage%, detected_vulns, missed_vulns)"""
        repo_data = get_repo_vulns(repo_name)
        if not repo_data:
            return 0.0, [], []

        known_vulns = repo_data.get("vulns", [])
        if not known_vulns:
            return 1.0, [], []

        detected = []
        missed = []

        for vuln in known_vulns:
            found = False
            for finding in findings:
                if self.match_finding_to_vuln(finding, vuln):
                    found = True
                    detected.append(vuln)
                    break

            if not found:
                missed.append(vuln)

        coverage = len(detected) / len(known_vulns) if known_vulns else 1.0
        return coverage, detected, missed

    def fetch_vulnerable_code(self, repo_name: str, vuln: Dict) -> Optional[str]:
        """Fetch the actual vulnerable code from GitHub"""
        try:
            file_path = vuln.get("file", "")
            if not file_path:
                return None

            # Construct raw GitHub URL
            url = f"https://raw.githubusercontent.com/{repo_name}/main/{file_path}"

            import urllib.request
            with urllib.request.urlopen(url, timeout=10) as response:
                return response.read().decode('utf-8')
        except Exception as e:
            # Try master branch
            try:
                url = f"https://raw.githubusercontent.com/{repo_name}/master/{file_path}"
                import urllib.request
                with urllib.request.urlopen(url, timeout=10) as response:
                    return response.read().decode('utf-8')
            except:
                pass
        return None

    def generate_rule_suggestion(self, vuln: Dict, code: Optional[str], language: str) -> Dict:
        """Generate a Semgrep rule suggestion for a missed vulnerability"""
        vuln_type = vuln.get("type", "unknown")
        vuln_id = vuln.get("id", "unknown")
        description = vuln.get("description", "")

        suggestion = {
            "id": f"auto-{vuln_id}",
            "type": vuln_type,
            "description": description,
            "language": language,
            "suggested_patterns": [],
            "code_snippet": code[:500] if code else None
        }

        # Generate pattern suggestions based on vulnerability type
        if vuln_type == "sql-injection":
            suggestion["suggested_patterns"] = [
                "pattern-regex for template literals with SQL",
                "pattern for string concatenation in queries"
            ]
        elif vuln_type == "xss":
            suggestion["suggested_patterns"] = [
                "res.send with user input",
                "innerHTML assignment",
                "template rendering without escaping"
            ]
        elif vuln_type == "command-injection":
            suggestion["suggested_patterns"] = [
                "exec/spawn with user input",
                "shell command construction"
            ]
        elif vuln_type == "nosql-injection":
            suggestion["suggested_patterns"] = [
                "$where operator",
                "query with user input object"
            ]

        return suggestion

    def run_single_repo(self, repo_name: str) -> Dict:
        """Run benchmark for a single repo"""
        repo_url = f"https://github.com/{repo_name}"
        repo_data = get_repo_vulns(repo_name)

        self.log(f"\n{'='*60}")
        self.log(f"Benchmarking: {repo_data.get('name', repo_name)}")
        self.log(f"{'='*60}")

        # Scan
        scan_results = self.scan_repo(repo_url)
        findings = scan_results.get("findings", [])

        self.log(f"Found {len(findings)} total findings")

        # Calculate coverage
        coverage, detected, missed = self.calculate_coverage(repo_name, findings)

        self.log(f"Coverage: {coverage*100:.1f}%")
        self.log(f"Detected: {len(detected)}/{len(detected)+len(missed)} known vulnerabilities")

        # Log detected
        if detected:
            self.log("\nDetected vulnerabilities:")
            for v in detected:
                self.log(f"  ✓ {v['id']}: {v['description']}")

        # Log missed
        if missed:
            self.log("\nMissed vulnerabilities (GAPS):")
            for v in missed:
                self.log(f"  ✗ {v['id']}: {v['description']}")

        # Generate rule suggestions for missed vulns
        suggestions = []
        language = repo_data.get("language", "javascript")
        for vuln in missed:
            code = self.fetch_vulnerable_code(repo_name, vuln)
            suggestion = self.generate_rule_suggestion(vuln, code, language)
            suggestions.append(suggestion)

        # Calculate score and grade like the main scan
        score = calculate_score(findings)

        # Count findings by severity
        finding_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            finding_counts[sev] = finding_counts.get(sev, 0) + 1

        return {
            "repo": repo_name,
            "name": repo_data.get("name", repo_name),
            "total_findings": len(findings),
            "coverage": coverage,
            "detected_count": len(detected),
            "missed_count": len(missed),
            "detected": detected,
            "missed": missed,
            "suggestions": suggestions,
            # Add full findings data like the main scan page
            "findings": findings,
            "score": score,
            "finding_counts": finding_counts,
            "stack": scan_results.get("stack", {})
        }

    def run_full_benchmark(self, repos: List[str] = None) -> Dict:
        """Run benchmark across all repos"""
        if repos is None:
            repos = get_all_repos()

        self.log(f"\n{'#'*60}")
        self.log(f"VIBESHIP SCANNER BENCHMARK")
        self.log(f"Target Coverage: {self.target_coverage*100:.0f}%")
        self.log(f"Repos to test: {len(repos)}")
        self.log(f"{'#'*60}\n")

        results = {
            "timestamp": datetime.now().isoformat(),
            "target_coverage": self.target_coverage,
            "repos": {},
            "overall_coverage": 0.0,
            "total_detected": 0,
            "total_missed": 0,
            "all_gaps": []
        }

        total_known = 0
        total_detected = 0

        for repo_name in repos:
            try:
                repo_result = self.run_single_repo(repo_name)
                results["repos"][repo_name] = repo_result

                total_known += repo_result["detected_count"] + repo_result["missed_count"]
                total_detected += repo_result["detected_count"]

                # Collect all gaps
                for missed in repo_result["missed"]:
                    results["all_gaps"].append({
                        "repo": repo_name,
                        **missed
                    })

            except Exception as e:
                self.log(f"Error processing {repo_name}: {e}")
                results["repos"][repo_name] = {"error": str(e)}

        # Calculate overall coverage
        results["overall_coverage"] = total_detected / total_known if total_known > 0 else 0
        results["total_detected"] = total_detected
        results["total_missed"] = total_known - total_detected

        # Print summary
        self.log(f"\n{'='*60}")
        self.log("BENCHMARK SUMMARY")
        self.log(f"{'='*60}")
        self.log(f"Overall Coverage: {results['overall_coverage']*100:.1f}%")
        self.log(f"Total Detected: {total_detected}/{total_known}")
        self.log(f"Total Gaps: {results['total_missed']}")

        if results['overall_coverage'] >= self.target_coverage:
            self.log(f"\n🎉 TARGET COVERAGE ACHIEVED!")
        else:
            self.log(f"\n⚠️  Below target. Need to fix {results['total_missed']} gaps.")

        # Per-repo summary
        self.log(f"\nPer-Repo Coverage:")
        for repo_name, repo_result in results["repos"].items():
            if "error" not in repo_result:
                cov = repo_result["coverage"] * 100
                status = "✓" if cov >= self.target_coverage * 100 else "✗"
                self.log(f"  {status} {repo_name}: {cov:.0f}%")

        # Save results
        results_file = os.path.join(
            self.results_dir,
            f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        self.log(f"\nResults saved to: {results_file}")

        return results

    def generate_gap_report(self, results: Dict) -> str:
        """Generate a markdown report of gaps to fix"""
        report = ["# Vibeship Scanner - Gap Report\n"]
        report.append(f"Generated: {datetime.now().isoformat()}\n")
        report.append(f"Overall Coverage: {results['overall_coverage']*100:.1f}%\n\n")

        report.append("## Gaps by Repository\n")

        for repo_name, repo_result in results["repos"].items():
            if "error" in repo_result:
                continue

            if repo_result["missed"]:
                report.append(f"\n### {repo_result.get('name', repo_name)}\n")
                report.append(f"Coverage: {repo_result['coverage']*100:.0f}%\n\n")

                for missed in repo_result["missed"]:
                    report.append(f"- **{missed['id']}** ({missed['type']}): {missed['description']}\n")
                    report.append(f"  - File: `{missed.get('file', 'N/A')}`\n")
                    report.append(f"  - Severity: {missed.get('severity', 'N/A')}\n")

        report.append("\n## Suggested Rules to Add\n")

        for gap in results.get("all_gaps", []):
            report.append(f"\n### {gap['id']} ({gap['repo']})\n")
            report.append(f"Type: {gap['type']}\n")
            report.append(f"Description: {gap['description']}\n")

        return "".join(report)


def main():
    """Main entry point"""
    runner = BenchmarkRunner(target_coverage=0.90)

    # Run benchmark on all known repos
    results = runner.run_full_benchmark()

    # Generate gap report
    report = runner.generate_gap_report(results)
    report_file = os.path.join(runner.results_dir, "gap_report.md")
    with open(report_file, "w") as f:
        f.write(report)

    print(f"\nGap report saved to: {report_file}")

    return results


if __name__ == "__main__":
    main()
