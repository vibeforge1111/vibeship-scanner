#!/usr/bin/env python3
"""
Scan Diff Tool - Compare two Vibeship security scan results

Usage:
    python diff_scans.py <before_scan.txt> <after_scan.txt> [--markdown] [--expected <vulns.txt>]

Output:
    - Summary of changes (new findings, lost findings, severity changes)
    - Coverage improvement metrics
    - OWASP API Top 10 coverage
    - CWE coverage analysis
    - Rule-by-rule breakdown
"""

import sys
import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime

# OWASP API Top 10 2023 mapping
OWASP_API_KEYWORDS = {
    'API1': ['BOLA', 'IDOR', 'object level', 'authorization check', 'ownership'],
    'API2': ['authentication', 'JWT', 'token', 'password', 'login', 'session', 'brute force'],
    'API3': ['data exposure', 'excessive data', 'sensitive field', 'PII', 'credit card', 'SSN', 'password in response'],
    'API4': ['rate limit', 'resource consumption', 'DoS', 'pagination', 'limit parameter', 'unbounded'],
    'API5': ['BFLA', 'function level', 'admin', 'role', 'privilege', 'authorization'],
    'API6': ['mass assignment', 'unrestricted access', 'sensitive field assign'],
    'API7': ['misconfiguration', 'debug', 'CORS', 'Redis', 'MongoDB', 'SSL', 'security header'],
    'API8': ['injection', 'SQL', 'command', 'XSS', 'SSRF', 'XXE', 'template'],
    'API9': ['asset management', 'deprecated', 'version', 'v1', 'legacy', 'inventory'],
    'API10': ['logging', 'monitoring', 'audit', 'insufficient logging'],
}

# Known vulnerable repos and their expected vulnerabilities
KNOWN_VULNS = {
    'Checkmarx/capital': {
        'expected': ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10'],
        'description': 'OWASP API Top 10 CTF - should detect all 10 categories',
    },
    'OWASP/crAPI': {
        'expected': ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8'],
        'description': 'Completely Ridiculous API - multiple API vulns',
    },
    'erev0s/VAmPI': {
        'expected': ['API1', 'API2', 'API3', 'API6', 'API8'],
        'description': 'Vulnerable API with SQLi, BOLA, mass assignment',
    },
}

# Paths that are likely test/example code (potential FP)
TEST_PATH_PATTERNS = [
    r'/test[s]?/',
    r'/spec[s]?/',
    r'/__test__/',
    r'/fixture[s]?/',
    r'/mock[s]?/',
    r'/example[s]?/',
    r'/sample[s]?/',
    r'/demo/',
    r'_test\.',
    r'\.test\.',
    r'_spec\.',
    r'\.spec\.',
]


def classify_owasp(message: str) -> list:
    """Classify a finding message into OWASP API Top 10 categories."""
    categories = []
    message_lower = message.lower()
    for api_cat, keywords in OWASP_API_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in message_lower:
                categories.append(api_cat)
                break
    return categories if categories else ['Unknown']


def is_test_path(location: str) -> bool:
    """Check if a finding is in a test/example path (potential FP)."""
    for pattern in TEST_PATH_PATTERNS:
        if re.search(pattern, location, re.IGNORECASE):
            return True
    return False


def extract_cwe(content_block: str) -> str:
    """Extract CWE ID from a finding block."""
    match = re.search(r'CWE[- ]?(\d+)', content_block)
    return f"CWE-{match.group(1)}" if match else None


def get_repo_key(repo_url: str) -> str:
    """Extract owner/repo from GitHub URL."""
    match = re.search(r'github\.com/([^/]+/[^/]+)', repo_url)
    return match.group(1) if match else repo_url


def parse_scan_file(filepath: str) -> dict:
    """Parse a Vibeship scan results file into structured data."""

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    result = {
        'repo': '',
        'repo_key': '',
        'date': '',
        'counts': {},
        'findings': [],
        'findings_by_location': {},  # location -> finding
        'findings_by_rule': defaultdict(list),  # rule message -> [findings]
        'findings_by_owasp': defaultdict(list),  # OWASP category -> [findings]
        'findings_by_cwe': defaultdict(list),  # CWE -> [findings]
        'test_path_findings': [],  # findings in test paths (potential FP)
    }

    # Extract repo
    repo_match = re.search(r'Repository:\s*(.+)', content)
    if repo_match:
        result['repo'] = repo_match.group(1).strip()
        result['repo_key'] = get_repo_key(result['repo'])

    # Extract date
    date_match = re.search(r'Date:\s*(.+)', content)
    if date_match:
        result['date'] = date_match.group(1).strip()

    # Extract counts
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count_match = re.search(rf'{severity}:\s*(\d+)', content)
        if count_match:
            result['counts'][severity] = int(count_match.group(1))

    # Parse individual findings with full block for CWE extraction
    finding_pattern = re.compile(
        r'\[(\d+)\]\s*(.+?)\n-+\n(.*?)(?=\n\[\d+\]|\n={10,}|$)',
        re.DOTALL
    )

    for match in finding_pattern.finditer(content):
        finding_num = int(match.group(1))
        message = match.group(2).strip()
        block = match.group(3)

        # Extract severity
        sev_match = re.search(r'Severity:\s*(\w+)', block)
        severity = sev_match.group(1) if sev_match else 'Unknown'

        # Extract location
        loc_match = re.search(r'Location:\s*([^\n]+)', block)
        location = loc_match.group(1).strip() if loc_match else 'Unknown'

        # Extract CWE
        cwe = extract_cwe(block)

        # Classify OWASP categories
        owasp_cats = classify_owasp(message)

        # Check if test path
        in_test_path = is_test_path(location)

        finding = {
            'num': finding_num,
            'message': message,
            'severity': severity,
            'location': location,
            'cwe': cwe,
            'owasp': owasp_cats,
            'is_test_path': in_test_path,
            'key': f"{location}::{message}",  # Unique key for comparison
        }

        result['findings'].append(finding)
        result['findings_by_location'][location] = finding
        result['findings_by_rule'][message].append(finding)

        # Index by OWASP
        for cat in owasp_cats:
            result['findings_by_owasp'][cat].append(finding)

        # Index by CWE
        if cwe:
            result['findings_by_cwe'][cwe].append(finding)

        # Track test path findings
        if in_test_path:
            result['test_path_findings'].append(finding)

    return result


def diff_scans(before: dict, after: dict) -> dict:
    """Compare two scan results and return differences."""

    before_keys = {f['key'] for f in before['findings']}
    after_keys = {f['key'] for f in after['findings']}

    # Find new and lost findings
    new_keys = after_keys - before_keys
    lost_keys = before_keys - after_keys

    new_findings = [f for f in after['findings'] if f['key'] in new_keys]
    lost_findings = [f for f in before['findings'] if f['key'] in lost_keys]

    # Group by rule message for better readability
    new_by_rule = defaultdict(list)
    for f in new_findings:
        new_by_rule[f['message']].append(f)

    lost_by_rule = defaultdict(list)
    for f in lost_findings:
        lost_by_rule[f['message']].append(f)

    # Count changes by severity
    new_by_severity = defaultdict(int)
    for f in new_findings:
        new_by_severity[f['severity']] += 1

    lost_by_severity = defaultdict(int)
    for f in lost_findings:
        lost_by_severity[f['severity']] += 1

    # Rule coverage comparison
    before_rules = set(before['findings_by_rule'].keys())
    after_rules = set(after['findings_by_rule'].keys())
    new_rules = after_rules - before_rules
    lost_rules = before_rules - after_rules

    # OWASP coverage comparison
    before_owasp = set(before['findings_by_owasp'].keys())
    after_owasp = set(after['findings_by_owasp'].keys())
    new_owasp = after_owasp - before_owasp
    lost_owasp = before_owasp - after_owasp

    # CWE coverage comparison
    before_cwes = set(before['findings_by_cwe'].keys())
    after_cwes = set(after['findings_by_cwe'].keys())
    new_cwes = after_cwes - before_cwes

    # Count test path findings (potential FPs)
    new_in_test_paths = [f for f in new_findings if f.get('is_test_path')]

    return {
        'new_findings': new_findings,
        'lost_findings': lost_findings,
        'new_by_rule': dict(new_by_rule),
        'lost_by_rule': dict(lost_by_rule),
        'new_by_severity': dict(new_by_severity),
        'lost_by_severity': dict(lost_by_severity),
        'new_rules': new_rules,
        'lost_rules': lost_rules,
        'before_total': len(before['findings']),
        'after_total': len(after['findings']),
        'before_counts': before['counts'],
        'after_counts': after['counts'],
        # OWASP coverage
        'before_owasp': before_owasp,
        'after_owasp': after_owasp,
        'new_owasp': new_owasp,
        'lost_owasp': lost_owasp,
        'before_owasp_counts': {k: len(v) for k, v in before['findings_by_owasp'].items()},
        'after_owasp_counts': {k: len(v) for k, v in after['findings_by_owasp'].items()},
        # CWE coverage
        'before_cwes': before_cwes,
        'after_cwes': after_cwes,
        'new_cwes': new_cwes,
        # Test path analysis
        'new_in_test_paths': new_in_test_paths,
        'after_test_path_count': len(after['test_path_findings']),
    }


def print_diff_report(before: dict, after: dict, diff: dict):
    """Print a formatted diff report."""

    print("=" * 70)
    print("VIBESHIP SCAN DIFF REPORT")
    print("=" * 70)
    print()
    print(f"Repository: {after['repo']}")
    print(f"Before: {before['date']}")
    print(f"After:  {after['date']}")
    print()

    # Summary
    print("-" * 70)
    print("SUMMARY")
    print("-" * 70)
    total_change = diff['after_total'] - diff['before_total']
    sign = "+" if total_change >= 0 else ""
    print(f"Total Findings: {diff['before_total']} -> {diff['after_total']} ({sign}{total_change})")
    print()

    # Counts by severity
    print("By Severity:")
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        before_count = diff['before_counts'].get(severity, 0)
        after_count = diff['after_counts'].get(severity, 0)
        change = after_count - before_count
        sign = "+" if change >= 0 else ""
        indicator = "^" if change > 0 else ("v" if change < 0 else "=")
        print(f"  {severity:10} {before_count:4} -> {after_count:4} ({sign}{change}) {indicator}")
    print()

    # New findings
    print("-" * 70)
    print(f"NEW FINDINGS (+{len(diff['new_findings'])})")
    print("-" * 70)

    if diff['new_findings']:
        for rule, findings in sorted(diff['new_by_rule'].items(), key=lambda x: -len(x[1])):
            print(f"\n[+{len(findings)}] {rule}")
            for f in findings[:5]:  # Show max 5 locations per rule
                print(f"      {f['severity']:8} {f['location']}")
            if len(findings) > 5:
                print(f"      ... and {len(findings) - 5} more")
    else:
        print("  (none)")
    print()

    # Lost findings
    print("-" * 70)
    print(f"LOST FINDINGS (-{len(diff['lost_findings'])})")
    print("-" * 70)

    if diff['lost_findings']:
        for rule, findings in sorted(diff['lost_by_rule'].items(), key=lambda x: -len(x[1])):
            print(f"\n[-{len(findings)}] {rule}")
            for f in findings[:5]:
                print(f"      {f['severity']:8} {f['location']}")
            if len(findings) > 5:
                print(f"      ... and {len(findings) - 5} more")
    else:
        print("  (none)")
    print()

    # New rule types detected
    if diff['new_rules']:
        print("-" * 70)
        print(f"NEW RULE TYPES DETECTING ({len(diff['new_rules'])})")
        print("-" * 70)
        for rule in sorted(diff['new_rules']):
            count = len(diff['new_by_rule'].get(rule, []))
            print(f"  [+{count}] {rule[:65]}...")
        print()

    # Lost rule coverage
    if diff['lost_rules']:
        print("-" * 70)
        print(f"LOST RULE COVERAGE ({len(diff['lost_rules'])})")
        print("-" * 70)
        for rule in sorted(diff['lost_rules']):
            print(f"  [-] {rule[:65]}...")
        print()

    # Coverage metrics
    print("-" * 70)
    print("COVERAGE METRICS")
    print("-" * 70)
    before_rule_count = len(set(before['findings_by_rule'].keys()))
    after_rule_count = len(set(after['findings_by_rule'].keys()))
    print(f"Unique rule types firing: {before_rule_count} -> {after_rule_count}")
    print(f"New detections: +{len(diff['new_findings'])}")
    print(f"Lost detections: -{len(diff['lost_findings'])}")
    net = len(diff['new_findings']) - len(diff['lost_findings'])
    print(f"Net change: {'+' if net >= 0 else ''}{net}")
    print()

    # OWASP API Top 10 Coverage
    print("-" * 70)
    print("OWASP API TOP 10 COVERAGE")
    print("-" * 70)
    all_apis = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10']
    api_names = {
        'API1': 'Broken Object Level Authorization',
        'API2': 'Broken Authentication',
        'API3': 'Broken Object Property Level Auth',
        'API4': 'Unrestricted Resource Consumption',
        'API5': 'Broken Function Level Authorization',
        'API6': 'Unrestricted Access to Sensitive Flows',
        'API7': 'Server Side Request Forgery',
        'API8': 'Security Misconfiguration',
        'API9': 'Improper Inventory Management',
        'API10': 'Unsafe Consumption of APIs',
    }

    for api in all_apis:
        before_count = diff['before_owasp_counts'].get(api, 0)
        after_count = diff['after_owasp_counts'].get(api, 0)
        change = after_count - before_count

        if after_count > 0:
            status = "[X]"
        else:
            status = "[ ]"

        change_str = ""
        if change > 0:
            change_str = f" (+{change})"
        elif change < 0:
            change_str = f" ({change})"

        print(f"  {status} {api}: {api_names.get(api, '')} - {after_count} findings{change_str}")

    covered = len([a for a in all_apis if diff['after_owasp_counts'].get(a, 0) > 0])
    print(f"\nCoverage: {covered}/10 OWASP API categories detected")

    # Check against known vulnerable repo expectations
    repo_key = after.get('repo_key', '')
    if repo_key in KNOWN_VULNS:
        print()
        print("-" * 70)
        print(f"EXPECTED VS DETECTED ({repo_key})")
        print("-" * 70)
        expected = set(KNOWN_VULNS[repo_key]['expected'])
        detected = set(a for a in all_apis if diff['after_owasp_counts'].get(a, 0) > 0)

        print(f"Description: {KNOWN_VULNS[repo_key]['description']}")
        print()

        missing = expected - detected
        extra = detected - expected
        matched = expected & detected

        print(f"Expected: {len(expected)} | Detected: {len(detected)} | Matched: {len(matched)}")
        print()

        if matched:
            print("Matched (expected & found):")
            for api in sorted(matched):
                print(f"  [OK] {api}")

        if missing:
            print("\nMISSING (expected but not found):")
            for api in sorted(missing):
                print(f"  [!!] {api} - {api_names.get(api, '')}")

        if extra:
            print("\nExtra (found but not expected):")
            for api in sorted(extra):
                print(f"  [+] {api}")

        coverage_pct = (len(matched) / len(expected)) * 100 if expected else 0
        print(f"\nExpected coverage: {coverage_pct:.0f}%")
    print()

    # CWE Coverage
    if diff['after_cwes']:
        print("-" * 70)
        print(f"CWE COVERAGE ({len(diff['after_cwes'])} unique)")
        print("-" * 70)
        for cwe in sorted(diff['after_cwes']):
            count = len(after['findings_by_cwe'].get(cwe, []))
            new_marker = " [NEW]" if cwe in diff['new_cwes'] else ""
            print(f"  {cwe}: {count} findings{new_marker}")
        print()

    # Test path findings (potential FPs)
    if diff['after_test_path_count'] > 0:
        print("-" * 70)
        print(f"TEST PATH FINDINGS ({diff['after_test_path_count']} potential FPs)")
        print("-" * 70)
        print(f"  Findings in test/example paths: {diff['after_test_path_count']}")
        if diff['new_in_test_paths']:
            print(f"  New findings in test paths: {len(diff['new_in_test_paths'])}")
            for f in diff['new_in_test_paths'][:5]:
                print(f"    - {f['location']}")
        print()

    # Verdict
    print("=" * 70)
    if net > 0 and len(diff['lost_findings']) == 0:
        print("[OK] IMPROVEMENT: More detections, no regressions")
    elif net > 0:
        print("[!!] MIXED: More detections, but some regressions to investigate")
    elif net == 0 and len(diff['new_findings']) == 0:
        print("[--] NO CHANGE: Same findings")
    elif net < 0:
        print("[XX] REGRESSION: Lost more detections than gained")
    else:
        print("[!!] CHANGED: Review the differences above")
    print("=" * 70)


def main():
    if len(sys.argv) != 3:
        print("Usage: python diff_scans.py <before_scan.txt> <after_scan.txt>")
        print()
        print("Compare two Vibeship scan results and show what changed.")
        print()
        print("Example:")
        print("  python diff_scans.py scan_v1.txt scan_v2.txt")
        sys.exit(1)

    before_path = sys.argv[1]
    after_path = sys.argv[2]

    if not Path(before_path).exists():
        print(f"Error: File not found: {before_path}")
        sys.exit(1)

    if not Path(after_path).exists():
        print(f"Error: File not found: {after_path}")
        sys.exit(1)

    print(f"Parsing {before_path}...")
    before = parse_scan_file(before_path)
    print(f"  Found {len(before['findings'])} findings")

    print(f"Parsing {after_path}...")
    after = parse_scan_file(after_path)
    print(f"  Found {len(after['findings'])} findings")
    print()

    diff = diff_scans(before, after)
    print_diff_report(before, after, diff)


if __name__ == '__main__':
    main()
