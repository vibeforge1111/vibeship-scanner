#!/usr/bin/env python3
"""
Validate Semgrep/OpenGrep rules to find patterns that may not parse correctly.
Identifies:
1. Patterns that aren't valid in their target language(s)
2. Template-specific syntax (JSX, Svelte, Pug, etc.) that needs pattern-regex
3. Partial expressions that aren't valid AST nodes
"""

import yaml
import os
import re
from pathlib import Path

RULES_DIR = Path(__file__).parent / 'rules'

# Patterns that are likely to fail as AST patterns
PROBLEMATIC_PATTERNS = [
    # Template/JSX-specific syntax
    (r'^\s*\{@html', 'Svelte @html directive - needs pattern-regex'),
    (r'^\s*href=\{', 'JSX attribute with curly braces - needs pattern-regex'),
    (r'^\s*v-html=', 'Vue directive - needs pattern-regex'),
    (r'^\s*!\{', 'Pug unescaped interpolation - needs pattern-regex'),
    (r'^\s*!=\s+\$', 'Pug unescaped operator - needs pattern-regex'),

    # Partial expressions that aren't valid
    (r'^:\s*any\b', 'TypeScript type annotation fragment'),
    (r'^\s*as\s+any\b', 'TypeScript type assertion fragment'),
    (r'^".write":', 'JSON fragment'),

    # Special characters that might fail
    (r'DEBUG\s*=\s*\*', 'Wildcard in non-regex pattern'),
]

def check_pattern_issues(pattern, lang):
    """Check a pattern for potential issues"""
    issues = []

    for regex, description in PROBLEMATIC_PATTERNS:
        if re.search(regex, pattern):
            issues.append(description)

    return issues

def validate_rule_file(filepath):
    """Validate all rules in a file"""
    errors = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
    except Exception as e:
        return [f"YAML parse error: {e}"]

    if not content or 'rules' not in content:
        return []

    for rule in content.get('rules', []):
        rule_id = rule.get('id', 'unknown')
        languages = rule.get('languages', [])

        # Get all patterns from the rule
        patterns = []

        if 'pattern' in rule:
            patterns.append(rule['pattern'])

        if 'patterns' in rule:
            for p in rule.get('patterns', []):
                if isinstance(p, str):
                    patterns.append(p)
                elif isinstance(p, dict):
                    for key in ['pattern', 'pattern-inside', 'pattern-not', 'pattern-not-inside']:
                        if key in p:
                            val = p[key]
                            if isinstance(val, str):
                                patterns.append(val)

        if 'pattern-either' in rule:
            for p in rule.get('pattern-either', []):
                if isinstance(p, dict) and 'pattern' in p:
                    patterns.append(p['pattern'])
                elif isinstance(p, str):
                    patterns.append(p)

        # Check each pattern for issues
        for pattern in patterns:
            if not isinstance(pattern, str):
                continue

            for lang in languages:
                issues = check_pattern_issues(pattern, lang)
                for issue in issues:
                    errors.append(f"{rule_id}: {issue} - pattern: {pattern[:60]}...")

    return errors

def main():
    """Validate all rule files"""
    total_errors = 0

    for rule_file in RULES_DIR.glob('**/*.yaml'):
        rel_path = rule_file.relative_to(RULES_DIR)
        errors = validate_rule_file(rule_file)

        if errors:
            print(f"\n{rel_path}:")
            for err in errors:
                print(f"  - {err}")
            total_errors += len(errors)

    print(f"\n\nTotal potential issues: {total_errors}")

    # Also count rules
    total_rules = 0
    for rule_file in RULES_DIR.glob('**/*.yaml'):
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
            if content and 'rules' in content:
                total_rules += len(content['rules'])
        except:
            pass

    print(f"Total rules: {total_rules}")

if __name__ == '__main__':
    main()
