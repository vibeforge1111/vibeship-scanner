"""
Rule Generator - Auto-generates Semgrep rules for detected gaps

This module analyzes vulnerable code patterns and generates
appropriate Semgrep rules to detect them.
"""

import os
import re
import yaml
from typing import Dict, List, Optional


# Rule templates by vulnerability type
RULE_TEMPLATES = {
    "sql-injection": {
        "javascript": [
            {
                "pattern_type": "pattern-regex",
                "template": '"{query_func}\\\\s*\\\\(\\\\s*`[^`]*\\\\$\\\\{{[^}}]*(req\\\\.|user)"',
                "description": "SQL query with template literal interpolation"
            },
            {
                "pattern_type": "pattern",
                "template": '{query_func}($QUERY + req.$INPUT)',
                "description": "SQL query with string concatenation"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'cursor.execute($SQL % ...)',
                "description": "SQL with string formatting"
            },
            {
                "pattern_type": "pattern",
                "template": 'cursor.execute($SQL.format(...))',
                "description": "SQL with .format()"
            },
            {
                "pattern_type": "pattern",
                "template": 'cursor.execute(f"...")',
                "description": "SQL with f-string"
            }
        ]
    },

    "xss": {
        "javascript": [
            {
                "pattern_type": "pattern",
                "template": 'res.send(`$X${{req.{input_source}.$PARAM}}$Y`)',
                "description": "XSS via res.send with template literal"
            },
            {
                "pattern_type": "pattern",
                "template": '$X.innerHTML = req.{input_source}.$PARAM',
                "description": "XSS via innerHTML assignment"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'return render_template_string($TEMPLATE)',
                "description": "SSTI via render_template_string"
            }
        ]
    },

    "command-injection": {
        "javascript": [
            {
                "pattern_type": "pattern",
                "template": 'exec($CMD + req.$INPUT)',
                "description": "Command injection via exec"
            },
            {
                "pattern_type": "pattern",
                "template": 'exec(`$CMD ${{req.$INPUT}}`)',
                "description": "Command injection via exec template literal"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'os.system($CMD + ...)',
                "description": "Command injection via os.system"
            },
            {
                "pattern_type": "pattern",
                "template": 'subprocess.call($CMD, shell=True)',
                "description": "Command injection via subprocess"
            }
        ]
    },

    "nosql-injection": {
        "javascript": [
            {
                "pattern_type": "pattern-regex",
                "template": '"\\\\$where\\\\s*:"',
                "description": "MongoDB $where operator"
            },
            {
                "pattern_type": "pattern",
                "template": 'collection.find({$FIELD: req.$INPUT})',
                "description": "NoSQL query with user input"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern-regex",
                "template": '"\\\\$where\\\\s*:"',
                "description": "MongoDB $where operator"
            }
        ]
    },

    "path-traversal": {
        "javascript": [
            {
                "pattern_type": "pattern",
                "template": 'fs.readFile(req.$INPUT)',
                "description": "Path traversal via fs.readFile"
            },
            {
                "pattern_type": "pattern",
                "template": 'path.join($BASE, req.$INPUT)',
                "description": "Path traversal via path.join"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'open(request.args.get(...))',
                "description": "Path traversal via open()"
            }
        ]
    },

    "ssrf": {
        "javascript": [
            {
                "pattern_type": "pattern",
                "template": 'fetch(req.body.$URL)',
                "description": "SSRF via fetch"
            },
            {
                "pattern_type": "pattern",
                "template": 'axios.get(req.query.$URL)',
                "description": "SSRF via axios"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'requests.get(request.args.get(...))',
                "description": "SSRF via requests"
            }
        ]
    },

    "bola": {
        "javascript": [
            {
                "pattern_type": "pattern",
                "template": 'Model.findById(req.params.id)',
                "description": "BOLA - direct object access without auth check"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern",
                "template": 'Model.query.get(request.args.get("id"))',
                "description": "BOLA - direct object access without auth check"
            }
        ]
    },

    "secrets": {
        "javascript": [
            {
                "pattern_type": "pattern-regex",
                "template": '"(password|secret|api_key|apikey)\\\\s*[=:]\\\\s*[\\"\\'`][^\\"\\'\\'`]{{8,}}"',
                "description": "Hardcoded secret"
            }
        ],
        "python": [
            {
                "pattern_type": "pattern-regex",
                "template": '"(password|secret|api_key)\\\\s*=\\\\s*[\\"\\'\\'][^\\"\\'\\']+[\\"\\'\\']"',
                "description": "Hardcoded secret"
            }
        ]
    }
}


class RuleGenerator:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir

    def analyze_code_pattern(self, code: str, vuln_type: str, language: str) -> List[Dict]:
        """Analyze code and suggest specific patterns"""
        suggestions = []

        # Language-specific analysis
        if language == "javascript":
            suggestions.extend(self._analyze_js_pattern(code, vuln_type))
        elif language == "python":
            suggestions.extend(self._analyze_python_pattern(code, vuln_type))

        return suggestions

    def _analyze_js_pattern(self, code: str, vuln_type: str) -> List[Dict]:
        """Analyze JavaScript code for patterns"""
        suggestions = []

        # Look for template literals with user input
        if re.search(r'`[^`]*\$\{[^}]*req\.', code):
            suggestions.append({
                "type": "template-literal-injection",
                "pattern_type": "pattern-regex",
                "pattern": r'`[^`]*\$\{[^}]*(req\.|user)',
                "context": "Template literal with user input"
            })

        # Look for string concatenation
        if re.search(r'[\+\s]req\.(body|query|params)', code):
            suggestions.append({
                "type": "string-concat-injection",
                "pattern_type": "pattern",
                "pattern": "$X + req.$INPUT",
                "context": "String concatenation with user input"
            })

        # Look for eval
        if re.search(r'\beval\s*\(', code):
            suggestions.append({
                "type": "eval-injection",
                "pattern_type": "pattern",
                "pattern": "eval(...)",
                "context": "eval() usage detected"
            })

        # Look for exec/spawn
        if re.search(r'\b(exec|spawn)\s*\(', code):
            suggestions.append({
                "type": "command-injection",
                "pattern_type": "pattern",
                "pattern": "exec(...)",
                "context": "Command execution detected"
            })

        return suggestions

    def _analyze_python_pattern(self, code: str, vuln_type: str) -> List[Dict]:
        """Analyze Python code for patterns"""
        suggestions = []

        # Look for f-strings in SQL
        if re.search(r'execute\s*\(\s*f["\']', code):
            suggestions.append({
                "type": "sql-fstring",
                "pattern_type": "pattern",
                "pattern": 'cursor.execute(f"...")',
                "context": "SQL with f-string"
            })

        # Look for .format() in SQL
        if re.search(r'execute\s*\([^)]*\.format\(', code):
            suggestions.append({
                "type": "sql-format",
                "pattern_type": "pattern",
                "pattern": 'cursor.execute($SQL.format(...))',
                "context": "SQL with .format()"
            })

        # Look for % formatting in SQL
        if re.search(r'execute\s*\([^)]*%', code):
            suggestions.append({
                "type": "sql-percent",
                "pattern_type": "pattern",
                "pattern": 'cursor.execute($SQL % ...)',
                "context": "SQL with % formatting"
            })

        # Look for os.system/subprocess
        if re.search(r'(os\.system|subprocess\.(call|run|Popen))', code):
            suggestions.append({
                "type": "command-injection",
                "pattern_type": "pattern",
                "pattern": "os.system(...)",
                "context": "Command execution detected"
            })

        return suggestions

    def generate_rule(self, vuln_id: str, vuln_type: str, language: str,
                     pattern: str, message: str, severity: str = "ERROR") -> Dict:
        """Generate a complete Semgrep rule"""
        languages = {
            "javascript": ["javascript", "typescript"],
            "python": ["python"],
            "php": ["php"],
            "java": ["java"],
            "go": ["go"]
        }

        rule = {
            "id": f"auto-{vuln_id}",
            "message": message,
            "languages": languages.get(language, [language]),
            "severity": severity.upper(),
            "metadata": {
                "tags": ["auto-generated", vuln_type]
            }
        }

        # Determine pattern type
        if pattern.startswith('"') or "\\\\s" in pattern or "\\\\$" in pattern:
            # Regex pattern
            rule["pattern-regex"] = pattern.strip('"')
        else:
            # Semgrep pattern
            rule["pattern"] = pattern

        return rule

    def add_rule_to_file(self, rule: Dict, language: str) -> bool:
        """Add a rule to the appropriate rules file"""
        # Determine target file
        file_map = {
            "javascript": "javascript.yaml",
            "typescript": "javascript.yaml",
            "python": "python.yaml",
            "php": "php.yaml",
            "java": "java.yaml",
            "go": "go.yaml"
        }

        target_file = os.path.join(self.rules_dir, file_map.get(language, "core.yaml"))

        try:
            # Load existing rules
            with open(target_file, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)

            if not content:
                content = {"rules": []}

            if "rules" not in content:
                content["rules"] = []

            # Check if rule already exists
            existing_ids = [r.get("id") for r in content["rules"]]
            if rule["id"] in existing_ids:
                print(f"Rule {rule['id']} already exists, skipping")
                return False

            # Add the new rule
            content["rules"].append(rule)

            # Write back
            with open(target_file, "w", encoding="utf-8") as f:
                yaml.dump(content, f, default_flow_style=False, allow_unicode=True)

            print(f"Added rule {rule['id']} to {target_file}")
            return True

        except Exception as e:
            print(f"Error adding rule to {target_file}: {e}")
            return False

    def generate_rules_for_gaps(self, gaps: List[Dict]) -> List[Dict]:
        """Generate rules for a list of gaps"""
        generated = []

        for gap in gaps:
            vuln_type = gap.get("type", "unknown")
            language = gap.get("language", "javascript")
            vuln_id = gap.get("id", "unknown")
            description = gap.get("description", "Security vulnerability")

            # Get templates for this vuln type
            templates = RULE_TEMPLATES.get(vuln_type, {}).get(language, [])

            for template in templates[:1]:  # Generate one rule per gap for now
                pattern = template["template"]
                message = f"{description} - {template['description']}"

                rule = self.generate_rule(
                    vuln_id=vuln_id,
                    vuln_type=vuln_type,
                    language=language,
                    pattern=pattern,
                    message=message,
                    severity=gap.get("severity", "ERROR")
                )

                generated.append(rule)

        return generated


def main():
    """Test the rule generator"""
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
    generator = RuleGenerator(rules_dir)

    # Test code analysis
    test_code = '''
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.query(query);
    '''

    suggestions = generator.analyze_code_pattern(test_code, "sql-injection", "javascript")
    print("Suggestions:")
    for s in suggestions:
        print(f"  - {s}")

    # Test rule generation
    rule = generator.generate_rule(
        vuln_id="test-sqli",
        vuln_type="sql-injection",
        language="javascript",
        pattern='db.query(`$X${req.$INPUT}$Y`)',
        message="SQL injection via template literal"
    )
    print(f"\nGenerated rule: {rule}")


if __name__ == "__main__":
    main()
