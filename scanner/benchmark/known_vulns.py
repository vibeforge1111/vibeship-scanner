"""
Known Vulnerabilities Database for Benchmark Testing

Each repo has a list of known vulnerabilities that MUST be detected.
Format:
- id: unique identifier
- file: file path pattern (can be partial)
- pattern: regex pattern to match in findings (message or location)
- type: vulnerability category
- severity: expected severity (critical, high, medium, low)
- description: what this vulnerability is
"""

KNOWN_VULNERABILITIES = {
    "juice-shop/juice-shop": {
        "name": "OWASP Juice Shop",
        "language": "javascript",
        "vulns": [
            {
                "id": "sqli-login",
                "file": "routes/login.ts",
                "pattern": r"(sql|injection|template.literal|sequelize)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection in login via template literal"
            },
            {
                "id": "sqli-search",
                "file": "routes/search.ts",
                "pattern": r"(sql|injection)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection in product search"
            },
            {
                "id": "xss-dom",
                "file": "frontend/src",
                "pattern": r"(xss|innerhtml|dangerously)",
                "type": "xss",
                "severity": "high",
                "description": "DOM-based XSS vulnerabilities"
            },
            {
                "id": "nosql-reviews",
                "file": "routes/product",
                "pattern": r"(nosql|\$where|mongodb)",
                "type": "nosql-injection",
                "severity": "high",
                "description": "NoSQL injection in product reviews"
            },
            {
                "id": "jwt-weak",
                "file": "lib/insecurity.ts",
                "pattern": r"(jwt|algorithm|none|weak)",
                "type": "auth",
                "severity": "critical",
                "description": "Weak JWT implementation"
            },
            {
                "id": "hardcoded-secrets",
                "file": "",
                "pattern": r"(secret|hardcoded|credential|api.key)",
                "type": "secrets",
                "severity": "critical",
                "description": "Hardcoded secrets in codebase"
            },
            {
                "id": "path-traversal",
                "file": "routes/fileServer.ts",
                "pattern": r"(path.traversal|\.\.\/|directory)",
                "type": "path-traversal",
                "severity": "high",
                "description": "Path traversal in file serving"
            },
            {
                "id": "xxe",
                "file": "routes/fileUpload.ts",
                "pattern": r"(xxe|xml|entity)",
                "type": "xxe",
                "severity": "high",
                "description": "XML External Entity vulnerability"
            },
            {
                "id": "ssrf",
                "file": "routes/profileImage",
                "pattern": r"(ssrf|url|fetch|request)",
                "type": "ssrf",
                "severity": "high",
                "description": "SSRF in profile image URL"
            },
            {
                "id": "weak-crypto-md5",
                "file": "",
                "pattern": r"(md5|weak.hash|crypto)",
                "type": "crypto",
                "severity": "medium",
                "description": "MD5 used for hashing"
            }
        ]
    },

    "OWASP/NodeGoat": {
        "name": "OWASP NodeGoat",
        "language": "javascript",
        "vulns": [
            {
                "id": "nosql-where",
                "file": "app/data/allocations-dao.js",
                "pattern": r"(\$where|mongodb|nosql)",
                "type": "nosql-injection",
                "severity": "high",
                "description": "MongoDB $where operator injection"
            },
            {
                "id": "eval-injection",
                "file": "app/routes/contributions.js",
                "pattern": r"(eval|code.injection)",
                "type": "code-injection",
                "severity": "critical",
                "description": "eval() with user input"
            },
            {
                "id": "command-injection",
                "file": "Gruntfile.js",
                "pattern": r"(command|exec|injection)",
                "type": "command-injection",
                "severity": "high",
                "description": "Command injection via exec()"
            },
            {
                "id": "session-no-expiry",
                "file": "server.js",
                "pattern": r"(session|maxage|expir)",
                "type": "session",
                "severity": "medium",
                "description": "Session without timeout"
            },
            {
                "id": "open-redirect",
                "file": "app/routes/index.js",
                "pattern": r"(redirect|open.redirect)",
                "type": "redirect",
                "severity": "medium",
                "description": "Open redirect vulnerability"
            },
            {
                "id": "missing-rate-limit",
                "file": "app/routes/index.js",
                "pattern": r"(rate.limit|login|brute)",
                "type": "rate-limiting",
                "severity": "medium",
                "description": "Missing rate limiting on login"
            },
            {
                "id": "log-injection",
                "file": "app/routes/session.js",
                "pattern": r"(log|injection|console)",
                "type": "log-injection",
                "severity": "medium",
                "description": "Log injection via username"
            },
            {
                "id": "hardcoded-secrets",
                "file": "",
                "pattern": r"(secret|hardcoded|credential)",
                "type": "secrets",
                "severity": "critical",
                "description": "Hardcoded secrets"
            },
            {
                "id": "weak-random",
                "file": "app/data/user-dao.js",
                "pattern": r"(math.random|crypto)",
                "type": "crypto",
                "severity": "medium",
                "description": "Math.random() for security"
            }
        ]
    },

    "appsecco/dvna": {
        "name": "Damn Vulnerable NodeJS Application",
        "language": "javascript",
        "vulns": [
            {
                "id": "sqli-login",
                "file": "core/appHandler.js",
                "pattern": r"(sql|injection)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection in login"
            },
            {
                "id": "command-injection",
                "file": "core/appHandler.js",
                "pattern": r"(command|exec|injection)",
                "type": "command-injection",
                "severity": "critical",
                "description": "Command injection"
            },
            {
                "id": "xss-stored",
                "file": "core/appHandler.js",
                "pattern": r"(xss|script)",
                "type": "xss",
                "severity": "high",
                "description": "Stored XSS"
            },
            {
                "id": "path-traversal",
                "file": "core/appHandler.js",
                "pattern": r"(path|traversal|\.\.)",
                "type": "path-traversal",
                "severity": "high",
                "description": "Path traversal"
            },
            {
                "id": "ssrf",
                "file": "core/appHandler.js",
                "pattern": r"(ssrf|url|request)",
                "type": "ssrf",
                "severity": "high",
                "description": "SSRF vulnerability"
            },
            {
                "id": "xxe",
                "file": "core/appHandler.js",
                "pattern": r"(xxe|xml)",
                "type": "xxe",
                "severity": "high",
                "description": "XXE vulnerability"
            },
            {
                "id": "insecure-deserialize",
                "file": "core/appHandler.js",
                "pattern": r"(deserialize|serialize|unserialize)",
                "type": "deserialization",
                "severity": "critical",
                "description": "Insecure deserialization"
            }
        ]
    },

    "erev0s/VAmPI": {
        "name": "Vulnerable API (VAmPI)",
        "language": "python",
        "vulns": [
            {
                "id": "bola-books",
                "file": "api_views/books.py",
                "pattern": r"(bola|idor|authorization)",
                "type": "bola",
                "severity": "high",
                "description": "Broken Object Level Authorization"
            },
            {
                "id": "sqli-users",
                "file": "api_views/users.py",
                "pattern": r"(sql|injection)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection in users endpoint"
            },
            {
                "id": "mass-assignment",
                "file": "api_views/users.py",
                "pattern": r"(mass.assignment|update)",
                "type": "mass-assignment",
                "severity": "medium",
                "description": "Mass assignment vulnerability"
            },
            {
                "id": "excessive-data",
                "file": "api_views/users.py",
                "pattern": r"(debug|excessive|sensitive|expose)",
                "type": "data-exposure",
                "severity": "high",
                "description": "Excessive data exposure"
            },
            {
                "id": "jwt-weak",
                "file": "",
                "pattern": r"(jwt|token|auth)",
                "type": "auth",
                "severity": "high",
                "description": "Weak JWT implementation"
            },
            {
                "id": "no-rate-limit",
                "file": "",
                "pattern": r"(rate.limit)",
                "type": "rate-limiting",
                "severity": "medium",
                "description": "Missing rate limiting"
            },
            {
                "id": "regex-dos",
                "file": "",
                "pattern": r"(redos|regex|denial)",
                "type": "redos",
                "severity": "medium",
                "description": "ReDoS vulnerability"
            }
        ]
    },

    "samoylenko/vulnerable-app-nodejs-express": {
        "name": "Vulnerable Express App",
        "language": "javascript",
        "vulns": [
            {
                "id": "sqli-typeorm",
                "file": "index.js",
                "pattern": r"(sql|injection|typeorm|template)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection via TypeORM"
            },
            {
                "id": "xss-response",
                "file": "index.js",
                "pattern": r"(xss|res\.send|template)",
                "type": "xss",
                "severity": "high",
                "description": "XSS via res.send with user input"
            },
            {
                "id": "hardcoded-password",
                "file": "index.js",
                "pattern": r"(password|hardcoded|secret|credential)",
                "type": "secrets",
                "severity": "critical",
                "description": "Hardcoded database password"
            },
            {
                "id": "missing-helmet",
                "file": "index.js",
                "pattern": r"(helmet|security.header)",
                "type": "headers",
                "severity": "info",
                "description": "Missing security headers"
            }
        ]
    },

    "digininja/DVWA": {
        "name": "Damn Vulnerable Web Application",
        "language": "php",
        "vulns": [
            {
                "id": "sqli-login",
                "file": "vulnerabilities/sqli",
                "pattern": r"(sql|injection)",
                "type": "sql-injection",
                "severity": "critical",
                "description": "SQL injection"
            },
            {
                "id": "xss-reflected",
                "file": "vulnerabilities/xss_r",
                "pattern": r"(xss|script)",
                "type": "xss",
                "severity": "high",
                "description": "Reflected XSS"
            },
            {
                "id": "xss-stored",
                "file": "vulnerabilities/xss_s",
                "pattern": r"(xss|script)",
                "type": "xss",
                "severity": "high",
                "description": "Stored XSS"
            },
            {
                "id": "command-injection",
                "file": "vulnerabilities/exec",
                "pattern": r"(command|exec|shell)",
                "type": "command-injection",
                "severity": "critical",
                "description": "Command injection"
            },
            {
                "id": "file-inclusion",
                "file": "vulnerabilities/fi",
                "pattern": r"(include|file|lfi|rfi)",
                "type": "file-inclusion",
                "severity": "critical",
                "description": "File inclusion"
            },
            {
                "id": "file-upload",
                "file": "vulnerabilities/upload",
                "pattern": r"(upload|file)",
                "type": "file-upload",
                "severity": "high",
                "description": "Unrestricted file upload"
            },
            {
                "id": "csrf",
                "file": "vulnerabilities/csrf",
                "pattern": r"(csrf|token)",
                "type": "csrf",
                "severity": "medium",
                "description": "CSRF vulnerability"
            }
        ]
    },

    "OWASP/crAPI": {
        "name": "OWASP crAPI",
        "language": "python",
        "vulns": [
            {
                "id": "bola",
                "file": "",
                "pattern": r"(bola|idor|authorization)",
                "type": "bola",
                "severity": "high",
                "description": "Broken Object Level Authorization"
            },
            {
                "id": "bfla",
                "file": "",
                "pattern": r"(bfla|function|authorization)",
                "type": "bfla",
                "severity": "high",
                "description": "Broken Function Level Authorization"
            },
            {
                "id": "mass-assignment",
                "file": "",
                "pattern": r"(mass.assignment)",
                "type": "mass-assignment",
                "severity": "medium",
                "description": "Mass assignment"
            },
            {
                "id": "ssrf",
                "file": "",
                "pattern": r"(ssrf|url|request)",
                "type": "ssrf",
                "severity": "high",
                "description": "SSRF vulnerability"
            },
            {
                "id": "injection",
                "file": "",
                "pattern": r"(injection|sql|nosql)",
                "type": "injection",
                "severity": "critical",
                "description": "Injection vulnerabilities"
            },
            {
                "id": "jwt-issues",
                "file": "",
                "pattern": r"(jwt|token)",
                "type": "auth",
                "severity": "high",
                "description": "JWT vulnerabilities"
            }
        ]
    }
}


def get_repo_vulns(repo_name: str) -> dict:
    """Get known vulnerabilities for a repo"""
    return KNOWN_VULNERABILITIES.get(repo_name, {})


def get_all_repos() -> list:
    """Get list of all benchmark repos"""
    return list(KNOWN_VULNERABILITIES.keys())


def get_vuln_count(repo_name: str) -> int:
    """Get total known vulns for a repo"""
    repo = KNOWN_VULNERABILITIES.get(repo_name, {})
    return len(repo.get("vulns", []))
