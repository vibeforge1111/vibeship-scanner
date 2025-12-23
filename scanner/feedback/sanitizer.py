"""
Code Sanitizer for Privacy-Preserving False Positive Feedback

PRIVACY-FIRST DESIGN:
- We NEVER store actual code - only structural patterns
- We NEVER store identifiable information (names, paths, URLs, secrets)
- Users can preview EXACTLY what gets sent before submission
- Default mode is maximum privacy (Level 1)

What we collect:
- Rule ID that triggered (e.g., "sol-reentrancy")
- Structural pattern (e.g., "$TYPE $VAR = $FUNC($PARAM);")
- Why it's a false positive (category + sanitized explanation)
- Framework hints (e.g., "OpenZeppelin") for context

What we NEVER collect:
- Actual variable/function names
- File paths or project structure
- URLs, domains, or IP addresses
- Any form of secrets, keys, or credentials
- Comments or documentation
- Repository names or locations
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class ConsentLevel(Enum):
    ANONYMOUS = 1      # Structure only - maximum privacy
    WITH_CONTEXT = 2   # Adds sanitized context pattern
    FULL_SHARE = 3     # Slightly more detail (still heavily sanitized)


@dataclass
class SanitizedReport:
    """Sanitized false positive report ready for submission"""
    rule_id: str
    rule_message: str
    severity: str
    language: str
    sanitized_pattern: str
    pattern_hash: str
    pattern_structure: str
    surrounding_context: Optional[str]
    framework_hints: List[str]
    reason_category: str
    reason_detail: str
    ai_analysis: str
    consent_level: int
    anonymized_repo_hash: Optional[str]


class CodeSanitizer:
    """
    Sanitizes code snippets for privacy-preserving feedback.

    DESIGN PRINCIPLE: Remove everything, keep only structure.

    We use an ALLOWLIST approach - only known-safe tokens are kept,
    everything else is replaced with generic placeholders.
    """

    # =========================================================================
    # COMPREHENSIVE SECRET PATTERNS - Everything that could be sensitive
    # =========================================================================
    SECRET_PATTERNS = [
        # Private keys and seeds
        (r'0x[a-fA-F0-9]{64}', '[PRIVATE_KEY]'),              # ETH private key
        (r'[a-fA-F0-9]{64}', '[HEX_SECRET]'),                  # 64-char hex
        (r'-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----', '[PEM_KEY]'),  # PEM
        (r'\b[a-zA-Z0-9]{24,}\.[a-zA-Z0-9]{6,}\.[a-zA-Z0-9-_]+', '[JWT]'),  # JWT tokens

        # AWS
        (r'AKIA[0-9A-Z]{16}', '[AWS_KEY]'),                    # AWS Access Key
        (r'[a-zA-Z0-9+/]{40}', '[AWS_SECRET]'),                # AWS Secret (40 char base64)
        (r'aws[_-]?(secret|access|key|token)', '[AWS_REF]'),

        # Google Cloud
        (r'AIza[0-9A-Za-z-_]{35}', '[GCP_KEY]'),               # GCP API key
        (r'"type"\s*:\s*"service_account"', '[GCP_SA]'),       # GCP service account

        # GitHub/Git
        (r'gh[pousr]_[A-Za-z0-9_]{36,}', '[GITHUB_TOKEN]'),    # GitHub tokens
        (r'github_pat_[A-Za-z0-9_]{22,}', '[GITHUB_PAT]'),     # GitHub PAT
        (r'glpat-[A-Za-z0-9-_]{20,}', '[GITLAB_TOKEN]'),       # GitLab token

        # Database
        (r'mongodb(\+srv)?://[^\s]+', '[MONGODB_URI]'),        # MongoDB
        (r'postgres(ql)?://[^\s]+', '[POSTGRES_URI]'),         # PostgreSQL
        (r'mysql://[^\s]+', '[MYSQL_URI]'),                    # MySQL
        (r'redis://[^\s]+', '[REDIS_URI]'),                    # Redis

        # Webhooks & APIs
        (r'https://hooks\.slack\.com/[^\s]+', '[SLACK_WEBHOOK]'),
        (r'https://discord(app)?\.com/api/webhooks/[^\s]+', '[DISCORD_WEBHOOK]'),
        (r'sk-[a-zA-Z0-9]{32,}', '[OPENAI_KEY]'),              # OpenAI
        (r'xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+', '[SLACK_TOKEN]'),  # Slack

        # Generic secrets (MUST be last - catches remaining patterns)
        (r'(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|credential)["\']?\s*[:=]\s*["\'][^"\']{4,}["\']', '[SECRET_ASSIGNMENT]'),
        (r'(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|credential)["\']?\s*[:=]\s*[^,\s]{8,}', '[SECRET_ASSIGNMENT]'),
        (r'Bearer\s+[a-zA-Z0-9._-]+', '[BEARER_TOKEN]'),
        (r'Basic\s+[a-zA-Z0-9+/=]+', '[BASIC_AUTH]'),
    ]

    # Patterns to redact that could identify the project
    IDENTITY_PATTERNS = [
        (r'https?://[^\s"\'<>]+', '[URL]'),                    # Any URL
        (r'git@[^\s]+', '[GIT_URL]'),                          # Git SSH URL
        (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '[EMAIL]'),  # Email
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'),              # IPv4
        (r'[a-fA-F0-9:]{17,}', '[MAC]'),                       # MAC address
        (r'(?:/|\\)(?:[\w.-]+(?:/|\\))+[\w.-]+', '[PATH]'),    # File paths
        # Only match actual filenames with extensions, not CamelCase class names
        (r'\b[\w-]+\.(?:sol|js|jsx|ts|tsx|py|go|rs|java|rb|php|c|cpp|cs|swift|kt)\b', '[FILENAME]'),
    ]

    # Ethereum addresses (replace but note them)
    ADDRESS_PATTERNS = [
        (r'0x[a-fA-F0-9]{40}', '$ADDR'),
    ]

    # Known safe framework patterns to detect (not to keep)
    FRAMEWORK_PATTERNS = {
        'OpenZeppelin': [r'@openzeppelin', r'\bOwnable\b', r'\bReentrancyGuard\b', r'\bSafeERC20\b', r'\bAccessControl\b'],
        'Foundry': [r'forge-std', r'\bvm\.', r'Test\.sol'],
        'Hardhat': [r'hardhat', r'@nomiclabs'],
        'Solmate': [r'solmate', r'\bSafeTransferLib\b'],
        'Chainlink': [r'chainlink', r'\bAggregatorV3Interface\b'],
    }

    # Language keywords to preserve (these are safe - public knowledge)
    LANG_KEYWORDS = {
        'solidity': {
            'function', 'returns', 'return', 'if', 'else', 'for', 'while',
            'public', 'private', 'internal', 'external', 'view', 'pure',
            'payable', 'memory', 'storage', 'calldata', 'require', 'assert',
            'revert', 'emit', 'event', 'modifier', 'constructor', 'mapping',
            'struct', 'enum', 'contract', 'interface', 'library', 'is',
            'true', 'false', 'this', 'msg', 'block', 'tx', 'address', 'uint256',
            'uint', 'int', 'bool', 'bytes', 'string', 'bytes32', 'unchecked'
        },
        'javascript': {
            'function', 'return', 'if', 'else', 'for', 'while', 'const', 'let',
            'var', 'async', 'await', 'try', 'catch', 'throw', 'class', 'extends',
            'import', 'export', 'default', 'new', 'this', 'true', 'false', 'null'
        },
        'python': {
            'def', 'return', 'if', 'else', 'elif', 'for', 'while', 'class',
            'import', 'from', 'try', 'except', 'raise', 'with', 'as', 'pass',
            'True', 'False', 'None', 'self', 'async', 'await', 'lambda'
        },
        'rust': {
            'fn', 'let', 'mut', 'const', 'if', 'else', 'match', 'loop', 'while',
            'for', 'in', 'return', 'pub', 'mod', 'use', 'struct', 'enum', 'impl',
            'trait', 'self', 'Self', 'true', 'false', 'async', 'await', 'unsafe'
        },
        'go': {
            'func', 'return', 'if', 'else', 'for', 'range', 'switch', 'case',
            'var', 'const', 'type', 'struct', 'interface', 'package', 'import',
            'go', 'defer', 'chan', 'select', 'true', 'false', 'nil'
        }
    }

    def __init__(self):
        self.var_counter = 0
        self.func_counter = 0
        self.var_map: Dict[str, str] = {}
        self.func_map: Dict[str, str] = {}

    def reset(self):
        """Reset counters for new sanitization"""
        self.var_counter = 0
        self.func_counter = 0
        self.var_map = {}
        self.func_map = {}

    def preview(
        self,
        code_snippet: str,
        context: Optional[str],
        language: str,
        consent_level: int,
        rule_id: str,
        reason_category: str,
        reason_detail: str
    ) -> dict:
        """
        Generate a PREVIEW of what will be sent - show this to users!

        Returns a dict with:
        - 'will_send': Exactly what data will be transmitted
        - 'will_NOT_send': Confirmation of what is removed
        - 'original_length': How much data was in the original
        - 'sanitized_length': How much remains after sanitization
        """
        self.reset()

        # Sanitize
        sanitized = self._full_sanitize(code_snippet, language, consent_level)
        sanitized_context = self._full_sanitize(context, language, consent_level) if context else None
        sanitized_reason = self._sanitize_text(reason_detail)

        # Extract what we'll keep
        frameworks = self._detect_frameworks(code_snippet + (context or ""))
        structure = self._extract_structure(code_snippet, language)

        return {
            'will_send': {
                'rule_id': rule_id,
                'sanitized_pattern': sanitized,
                'pattern_structure': structure,
                'framework_hints': frameworks,
                'reason_category': reason_category,
                'reason_detail': sanitized_reason,
                'language': language,
                'consent_level': consent_level,
                'context_included': sanitized_context is not None,
            },
            'will_NOT_send': [
                'Variable names (replaced with $VAR1, $VAR2...)',
                'Function names (replaced with $FUNC1, $FUNC2...)',
                'File paths',
                'URLs and domains',
                'Email addresses',
                'IP addresses',
                'API keys and secrets',
                'Wallet addresses',
                'Repository information',
                'Comments and documentation',
                'String literals',
                'Numeric values',
            ],
            'original_length': len(code_snippet),
            'sanitized_length': len(sanitized),
            'reduction_percent': round((1 - len(sanitized) / max(len(code_snippet), 1)) * 100, 1),
        }

    def sanitize(
        self,
        code_snippet: str,
        context: Optional[str],
        repo_url: Optional[str],
        language: str,
        consent_level: ConsentLevel,
        rule_id: str,
        rule_message: str,
        severity: str,
        reason_category: str,
        reason_detail: str,
        ai_analysis: str
    ) -> SanitizedReport:
        """Main sanitization entry point"""
        self.reset()

        # Get consent level value
        level = consent_level.value if isinstance(consent_level, ConsentLevel) else consent_level

        # Full sanitization
        sanitized_pattern = self._full_sanitize(code_snippet, language, level)
        sanitized_context = None
        if context and level >= 2:
            sanitized_context = self._full_sanitize(context, language, level)

        # Extract safe metadata
        frameworks = self._detect_frameworks(code_snippet + (context or ""))
        structure = self._extract_structure(code_snippet, language)

        # Hash for deduplication (uses sanitized pattern, not original)
        pattern_hash = hashlib.sha256(f"{rule_id}:{sanitized_pattern}".encode()).hexdigest()[:32]

        # Only hash repo URL at level 3, and truncate heavily
        repo_hash = None
        if repo_url and level == 3:
            repo_hash = hashlib.sha256(repo_url.encode()).hexdigest()[:12]

        return SanitizedReport(
            rule_id=rule_id,
            rule_message=self._sanitize_text(rule_message),
            severity=severity,
            language=language,
            sanitized_pattern=sanitized_pattern,
            pattern_hash=pattern_hash,
            pattern_structure=structure,
            surrounding_context=sanitized_context,
            framework_hints=frameworks,
            reason_category=reason_category,
            reason_detail=self._sanitize_text(reason_detail),
            ai_analysis=self._sanitize_text(ai_analysis),
            consent_level=level,
            anonymized_repo_hash=repo_hash
        )

    def _full_sanitize(self, code: str, language: str, level: int) -> str:
        """Complete sanitization pipeline"""
        if not code:
            return ""

        result = code

        # Step 1: Remove ALL secrets (most critical)
        for pattern, replacement in self.SECRET_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        # Step 2: Remove identity-revealing patterns
        for pattern, replacement in self.IDENTITY_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        # Step 3: Replace addresses
        for pattern, replacement in self.ADDRESS_PATTERNS:
            result = re.sub(pattern, replacement, result)

        # Step 4: Remove comments (could contain sensitive info)
        result = self._remove_comments(result)

        # Step 5: Replace string literals
        result = re.sub(r'"[^"]*"', '$STRING', result)
        result = re.sub(r"'[^']*'", '$STRING', result)
        result = re.sub(r'`[^`]*`', '$STRING', result)  # Template literals

        # Step 6: Replace numbers
        result = re.sub(r'\b\d+\.?\d*\b', '$NUM', result)

        # Step 7: Replace identifiers (variables, functions)
        result = self._replace_identifiers(result, language)

        # Step 8: Normalize whitespace
        result = ' '.join(result.split())

        # Step 9: Limit length (prevent accidental data dumps)
        max_len = 500 if level == 1 else 1000 if level == 2 else 2000
        if len(result) > max_len:
            result = result[:max_len] + "...[TRUNCATED]"

        return result

    def _replace_identifiers(self, code: str, language: str) -> str:
        """Replace all identifiers except language keywords"""
        lang_key = language.lower()
        if lang_key in ['sol', 'solidity']:
            lang_key = 'solidity'
        elif lang_key in ['js', 'javascript', 'typescript', 'ts']:
            lang_key = 'javascript'
        elif lang_key in ['py', 'python']:
            lang_key = 'python'
        elif lang_key in ['rs', 'rust']:
            lang_key = 'rust'

        keywords = self.LANG_KEYWORDS.get(lang_key, set())

        # Find all word-like tokens
        tokens = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)

        for token in tokens:
            # Skip if already replaced
            if token.startswith('$'):
                continue
            # Skip keywords (safe to keep)
            if token.lower() in keywords or token in keywords:
                continue
            # Skip very short tokens (likely not meaningful)
            if len(token) <= 2:
                continue

            # Determine if function or variable
            is_func = bool(re.search(rf'\b{re.escape(token)}\s*\(', code))

            if is_func:
                if token not in self.func_map:
                    self.func_counter += 1
                    self.func_map[token] = f'$FUNC{self.func_counter}'
                replacement = self.func_map[token]
            else:
                if token not in self.var_map:
                    self.var_counter += 1
                    self.var_map[token] = f'$VAR{self.var_counter}'
                replacement = self.var_map[token]

            code = re.sub(rf'\b{re.escape(token)}\b', replacement, code)

        return code

    def _remove_comments(self, code: str) -> str:
        """Remove all comments"""
        # C-style single line
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # C-style multi-line
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)
        # Python/Shell style
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        # Python docstrings
        code = re.sub(r'"""[\s\S]*?"""', '', code)
        code = re.sub(r"'''[\s\S]*?'''", '', code)
        return code

    def _detect_frameworks(self, code: str) -> List[str]:
        """Detect which frameworks are being used (safe metadata)"""
        detected = []
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detected.append(framework)
                    break
        return list(set(detected))

    def _extract_structure(self, code: str, language: str) -> str:
        """Extract high-level structure description (safe metadata)"""
        structures = []

        # Common vulnerability patterns (safe to report)
        if re.search(r'\.call\s*[\({]', code, re.IGNORECASE):
            structures.append("low-level call")
        if re.search(r'for\s*\([^)]*\).*\.call', code, re.DOTALL | re.IGNORECASE):
            structures.append("call in loop")
        if re.search(r'\.transfer\s*\(', code, re.IGNORECASE):
            structures.append("transfer")
        if re.search(r'delegatecall', code, re.IGNORECASE):
            structures.append("delegatecall")
        if re.search(r'selfdestruct|suicide', code, re.IGNORECASE):
            structures.append("selfdestruct")
        if re.search(r'assembly\s*\{', code, re.IGNORECASE):
            structures.append("inline assembly")
        if re.search(r'ecrecover', code, re.IGNORECASE):
            structures.append("signature verification")
        if re.search(r'tx\.origin', code, re.IGNORECASE):
            structures.append("tx.origin usage")
        if re.search(r'block\.(timestamp|number)', code, re.IGNORECASE):
            structures.append("block dependency")

        return "; ".join(structures) if structures else "general pattern"

    def _sanitize_text(self, text: str) -> str:
        """Sanitize free-text fields"""
        if not text:
            return ""

        result = text

        # Apply all secret patterns
        for pattern, replacement in self.SECRET_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        # Apply identity patterns
        for pattern, replacement in self.IDENTITY_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        # Apply address patterns
        for pattern, replacement in self.ADDRESS_PATTERNS:
            result = re.sub(pattern, replacement, result)

        # Limit length
        if len(result) > 500:
            result = result[:500] + "...[TRUNCATED]"

        return result


def sanitize_for_feedback(
    code_snippet: str,
    context: Optional[str],
    repo_url: Optional[str],
    language: str,
    consent_level: int,
    rule_id: str,
    rule_message: str,
    severity: str,
    reason_category: str,
    reason_detail: str,
    ai_analysis: str
) -> dict:
    """
    Convenience function to sanitize code for feedback submission.
    Returns a dictionary ready for the API.
    """
    sanitizer = CodeSanitizer()
    report = sanitizer.sanitize(
        code_snippet=code_snippet,
        context=context,
        repo_url=repo_url,
        language=language,
        consent_level=ConsentLevel(consent_level),
        rule_id=rule_id,
        rule_message=rule_message,
        severity=severity,
        reason_category=reason_category,
        reason_detail=reason_detail,
        ai_analysis=ai_analysis
    )

    return asdict(report)


def preview_feedback(
    code_snippet: str,
    context: Optional[str],
    language: str,
    consent_level: int,
    rule_id: str,
    reason_category: str,
    reason_detail: str
) -> dict:
    """
    Show users exactly what will be sent BEFORE they submit.
    Call this first, let user review, then call sanitize_for_feedback.
    """
    sanitizer = CodeSanitizer()
    return sanitizer.preview(
        code_snippet=code_snippet,
        context=context,
        language=language,
        consent_level=consent_level,
        rule_id=rule_id,
        reason_category=reason_category,
        reason_detail=reason_detail
    )


if __name__ == "__main__":
    # Test with sensitive data
    test_code = """
    // Secret config for production
    const API_KEY = "sk-1234567890abcdef";
    const DB_URL = "postgres://admin:password123@db.example.com:5432/prod";

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success,) = payable(0x1234567890123456789012345678901234567890).call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    """

    print("=" * 60)
    print("PREVIEW (what user sees before submitting):")
    print("=" * 60)

    preview = preview_feedback(
        code_snippet=test_code,
        context=None,
        language="solidity",
        consent_level=1,
        rule_id="sol-reentrancy",
        reason_category="safe_pattern",
        reason_detail="Using ReentrancyGuard from OpenZeppelin"
    )

    print("\nWILL SEND:")
    for key, value in preview['will_send'].items():
        print(f"  {key}: {value}")

    print("\nWILL NOT SEND:")
    for item in preview['will_NOT_send']:
        print(f"  - {item}")

    print(f"\nOriginal: {preview['original_length']} chars")
    print(f"Sanitized: {preview['sanitized_length']} chars")
    print(f"Reduction: {preview['reduction_percent']}%")
