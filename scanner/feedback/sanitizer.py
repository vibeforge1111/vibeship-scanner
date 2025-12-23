"""
Code Sanitizer for Privacy-Preserving False Positive Feedback

This module sanitizes code snippets before sending to the feedback system.
It replaces identifiable information with generic tokens while preserving
the structural pattern that caused the false positive.

Privacy Levels:
- Level 1: Most aggressive - only AST-like pattern structure
- Level 2: Moderate - adds surrounding context (still sanitized)
- Level 3: Light - keeps more detail for debugging (user explicitly opts in)
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ConsentLevel(Enum):
    ANONYMOUS = 1      # Pattern structure only
    WITH_CONTEXT = 2   # Adds sanitized context
    FULL_SHARE = 3     # More detail for debugging


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

    The goal is to capture the PATTERN that triggered the false positive
    without capturing actual implementation details, variable names, or
    any potentially sensitive information.
    """

    # Patterns to detect and replace
    SOLIDITY_TYPES = [
        'uint256', 'uint128', 'uint64', 'uint32', 'uint16', 'uint8', 'uint',
        'int256', 'int128', 'int64', 'int32', 'int16', 'int8', 'int',
        'address', 'bool', 'string', 'bytes32', 'bytes', 'bytes4',
        'mapping', 'struct', 'enum', 'contract', 'interface', 'library'
    ]

    # Known safe framework patterns (for framework_hints extraction)
    FRAMEWORK_PATTERNS = {
        'OpenZeppelin': [
            r'@openzeppelin', r'Ownable', r'ReentrancyGuard', r'SafeERC20',
            r'SafeMath', r'AccessControl', r'Pausable', r'ERC20', r'ERC721'
        ],
        'Foundry': [
            r'forge-std', r'vm\.', r'Test\.sol', r'Script\.sol'
        ],
        'Hardhat': [
            r'hardhat', r'@nomiclabs', r'console\.log'
        ],
        'Solmate': [
            r'solmate', r'SafeTransferLib', r'FixedPointMathLib'
        ],
        'OpenZeppelin Upgrades': [
            r'Initializable', r'UUPSUpgradeable', r'TransparentUpgradeableProxy'
        ]
    }

    # Secrets patterns to always redact (even in Level 3)
    SECRET_PATTERNS = [
        r'0x[a-fA-F0-9]{64}',           # Private keys
        r'0x[a-fA-F0-9]{40}',           # Addresses (optionally keep)
        r'["\'][A-Za-z0-9+/]{32,}["\']', # Base64-like strings
        r'(?:password|secret|key|token|api_key|apikey|private)\s*[=:]\s*["\'][^"\']+["\']',
        r'-----BEGIN [A-Z ]+ KEY-----',  # PEM keys
    ]

    def __init__(self):
        self.var_counter = 0
        self.func_counter = 0
        self.type_counter = 0
        self.var_map: Dict[str, str] = {}
        self.func_map: Dict[str, str] = {}

    def reset_counters(self):
        """Reset counters for a new sanitization"""
        self.var_counter = 0
        self.func_counter = 0
        self.type_counter = 0
        self.var_map = {}
        self.func_map = {}

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
        """
        Main entry point for sanitizing code.

        Args:
            code_snippet: The code that triggered the finding
            context: Surrounding code (more lines)
            repo_url: Repository URL (for hashing only)
            language: Programming language
            consent_level: User's privacy preference
            rule_id: The rule that triggered
            rule_message: The rule's message
            severity: ERROR/WARNING/INFO
            reason_category: Why it's a false positive
            reason_detail: Detailed explanation
            ai_analysis: What the AI concluded

        Returns:
            SanitizedReport ready for submission
        """
        self.reset_counters()

        # Always redact secrets first (all levels)
        code_snippet = self._redact_secrets(code_snippet)
        if context:
            context = self._redact_secrets(context)

        # Extract framework hints before sanitization
        framework_hints = self._extract_framework_hints(code_snippet, context or "")

        # Sanitize based on consent level
        if consent_level == ConsentLevel.ANONYMOUS:
            sanitized_pattern = self._sanitize_level_1(code_snippet, language)
            surrounding_context = None
            pattern_structure = self._extract_structure(code_snippet, language)
            anonymized_repo_hash = None

        elif consent_level == ConsentLevel.WITH_CONTEXT:
            sanitized_pattern = self._sanitize_level_1(code_snippet, language)
            surrounding_context = self._sanitize_level_1(context, language) if context else None
            pattern_structure = self._extract_structure(code_snippet, language)
            anonymized_repo_hash = None

        else:  # FULL_SHARE
            sanitized_pattern = self._sanitize_level_3(code_snippet, language)
            surrounding_context = self._sanitize_level_3(context, language) if context else None
            pattern_structure = self._extract_structure(code_snippet, language)
            anonymized_repo_hash = self._hash_repo(repo_url) if repo_url else None

        # Generate pattern hash for deduplication
        pattern_hash = self._generate_pattern_hash(sanitized_pattern, rule_id)

        return SanitizedReport(
            rule_id=rule_id,
            rule_message=rule_message,
            severity=severity,
            language=language,
            sanitized_pattern=sanitized_pattern,
            pattern_hash=pattern_hash,
            pattern_structure=pattern_structure,
            surrounding_context=surrounding_context,
            framework_hints=framework_hints,
            reason_category=reason_category,
            reason_detail=self._sanitize_text(reason_detail),
            ai_analysis=self._sanitize_text(ai_analysis),
            consent_level=consent_level.value,
            anonymized_repo_hash=anonymized_repo_hash
        )

    def _sanitize_level_1(self, code: str, language: str) -> str:
        """
        Most aggressive sanitization - pattern structure only.

        Input:  "uint256 balance = token.balanceOf(address(this));"
        Output: "$TYPE $VAR1 = $VAR2.$FUNC1($FUNC2($KEYWORD));"
        """
        if not code:
            return ""

        sanitized = code

        # Remove comments
        sanitized = self._remove_comments(sanitized, language)

        # Remove string literals (replace with $STRING)
        sanitized = re.sub(r'"[^"]*"', '$STRING', sanitized)
        sanitized = re.sub(r"'[^']*'", '$STRING', sanitized)

        # Replace addresses with $ADDR
        sanitized = re.sub(r'0x[a-fA-F0-9]{40}', '$ADDR', sanitized)

        # Replace numbers with $NUM
        sanitized = re.sub(r'\b\d+\b', '$NUM', sanitized)

        # Replace identifiers (variables, functions) with tokens
        sanitized = self._replace_identifiers(sanitized, language)

        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())

        return sanitized

    def _sanitize_level_3(self, code: str, language: str) -> str:
        """
        Light sanitization - keeps more structure for debugging.
        Still removes secrets and addresses.
        """
        if not code:
            return ""

        sanitized = code

        # Always remove secrets
        sanitized = self._redact_secrets(sanitized)

        # Replace addresses with $ADDR (privacy)
        sanitized = re.sub(r'0x[a-fA-F0-9]{40}', '$ADDR', sanitized)

        # Keep structure but replace long hex strings
        sanitized = re.sub(r'0x[a-fA-F0-9]{64,}', '$HEX', sanitized)

        return sanitized

    def _replace_identifiers(self, code: str, language: str) -> str:
        """Replace variable and function names with generic tokens"""

        # Keep keywords and types as-is for pattern recognition
        keywords = self._get_keywords(language)

        # Find all identifiers (words that aren't keywords or types)
        # This is a simplified approach - a real AST parser would be better
        words = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)

        for word in words:
            if word in keywords or word in self.SOLIDITY_TYPES:
                continue  # Keep keywords
            if word.startswith('$'):
                continue  # Already replaced

            # Check if it looks like a function call (followed by parenthesis)
            if re.search(rf'\b{re.escape(word)}\s*\(', code):
                if word not in self.func_map:
                    self.func_counter += 1
                    self.func_map[word] = f'$FUNC{self.func_counter}'
                replacement = self.func_map[word]
            else:
                if word not in self.var_map:
                    self.var_counter += 1
                    self.var_map[word] = f'$VAR{self.var_counter}'
                replacement = self.var_map[word]

            # Replace all occurrences
            code = re.sub(rf'\b{re.escape(word)}\b', replacement, code)

        return code

    def _get_keywords(self, language: str) -> set:
        """Get language keywords to preserve"""

        if language.lower() in ['solidity', 'sol']:
            return {
                'function', 'returns', 'return', 'if', 'else', 'for', 'while',
                'do', 'break', 'continue', 'public', 'private', 'internal',
                'external', 'view', 'pure', 'payable', 'memory', 'storage',
                'calldata', 'constant', 'immutable', 'virtual', 'override',
                'modifier', 'event', 'emit', 'require', 'assert', 'revert',
                'try', 'catch', 'new', 'delete', 'true', 'false', 'this',
                'super', 'msg', 'block', 'tx', 'abi', 'type', 'assembly',
                'pragma', 'import', 'using', 'is', 'abstract', 'constructor',
                'fallback', 'receive', 'error', 'unchecked', 'indexed',
                'anonymous', 'selfdestruct', 'delegatecall', 'call', 'transfer',
                'send', 'balance', 'keccak256', 'sha256', 'ecrecover'
            }
        elif language.lower() in ['rust', 'rs']:
            return {
                'fn', 'let', 'mut', 'const', 'static', 'if', 'else', 'match',
                'loop', 'while', 'for', 'in', 'break', 'continue', 'return',
                'pub', 'mod', 'use', 'struct', 'enum', 'impl', 'trait', 'type',
                'where', 'async', 'await', 'move', 'ref', 'self', 'Self',
                'super', 'crate', 'unsafe', 'extern', 'dyn', 'true', 'false'
            }
        else:
            return {
                'function', 'return', 'if', 'else', 'for', 'while', 'do',
                'switch', 'case', 'break', 'continue', 'var', 'let', 'const',
                'class', 'extends', 'import', 'export', 'default', 'async',
                'await', 'try', 'catch', 'throw', 'new', 'this', 'true', 'false'
            }

    def _remove_comments(self, code: str, language: str) -> str:
        """Remove comments from code"""
        # Single-line comments
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # Multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Python-style comments
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        return code

    def _redact_secrets(self, code: str) -> str:
        """Redact anything that looks like a secret"""
        for pattern in self.SECRET_PATTERNS:
            code = re.sub(pattern, '[REDACTED]', code, flags=re.IGNORECASE)
        return code

    def _extract_framework_hints(self, code: str, context: str) -> List[str]:
        """Extract framework hints from code patterns"""
        combined = code + " " + context
        hints = []

        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    hints.append(framework)
                    break

        return list(set(hints))

    def _extract_structure(self, code: str, language: str) -> str:
        """
        Extract high-level structure description.

        Examples:
        - "external call in loop"
        - "transfer before state update"
        - "unchecked return value"
        """
        structures = []

        # Detect common patterns
        if re.search(r'for\s*\(.*\).*\.call', code, re.DOTALL):
            structures.append("external call in loop")
        if re.search(r'\.call.*=.*\+', code, re.DOTALL):
            structures.append("state update after call")
        if re.search(r'\.call\s*\{', code):
            structures.append("low-level call")
        if re.search(r'\.transfer\s*\(', code):
            structures.append("transfer call")
        if re.search(r'delegatecall', code):
            structures.append("delegatecall")
        if re.search(r'assembly\s*\{', code):
            structures.append("inline assembly")
        if re.search(r'ecrecover', code):
            structures.append("signature verification")
        if re.search(r'selfdestruct', code):
            structures.append("selfdestruct")

        return "; ".join(structures) if structures else "general pattern"

    def _generate_pattern_hash(self, sanitized_pattern: str, rule_id: str) -> str:
        """Generate hash for deduplication"""
        # Normalize whitespace
        normalized = ' '.join(sanitized_pattern.lower().split())
        # Include rule_id in hash
        to_hash = f"{rule_id}:{normalized}"
        return hashlib.sha256(to_hash.encode()).hexdigest()[:32]

    def _hash_repo(self, repo_url: str) -> str:
        """Hash repo URL for anonymization (truncated for privacy)"""
        return hashlib.sha256(repo_url.encode()).hexdigest()[:16]

    def _sanitize_text(self, text: str) -> str:
        """Sanitize free-text fields (reason, analysis)"""
        if not text:
            return ""

        # Remove potential file paths
        text = re.sub(r'[/\\][\w/\\.-]+\.\w+', '[PATH]', text)
        # Remove URLs
        text = re.sub(r'https?://[^\s]+', '[URL]', text)
        # Remove addresses
        text = re.sub(r'0x[a-fA-F0-9]{40}', '$ADDR', text)

        return text


# Convenience function for direct use
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

    Returns a dictionary ready to be sent to the feedback API.
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

    return {
        'rule_id': report.rule_id,
        'rule_message': report.rule_message,
        'severity': report.severity,
        'language': report.language,
        'sanitized_pattern': report.sanitized_pattern,
        'pattern_hash': report.pattern_hash,
        'pattern_structure': report.pattern_structure,
        'surrounding_context': report.surrounding_context,
        'framework_hints': report.framework_hints,
        'reason_category': report.reason_category,
        'reason_detail': report.reason_detail,
        'ai_analysis': report.ai_analysis,
        'consent_level': report.consent_level,
        'anonymized_repo_hash': report.anonymized_repo_hash
    }


if __name__ == "__main__":
    # Test the sanitizer
    test_code = """
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    """

    sanitizer = CodeSanitizer()

    # Test Level 1
    result = sanitizer.sanitize(
        code_snippet=test_code,
        context=None,
        repo_url="https://github.com/example/repo",
        language="solidity",
        consent_level=ConsentLevel.ANONYMOUS,
        rule_id="sol-unchecked-call-return",
        rule_message="Low-level call return value not checked",
        severity="ERROR",
        reason_category="safe_pattern",
        reason_detail="The success variable is intentionally unused here",
        ai_analysis="This appears to be a false positive because..."
    )

    print("=== Level 1 Sanitization ===")
    print(f"Pattern: {result.sanitized_pattern}")
    print(f"Hash: {result.pattern_hash}")
    print(f"Structure: {result.pattern_structure}")
    print(f"Frameworks: {result.framework_hints}")
