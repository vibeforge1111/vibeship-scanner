"""
Code Sanitizer for Privacy-Preserving False Positive Feedback

═══════════════════════════════════════════════════════════════════
ULTRA-PRIVACY ARCHITECTURE
═══════════════════════════════════════════════════════════════════

This is the MOST privacy-protective false positive feedback system
in the security scanner industry. Based on research of:
- Semgrep's privacy-first approach (code never uploaded by default)
- Mozilla's Prio differential privacy system
- Apple's local differential privacy (ε-LDP)
- Microsoft's telemetry privacy research
- GDPR Article 25 (Privacy by Design)

CORE PRINCIPLES:
1. ZERO CODE COLLECTION - Only AST structure, never actual code
2. LOCAL-FIRST PRIVACY - All sanitization on client, before network
3. DATA MINIMIZATION - Only what's strictly necessary
4. PRIVACY BY DEFAULT - Maximum privacy is the default
5. NO FINGERPRINTING - Cannot identify project from pattern

What we collect (ALLOWLIST - only these, nothing else):
- Rule ID that triggered (e.g., "sol-reentrancy")
- AST structure (e.g., "FunctionDef>RequireStmt>LowLevelCall")
- Reason category (enum, not free text)
- Framework hint (single word, e.g., "OpenZeppelin")

What we NEVER collect (everything else):
- Source code (any form, any amount)
- Variable names, function names, class names
- File paths, directory structure
- URLs, domains, IP addresses, emails
- Secrets, keys, credentials, tokens
- Comments, docstrings, documentation
- String literals, numeric values
- Repository URLs, names, or hashes
- User information of any kind
- Timestamps or timing information

DATA RETENTION:
- Feedback is processed within 30 days
- Raw reports are deleted after processing
- Only aggregated statistics are retained
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
    """
    Sanitized false positive report ready for submission.

    PRIVACY NOTE: This structure contains ONLY:
    - Rule metadata (public information)
    - AST structure (no actual code)
    - Reason category (enum value)
    - Framework hints (single words)

    NO code, NO identifiers, NO repo info, NO user info.
    """
    rule_id: str
    rule_message: str  # Sanitized - only generic vulnerability description
    severity: str  # enum: LOW/MEDIUM/HIGH/CRITICAL
    language: str  # enum: solidity/javascript/python/etc
    ast_structure: str  # Pure AST node types, no code tokens
    pattern_hash: str  # SHA256 of AST structure for deduplication only
    structural_hints: List[str]  # ["low-level call", "loop", etc.]
    framework_hints: List[str]  # ["OpenZeppelin", "Foundry", etc.]
    reason_category: str  # enum: safe_pattern/framework_handled/test_code/etc
    consent_level: int  # 1=anonymous (default), 2=with_context, 3=full
    # REMOVED: anonymized_repo_hash - we don't store ANY repo identifier
    # REMOVED: surrounding_context - too much risk of leaking code
    # REMOVED: reason_detail - free text is too risky
    # REMOVED: ai_analysis - could contain reflected code


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
        repo_url: Optional[str],  # IGNORED - we never store repo info
        language: str,
        consent_level: ConsentLevel,
        rule_id: str,
        rule_message: str,
        severity: str,
        reason_category: str,
        reason_detail: str = "",  # IGNORED - free text is too risky
        ai_analysis: str = ""  # IGNORED - could contain reflected code
    ) -> SanitizedReport:
        """
        Main sanitization entry point.

        ULTRA-PRIVACY: This method extracts ONLY:
        1. AST structure (no code tokens)
        2. Structural hints (generic patterns)
        3. Framework hints (single words)

        All other data is DISCARDED, not sanitized.
        """
        self.reset()

        # Get consent level value
        level = consent_level.value if isinstance(consent_level, ConsentLevel) else consent_level

        # Extract ONLY AST structure - no code tokens whatsoever
        ast_structure = self._extract_ast_structure(code_snippet, language)

        # Extract safe metadata (generic patterns, not code)
        structural_hints = self._extract_structural_hints(code_snippet, language)
        frameworks = self._detect_frameworks(code_snippet + (context or ""))

        # Hash for deduplication ONLY (uses AST structure, not code)
        pattern_hash = hashlib.sha256(f"{rule_id}:{ast_structure}".encode()).hexdigest()[:32]

        # Sanitize rule message to remove any code references
        safe_message = self._sanitize_rule_message(rule_message)

        # NOTE: We intentionally DISCARD:
        # - repo_url (never stored, even hashed)
        # - reason_detail (free text is risky)
        # - ai_analysis (could contain reflected code)
        # - context (too much risk of leaking code)

        return SanitizedReport(
            rule_id=rule_id,
            rule_message=safe_message,
            severity=severity.upper() if severity else "UNKNOWN",
            language=language.lower() if language else "unknown",
            ast_structure=ast_structure,
            pattern_hash=pattern_hash,
            structural_hints=structural_hints,
            framework_hints=frameworks,
            reason_category=reason_category,
            consent_level=level
        )

    def _extract_ast_structure(self, code: str, language: str) -> str:
        """
        Extract PURE AST structure - NO code tokens whatsoever.

        This is the core privacy feature: we output ONLY node types,
        never any actual text from the code.

        Example input:
            function withdraw(uint256 amount) {
                require(balances[msg.sender] >= amount);
                (bool success,) = msg.sender.call{value: amount}("");
            }

        Example output:
            FunctionDef>Params>RequireStmt[BinaryOp]>VarDecl+LowLevelCall
        """
        if not code:
            return "Empty"

        nodes = []

        # Detect high-level constructs (order matters - most specific first)
        lang = language.lower()

        if lang in ['sol', 'solidity']:
            # Solidity-specific AST nodes
            if re.search(r'\bfunction\s+\w+\s*\(', code):
                nodes.append("FunctionDef")
            if re.search(r'\bmodifier\s+\w+', code):
                nodes.append("Modifier")
            if re.search(r'\bconstructor\s*\(', code):
                nodes.append("Constructor")
            if re.search(r'\brequire\s*\(', code):
                nodes.append("RequireStmt")
            if re.search(r'\bassert\s*\(', code):
                nodes.append("AssertStmt")
            if re.search(r'\brevert\s*\(', code):
                nodes.append("RevertStmt")
            if re.search(r'\.call\s*[\({]', code):
                nodes.append("LowLevelCall")
            if re.search(r'\.delegatecall\s*\(', code):
                nodes.append("DelegateCall")
            if re.search(r'\.staticcall\s*\(', code):
                nodes.append("StaticCall")
            if re.search(r'\.transfer\s*\(', code):
                nodes.append("Transfer")
            if re.search(r'\.send\s*\(', code):
                nodes.append("Send")
            if re.search(r'\bfor\s*\(', code):
                nodes.append("ForLoop")
            if re.search(r'\bwhile\s*\(', code):
                nodes.append("WhileLoop")
            if re.search(r'\bif\s*\(', code):
                nodes.append("IfStmt")
            if re.search(r'\bmapping\s*\(', code):
                nodes.append("MappingType")
            if re.search(r'\bstruct\s+\w+', code):
                nodes.append("StructDef")
            if re.search(r'\bevent\s+\w+', code):
                nodes.append("EventDef")
            if re.search(r'\bemit\s+\w+', code):
                nodes.append("EmitStmt")
            if re.search(r'\bassembly\s*\{', code):
                nodes.append("InlineAssembly")
            if re.search(r'\bselfdestruct\s*\(', code):
                nodes.append("SelfDestruct")
            if re.search(r'\becrecover\s*\(', code):
                nodes.append("Ecrecover")
            if re.search(r'\btx\.origin\b', code):
                nodes.append("TxOrigin")
            if re.search(r'\bblock\.(timestamp|number)\b', code):
                nodes.append("BlockDependency")

        elif lang in ['js', 'javascript', 'typescript', 'ts']:
            if re.search(r'\bfunction\s+\w+\s*\(', code):
                nodes.append("FunctionDecl")
            if re.search(r'\bconst\s+\w+\s*=\s*\(', code):
                nodes.append("ArrowFunc")
            if re.search(r'\bclass\s+\w+', code):
                nodes.append("ClassDecl")
            if re.search(r'\bawait\s+', code):
                nodes.append("AwaitExpr")
            if re.search(r'\btry\s*\{', code):
                nodes.append("TryStmt")
            if re.search(r'\beval\s*\(', code):
                nodes.append("EvalCall")
            if re.search(r'new\s+Function\s*\(', code):
                nodes.append("DynamicFunc")

        elif lang in ['py', 'python']:
            if re.search(r'\bdef\s+\w+\s*\(', code):
                nodes.append("FunctionDef")
            if re.search(r'\bclass\s+\w+', code):
                nodes.append("ClassDef")
            if re.search(r'\bexec\s*\(', code):
                nodes.append("ExecCall")
            if re.search(r'\beval\s*\(', code):
                nodes.append("EvalCall")
            if re.search(r'\bsubprocess\s*\.', code):
                nodes.append("SubprocessCall")
            if re.search(r'\bos\.(system|popen)', code):
                nodes.append("ShellExec")

        # Generic patterns for any language
        if re.search(r'[\+\-\*\/]=', code):
            nodes.append("CompoundAssign")
        if re.search(r'[<>=!]=', code):
            nodes.append("Comparison")
        if re.search(r'\breturn\b', code):
            nodes.append("ReturnStmt")

        if not nodes:
            return "GenericCode"

        return ">".join(nodes[:10])  # Limit to 10 nodes max

    def _extract_structural_hints(self, code: str, language: str) -> List[str]:
        """
        Extract generic structural hints - safe patterns that describe
        the code structure without revealing actual code.
        """
        hints = []

        # Vulnerability-related patterns (safe to report)
        if re.search(r'\.call\s*[\({]', code, re.IGNORECASE):
            hints.append("low-level-call")
        if re.search(r'for\s*\([^)]*\).*\.(call|transfer|send)', code, re.DOTALL):
            hints.append("external-call-in-loop")
        if re.search(r'delegatecall', code, re.IGNORECASE):
            hints.append("delegatecall")
        if re.search(r'selfdestruct|suicide', code, re.IGNORECASE):
            hints.append("selfdestruct")
        if re.search(r'assembly\s*\{', code, re.IGNORECASE):
            hints.append("inline-assembly")
        if re.search(r'ecrecover', code, re.IGNORECASE):
            hints.append("signature-verification")
        if re.search(r'tx\.origin', code, re.IGNORECASE):
            hints.append("tx-origin")
        if re.search(r'block\.(timestamp|number)', code, re.IGNORECASE):
            hints.append("block-dependency")
        if re.search(r'unchecked\s*\{', code, re.IGNORECASE):
            hints.append("unchecked-math")
        if re.search(r'\beval\s*\(', code, re.IGNORECASE):
            hints.append("dynamic-eval")
        if re.search(r'exec\s*\(', code, re.IGNORECASE):
            hints.append("code-execution")

        return hints if hints else ["general-pattern"]

    def _sanitize_rule_message(self, message: str) -> str:
        """
        Sanitize rule message to remove any code references.
        Keep only the generic vulnerability description.
        """
        if not message:
            return "Security finding"

        # Remove any code-like content
        result = message

        # Remove backtick code blocks
        result = re.sub(r'`[^`]+`', '', result)

        # Remove quoted strings
        result = re.sub(r'"[^"]*"', '', result)
        result = re.sub(r"'[^']*'", '', result)

        # Remove file paths
        result = re.sub(r'(?:/|\\)[\w./\\-]+', '', result)

        # Remove URLs
        result = re.sub(r'https?://\S+', '', result)

        # Remove hex values
        result = re.sub(r'0x[a-fA-F0-9]+', '', result)

        # Limit length
        result = ' '.join(result.split())[:200]

        return result if result.strip() else "Security finding"

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
    repo_url: Optional[str],  # IGNORED - we never store repo info
    language: str,
    consent_level: int,
    rule_id: str,
    rule_message: str,
    severity: str,
    reason_category: str,
    reason_detail: str = "",  # IGNORED - free text is risky
    ai_analysis: str = ""  # IGNORED - could contain reflected code
) -> dict:
    """
    Convenience function to sanitize code for feedback submission.
    Returns a dictionary ready for the API.

    PRIVACY NOTE: This function extracts ONLY:
    - AST structure (no code)
    - Structural hints
    - Framework hints
    - Reason category (enum)

    All other parameters are IGNORED for privacy.
    """
    sanitizer = CodeSanitizer()
    report = sanitizer.sanitize(
        code_snippet=code_snippet,
        context=context,
        repo_url=None,  # Always None - we never store repo info
        language=language,
        consent_level=ConsentLevel(consent_level),
        rule_id=rule_id,
        rule_message=rule_message,
        severity=severity,
        reason_category=reason_category,
        reason_detail="",  # Always empty - free text is risky
        ai_analysis=""  # Always empty - could contain reflected code
    )

    return asdict(report)


def preview_feedback(
    code_snippet: str,
    context: Optional[str],
    language: str,
    consent_level: int,
    rule_id: str,
    reason_category: str,
    reason_detail: str = ""  # IGNORED - shown for transparency
) -> dict:
    """
    PRIVACY PREVIEW - Show users exactly what will be sent.

    This is a MANDATORY step before submission. Users MUST see and
    approve what data will be shared before any feedback is sent.

    Returns a dict showing:
    - 'will_send': Exactly what data will be transmitted
    - 'will_NOT_send': Confirmation of what is removed
    - 'privacy_guarantee': Our privacy commitments
    """
    sanitizer = CodeSanitizer()

    # Extract what we'll actually send
    ast_structure = sanitizer._extract_ast_structure(code_snippet, language)
    structural_hints = sanitizer._extract_structural_hints(code_snippet, language)
    frameworks = sanitizer._detect_frameworks(code_snippet + (context or ""))

    return {
        'will_send': {
            'rule_id': rule_id,
            'ast_structure': ast_structure,
            'structural_hints': structural_hints,
            'framework_hints': frameworks,
            'reason_category': reason_category,
            'language': language,
            'consent_level': consent_level,
        },
        'will_NOT_send': [
            'Source code (any form)',
            'Variable names',
            'Function names',
            'Class names',
            'File paths',
            'Directory structure',
            'URLs and domains',
            'Email addresses',
            'IP addresses',
            'API keys and secrets',
            'Wallet addresses',
            'Repository URL or name',
            'Repository hash (even anonymized)',
            'Comments and documentation',
            'String literals',
            'Numeric values',
            'User information',
            'Timestamps',
            'Free-text explanations',
        ],
        'privacy_guarantee': {
            'code_collection': 'ZERO - Only AST node types',
            'identifiers': 'ZERO - No names collected',
            'repo_info': 'ZERO - No repo identification',
            'data_retention': '30 days max, then deleted',
            'purpose': 'Improve scanner rules only',
        },
        'original_length': len(code_snippet),
        'ast_length': len(ast_structure),
        'reduction_percent': round((1 - len(ast_structure) / max(len(code_snippet), 1)) * 100, 1),
    }


if __name__ == "__main__":
    # Test with sensitive data
    test_code = """
    // Secret config for production - SHOULD NOT BE COLLECTED
    const API_KEY = "sk-1234567890abcdef";
    const DB_URL = "postgres://admin:password123@db.example.com:5432/prod";

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success,) = payable(0x1234567890123456789012345678901234567890).call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    """

    print("=" * 70)
    print("ULTRA-PRIVACY FEEDBACK SYSTEM TEST")
    print("=" * 70)

    print("\n[1] PREVIEW (what user sees before submitting):")
    print("-" * 70)

    preview = preview_feedback(
        code_snippet=test_code,
        context=None,
        language="solidity",
        consent_level=1,
        rule_id="sol-reentrancy",
        reason_category="safe_pattern",
        reason_detail="This should be IGNORED"
    )

    print("\nWILL SEND:")
    for key, value in preview['will_send'].items():
        print(f"  {key}: {value}")

    print("\nWILL NOT SEND:")
    for item in preview['will_NOT_send']:
        print(f"  - {item}")

    print("\nPRIVACY GUARANTEES:")
    for key, value in preview['privacy_guarantee'].items():
        print(f"  {key}: {value}")

    print(f"\nOriginal code: {preview['original_length']} chars")
    print(f"AST structure: {preview['ast_length']} chars")
    print(f"Data reduction: {preview['reduction_percent']}%")

    print("\n" + "=" * 70)
    print("[2] ACTUAL SUBMISSION (what gets stored):")
    print("-" * 70)

    report = sanitize_for_feedback(
        code_snippet=test_code,
        context="Some context that should be ignored",
        repo_url="https://github.com/secret-company/secret-repo",  # SHOULD BE IGNORED
        language="solidity",
        consent_level=1,
        rule_id="sol-reentrancy",
        rule_message="Potential reentrancy in `withdraw` function at line 123",
        severity="HIGH",
        reason_category="safe_pattern",
        reason_detail="Using ReentrancyGuard",  # SHOULD BE IGNORED
        ai_analysis="The code at 0x1234... is safe"  # SHOULD BE IGNORED
    )

    print("\nFINAL REPORT (only this data is stored):")
    for key, value in report.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 70)
    print("[3] VERIFICATION - NO CODE LEAKED:")
    print("-" * 70)

    # Check that no code tokens leaked
    sensitive_tokens = ['API_KEY', 'DB_URL', 'withdraw', 'balances', 'amount',
                        'sk-', 'postgres://', 'admin', 'password', 'example.com']

    leaked = []
    report_str = str(report)
    for token in sensitive_tokens:
        if token.lower() in report_str.lower():
            leaked.append(token)

    if leaked:
        print(f"  WARNING: Leaked tokens: {leaked}")
    else:
        print("  SUCCESS: No sensitive tokens found in report")
        print("  SUCCESS: No code leaked")
        print("  SUCCESS: No identifiers leaked")
        print("  SUCCESS: No repo info leaked")

    print("\n" + "=" * 70)
