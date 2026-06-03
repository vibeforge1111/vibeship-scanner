#!/usr/bin/env python3
"""
Vibeship Scanner - Security scanning orchestrator
Runs Semgrep, Trivy, and Gitleaks on a repository
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import hashlib
import re
from urllib.parse import quote, urlparse
from collections import Counter
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

SEVERITY_MAP = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'INFO': 'info',
    'WARNING': 'medium',
    'ERROR': 'high',
}

SCRIPT_DIR = Path(__file__).parent
RULES_DIR = SCRIPT_DIR / 'rules'
GITLEAKS_CONFIG = SCRIPT_DIR / 'gitleaks.toml'

# Map detected languages to rule files
LANGUAGE_RULES = {
    'JavaScript': 'javascript.yaml',
    'TypeScript': 'javascript.yaml',
    'Python': 'python.yaml',
    'PHP': 'php.yaml',
    'Ruby': 'ruby.yaml',
    'Go': 'go.yaml',
    'Java': 'java.yaml',
    'C#': 'csharp.yaml',
    'Kotlin': 'kotlin.yaml',
    'Swift': 'swift.yaml',
    'Rust': 'rust.yaml',
    'Bash': 'bash.yaml',
    'Shell': 'bash.yaml',
    'Solidity': 'solidity.yaml',
    'Dart': 'dart.yaml',
    'YAML': 'yaml-config.yaml',
    'Scala': 'scala.yaml',
    'Groovy': 'groovy.yaml',
    'Perl': 'perl.yaml',
    'CoffeeScript': 'coffeescript.yaml',
    'C': 'c.yaml',
    'C++': 'c.yaml',
}

# Shared rules that apply to ALL scans regardless of language
SHARED_RULES_DIR = RULES_DIR / '_shared'
SHARED_RULES = [
    'secrets.yaml',
    'urls.yaml',
    'comments.yaml',
]

# Rule files that should ALWAYS be loaded regardless of detected languages
# These are small files and missing vulnerabilities is worse than slower scans
ALWAYS_LOAD_RULES = [
    'templates.yaml',   # Pug, EJS, Handlebars, Nunjucks, Mustache, Twig XSS detection
    'yaml-config.yaml', # CI/CD, Kubernetes, Docker secrets and misconfigs
    'ethernaut-gaps.yaml', # Ethernaut wargame gap-closing rules for Solidity
    'defi-advanced.yaml',  # DeFi protocol patterns (flash loans, AMM, lending, oracles)
    'security-hints.yaml', # Security guidance and fuzzing recommendations
    'defi-exploits-tier1.yaml',  # TIER 1: precision, signatures, MEV, access control, logic flaws
    'defivulnlabs-gaps.yaml',    # Gap-closing rules for DeFiVulnLabs coverage
    'defi-exploits-tier2.yaml',  # TIER 2: bridges, storage layout, oracle enhancements
    'part5-gap-closing.yaml',    # Part 5: GCTF-2024, OnlyPwner, Faillapop gap-closing rules
]


def build_github_auth_clone_url(url: str, github_token: str) -> Optional[str]:
    """
    Build a GitHub HTTPS clone URL authenticated with a token.

    Supports common GitHub URL forms:
    - https://github.com/owner/repo(.git)
    - https://www.github.com/owner/repo(.git)
    - git@github.com:owner/repo(.git)
    - ssh://git@github.com/owner/repo(.git)
    """
    if not github_token:
        return None

    repo_path = None
    lowered = url.lower()

    if lowered.startswith('git@github.com:'):
        repo_path = url.split(':', 1)[1]
    else:
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        if host.endswith('github.com'):
            repo_path = parsed.path.lstrip('/')

    if not repo_path:
        return None

    repo_path = repo_path.strip().rstrip('/')
    if not repo_path or repo_path.count('/') < 1:
        return None

    if repo_path.endswith('.git'):
        repo_path = repo_path[:-4]

    safe_token = quote(github_token, safe='')
    return f'https://x-access-token:{safe_token}@github.com/{repo_path}.git'


def clone_repo(url: str, target_dir: str, branch: str = 'main', github_token: str = None) -> bool:
    """Clone a git repository (shallow clone for speed)

    For private GitHub repos, uses token-authenticated HTTPS clone URL:
    https://x-access-token:TOKEN@github.com/owner/repo.git
    """
    try:
        clone_url = url
        print(f"[Clone] Starting clone: url={url}, hasToken={bool(github_token)}", file=sys.stderr, flush=True)

        # If we have a GitHub token, convert any GitHub URL format to authenticated HTTPS.
        if github_token:
            auth_clone_url = build_github_auth_clone_url(url, github_token)
            if auth_clone_url:
                clone_url = auth_clone_url
                print("[Clone] Using token-authenticated GitHub clone URL", file=sys.stderr, flush=True)
            elif 'github.com' in url.lower():
                print("[Clone] GitHub token provided, but URL could not be normalized for token auth", file=sys.stderr, flush=True)

        # For logging, mask the token in the URL
        log_url = clone_url
        if github_token:
            log_url = clone_url.replace(github_token, 'TOKEN_HIDDEN')
        print(f"[Clone] Running: git clone --depth 1 --branch {branch} {log_url}", file=sys.stderr, flush=True)

        git_env = os.environ.copy()
        git_env['GIT_TERMINAL_PROMPT'] = '0'

        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--branch', branch, clone_url, target_dir],
            capture_output=True,
            text=True,
            timeout=120,
            env=git_env
        )
        if result.returncode != 0:
            # Mask token in error output
            stderr = result.stderr
            if github_token:
                stderr = stderr.replace(github_token, 'TOKEN_HIDDEN')
            print(f"[Clone] Branch clone failed (code {result.returncode}): {stderr}", file=sys.stderr, flush=True)

            # Clean up partial clone directory before retry
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
                print(f"[Clone] Cleaned up partial clone directory", file=sys.stderr, flush=True)

            print(f"[Clone] Retrying without branch specification...", file=sys.stderr, flush=True)
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', clone_url, target_dir],
                capture_output=True,
                text=True,
                timeout=120,
                env=git_env
            )
            if result.returncode != 0:
                stderr = result.stderr
                if github_token:
                    stderr = stderr.replace(github_token, 'TOKEN_HIDDEN')
                print(f"[Clone] Default clone also failed (code {result.returncode}): {stderr}", file=sys.stderr, flush=True)

        success = result.returncode == 0
        print(f"[Clone] Result: {'SUCCESS' if success else 'FAILED'}", file=sys.stderr, flush=True)

        # Initialize git submodules (for Foundry/forge-std projects)
        if success:
            try:
                print("[Clone] Initializing git submodules...", file=sys.stderr, flush=True)
                submodule_result = subprocess.run(
                    ['git', 'submodule', 'update', '--init', '--recursive', '--depth', '1'],
                    cwd=target_dir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if submodule_result.returncode == 0:
                    print("[Clone] Submodules initialized successfully", file=sys.stderr, flush=True)
                else:
                    # Non-fatal - many repos don't have submodules
                    print(f"[Clone] Submodule init returned {submodule_result.returncode} (may have no submodules)", file=sys.stderr, flush=True)
            except subprocess.TimeoutExpired:
                print("[Clone] Submodule init timeout (continuing without)", file=sys.stderr, flush=True)
            except Exception as e:
                print(f"[Clone] Submodule init error: {e} (continuing without)", file=sys.stderr, flush=True)

            # Create .semgrepignore to:
            # 1. Include test directories (Opengrep excludes by default, but we want to scan tests)
            # 2. Exclude only DEFINITE dependency directories (node_modules, vendor)
            #
            # IMPORTANT: We do NOT exclude packages/, deps/, external/, lib/ here because
            # they could contain first-party code. lib/ is only excluded for Foundry projects
            # which is handled dynamically in run_opengrep().
            try:
                semgrepignore_path = os.path.join(target_dir, '.semgrepignore')
                with open(semgrepignore_path, 'w') as f:
                    # Include test directories (useful for CTF/vulnerable app scanning)
                    f.write("!test/\n")
                    f.write("!tests/\n")
                    f.write("!src/test/\n")
                    f.write("!src/tests/\n")
                    f.write("!**/test/\n")
                    f.write("!**/tests/\n")
                    f.write("!spec/\n")
                    # Exclude ONLY definite third-party directories (industry standard)
                    f.write("node_modules/\n")
                    f.write("vendor/\n")
                    f.write(".yarn/\n")
                    # Note: lib/ excluded dynamically only for Foundry projects
                print("[Clone] Created .semgrepignore to include tests, exclude vendor/node_modules", file=sys.stderr, flush=True)
            except Exception as e:
                print(f"[Clone] Warning: Could not create .semgrepignore: {e}", file=sys.stderr, flush=True)

        return success
    except subprocess.TimeoutExpired:
        print("Clone timeout", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Clone error: {e}", file=sys.stderr)
        return False


def detect_stack(repo_dir: str) -> Dict[str, Any]:
    """Detect the tech stack from repository files"""
    languages = set()
    frameworks = set()

    try:
        files = os.listdir(repo_dir)
    except:
        files = []

    # Walk through repo to detect languages by file extensions
    lang_extensions = {
        '.js': 'JavaScript',
        '.jsx': 'JavaScript',
        '.mjs': 'JavaScript',
        '.cjs': 'JavaScript',
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript',
        '.mts': 'TypeScript',
        '.cts': 'TypeScript',
        '.py': 'Python',
        '.pyw': 'Python',
        '.php': 'PHP',
        '.phtml': 'PHP',
        '.rb': 'Ruby',
        '.erb': 'Ruby',
        '.go': 'Go',
        '.java': 'Java',
        '.jsp': 'Java',   # Java Server Pages - high XSS risk
        '.jspx': 'Java',
        '.kt': 'Kotlin',
        '.kts': 'Kotlin',
        '.swift': 'Swift',
        '.rs': 'Rust',
        '.cs': 'C#',
        '.sh': 'Bash',
        '.bash': 'Bash',
        '.zsh': 'Bash',
        '.sol': 'Solidity',
        '.dart': 'Dart',
        # C/C++
        '.c': 'C',
        '.h': 'C',
        '.cpp': 'C++',
        '.cc': 'C++',
        '.cxx': 'C++',
        '.hpp': 'C++',
        '.hxx': 'C++',
        '.hh': 'C++',
        # JVM languages
        '.scala': 'Scala',
        '.sc': 'Scala',
        '.groovy': 'Groovy',
        '.gvy': 'Groovy',
        '.gradle': 'Groovy',
        # Scripting
        '.pl': 'Perl',
        '.pm': 'Perl',
        '.coffee': 'CoffeeScript',
    }

    # Special filenames that indicate languages (no extension needed)
    special_files = {
        'Dockerfile': 'Bash',           # Dockerfiles contain shell commands
        'Containerfile': 'Bash',        # Podman containerfiles
        'Makefile': 'Bash',             # Makefiles contain shell commands
        'GNUmakefile': 'Bash',
        'Jenkinsfile': 'Java',          # Groovy-based, use Java rules
        'Vagrantfile': 'Ruby',          # Ruby-based
        '.gitlab-ci.yml': 'YAML',
        '.travis.yml': 'YAML',
        'azure-pipelines.yml': 'YAML',
        'bitbucket-pipelines.yml': 'YAML',
        'cloudbuild.yaml': 'YAML',
        'appveyor.yml': 'YAML',
        '.circleci/config.yml': 'YAML',
    }

    # Shebang patterns to detect language from file content
    shebang_patterns = {
        'python': 'Python',
        'python3': 'Python',
        'node': 'JavaScript',
        'bash': 'Bash',
        'sh': 'Bash',
        'zsh': 'Bash',
        'ruby': 'Ruby',
        'perl': 'Bash',  # Use bash rules as fallback
        'php': 'PHP',
    }

    try:
        for root, dirs, filenames in os.walk(repo_dir):
            # Get relative path for pattern matching
            rel_root = os.path.relpath(root, repo_dir)

            # Skip hidden directories and dependency folders
            # IMPORTANT: Only exclude directories that are ALWAYS third-party.
            # We do NOT exclude packages/, deps/, external/, lib/ here as they could be first-party.
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                      ['node_modules', 'vendor', 'venv', '__pycache__', 'target', 'build', 'dist',
                       'third_party', 'out', 'discord-export']]

            for filename in filenames:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()

                # Check extension-based detection
                if ext in lang_extensions:
                    languages.add(lang_extensions[ext])

                # Check special filenames
                if filename in special_files:
                    languages.add(special_files[filename])

                # Check for docker-compose files
                if filename.startswith('docker-compose') and ext in ['.yml', '.yaml']:
                    languages.add('YAML')

                # Check for CI config files
                if filename in ['.gitlab-ci.yml', '.travis.yml', 'azure-pipelines.yml', 'bitbucket-pipelines.yml']:
                    languages.add('YAML')

                # Check for Terraform/IaC
                if ext == '.tf' or ext == '.tfvars':
                    languages.add('YAML')  # Use YAML rules for config scanning

                # Check for extensionless files with shebangs (limit to avoid reading large files)
                if not ext and filename not in ['LICENSE', 'README', 'CHANGELOG', 'AUTHORS', 'CONTRIBUTORS']:
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            first_line = f.readline(256)  # Read first 256 chars max
                            if first_line.startswith('#!'):
                                for pattern, lang in shebang_patterns.items():
                                    if pattern in first_line.lower():
                                        languages.add(lang)
                                        break
                    except:
                        pass
    except:
        pass

    # Check for GitHub Actions specifically (since .github is hidden)
    github_workflows = os.path.join(repo_dir, '.github', 'workflows')
    if os.path.isdir(github_workflows):
        languages.add('YAML')

    # Detect from package files (more reliable)
    if 'package.json' in files:
        languages.add('JavaScript')
        try:
            with open(os.path.join(repo_dir, 'package.json')) as f:
                pkg = json.load(f)
                deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
                if 'typescript' in deps:
                    languages.add('TypeScript')
                if 'next' in deps:
                    frameworks.add('Next.js')
                if 'svelte' in deps or '@sveltejs/kit' in deps:
                    frameworks.add('SvelteKit')
                if 'vue' in deps or 'nuxt' in deps:
                    frameworks.add('Vue')
                if 'react' in deps:
                    frameworks.add('React')
                if 'express' in deps:
                    frameworks.add('Express')
                if '@supabase/supabase-js' in deps:
                    frameworks.add('Supabase')
                if 'mongoose' in deps or 'mongodb' in deps:
                    frameworks.add('MongoDB')
                if 'firebase' in deps or 'firebase-admin' in deps:
                    frameworks.add('Firebase')
                if '@angular/core' in deps:
                    frameworks.add('Angular')
                if 'fastify' in deps:
                    frameworks.add('Fastify')
                if 'hono' in deps:
                    frameworks.add('Hono')
                if 'prisma' in deps or '@prisma/client' in deps:
                    frameworks.add('Prisma')
                if 'drizzle-orm' in deps:
                    frameworks.add('Drizzle')
                # Template engines (high XSS risk)
                if 'pug' in deps or 'jade' in deps:
                    frameworks.add('Pug')
                if 'ejs' in deps:
                    frameworks.add('EJS')
                if 'handlebars' in deps or 'hbs' in deps:
                    frameworks.add('Handlebars')
                # Database clients (SQL injection risk)
                if 'pg' in deps or 'postgres' in deps:
                    frameworks.add('PostgreSQL')
                if 'mysql' in deps or 'mysql2' in deps:
                    frameworks.add('MySQL')
                # Auth libraries (high-value security targets)
                if 'passport' in deps:
                    frameworks.add('Passport')
                if 'jsonwebtoken' in deps or 'jose' in deps:
                    frameworks.add('JWT')
        except:
            pass

    if 'requirements.txt' in files or 'pyproject.toml' in files or 'setup.py' in files or 'Pipfile' in files:
        languages.add('Python')
        if 'manage.py' in files:
            frameworks.add('Django')
        # Check requirements.txt for frameworks
        req_file = os.path.join(repo_dir, 'requirements.txt')
        if os.path.isfile(req_file):
            try:
                with open(req_file, 'r') as f:
                    reqs = f.read().lower()
                    if 'flask' in reqs:
                        frameworks.add('Flask')
                    if 'fastapi' in reqs:
                        frameworks.add('FastAPI')
                    if 'django' in reqs:
                        frameworks.add('Django')
                    if 'sqlalchemy' in reqs:
                        frameworks.add('SQLAlchemy')
                    if 'celery' in reqs:
                        frameworks.add('Celery')
            except:
                pass

    if 'composer.json' in files:
        languages.add('PHP')
        try:
            with open(os.path.join(repo_dir, 'composer.json')) as f:
                composer = json.load(f)
                require = composer.get('require', {})
                if 'laravel/framework' in require:
                    frameworks.add('Laravel')
                if 'symfony/framework-bundle' in require:
                    frameworks.add('Symfony')
        except:
            pass

    if 'Gemfile' in files:
        languages.add('Ruby')
        frameworks.add('Rails')  # Most Gemfiles are Rails

    if 'go.mod' in files:
        languages.add('Go')

    if 'Cargo.toml' in files:
        languages.add('Rust')

    if 'pom.xml' in files or 'build.gradle' in files or 'build.gradle.kts' in files:
        languages.add('Java')
        if 'build.gradle.kts' in files:
            languages.add('Kotlin')

    if any(f.endswith('.csproj') or f.endswith('.sln') for f in files):
        languages.add('C#')

    if 'Package.swift' in files:
        languages.add('Swift')

    if 'pubspec.yaml' in files:
        languages.add('Dart')
        frameworks.add('Flutter')

    lang_list = sorted(list(languages))
    framework_list = sorted(list(frameworks))
    signature = ','.join(lang_list + framework_list).lower()

    return {
        'languages': lang_list,
        'frameworks': framework_list,
        'signature': signature
    }


def run_opengrep(repo_dir: str, detected_languages: List[str] = None) -> List[Dict[str, Any]]:
    """Run Opengrep SAST scanner with language-specific rules (LGPL fork of Semgrep)

    For performance, runs multiple focused scans instead of one massive scan:
    1. Base scan: shared rules + always-load rules on all files
    2. Language scans: each language's rules on only matching file extensions
    3. For large repos (>30 files of a type), uses file-based chunking

    This prevents timeouts on large multi-language repos like LoopFi (92 Solidity files).
    """
    findings = []

    # Map language rules to their file extensions
    LANGUAGE_EXTENSIONS = {
        'solidity.yaml': ['*.sol'],
        'javascript.yaml': ['*.js', '*.ts', '*.jsx', '*.tsx'],
        'python.yaml': ['*.py'],
        'php.yaml': ['*.php'],
        'ruby.yaml': ['*.rb'],
        'go.yaml': ['*.go'],
        'java.yaml': ['*.java'],
        'csharp.yaml': ['*.cs'],
        'kotlin.yaml': ['*.kt', '*.kts'],
        'swift.yaml': ['*.swift'],
        'rust.yaml': ['*.rs'],
        'bash.yaml': ['*.sh', '*.bash'],
        'dart.yaml': ['*.dart'],
        'yaml-config.yaml': ['*.yaml', '*.yml'],  # CI/CD, K8s, Docker configs
    }

    # Chunking thresholds for large repos
    CHUNK_THRESHOLD = 30  # If more than this many files, chunk them
    CHUNK_SIZE = 15       # Number of files per chunk

    # All file extensions for base scan (including YAML for CI/CD, K8s, Docker configs, XML for Android manifests)
    ALL_EXTENSIONS = ['*.sol', '*.py', '*.js', '*.ts', '*.go', '*.rb', '*.php', '*.java', '*.rs', '*.yaml', '*.yml', '*.xml']

    # Directories to exclude from scanning (third-party code / dependencies)
    # IMPORTANT: Only exclude directories that are ALWAYS third-party code.
    # See: https://semgrep.dev/docs/ignoring-files-folders-code for industry standards.
    #
    # We intentionally DO NOT exclude:
    #   - packages/  → Monorepos store FIRST-PARTY code here (Lerna, Turborepo)
    #   - deps/      → Could be first-party shared libraries
    #   - external/  → Could be first-party code in multi-repo setups
    #   - lib/       → Only safe to exclude in Foundry projects (handled separately)
    EXCLUDE_DIRS = {
        # Package manager dependencies (industry standard to exclude)
        'node_modules',     # NPM/Yarn packages - scanned by npm audit/Trivy
        'vendor',           # Go/PHP/Ruby dependencies - scanned by Trivy
        '.yarn',            # Yarn cache
        '.pnp',             # Yarn Plug'n'Play
        # Python artifacts
        'venv', '.venv',    # Python virtual environments
        '__pycache__',      # Python bytecode cache
        '.tox',             # Tox testing environments
        # Build outputs (not source code)
        'build',            # Generic build output
        'dist',             # Distribution bundles
        'target',           # Rust/Java/Maven build output
        'out',              # Common build output folder
        '.next',            # Next.js build cache
        # Caches and generated files
        '.cache',           # Various tool caches
        '.npm',             # NPM cache
        # Explicitly labeled third-party
        'third_party',      # Name explicitly indicates external code
        # Code4rena specific (chat exports, not source)
        'discord-export',
    }

    # Check if this is a Foundry project (has foundry.toml)
    # Only then is it safe to exclude lib/ (contains forge-std, openzeppelin, etc.)
    is_foundry_project = os.path.exists(os.path.join(repo_dir, 'foundry.toml'))
    if is_foundry_project:
        EXCLUDE_DIRS.add('lib')
        print(f"Foundry project detected - excluding lib/ (forge dependencies)", file=sys.stderr)

    # Build --exclude args for Opengrep (used in non-chunked scans)
    EXCLUDE_ARGS = [f'--exclude={d}' for d in EXCLUDE_DIRS]

    def find_matching_files(repo_dir: str, extensions: List[str]) -> List[str]:
        """Find all files matching the given extension patterns, excluding dependencies"""
        import fnmatch
        matching_files = []
        for root, dirs, filenames in os.walk(repo_dir):
            # Skip hidden dirs and dependency directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in EXCLUDE_DIRS]
            for filename in filenames:
                for ext_pattern in extensions:
                    if fnmatch.fnmatch(filename, ext_pattern):
                        matching_files.append(os.path.join(root, filename))
                        break
        return matching_files

    def chunk_list(lst: List, chunk_size: int) -> List[List]:
        """Split a list into chunks of specified size"""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

    # Build base configs (shared + always-load rules)
    base_configs = []
    base_rule_files = []

    if SHARED_RULES_DIR.exists():
        for shared_rule in SHARED_RULES:
            shared_path = SHARED_RULES_DIR / shared_rule
            if shared_path.exists():
                base_configs.extend(['-f', str(shared_path)])
                base_rule_files.append(f'_shared/{shared_rule}')

    for always_rule in ALWAYS_LOAD_RULES:
        always_path = RULES_DIR / always_rule
        if always_path.exists():
            base_configs.extend(['-f', str(always_path)])
            base_rule_files.append(always_rule)

    # Build language-specific scan configs (deduplicated by rule file)
    lang_scans = []  # List of (rule_file, extensions, configs)
    added_rules = set()  # Track which rule files we've already added

    if detected_languages:
        for lang in detected_languages:
            if lang in LANGUAGE_RULES:
                rule_file = LANGUAGE_RULES[lang]
                # Skip if already added (e.g., JavaScript and TypeScript both use javascript.yaml)
                if rule_file in added_rules:
                    continue
                rule_path = RULES_DIR / rule_file
                if rule_path.exists() and rule_file in LANGUAGE_EXTENSIONS:
                    extensions = LANGUAGE_EXTENSIONS[rule_file]
                    lang_scans.append((rule_file, extensions, ['-f', str(rule_path)]))
                    added_rules.add(rule_file)

    # Log what we're about to run
    print(f"Base rules: {', '.join(base_rule_files)}", file=sys.stderr)
    print(f"Language scans: {len(lang_scans)}", file=sys.stderr)
    for rule_file, exts, _ in lang_scans:
        print(f"  - {rule_file} on {', '.join(exts)}", file=sys.stderr)

    def run_single_scan(configs, target, scan_name, timeout=300, is_file_list=False):
        """Run a single Opengrep scan with specific rules

        Args:
            configs: List of config args (e.g., ['-f', 'rules.yaml'])
            target: Either repo_dir (for extension-based) or list of file paths (for chunked)
            scan_name: Name for logging
            timeout: Timeout in seconds
            is_file_list: If True, target is a list of specific files to scan
        """
        if is_file_list:
            # Scan specific files (chunked mode) - files already filtered by find_matching_files
            cmd = [
                'opengrep', 'scan', '--json',
                '--no-git-ignore',
                '--x-ignore-semgrepignore-files',
            ] + configs + target  # target is list of file paths
        else:
            # Scan by extension pattern (normal mode) - add explicit exclusions
            include_args = [f'--include={ext}' for ext in target]
            cmd = [
                'opengrep', 'scan', '--json',
                '--no-git-ignore',
                '--x-ignore-semgrepignore-files',
            ] + include_args + EXCLUDE_ARGS + configs + [repo_dir]

        try:
            if is_file_list:
                print(f"Running {scan_name}: {len(configs)//2} rule files on {len(target)} files", file=sys.stderr)
            else:
                print(f"Running {scan_name}: {len(configs)//2} rule files on {target}", file=sys.stderr)
            # Debug: print first 800 chars of command for base-scan
            if scan_name == "base-scan":
                cmd_str = ' '.join(cmd)
                print(f"  base-scan cmd (first 800): {cmd_str[:800]}", file=sys.stderr)
                # Print rule files specifically
                rule_files = [c for i, c in enumerate(cmd) if i > 0 and cmd[i-1] == '-f']
                print(f"  base-scan rule files: {rule_files}", file=sys.stderr)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            # Debug: check stderr for rule validation errors
            if result.stderr and scan_name == "base-scan":
                print(f"  base-scan stderr: {result.stderr[:500]}", file=sys.stderr)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    results = data.get('results', [])
                    print(f"  {scan_name}: {len(results)} findings", file=sys.stderr)
                    return results
                except json.JSONDecodeError:
                    print(f"  {scan_name}: JSON parse error", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f"  {scan_name}: timeout after {timeout}s", file=sys.stderr)
        except Exception as e:
            print(f"  {scan_name}: error - {e}", file=sys.stderr)
        return []

    # Run base scan (shared rules on all files) - 10 min timeout
    if base_configs:
        base_results = run_single_scan(base_configs, ALL_EXTENSIONS, "base-scan", timeout=600)
        findings.extend(base_results)

    # Run language-specific scans with chunking for large repos
    for rule_file, extensions, configs in lang_scans:
        # Find all matching files for this language
        matching_files = find_matching_files(repo_dir, extensions)
        file_count = len(matching_files)

        if file_count > CHUNK_THRESHOLD:
            # Large repo - use file-based chunking
            print(f"Large repo detected: {file_count} files for {rule_file}, using chunked scanning", file=sys.stderr)
            file_chunks = chunk_list(matching_files, CHUNK_SIZE)
            print(f"  Split into {len(file_chunks)} chunks of ~{CHUNK_SIZE} files each", file=sys.stderr)

            for i, chunk in enumerate(file_chunks, 1):
                chunk_name = f"{rule_file}-chunk-{i}/{len(file_chunks)}"
                chunk_results = run_single_scan(configs, chunk, chunk_name, timeout=600, is_file_list=True)
                findings.extend(chunk_results)
        else:
            # Normal repo - use extension-based scanning
            lang_results = run_single_scan(configs, extensions, rule_file, timeout=600)
            findings.extend(lang_results)

    # Convert raw Opengrep results to our finding format
    formatted_findings = []
    for item in findings:
        severity = SEVERITY_MAP.get(
            item.get('extra', {}).get('severity', 'INFO').upper(),
            'info'
        )
        formatted_findings.append({
            'id': hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()[:12],
            'ruleId': item.get('check_id', 'unknown'),
            'severity': severity,
            'category': 'code',
            'title': item.get('extra', {}).get('message', 'Security Issue'),
            'description': item.get('extra', {}).get('metadata', {}).get('message', ''),
            'location': {
                'file': item.get('path', '').replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                'line': item.get('start', {}).get('line', 0),
                'column': item.get('start', {}).get('col', 0)
            },
            'snippet': {
                'code': item.get('extra', {}).get('lines', ''),
                'highlightLines': [item.get('start', {}).get('line', 0)]
            },
            'fix': {
                'available': bool(item.get('extra', {}).get('fix')),
                'template': item.get('extra', {}).get('fix')
            },
            'references': item.get('extra', {}).get('metadata', {}).get('references', [])
        })

    print(f"Semgrep found {len(formatted_findings)} findings", file=sys.stderr)
    return formatted_findings


def run_trivy(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Trivy dependency and secret scanner"""
    findings = []

    cmd = [
        'trivy', 'fs',
        '--format', 'json',
        '--scanners', 'vuln,secret',
        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
        repo_dir
    ]

    try:
        print(f"Running Trivy: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"Trivy exit code: {result.returncode}", file=sys.stderr)

        if result.stderr:
            errors = [l for l in result.stderr.split('\n') if 'error' in l.lower()][:3]
            if errors:
                print(f"Trivy errors: {errors}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                # Process vulnerability results
                for target in data.get('Results', []):
                    target_file = target.get('Target', '')

                    # Vulnerabilities
                    for vuln in target.get('Vulnerabilities', []) or []:
                        severity = SEVERITY_MAP.get(vuln.get('Severity', 'UNKNOWN').upper(), 'info')
                        findings.append({
                            'id': vuln.get('VulnerabilityID', hashlib.md5(str(vuln).encode()).hexdigest()[:12]),
                            'ruleId': f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                            'severity': severity,
                            'category': 'dependencies',
                            'title': f"{vuln.get('PkgName', 'Unknown')}: {vuln.get('Title', vuln.get('VulnerabilityID', 'Vulnerability'))}",
                            'description': vuln.get('Description', ''),
                            'location': {
                                'file': target_file.replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': 0
                            },
                            'fix': {
                                'available': bool(vuln.get('FixedVersion')),
                                'template': f"Update {vuln.get('PkgName')} to {vuln.get('FixedVersion')}" if vuln.get('FixedVersion') else None
                            },
                            'references': vuln.get('References', [])[:3]
                        })

                    # Secrets
                    for secret in target.get('Secrets', []) or []:
                        findings.append({
                            'id': hashlib.md5(str(secret).encode()).hexdigest()[:12],
                            'ruleId': f"trivy-secret-{secret.get('RuleID', 'unknown')}",
                            'severity': 'critical',
                            'category': 'secrets',
                            'title': f"Secret Detected: {secret.get('Title', secret.get('RuleID', 'Secret'))}",
                            'description': secret.get('Match', ''),
                            'location': {
                                'file': target_file.replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': secret.get('StartLine', 0)
                            },
                            'fix': {
                                'available': True,
                                'template': 'Remove secret and rotate credentials immediately'
                            }
                        })

            except json.JSONDecodeError as e:
                print(f"Trivy JSON parse error: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Trivy timeout after 300s", file=sys.stderr)
    except Exception as e:
        print(f"Trivy error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Trivy found {len(findings)} findings", file=sys.stderr)
    return findings


def run_gitleaks(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Gitleaks secret scanner"""
    findings = []

    cmd = [
        'gitleaks', 'detect',
        '--source', repo_dir,
        '--report-format', 'json',
        '--report-path', '/dev/stdout',
        '--no-git'
    ]

    if GITLEAKS_CONFIG.exists():
        cmd.extend(['--config', str(GITLEAKS_CONFIG)])

    try:
        print(f"Running Gitleaks: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        # Gitleaks returns 1 when secrets are found, 0 when clean
        print(f"Gitleaks exit code: {result.returncode}", file=sys.stderr)

        if result.stdout and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    for item in data:
                        match_text = item.get('Match', item.get('Secret', ''))
                        if len(match_text) > 50:
                            match_text = match_text[:50] + '...'

                        findings.append({
                            'id': hashlib.md5(str(item).encode()).hexdigest()[:12],
                            'ruleId': f"gitleaks-{item.get('RuleID', 'secret')}",
                            'severity': 'critical',
                            'category': 'secrets',
                            'title': f"Exposed Secret: {item.get('Description', item.get('RuleID', 'Secret'))}",
                            'description': f"Found {item.get('RuleID', 'secret')} in source code",
                            'location': {
                                'file': item.get('File', '').replace(repo_dir + '/', '').replace(repo_dir + '\\', ''),
                                'line': item.get('StartLine', 0)
                            },
                            'snippet': {
                                'code': match_text,
                                'highlightLines': [item.get('StartLine', 0)]
                            },
                            'fix': {
                                'available': True,
                                'template': 'Move to environment variable and rotate the exposed secret immediately'
                            }
                        })
            except json.JSONDecodeError:
                # Empty or no results
                pass

    except subprocess.TimeoutExpired:
        print("Gitleaks timeout after 120s", file=sys.stderr)
    except Exception as e:
        print(f"Gitleaks error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Gitleaks found {len(findings)} findings", file=sys.stderr)
    return findings


def run_retirejs(repo_dir: str) -> List[Dict[str, Any]]:
    """Run npm audit to detect vulnerable JavaScript dependencies"""
    findings = []

    # Check for package.json and package-lock.json
    package_json = os.path.join(repo_dir, 'package.json')
    package_lock = os.path.join(repo_dir, 'package-lock.json')

    if not os.path.exists(package_json):
        print("No package.json found, skipping npm audit", file=sys.stderr)
        return findings

    # If no package-lock.json exists, try to generate one (non-installing)
    if not os.path.exists(package_lock):
        print("No package-lock.json found, attempting to generate...", file=sys.stderr)
        try:
            # Use npm install --package-lock-only to generate lock file without installing
            # Large repos like Juice Shop can take 5+ minutes for dependency resolution
            # Timeout increased to 600s (10 min) to handle large dependency trees
            gen_result = subprocess.run(
                ['npm', 'install', '--package-lock-only', '--ignore-scripts', '--legacy-peer-deps'],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=600
            )
            if gen_result.returncode != 0:
                print(f"Could not generate package-lock.json: {gen_result.stderr[:200]}", file=sys.stderr)
            else:
                print("Successfully generated package-lock.json", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("npm install timed out after 600s - very large dependency tree", file=sys.stderr)
        except Exception as e:
            print(f"Error generating package-lock.json: {e}", file=sys.stderr)

    # Run npm audit
    cmd = ['npm', 'audit', '--json']

    try:
        print(f"Running npm audit in {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=180
        )

        # npm audit exits non-zero if vulnerabilities found, which is expected
        output = result.stdout if result.stdout else result.stderr

        if output and output.strip():
            try:
                data = json.loads(output)

                # npm audit JSON format has "vulnerabilities" object
                vulnerabilities = data.get('vulnerabilities', {})

                for pkg_name, vuln_info in vulnerabilities.items():
                    severity_raw = vuln_info.get('severity', 'moderate').lower()
                    if severity_raw == 'critical':
                        severity = 'critical'
                    elif severity_raw == 'high':
                        severity = 'high'
                    elif severity_raw in ['moderate', 'medium']:
                        severity = 'medium'
                    else:
                        severity = 'low'

                    via = vuln_info.get('via', [])
                    # 'via' can be strings or objects
                    cve_list = []
                    descriptions = []
                    urls = []

                    for v in via:
                        if isinstance(v, dict):
                            if 'url' in v:
                                urls.append(v['url'])
                            if 'title' in v:
                                descriptions.append(v['title'])
                            # Extract CVE from URL if present
                            url = v.get('url', '')
                            if 'CVE-' in url:
                                import re
                                cve_match = re.search(r'CVE-\d{4}-\d+', url)
                                if cve_match:
                                    cve_list.append(cve_match.group())
                        elif isinstance(v, str):
                            descriptions.append(f"Vulnerable dependency: {v}")

                    cve_str = cve_list[0] if cve_list else ''
                    description = descriptions[0] if descriptions else f"Vulnerable npm package: {pkg_name}"

                    version_range = vuln_info.get('range', 'unknown')
                    fix_available = vuln_info.get('fixAvailable', False)

                    findings.append({
                        'id': hashlib.md5(f"npm-{pkg_name}:{version_range}:{cve_str}".encode()).hexdigest()[:12],
                        'ruleId': f"npm-audit-{cve_str}" if cve_str else f"npm-audit-{pkg_name}",
                        'severity': severity,
                        'category': 'dependencies',
                        'title': f"Vulnerable npm package: {pkg_name}" + (f" ({cve_str})" if cve_str else ""),
                        'description': description,
                        'cwe': vuln_info.get('cwe', ['CWE-1035'])[0] if isinstance(vuln_info.get('cwe'), list) else 'CWE-1035',
                        'location': {
                            'file': 'package.json',
                            'line': 0
                        },
                        'fix': {
                            'available': bool(fix_available),
                            'template': f"Run 'npm audit fix' or update {pkg_name} to a patched version"
                        },
                        'references': urls[:3]
                    })

                # Also check metadata for summary
                metadata = data.get('metadata', {})
                vulns_meta = metadata.get('vulnerabilities', {})
                total_vulns = sum(vulns_meta.values()) if vulns_meta else len(vulnerabilities)
                print(f"npm audit found {total_vulns} vulnerable packages", file=sys.stderr)

            except json.JSONDecodeError as e:
                print(f"npm audit JSON parse error: {e}", file=sys.stderr)
                print(f"Output preview: {output[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("npm audit timeout after 180s", file=sys.stderr)
    except FileNotFoundError:
        print("npm not installed, skipping npm audit", file=sys.stderr)
    except Exception as e:
        print(f"npm audit error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"npm audit returned {len(findings)} findings", file=sys.stderr)
    return findings


def run_hadolint(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Hadolint Dockerfile linter

    Hadolint checks Dockerfiles for:
    - Best practices violations
    - Security issues (running as root, etc.)
    - Shell script issues (via ShellCheck)
    """
    findings = []

    # Find all Dockerfiles
    dockerfiles = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'vendor', '.git']]
        for f in files:
            if f == 'Dockerfile' or f.startswith('Dockerfile.') or f.endswith('.dockerfile'):
                dockerfiles.append(os.path.join(root, f))

    if not dockerfiles:
        print("No Dockerfiles found, skipping Hadolint", file=sys.stderr)
        return findings

    print(f"Running Hadolint on {len(dockerfiles)} Dockerfile(s)", file=sys.stderr)

    # Severity mapping for Hadolint
    severity_map = {
        'error': 'high',
        'warning': 'medium',
        'info': 'low',
        'style': 'info'
    }

    for dockerfile in dockerfiles:
        cmd = ['hadolint', '-f', 'json', dockerfile]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                try:
                    issues = json.loads(result.stdout)

                    for issue in issues:
                        file_path = dockerfile
                        if file_path.startswith(repo_dir):
                            file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')

                        severity = severity_map.get(issue.get('level', 'warning'), 'medium')

                        findings.append({
                            'id': hashlib.md5(f"hadolint-{issue.get('code', '')}-{file_path}:{issue.get('line', 0)}".encode()).hexdigest()[:12],
                            'ruleId': f"hadolint-{issue.get('code', 'DL0000')}",
                            'severity': severity,
                            'category': 'code',
                            'title': f"[Hadolint] {issue.get('code', '')}: {issue.get('message', '')}",
                            'description': issue.get('message', ''),
                            'location': {
                                'file': file_path,
                                'line': issue.get('line', 0),
                                'column': issue.get('column', 0)
                            },
                            'fix': {
                                'available': False,
                                'template': None
                            },
                            'references': [f"https://github.com/hadolint/hadolint/wiki/{issue.get('code', '')}"]
                        })

                except json.JSONDecodeError as e:
                    print(f"Hadolint JSON parse error for {dockerfile}: {e}", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print(f"Hadolint timeout for {dockerfile}", file=sys.stderr)
        except Exception as e:
            print(f"Hadolint error for {dockerfile}: {e}", file=sys.stderr)

    print(f"Hadolint found {len(findings)} findings", file=sys.stderr)
    return findings


def run_checkov(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Checkov IaC security scanner

    Checkov scans infrastructure-as-code for security issues:
    - Terraform configurations
    - Kubernetes manifests
    - Docker compose files
    - CloudFormation templates
    - Helm charts
    """
    findings = []

    # Check for IaC files
    iac_extensions = ['.tf', '.yaml', '.yml', '.json']
    iac_files = ['docker-compose', 'kubernetes', 'k8s', 'terraform', 'cloudformation', 'helm']

    has_iac = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'vendor', '.git', 'venv']]
        for f in files:
            # Check by extension
            if any(f.endswith(ext) for ext in iac_extensions):
                # Skip package.json and other non-IaC JSON/YAML
                if f in ['package.json', 'package-lock.json', 'tsconfig.json']:
                    continue
                has_iac = True
                break
            # Check for specific IaC files
            if any(iac in f.lower() for iac in iac_files):
                has_iac = True
                break
        if has_iac:
            break

    if not has_iac:
        print("No IaC files found, skipping Checkov", file=sys.stderr)
        return findings

    cmd = [
        'checkov',
        '-d', repo_dir,
        '-o', 'json',
        '--quiet',
        '--compact',
        '--skip-download'  # Don't download external modules
    ]

    try:
        print(f"Running Checkov on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"Checkov exit code: {result.returncode}", file=sys.stderr)

        if result.stdout:
            try:
                # Checkov outputs an array of check results
                data = json.loads(result.stdout)

                # Handle both single and multiple framework results
                if isinstance(data, list):
                    all_results = data
                else:
                    all_results = [data]

                for framework_result in all_results:
                    if not isinstance(framework_result, dict):
                        continue

                    failed_checks = framework_result.get('results', {}).get('failed_checks', [])

                    for check in failed_checks:
                        severity_map = {
                            'CRITICAL': 'critical',
                            'HIGH': 'high',
                            'MEDIUM': 'medium',
                            'LOW': 'low'
                        }
                        severity = severity_map.get(check.get('severity', 'MEDIUM'), 'medium')

                        file_path = check.get('file_path', '')
                        if file_path.startswith(repo_dir):
                            file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')
                        if file_path.startswith('/'):
                            file_path = file_path[1:]

                        check_id = check.get('check_id', 'CKV_UNKNOWN')

                        findings.append({
                            'id': hashlib.md5(f"checkov-{check_id}-{file_path}".encode()).hexdigest()[:12],
                            'ruleId': f"checkov-{check_id}",
                            'severity': severity,
                            'category': 'code',
                            'title': f"[Checkov] {check.get('check_name', 'IaC Security Issue')}",
                            'description': check.get('guideline', check.get('check_name', '')),
                            'location': {
                                'file': file_path,
                                'line': check.get('file_line_range', [0, 0])[0],
                                'column': 0
                            },
                            'fix': {
                                'available': False,
                                'template': None
                            },
                            'references': [check.get('guideline', f"https://docs.prismacloud.io/en/enterprise-edition/policy-reference/check-id-{check_id.lower()}")]
                        })

            except json.JSONDecodeError as e:
                print(f"Checkov JSON parse error: {e}", file=sys.stderr)
                if result.stderr:
                    print(f"Checkov stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Checkov timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Checkov not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Checkov error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Checkov found {len(findings)} findings", file=sys.stderr)
    return findings


def run_brakeman(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Brakeman Ruby/Rails security scanner

    Brakeman scans Ruby on Rails applications for:
    - SQL injection
    - Cross-site scripting (XSS)
    - Command injection
    - Mass assignment
    - Insecure redirects
    - Session manipulation
    """
    findings = []

    # Check for Rails app (Gemfile with rails, or config/routes.rb)
    gemfile = os.path.join(repo_dir, 'Gemfile')
    routes = os.path.join(repo_dir, 'config', 'routes.rb')

    is_rails = False
    if os.path.exists(routes):
        is_rails = True
    elif os.path.exists(gemfile):
        try:
            with open(gemfile, 'r') as f:
                content = f.read().lower()
                if 'rails' in content:
                    is_rails = True
        except:
            pass

    if not is_rails:
        print("No Rails app found, skipping Brakeman", file=sys.stderr)
        return findings

    cmd = [
        'brakeman',
        '-f', 'json',
        '-q',  # Quiet mode
        '--no-pager',
        repo_dir
    ]

    try:
        print(f"Running Brakeman on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Brakeman exits with various codes based on findings
        print(f"Brakeman exit code: {result.returncode}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                for warning in data.get('warnings', []):
                    severity_map = {
                        'High': 'high',
                        'Medium': 'medium',
                        'Weak': 'low'
                    }
                    confidence = warning.get('confidence', 'Medium')
                    severity = severity_map.get(confidence, 'medium')

                    file_path = warning.get('file', '')
                    if file_path.startswith(repo_dir):
                        file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')

                    findings.append({
                        'id': hashlib.md5(f"brakeman-{warning.get('warning_type', '')}-{file_path}:{warning.get('line', 0)}".encode()).hexdigest()[:12],
                        'ruleId': f"brakeman-{warning.get('warning_code', 0)}",
                        'severity': severity,
                        'category': 'code',
                        'title': f"[Brakeman] {warning.get('warning_type', 'Security Issue')}: {warning.get('message', '')}",
                        'description': warning.get('message', ''),
                        'cwe': warning.get('cwe_id', [None])[0] if warning.get('cwe_id') else None,
                        'location': {
                            'file': file_path,
                            'line': warning.get('line', 0),
                            'column': 0
                        },
                        'snippet': {
                            'code': warning.get('code', ''),
                            'highlightLines': [warning.get('line', 0)]
                        },
                        'fix': {
                            'available': False,
                            'template': None
                        },
                        'references': [warning.get('link', f"https://brakemanscanner.org/docs/warning_types/{warning.get('warning_type', '').replace(' ', '_')}/")]
                    })

            except json.JSONDecodeError as e:
                print(f"Brakeman JSON parse error: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Brakeman timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Brakeman not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Brakeman error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Brakeman found {len(findings)} findings", file=sys.stderr)
    return findings


def run_slither(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Slither Solidity static analyzer

    Slither detects smart contract vulnerabilities:
    - Reentrancy
    - Unchecked external calls
    - Integer overflow/underflow
    - Access control issues
    - State variable shadowing
    - Uninitialized storage
    """
    findings = []

    # Check for Solidity files - don't exclude 'lib' for file detection
    # (it may contain relevant contracts in non-Foundry repos)
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        # Only exclude node_modules and .git, keep lib for now
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git']]
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    if not sol_files:
        print("No Solidity files found, skipping Slither", file=sys.stderr)
        return findings

    print(f"Found {len(sol_files)} Solidity files", file=sys.stderr)

    # Skip compilation for massive repos to prevent OOM
    MAX_SOL_FILES_FOR_COMPILATION = 400
    if len(sol_files) > MAX_SOL_FILES_FOR_COMPILATION:
        print(f"LARGE REPO: {len(sol_files)} Solidity files exceeds {MAX_SOL_FILES_FOR_COMPILATION} threshold", file=sys.stderr)
        print("Skipping Slither (requires compilation) - use Opengrep for pattern-based analysis", file=sys.stderr)
        findings.append({
            'ruleId': 'scanner-large-repo-warning',
            'severity': 'info',
            'title': f'Large repository ({len(sol_files)} Solidity files) - compilation-based analysis skipped',
            'description': f'This repository contains {len(sol_files)} Solidity files, which exceeds the {MAX_SOL_FILES_FOR_COMPILATION} file threshold for compilation-based scanners (Slither, Aderyn, Mythril). Pattern-based scanning (Opengrep) still runs. For full analysis, scan specific subdirectories.',
            'file': repo_dir,
            'line': 0,
            'category': 'scanner-limitation'
        })
        return findings

    # Detect project type (check root and common subdirectories)
    def find_config(filename):
        if os.path.exists(os.path.join(repo_dir, filename)):
            return True
        # Check common monorepo subdirs
        for subdir in ['contracts', 'packages/contracts', 'client']:
            if os.path.exists(os.path.join(repo_dir, subdir, filename)):
                return True
        return False

    is_foundry = find_config('foundry.toml')
    is_hardhat = find_config('hardhat.config.js') or find_config('hardhat.config.ts')
    is_truffle = find_config('truffle-config.js') or find_config('truffle.js')
    is_standalone = not (is_foundry or is_hardhat or is_truffle)

    print(f"Project detection: foundry={is_foundry}, hardhat={is_hardhat}, truffle={is_truffle}, standalone={is_standalone}", file=sys.stderr)

    # Compile if needed
    if is_foundry:
        try:
            print("Foundry project detected, running forge build...", file=sys.stderr)
            build_result = subprocess.run(
                ['forge', 'build'],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=300
            )
            if build_result.returncode == 0:
                print("Forge build successful", file=sys.stderr)
            else:
                print(f"Forge build warning (code {build_result.returncode}): {build_result.stderr[:300]}", file=sys.stderr)
        except FileNotFoundError:
            print("Forge not available, will try standalone analysis", file=sys.stderr)
            is_standalone = True
        except Exception as e:
            print(f"Forge build error: {e}", file=sys.stderr)

    if is_hardhat:
        try:
            print("Hardhat project detected, installing deps and compiling...", file=sys.stderr)
            subprocess.run(['npm', 'install'], cwd=repo_dir, capture_output=True, timeout=120)
            subprocess.run(['npx', 'hardhat', 'compile'], cwd=repo_dir, capture_output=True, timeout=120)
        except Exception as e:
            print(f"Hardhat setup warning: {e}", file=sys.stderr)

    # Build Slither command based on project type
    if is_standalone:
        # For standalone .sol files, detect pragma and select appropriate solc
        print(f"Standalone Solidity files detected, checking pragma versions...", file=sys.stderr)

        # Detect the most common pragma version in the repo
        pragma_versions = []
        pragma_pattern = re.compile(r'pragma\s+solidity\s+[\^>=<]*\s*(\d+\.\d+\.\d+|\d+\.\d+)')

        for sol_file in sol_files[:20]:  # Check first 20 files to avoid slowdown
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)  # First 2KB should have pragma
                    match = pragma_pattern.search(content)
                    if match:
                        version = match.group(1)
                        # Normalize to major.minor format
                        parts = version.split('.')
                        if len(parts) >= 2:
                            pragma_versions.append(f"{parts[0]}.{parts[1]}")
            except Exception as e:
                print(f"Error reading {sol_file}: {e}", file=sys.stderr)

        # Pick the most common version, fallback to 0.8
        if pragma_versions:
            most_common = Counter(pragma_versions).most_common(1)[0][0]
            print(f"Detected pragma version: {most_common}", file=sys.stderr)

            # Map to installed solc versions
            version_map = {
                '0.4': '0.4.26',
                '0.5': '0.5.17',
                '0.6': '0.6.12',
                '0.7': '0.7.6',
                '0.8': '0.8.24'
            }
            solc_version = version_map.get(most_common, '0.8.24')

            # Use solc-select to switch to appropriate version
            try:
                select_result = subprocess.run(
                    ['solc-select', 'use', solc_version],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if select_result.returncode == 0:
                    print(f"Selected solc version: {solc_version}", file=sys.stderr)
                else:
                    print(f"solc-select warning: {select_result.stderr}", file=sys.stderr)
            except Exception as e:
                print(f"solc-select error: {e}", file=sys.stderr)
        else:
            print("No pragma version detected, using default solc 0.8.24", file=sys.stderr)

        # For standalone files (likely benchmark/test repos), include low severity
        # as many intentional vulnerabilities are classified as low
        cmd = [
            'slither',
            repo_dir,
            '--json', '-',
            '--exclude-informational',
            '--exclude-optimization',
            '--solc-disable-warnings',  # Don't fail on warnings
            '--skip-clean',  # Don't clean temp files (faster)
            '--filter-paths', 'node_modules,test,tests,mock,mocks'
        ]
    else:
        # For proper projects (Foundry/Hardhat/Truffle), filter more strictly
        cmd = [
            'slither',
            repo_dir,
            '--json', '-',
            '--exclude-informational',
            '--exclude-low',  # Focus on medium+ severity
            '--exclude-optimization',
            '--filter-paths', 'node_modules,test,tests,mock,mocks,lib/forge-std'
        ]

    try:
        print(f"Running Slither on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # Slither can be slow on large contracts
        )

        # Slither exits with 1 if issues found
        print(f"Slither exit code: {result.returncode}", file=sys.stderr)

        # Always log stderr for debugging
        if result.stderr:
            print(f"Slither stderr: {result.stderr[:500]}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                # Debug: log Slither output structure
                success = data.get('success', None)
                error = data.get('error', None)
                detectors_count = len(data.get('results', {}).get('detectors', []))
                print(f"Slither output: success={success}, error={error}, detectors={detectors_count}", file=sys.stderr)

                # Log compilation errors if any
                if data.get('results', {}).get('compilation_errors'):
                    print(f"Slither compilation errors: {data['results']['compilation_errors'][:500]}", file=sys.stderr)

                for detector in data.get('results', {}).get('detectors', []):
                    severity_map = {
                        'High': 'high',
                        'Medium': 'medium',
                        'Low': 'low',
                        'Informational': 'info'
                    }
                    impact = detector.get('impact', 'Medium')
                    severity = severity_map.get(impact, 'medium')

                    # Get first element location
                    elements = detector.get('elements', [])
                    file_path = ''
                    line = 0
                    if elements:
                        first_elem = elements[0]
                        source_mapping = first_elem.get('source_mapping', {})
                        file_path = source_mapping.get('filename_relative', '')
                        lines = source_mapping.get('lines', [0])
                        line = lines[0] if lines else 0

                    findings.append({
                        'id': hashlib.md5(f"slither-{detector.get('check', '')}-{file_path}:{line}".encode()).hexdigest()[:12],
                        'ruleId': f"slither-{detector.get('check', 'unknown')}",
                        'severity': severity,
                        'category': 'code',
                        'title': f"[Slither] {detector.get('check', 'Issue')}: {detector.get('description', '')[:100]}",
                        'description': detector.get('description', ''),
                        'location': {
                            'file': file_path,
                            'line': line,
                            'column': 0
                        },
                        'fix': {
                            'available': False,
                            'template': None
                        },
                        'references': [f"https://github.com/crytic/slither/wiki/Detector-Documentation#{detector.get('check', '')}"]
                    })

            except json.JSONDecodeError as e:
                print(f"Slither JSON parse error: {e}", file=sys.stderr)
                if result.stderr:
                    print(f"Slither stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Slither timeout after 600s", file=sys.stderr)
    except FileNotFoundError:
        print("Slither not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Slither error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Slither found {len(findings)} findings", file=sys.stderr)
    return findings


def run_slither_upgradeability(repo_dir: str) -> List[Dict[str, Any]]:
    """Run slither-check-upgradeability for storage collision detection (SWC-124)

    This specialized Slither tool detects:
    - Storage layout collisions between proxy and implementation
    - Missing gap variables in upgradeable contracts
    - Order-dependent state variable issues
    - Incorrect slot usage in EIP-1967 patterns

    Triggers when proxy patterns are detected:
    - UUPS (EIP-1822)
    - TransparentUpgradeableProxy
    - EIP-1967 storage slots
    - delegatecall in fallback functions
    """
    findings = []

    # Check for Solidity files
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'forge-std']]
        for f in files:
            if f.endswith('.sol'):
                full_path = os.path.join(root, f)
                sol_files.append(full_path)

    if not sol_files:
        print("No .sol files found, skipping slither-check-upgradeability", file=sys.stderr)
        return findings

    # Skip for massive repos to prevent OOM
    MAX_SOL_FILES_FOR_COMPILATION = 400
    if len(sol_files) > MAX_SOL_FILES_FOR_COMPILATION:
        print(f"LARGE REPO: Skipping slither-upgradeability ({len(sol_files)} files > {MAX_SOL_FILES_FOR_COMPILATION} threshold)", file=sys.stderr)
        return findings

    # Detect proxy patterns by scanning file contents
    proxy_contracts = []
    implementation_contracts = []

    # Patterns that indicate proxy contracts
    proxy_patterns = [
        'delegatecall',
        'ERC1967Upgrade',
        'TransparentUpgradeableProxy',
        'UUPSUpgradeable',
        '_IMPLEMENTATION_SLOT',
        'IMPLEMENTATION_SLOT',
        '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',  # EIP-1967 impl slot
        '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',  # EIP-1967 admin slot
        'Proxy',
        'upgradeTo',
        'upgradeToAndCall',
    ]

    # Patterns that indicate implementation contracts
    impl_patterns = [
        'Initializable',
        'initializer',
        '__gap',
        'initialize(',
        '_disableInitializers',
    ]

    for sol_file in sol_files:
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Check for proxy patterns
                is_proxy = any(pattern in content for pattern in proxy_patterns)
                is_impl = any(pattern in content for pattern in impl_patterns)

                if is_proxy:
                    proxy_contracts.append(sol_file)
                if is_impl:
                    implementation_contracts.append(sol_file)
        except Exception as e:
            print(f"Error reading {sol_file}: {e}", file=sys.stderr)
            continue

    if not proxy_contracts and not implementation_contracts:
        print("No proxy/upgradeable patterns detected, skipping slither-check-upgradeability", file=sys.stderr)
        return findings

    print(f"Found {len(proxy_contracts)} proxy contracts and {len(implementation_contracts)} implementation contracts", file=sys.stderr)

    # Try running slither with --detect to catch storage-related issues
    # This is more reliable than trying to pair proxies with implementations
    try:
        # Use Slither's storage-focused detectors
        storage_detectors = [
            'uninitialized-storage',
            'variable-scope',
            'shadowing-state',
            'shadowing-local',
            'storage-array',
        ]

        cmd = [
            'slither',
            repo_dir,
            '--json', '-',
            '--detect', ','.join(storage_detectors),
            '--solc-disable-warnings',
            '--skip-clean',
            '--filter-paths', 'node_modules,test,tests,mock,mocks,lib,forge-std'
        ]

        print(f"Running Slither storage analysis: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse results
        if result.stdout:
            try:
                data = json.loads(result.stdout)

                for detector in data.get('results', {}).get('detectors', []):
                    check = detector.get('check', 'unknown')
                    impact = detector.get('impact', 'Medium')
                    confidence = detector.get('confidence', 'Medium')
                    description = detector.get('description', '')

                    # Map to SWC-124 if it's a storage issue
                    rule_id = f"slither-upgrade-{check}"

                    # Get file locations
                    elements = detector.get('elements', [])
                    for elem in elements:
                        source = elem.get('source_mapping', {})
                        filename = source.get('filename_relative', source.get('filename', ''))
                        start_line = source.get('lines', [0])[0] if source.get('lines') else 0

                        if filename:
                            findings.append({
                                'rule_id': rule_id,
                                'message': f"[SWC-124] Storage Issue ({check}): {description[:200]}",
                                'severity': 'high' if impact == 'High' else 'medium',
                                'file': filename,
                                'line': start_line,
                                'column': 0,
                                'scanner': 'slither-upgradeability',
                                'category': 'smart-contract',
                                'subcategory': 'storage-collision',
                                'cwe_id': 'CWE-787',  # Out-of-bounds Write
                                'swc_id': 'SWC-124',
                                'fix': {
                                    'available': False,
                                    'template': None
                                },
                                'references': [
                                    'https://swcregistry.io/docs/SWC-124',
                                    'https://github.com/crytic/slither/wiki/Detector-Documentation'
                                ]
                            })
                            break  # One finding per detector

            except json.JSONDecodeError as e:
                print(f"Slither upgradeability JSON parse error: {e}", file=sys.stderr)

        # Also scan for __gap variable issues in implementation contracts
        for impl_file in implementation_contracts:
            try:
                with open(impl_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if it's upgradeable but missing __gap
                    has_initializable = 'Initializable' in content or 'initializer' in content
                    has_gap = '__gap' in content
                    has_inheritance = 'is ' in content and ('Upgradeable' in content or 'Initializable' in content)

                    if has_initializable and has_inheritance and not has_gap:
                        # Find the contract declaration line
                        for i, line in enumerate(lines):
                            if 'contract ' in line and 'is ' in line:
                                rel_path = os.path.relpath(impl_file, repo_dir)
                                findings.append({
                                    'rule_id': 'slither-upgrade-missing-gap',
                                    'message': '[SWC-124] Upgradeable contract missing __gap storage variable for future upgrades. Add `uint256[50] private __gap;` at end of storage variables.',
                                    'severity': 'high',
                                    'file': rel_path,
                                    'line': i + 1,
                                    'column': 0,
                                    'scanner': 'slither-upgradeability',
                                    'category': 'smart-contract',
                                    'subcategory': 'storage-collision',
                                    'cwe_id': 'CWE-787',
                                    'swc_id': 'SWC-124',
                                    'fix': {
                                        'available': True,
                                        'template': 'Add at end of state variables: uint256[50] private __gap;'
                                    },
                                    'references': [
                                        'https://swcregistry.io/docs/SWC-124',
                                        'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps'
                                    ]
                                })
                                break

            except Exception as e:
                print(f"Error analyzing {impl_file}: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Slither upgradeability timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Slither not installed, skipping upgradeability check", file=sys.stderr)
    except Exception as e:
        print(f"Slither upgradeability error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Slither upgradeability found {len(findings)} findings", file=sys.stderr)
    return findings


def run_osv_scanner(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Google's OSV-Scanner for dependency vulnerabilities

    OSV-Scanner checks dependencies against the Open Source Vulnerabilities database:
    - npm/yarn (package-lock.json, yarn.lock)
    - pip (requirements.txt, Pipfile.lock, poetry.lock)
    - Go (go.mod)
    - Cargo (Cargo.lock)
    - Maven/Gradle (pom.xml)
    - And many more ecosystems

    This complements Trivy by using Google's OSV database which has
    excellent coverage of open source vulnerabilities.
    """
    findings = []

    # Check for any dependency files
    dep_files = [
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',  # JS
        'requirements.txt', 'Pipfile.lock', 'poetry.lock',   # Python
        'go.mod', 'go.sum',                                   # Go
        'Cargo.lock',                                         # Rust
        'pom.xml', 'build.gradle', 'build.gradle.kts',       # Java
        'Gemfile.lock',                                       # Ruby
        'composer.lock',                                      # PHP
    ]

    has_deps = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'vendor', '.git']]
        for f in files:
            if f in dep_files:
                has_deps = True
                break
        if has_deps:
            break

    if not has_deps:
        print("No dependency lock files found, skipping OSV-Scanner", file=sys.stderr)
        return findings

    cmd = [
        'osv-scanner',
        '--format', 'json',
        '-r',  # Recursive scan
        repo_dir
    ]

    try:
        print(f"Running OSV-Scanner on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # OSV-Scanner exits with 1 if vulnerabilities found
        print(f"OSV-Scanner exit code: {result.returncode}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                for result_entry in data.get('results', []):
                    source_path = result_entry.get('source', {}).get('path', '')
                    if source_path.startswith(repo_dir):
                        source_path = source_path[len(repo_dir):].lstrip('/').lstrip('\\')

                    for package in result_entry.get('packages', []):
                        pkg_info = package.get('package', {})
                        pkg_name = pkg_info.get('name', 'unknown')
                        pkg_version = pkg_info.get('version', 'unknown')
                        ecosystem = pkg_info.get('ecosystem', 'unknown')

                        for vuln in package.get('vulnerabilities', []):
                            vuln_id = vuln.get('id', 'OSV-UNKNOWN')

                            # Determine severity from database_specific or severity array
                            severity = 'medium'
                            severity_data = vuln.get('severity', [])
                            if severity_data:
                                for sev in severity_data:
                                    if sev.get('type') == 'CVSS_V3':
                                        score = sev.get('score', '')
                                        # Parse CVSS score to severity
                                        try:
                                            # Extract base score from CVSS string
                                            if '/' in score:
                                                base_score = float(score.split('/')[0].split(':')[-1])
                                            else:
                                                base_score = float(score)
                                            if base_score >= 9.0:
                                                severity = 'critical'
                                            elif base_score >= 7.0:
                                                severity = 'high'
                                            elif base_score >= 4.0:
                                                severity = 'medium'
                                            else:
                                                severity = 'low'
                                        except:
                                            pass

                            # Get aliases (CVE IDs)
                            aliases = vuln.get('aliases', [])
                            cve_id = next((a for a in aliases if a.startswith('CVE-')), None)

                            findings.append({
                                'id': hashlib.md5(f"osv-{vuln_id}-{pkg_name}".encode()).hexdigest()[:12],
                                'ruleId': f"osv-{vuln_id}",
                                'severity': severity,
                                'category': 'dependencies',
                                'title': f"[OSV] {pkg_name}@{pkg_version}: {vuln.get('summary', vuln_id)[:80]}",
                                'description': vuln.get('details', vuln.get('summary', '')),
                                'cwe': None,
                                'location': {
                                    'file': source_path,
                                    'line': 0
                                },
                                'fix': {
                                    'available': bool(vuln.get('affected', [{}])[0].get('ranges', [{}])[0].get('events', [{}])[-1].get('fixed')),
                                    'template': f"Update {pkg_name} to a patched version"
                                },
                                'references': [vuln.get('references', [{}])[0].get('url', f"https://osv.dev/vulnerability/{vuln_id}")] if vuln.get('references') else [f"https://osv.dev/vulnerability/{vuln_id}"]
                            })

            except json.JSONDecodeError as e:
                print(f"OSV-Scanner JSON parse error: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("OSV-Scanner timeout after 180s", file=sys.stderr)
    except FileNotFoundError:
        print("OSV-Scanner not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"OSV-Scanner error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"OSV-Scanner found {len(findings)} findings", file=sys.stderr)
    return findings


def run_aderyn(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Aderyn Solidity static analyzer (by Cyfrin)

    Aderyn is a Rust-based Solidity analyzer that detects:
    - Reentrancy vulnerabilities
    - Centralization risks
    - Unsafe external calls
    - Missing access controls
    - Gas optimization issues
    - And more security patterns

    It's designed to be fast and complement Slither with different detection patterns.
    """
    findings = []

    # Check for Solidity files
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib']]
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    if not sol_files:
        print("No Solidity files found, skipping Aderyn", file=sys.stderr)
        return findings

    print(f"Found {len(sol_files)} Solidity files for Aderyn", file=sys.stderr)

    # Skip for massive repos to prevent OOM
    MAX_SOL_FILES_FOR_COMPILATION = 400
    if len(sol_files) > MAX_SOL_FILES_FOR_COMPILATION:
        print(f"LARGE REPO: Skipping Aderyn ({len(sol_files)} files > {MAX_SOL_FILES_FOR_COMPILATION} threshold)", file=sys.stderr)
        return findings

    # Aderyn outputs JSON report
    output_file = os.path.join(repo_dir, 'aderyn-report.json')

    cmd = [
        'aderyn',
        repo_dir,
        '--output', output_file
    ]

    try:
        print(f"Running Aderyn on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"Aderyn exit code: {result.returncode}", file=sys.stderr)

        # Read the JSON report
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)

                # Aderyn report structure
                for issue in data.get('high_issues', {}).get('issues', []):
                    findings.append(create_aderyn_finding(issue, 'high', repo_dir))

                for issue in data.get('medium_issues', {}).get('issues', []):
                    findings.append(create_aderyn_finding(issue, 'medium', repo_dir))

                for issue in data.get('low_issues', {}).get('issues', []):
                    findings.append(create_aderyn_finding(issue, 'low', repo_dir))

                for issue in data.get('nc_issues', {}).get('issues', []):
                    findings.append(create_aderyn_finding(issue, 'info', repo_dir))

            except json.JSONDecodeError as e:
                print(f"Aderyn JSON parse error: {e}", file=sys.stderr)
            finally:
                # Clean up report file
                try:
                    os.remove(output_file)
                except:
                    pass
        else:
            print(f"Aderyn report not found at {output_file}", file=sys.stderr)
            if result.stderr:
                print(f"Aderyn stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Aderyn timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Aderyn not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Aderyn error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Aderyn found {len(findings)} findings", file=sys.stderr)
    return findings


def create_aderyn_finding(issue: Dict, severity: str, repo_dir: str) -> Dict[str, Any]:
    """Helper to create a finding from an Aderyn issue"""
    title = issue.get('title', 'Security Issue')
    description = issue.get('description', '')

    # Get location from instances
    instances = issue.get('instances', [])
    file_path = ''
    line = 0
    if instances:
        first = instances[0]
        file_path = first.get('contract_path', '')
        if file_path.startswith(repo_dir):
            file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')
        line = first.get('line_no', 0)

    return {
        'id': hashlib.md5(f"aderyn-{title}-{file_path}:{line}".encode()).hexdigest()[:12],
        'ruleId': f"aderyn-{title.lower().replace(' ', '-')[:30]}",
        'severity': severity,
        'category': 'code',
        'title': f"[Aderyn] {title}",
        'description': description,
        'location': {
            'file': file_path,
            'line': line,
            'column': 0
        },
        'fix': {
            'available': False,
            'template': None
        },
        'references': ['https://github.com/Cyfrin/aderyn']
    }


def run_mythril(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Mythril Solidity symbolic execution analyzer

    Mythril uses symbolic execution and SMT solving to detect:
    - Integer overflow/underflow
    - Reentrancy
    - Unprotected selfdestruct
    - Unchecked external calls
    - State variable manipulation
    - Transaction ordering dependencies

    Note: Mythril is slower than static analyzers but finds deeper bugs.
    We run it with a timeout and limited execution depth for speed.
    """
    findings = []

    # Check for Solidity files
    # NOTE: Don't exclude test/tests - benchmark repos like DeFiVulnLabs have vulns in test dirs
    # Only exclude node_modules, .git, and lib (Foundry dependencies)
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib']]
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    if not sol_files:
        print("No Solidity files found, skipping Mythril", file=sys.stderr)
        return findings

    print(f"Found {len(sol_files)} Solidity files for Mythril", file=sys.stderr)

    # Skip for massive repos to prevent OOM during compilation
    MAX_SOL_FILES_FOR_COMPILATION = 400
    if len(sol_files) > MAX_SOL_FILES_FOR_COMPILATION:
        print(f"LARGE REPO: Skipping Mythril ({len(sol_files)} files > {MAX_SOL_FILES_FOR_COMPILATION} threshold)", file=sys.stderr)
        return findings

    # Limit to first 5 files to avoid timeout (Mythril is very slow)
    if len(sol_files) > 5:
        print(f"Limiting Mythril to first 5 files (out of {len(sol_files)})", file=sys.stderr)
        sol_files = sol_files[:5]

    # Helper to detect pragma version from file
    def detect_solc_version(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Match pragma solidity ^0.8.0, >=0.8.0, =0.8.0, etc.
                import re
                match = re.search(r'pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+\.\d+|\d+\.\d+)', content)
                if match:
                    version = match.group(1)
                    # Add .0 if only major.minor
                    if version.count('.') == 1:
                        version += '.0'
                    return version
        except:
            pass
        return None

    # Run Mythril on each file with limited depth
    for sol_file in sol_files:
        relative_path = sol_file
        if relative_path.startswith(repo_dir):
            relative_path = relative_path[len(repo_dir):].lstrip('/').lstrip('\\')

        # Detect solc version for this file
        solc_version = detect_solc_version(sol_file)

        cmd = [
            'myth', 'analyze',
            sol_file,
            '--execution-timeout', '30',  # 30s per file max (reduced for speed)
            '--max-depth', '8',           # Limit search depth (reduced for speed)
            '-o', 'json'
        ]

        # Add solc version if detected
        if solc_version:
            cmd.extend(['--solv', solc_version])
            print(f"Running Mythril on {relative_path} (solc {solc_version})", file=sys.stderr)
        else:
            print(f"Running Mythril on {relative_path}", file=sys.stderr)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 60s timeout per file (reduced from 120)
                cwd=repo_dir  # Run from repo dir for better import resolution
            )

            # Debug: print stderr if no findings
            if result.returncode != 0 and not result.stdout:
                if result.stderr:
                    # Only print first line of error for brevity
                    err_line = result.stderr.strip().split('\n')[0][:200]
                    print(f"Mythril stderr: {err_line}", file=sys.stderr)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)

                    for issue in data.get('issues', []):
                        severity_map = {
                            'High': 'high',
                            'Medium': 'medium',
                            'Low': 'low'
                        }
                        severity = severity_map.get(issue.get('severity', 'Medium'), 'medium')

                        findings.append({
                            'id': hashlib.md5(f"mythril-{issue.get('swc-id', '')}-{relative_path}:{issue.get('lineno', 0)}".encode()).hexdigest()[:12],
                            'ruleId': f"mythril-swc-{issue.get('swc-id', 'unknown')}",
                            'severity': severity,
                            'category': 'code',
                            'title': f"[Mythril] {issue.get('title', 'Security Issue')}",
                            'description': issue.get('description', ''),
                            'location': {
                                'file': relative_path,
                                'line': issue.get('lineno', 0),
                                'column': 0
                            },
                            'snippet': {
                                'code': issue.get('code', ''),
                                'highlightLines': [issue.get('lineno', 0)]
                            },
                            'fix': {
                                'available': False,
                                'template': None
                            },
                            'references': [f"https://swcregistry.io/docs/SWC-{issue.get('swc-id', '')}"]
                        })

                except json.JSONDecodeError:
                    # Mythril may output non-JSON on errors
                    pass

        except subprocess.TimeoutExpired:
            print(f"Mythril timeout for {relative_path}", file=sys.stderr)
        except Exception as e:
            print(f"Mythril error for {relative_path}: {e}", file=sys.stderr)

    print(f"Mythril found {len(findings)} findings", file=sys.stderr)
    return findings


# Nuclei removed - it's a DAST tool for scanning live web apps, not source code.
# Our SAST needs are covered by Opengrep + Gitleaks.


def run_solhint(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Solhint Solidity linter for security and style issues

    Solhint checks for:
    - Security issues (avoid-tx-origin, avoid-sha3, etc.)
    - Best practices (no-unused-vars, no-empty-blocks, etc.)
    - Style guide compliance

    Complements Slither/Aderyn with additional lint-style checks.
    """
    findings = []

    # Check for Solidity files
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib']]
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    if not sol_files:
        print("No Solidity files found, skipping Solhint", file=sys.stderr)
        return findings

    print(f"Found {len(sol_files)} Solidity files for Solhint", file=sys.stderr)

    # Create a temporary .solhint.json config with recommended + security rules
    solhint_config = {
        "extends": "solhint:recommended",
        "rules": {
            # Security rules (ERROR severity)
            "avoid-tx-origin": "error",
            "avoid-sha3": "warn",
            "func-visibility": ["error", {"ignoreConstructors": True}],
            "state-visibility": "error",
            "avoid-call-value": "error",
            "check-send-result": "error",
            "reentrancy": "error",
            "avoid-suicide": "error",
            "avoid-throw": "warn",
            "compiler-version": "off",  # Don't enforce specific version
            "no-inline-assembly": "warn",
            # Best practice rules
            "not-rely-on-time": "warn",
            "not-rely-on-block-hash": "warn",
            "no-complex-fallback": "warn",
            "no-empty-blocks": "warn"
        }
    }

    config_path = os.path.join(repo_dir, '.solhint.json')
    config_existed = os.path.exists(config_path)
    if not config_existed:
        with open(config_path, 'w') as f:
            json.dump(solhint_config, f)

    # Run solhint with JSON output - pass actual files, not glob (subprocess doesn't expand globs)
    cmd = [
        'solhint',
        '--formatter', 'json',
    ] + sol_files  # Pass the actual file paths

    try:
        print(f"Running Solhint on {len(sol_files)} files (individually)", file=sys.stderr)
        parse_errors = 0

        # Process files one at a time to avoid parse errors breaking everything
        for sol_file in sol_files:
            file_cmd = ['solhint', '--formatter', 'json', sol_file]
            try:
                result = subprocess.run(
                    file_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=repo_dir
                )

                # Make path relative
                rel_file = sol_file
                if rel_file.startswith(repo_dir):
                    rel_file = rel_file[len(repo_dir):].lstrip('/').lstrip('\\')

                # Solhint outputs JSON - may go to stdout or stderr depending on platform
                # Check both, preferring the one with JSON content
                output = ''
                for out in [result.stderr or '', result.stdout or '']:
                    if '[' in out and ']' in out:
                        output = out
                        break

                if not output:
                    output = result.stderr or result.stdout or ''

                # Find the JSON array in the output (may have debug noise before it)
                json_start = output.find('[')
                json_end = output.rfind(']')

                if json_start >= 0 and json_end > json_start:
                    json_str = output[json_start:json_end + 1]
                    try:
                        data = json.loads(json_str)

                        # Solhint outputs flat array of findings + conclusion object
                        # Format: [{line, column, severity, message, ruleId, filePath}, ..., {conclusion: "..."}]
                        for msg in data:
                            # Skip the conclusion summary object
                            if 'conclusion' in msg:
                                continue

                            # Skip if no ruleId (invalid entry)
                            rule_id = msg.get('ruleId')
                            if not rule_id:
                                continue

                            # Map severity: "Error" = high, "Warning" = medium/low
                            severity_str = msg.get('severity', 'Warning')
                            severity = 'medium' if severity_str == 'Error' else 'low'

                            # Map security rules to higher severity
                            security_rules = ['avoid-tx-origin', 'avoid-sha3', 'avoid-suicide',
                                             'avoid-throw', 'func-visibility', 'state-visibility',
                                             'avoid-call-value', 'check-send-result', 'reentrancy',
                                             'no-inline-assembly', 'not-rely-on-time', 'not-rely-on-block-hash']
                            if rule_id in security_rules:
                                severity = 'high' if severity_str == 'Error' else 'medium'

                            findings.append({
                                'id': hashlib.md5(f"solhint-{rule_id}-{rel_file}:{msg.get('line', 0)}".encode()).hexdigest()[:12],
                                'ruleId': f"solhint-{rule_id}",
                                'severity': severity,
                                'category': 'code',
                                'title': f"[Solhint] {msg.get('message', 'Issue')}",
                                'description': msg.get('message', ''),
                                'location': {
                                    'file': rel_file,
                                    'line': msg.get('line', 0),
                                    'column': msg.get('column', 0)
                                },
                                'fix': {
                                    'available': False,
                                    'template': None
                                },
                                'references': [f"https://protofire.github.io/solhint/docs/rules/{rule_id}"]
                            })
                    except json.JSONDecodeError:
                        parse_errors += 1
                else:
                    # No JSON found in output - could be no issues or a real error
                    if result.returncode == 255:
                        # Config error
                        parse_errors += 1

            except subprocess.TimeoutExpired:
                parse_errors += 1
            except Exception:
                parse_errors += 1

        print(f"Solhint found {len(findings)} findings", file=sys.stderr)
        if parse_errors > 0:
            print(f"Solhint: {parse_errors} files had parse errors (skipped)", file=sys.stderr)

    except FileNotFoundError:
        print("Solhint not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Solhint error: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        # Clean up temp config if we created it
        if not config_existed and os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception:
                pass

    print(f"Solhint found {len(findings)} findings", file=sys.stderr)
    return findings


def run_echidna(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Echidna property-based fuzzer on Solidity contracts

    Echidna is a fuzzer that:
    - Finds invariant violations through property-based testing
    - Detects assertion failures and revert conditions
    - Discovers unexpected state transitions
    - Requires contracts to have property tests (echidna_* functions)

    Note: Echidna requires:
    1. Compilable contracts (foundry.toml or hardhat.config.js)
    2. Property tests defined (function echidna_*() returns (bool))
    3. Can be slow (runs multiple iterations)
    """
    findings = []

    # Check for Solidity files
    sol_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'out', 'cache']]
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    if not sol_files:
        print("No Solidity files found, skipping Echidna", file=sys.stderr)
        return findings

    # Check if project has echidna property tests
    has_echidna_tests = False
    for sol_file in sol_files[:20]:  # Check first 20 files
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if 'echidna_' in content or 'invariant_' in content:
                    has_echidna_tests = True
                    break
        except Exception:
            continue

    if not has_echidna_tests:
        print("No Echidna property tests found (echidna_* or invariant_*), skipping", file=sys.stderr)
        return findings

    print(f"Found {len(sol_files)} Solidity files with Echidna tests", file=sys.stderr)

    # Check for foundry.toml (Foundry project) or hardhat.config (Hardhat)
    has_foundry = os.path.exists(os.path.join(repo_dir, 'foundry.toml'))
    has_hardhat = os.path.exists(os.path.join(repo_dir, 'hardhat.config.js')) or \
                  os.path.exists(os.path.join(repo_dir, 'hardhat.config.ts'))

    if not has_foundry and not has_hardhat:
        print("No build config (foundry.toml or hardhat.config) found, skipping Echidna", file=sys.stderr)
        return findings

    # Echidna config - run quick mode for CI
    config_content = """
testLimit: 1000
shrinkLimit: 100
seqLen: 50
testMode: "assertion"
"""

    config_path = os.path.join(repo_dir, 'echidna.yaml')
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
    except Exception as e:
        print(f"Could not create Echidna config: {e}", file=sys.stderr)
        return findings

    try:
        # Run echidna
        cmd = [
            'echidna',
            '.',
            '--config', 'echidna.yaml',
            '--format', 'json'
        ]

        print(f"Running Echidna in {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,  # 3 min timeout for fuzzing
            cwd=repo_dir
        )

        print(f"Echidna exit code: {result.returncode}", file=sys.stderr)

        # Parse JSON output
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                # Echidna JSON format: list of test results
                if isinstance(data, list):
                    for test in data:
                        if test.get('status') == 'falsified':
                            # Found invariant violation!
                            name = test.get('name', 'unknown')
                            findings.append({
                                'id': hashlib.md5(f"echidna-{name}".encode()).hexdigest()[:12],
                                'ruleId': 'echidna-invariant-violation',
                                'severity': 'critical',
                                'category': 'fuzzing',
                                'title': f"[Echidna] Invariant Violated: {name}",
                                'description': f"Property test '{name}' was falsified. The fuzzer found inputs that violate this invariant.",
                                'location': {
                                    'file': test.get('contract', ''),
                                    'line': 0,
                                    'column': 0
                                },
                                'fix': {
                                    'available': False,
                                    'template': None
                                },
                                'references': ['https://github.com/crytic/echidna']
                            })
            except json.JSONDecodeError as e:
                print(f"Echidna JSON parse error: {e}", file=sys.stderr)

        if result.stderr:
            print(f"Echidna stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Echidna timeout after 180s", file=sys.stderr)
    except FileNotFoundError:
        print("Echidna not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Echidna error: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        # Clean up config
        try:
            if os.path.exists(config_path):
                os.remove(config_path)
        except Exception:
            pass

    print(f"Echidna found {len(findings)} findings", file=sys.stderr)
    return findings


def run_foundry_fuzz(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Foundry's built-in fuzzer on project tests

    Foundry fuzz testing:
    - Runs fuzz tests (functions with fuzz_ prefix or random inputs)
    - Detects assertion failures and reverts
    - Tests invariants through property-based testing
    - Much faster than Echidna for basic fuzzing

    Requires:
    1. Foundry project (foundry.toml)
    2. Test files with fuzz tests
    """
    findings = []

    # Check for Foundry project
    if not os.path.exists(os.path.join(repo_dir, 'foundry.toml')):
        print("No foundry.toml found, skipping Foundry fuzz", file=sys.stderr)
        return findings

    # Check for test files with fuzz patterns
    test_files = []
    fuzz_test_found = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'out', 'cache']]
        for f in files:
            if f.endswith('.t.sol') or f.endswith('.test.sol'):
                test_files.append(os.path.join(root, f))
                # Quick check for fuzz tests
                try:
                    with open(os.path.join(root, f), 'r', encoding='utf-8', errors='ignore') as tf:
                        content = tf.read()
                        # Foundry fuzz tests have random inputs in function params
                        if 'function test' in content.lower() and ('uint' in content or 'int' in content or 'bytes' in content):
                            fuzz_test_found = True
                except Exception:
                    continue

    if not test_files:
        print("No test files (.t.sol) found, skipping Foundry fuzz", file=sys.stderr)
        return findings

    print(f"Found {len(test_files)} test files for Foundry fuzz", file=sys.stderr)

    try:
        # First, try to compile the project
        print("Compiling Foundry project...", file=sys.stderr)
        compile_result = subprocess.run(
            ['forge', 'build'],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_dir
        )

        if compile_result.returncode != 0:
            print(f"Forge build failed: {compile_result.stderr[:300]}", file=sys.stderr)
            return findings

        # Run fuzz tests with limited runs for speed
        cmd = [
            'forge', 'test',
            '--fuzz-runs', '100',  # Reduced for CI speed
            '--json'
        ]

        print(f"Running Foundry fuzz tests in {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout
            cwd=repo_dir
        )

        print(f"Forge test exit code: {result.returncode}", file=sys.stderr)

        # Parse JSON output (one JSON object per line)
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)

                    # Check test results for failures
                    for suite_name, suite in data.items():
                        if not isinstance(suite, dict):
                            continue

                        test_results = suite.get('test_results', {})
                        for test_name, test_result in test_results.items():
                            if not isinstance(test_result, dict):
                                continue

                            status = test_result.get('status')
                            if status == 'Failure':
                                # Found a fuzz test failure!
                                reason = test_result.get('reason', 'Unknown failure')
                                counterexample = test_result.get('counterexample', {})

                                desc = f"Fuzz test '{test_name}' failed: {reason}"
                                if counterexample:
                                    desc += f"\nCounterexample: {json.dumps(counterexample)}"

                                findings.append({
                                    'id': hashlib.md5(f"foundry-fuzz-{suite_name}-{test_name}".encode()).hexdigest()[:12],
                                    'ruleId': 'foundry-fuzz-failure',
                                    'severity': 'high',
                                    'category': 'fuzzing',
                                    'title': f"[Foundry Fuzz] {test_name} Failed",
                                    'description': desc,
                                    'location': {
                                        'file': suite_name.replace('::', '/') + '.sol' if '::' in suite_name else '',
                                        'line': 0,
                                        'column': 0
                                    },
                                    'fix': {
                                        'available': False,
                                        'template': None
                                    },
                                    'references': ['https://book.getfoundry.sh/forge/fuzz-testing']
                                })

                except json.JSONDecodeError:
                    continue

        if result.returncode != 0 and result.stderr:
            print(f"Forge test stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Foundry fuzz timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Forge not installed, skipping Foundry fuzz", file=sys.stderr)
    except Exception as e:
        print(f"Foundry fuzz error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Foundry fuzz found {len(findings)} findings", file=sys.stderr)
    return findings


def check_fuzz_coverage(repo_dir: str) -> List[Dict[str, Any]]:
    """Check for Solidity contracts that should have fuzz tests but don't

    This is a lightweight static check that flags:
    - Contracts with complex math (division, exponentiation) without fuzz tests
    - DeFi patterns (swap, deposit, withdraw) without fuzz tests
    - Gives developers actionable guidance on what to fuzz

    Returns INFO-level findings to guide developers.
    """
    findings = []

    # Patterns that indicate complex/risky operations needing fuzz tests
    FUZZ_WORTHY_PATTERNS = [
        (r'\s*\*\s*[^/]+\s*/\s*', 'Complex arithmetic (multiply then divide)'),
        (r'\.mul\([^)]+\)\.div\(', 'SafeMath arithmetic'),
        (r'\*\*\s*\d+', 'Exponentiation'),
        (r'Math\.sqrt\(', 'Square root calculation'),
        (r'Math\.mulDiv\(', 'MulDiv calculation'),
        (r'FullMath\.mulDiv\(', 'FullMath calculation'),
        (r'function\s+swap\s*\(', 'Swap function'),
        (r'function\s+deposit\s*\(', 'Deposit function'),
        (r'function\s+withdraw\s*\(', 'Withdraw function'),
        (r'function\s+mint\s*\(', 'Mint function'),
        (r'function\s+burn\s*\(', 'Burn function'),
        (r'function\s+liquidate\s*\(', 'Liquidation function'),
        (r'function\s+borrow\s*\(', 'Borrow function'),
        (r'function\s+repay\s*\(', 'Repay function'),
    ]

    # Find all Solidity source files (not tests)
    sol_files = []
    test_files = set()

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'out', 'cache', 'forge-std']]
        for f in files:
            if f.endswith('.sol'):
                filepath = os.path.join(root, f)
                if f.endswith('.t.sol') or 'test' in root.lower():
                    test_files.add(os.path.basename(f).replace('.t.sol', '').replace('.sol', ''))
                else:
                    sol_files.append(filepath)

    if not sol_files:
        return findings

    # Check each source file for fuzz-worthy patterns
    contracts_needing_fuzz = []

    for sol_file in sol_files:
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Get contract name
            contract_match = re.search(r'contract\s+(\w+)', content)
            if not contract_match:
                continue
            contract_name = contract_match.group(1)

            # Check if corresponding test file exists
            has_test = contract_name in test_files or f"{contract_name}Test" in test_files

            # Find risky patterns
            risky_patterns_found = []
            for pattern, description in FUZZ_WORTHY_PATTERNS:
                if re.search(pattern, content):
                    risky_patterns_found.append(description)

            if risky_patterns_found and not has_test:
                rel_path = os.path.relpath(sol_file, repo_dir)
                contracts_needing_fuzz.append({
                    'file': rel_path,
                    'contract': contract_name,
                    'patterns': risky_patterns_found[:3]  # Limit to top 3
                })
        except Exception:
            continue

    # Generate findings for contracts without fuzz coverage
    for contract in contracts_needing_fuzz[:10]:  # Limit to 10 findings
        patterns_str = ', '.join(contract['patterns'])
        findings.append({
            'id': hashlib.md5(f"fuzz-coverage-{contract['contract']}".encode()).hexdigest()[:12],
            'ruleId': 'missing-fuzz-coverage',
            'severity': 'info',
            'category': 'testing',
            'title': f"[Fuzz Coverage] {contract['contract']} has no fuzz tests",
            'description': f"Contract '{contract['contract']}' contains risky patterns ({patterns_str}) but has no corresponding fuzz tests. Consider adding invariant tests with Foundry or Echidna.",
            'location': {
                'file': contract['file'],
                'line': 1,
                'column': 0
            },
            'fix': {
                'available': False,
                'template': f"""// Add to test/{contract['contract']}.t.sol
function testFuzz_{contract['contract']}(uint256 input) public {{
    vm.assume(input > 0 && input < type(uint128).max);
    // Add invariant assertions
}}"""
            },
            'references': [
                'https://book.getfoundry.sh/forge/fuzz-testing',
                'https://github.com/crytic/echidna'
            ]
        })

    print(f"Fuzz coverage check found {len(findings)} contracts without fuzz tests", file=sys.stderr)
    return findings


# ============================================
# CONSOLIDATED SCANNER ORCHESTRATION
# All scanner execution goes through here
# Adding a new scanner? Just add it to SCANNERS list below!
# ============================================

# Scanner categories for visibility
SCANNER_CATEGORY_UNIVERSAL = 'universal'      # Always runs
SCANNER_CATEGORY_STACK = 'stack-specific'     # Only runs when relevant files detected

def run_all_scanners(repo_dir: str, stack: Dict[str, Any] = None, on_scanner_complete=None) -> Dict[str, Any]:
    """
    Run all security scanners in parallel and return combined results.

    This is the SINGLE SOURCE OF TRUTH for scanner execution.
    server.py and scan.py main() both call this function.

    Args:
        repo_dir: Path to the repository to scan
        stack: Detected stack info (languages, frameworks)
        on_scanner_complete: Optional callback called when each scanner completes.
            Signature: on_scanner_complete(scanner_status: dict)
            scanner_status contains: {
                'completed': int,  # Number of scanners completed so far
                'total': int,  # Total number of scanners
                'percent': int,  # Completion percentage (40-85 range)
                'current_scanner': str,  # Name of scanner that just completed
                'status': str,  # 'complete' or 'error'
                'findings': int,  # Number of findings from this scanner
                'duration_ms': int,  # How long this scanner took
                'scanners': list  # Full list of scanner statuses
            }

    To add a new scanner:
    1. Create run_newscanner() function above
    2. Add entry to SCANNERS list below with metadata
    3. That's it! No other changes needed.

    Returns:
        Dict with keys:
        - findings: List of all deduplicated findings
        - raw_count: Count before deduplication
        - scanner_results: Dict of {scanner_name: finding_count}
        - timing: Dict of {scanner_name: duration_ms}
        - scanners_run: List of scanners that actually executed
        - scanners_skipped: List of scanners skipped (no relevant files)
        - detected_stack: The detected languages/frameworks
    """
    from datetime import datetime

    if stack is None:
        stack = detect_stack(repo_dir)

    languages = stack.get('languages', [])
    frameworks = stack.get('frameworks', [])

    # ============================================
    # SCANNER REGISTRY - Add new scanners here!
    # Format: {
    #   'name': scanner name,
    #   'func': scanner function,
    #   'args': args tuple,
    #   'category': universal or stack-specific,
    #   'targets': what it scans (for display),
    #   'trigger': what causes it to run (for stack-specific)
    # }
    # ============================================
    SCANNERS = [
        {
            'name': 'opengrep',
            'func': run_opengrep,
            'args': (repo_dir, languages),
            'category': SCANNER_CATEGORY_UNIVERSAL,
            'targets': 'SAST patterns across all languages',
            'trigger': 'always'
        },
        {
            'name': 'trivy',
            'func': run_trivy,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_UNIVERSAL,
            'targets': 'Dependencies & secrets',
            'trigger': 'always'
        },
        {
            'name': 'gitleaks',
            'func': run_gitleaks,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_UNIVERSAL,
            'targets': 'Hardcoded secrets',
            'trigger': 'always'
        },
        {
            'name': 'retirejs',
            'func': run_retirejs,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'npm package vulnerabilities',
            'trigger': 'package.json'
        },
        {
            'name': 'hadolint',
            'func': run_hadolint,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Dockerfile best practices',
            'trigger': 'Dockerfile'
        },
        {
            'name': 'checkov',
            'func': run_checkov,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'IaC security (Terraform, K8s, Docker)',
            'trigger': '.tf, .yaml, k8s manifests'
        },
        {
            'name': 'brakeman',
            'func': run_brakeman,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Ruby on Rails vulnerabilities',
            'trigger': 'Rails app (Gemfile + routes.rb)'
        },
        {
            'name': 'slither',
            'func': run_slither,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Solidity smart contract issues',
            'trigger': '.sol files'
        },
        {
            'name': 'slither-upgradeability',
            'func': run_slither_upgradeability,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Storage collision in upgradeable contracts (SWC-124)',
            'trigger': 'Proxy/upgradeable patterns'
        },
        {
            'name': 'osv-scanner',
            'func': run_osv_scanner,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_UNIVERSAL,
            'targets': 'Dependency vulnerabilities (OSV database)',
            'trigger': 'always'
        },
        {
            'name': 'aderyn',
            'func': run_aderyn,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Solidity security patterns (Cyfrin)',
            'trigger': '.sol files'
        },
        {
            'name': 'mythril',
            'func': run_mythril,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Solidity symbolic execution',
            'trigger': '.sol files'
        },
        {
            'name': 'solhint',
            'func': run_solhint,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Solidity linting + security rules',
            'trigger': '.sol files'
        },
        {
            'name': 'echidna',
            'func': run_echidna,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Solidity invariant fuzzing',
            'trigger': '.sol files with echidna_* tests'
        },
        {
            'name': 'foundry-fuzz',
            'func': run_foundry_fuzz,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Foundry fuzz test failures',
            'trigger': 'foundry.toml + .t.sol files'
        },
        {
            'name': 'fuzz-coverage',
            'func': check_fuzz_coverage,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Missing fuzz test coverage detection',
            'trigger': '.sol files'
        },
    ]

    # Results storage
    scanner_findings = {s['name']: [] for s in SCANNERS}
    scanner_times = {}
    scanner_start_times = {}
    scanners_run = []
    scanners_skipped = []

    # Real-time scanner status tracking for progress callbacks
    scanner_statuses = {}
    for s in SCANNERS:
        scanner_statuses[s['name']] = {
            'name': s['name'],
            'category': s['category'],
            'targets': s['targets'],
            'trigger': s['trigger'],
            'status': 'pending',  # pending, running, complete, error, skipped
            'findings': 0,
            'duration_ms': 0
        }
    completed_count = 0

    # Log what we detected
    print(f"[Stack] Detected languages: {', '.join(languages) if languages else 'none'}", file=sys.stderr)
    print(f"[Stack] Detected frameworks: {', '.join(frameworks) if frameworks else 'none'}", file=sys.stderr)

    # Show scanner plan
    universal_count = len([s for s in SCANNERS if s['category'] == SCANNER_CATEGORY_UNIVERSAL])
    stack_count = len([s for s in SCANNERS if s['category'] == SCANNER_CATEGORY_STACK])
    print(f"[Scanners] Launching {len(SCANNERS)} scanners in parallel ({universal_count} universal + {stack_count} stack-specific)...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=len(SCANNERS)) as executor:
        # Submit all scanner jobs and mark as running
        futures = {}
        for scanner in SCANNERS:
            name = scanner['name']
            scanner_start_times[name] = datetime.now()
            scanner_statuses[name]['status'] = 'running'
            future = executor.submit(scanner['func'], *scanner['args'])
            futures[future] = scanner

        # Collect results as they complete
        for future in as_completed(futures):
            scanner = futures[future]
            name = scanner['name']
            scanner_end = datetime.now()
            duration_ms = int((scanner_end - scanner_start_times[name]).total_seconds() * 1000)
            scanner_times[name] = duration_ms
            completed_count += 1

            try:
                result = future.result()
                scanner_findings[name] = result
                finding_count = len(result)

                # Update scanner status
                scanner_statuses[name]['status'] = 'complete'
                scanner_statuses[name]['findings'] = finding_count
                scanner_statuses[name]['duration_ms'] = duration_ms

                # Track if scanner actually ran (found files) or was skipped
                # Scanners return [] for both "no findings" and "skipped"
                # We check the log messages to determine if it ran
                if result or scanner['category'] == SCANNER_CATEGORY_UNIVERSAL:
                    scanners_run.append({
                        'name': name,
                        'category': scanner['category'],
                        'targets': scanner['targets'],
                        'findings': finding_count,
                        'duration_ms': duration_ms
                    })
                    status = f"✓ {finding_count} findings"
                else:
                    # Stack-specific scanner with 0 findings could be skipped or just clean
                    # For now, track all stack-specific as "run" if they completed without error
                    scanners_run.append({
                        'name': name,
                        'category': scanner['category'],
                        'targets': scanner['targets'],
                        'findings': 0,
                        'duration_ms': duration_ms
                    })
                    status = "✓ clean"

                print(f"[Scanners] {name} ({duration_ms}ms) → {status}", file=sys.stderr)

            except Exception as e:
                print(f"[Scanners] {name} ({duration_ms}ms) → ✗ error: {e}", file=sys.stderr)
                scanner_statuses[name]['status'] = 'error'
                scanner_statuses[name]['duration_ms'] = duration_ms
                scanners_skipped.append({
                    'name': name,
                    'reason': str(e)
                })

            # Call progress callback if provided (regardless of success/error)
            if on_scanner_complete:
                try:
                    # Calculate progress percentage (scanners run from 40% to 85% of total)
                    scanner_percent = 40 + int((completed_count / len(SCANNERS)) * 45)
                    on_scanner_complete({
                        'completed': completed_count,
                        'total': len(SCANNERS),
                        'percent': scanner_percent,
                        'current_scanner': name,
                        'status': scanner_statuses[name]['status'],
                        'findings': scanner_statuses[name]['findings'],
                        'duration_ms': scanner_statuses[name]['duration_ms'],
                        'scanners': list(scanner_statuses.values())
                    })
                except Exception as cb_error:
                    print(f"[Scanners] Progress callback error: {cb_error}", file=sys.stderr)

    # Build visual summary
    print(f"\n[Scanners] ══════════════════════════════════════", file=sys.stderr)
    print(f"[Scanners] SCAN SUMMARY", file=sys.stderr)
    print(f"[Scanners] ──────────────────────────────────────", file=sys.stderr)

    # Group by category
    universal_scanners = [s for s in scanners_run if s['category'] == SCANNER_CATEGORY_UNIVERSAL]
    stack_scanners = [s for s in scanners_run if s['category'] == SCANNER_CATEGORY_STACK]

    print(f"[Scanners] Universal ({len(universal_scanners)}):", file=sys.stderr)
    for s in universal_scanners:
        print(f"[Scanners]   • {s['name']}: {s['findings']} findings ({s['duration_ms']}ms)", file=sys.stderr)

    if stack_scanners:
        active_stack = [s for s in stack_scanners if s['findings'] > 0]
        inactive_stack = [s for s in stack_scanners if s['findings'] == 0]

        if active_stack:
            print(f"[Scanners] Stack-specific (active):", file=sys.stderr)
            for s in active_stack:
                print(f"[Scanners]   • {s['name']}: {s['findings']} findings ({s['duration_ms']}ms)", file=sys.stderr)

        if inactive_stack:
            skipped_names = ', '.join([s['name'] for s in inactive_stack])
            print(f"[Scanners] Stack-specific (no relevant files): {skipped_names}", file=sys.stderr)

    print(f"[Scanners] ══════════════════════════════════════\n", file=sys.stderr)

    # Combine all findings
    all_findings = []
    for scanner in SCANNERS:
        all_findings.extend(scanner_findings[scanner['name']])

    raw_count = len(all_findings)
    print(f"[Scanners] Total raw findings: {raw_count}", file=sys.stderr)

    # Post-processing pipeline
    # 1. Calibrate severity (demote noisy rules)
    all_findings = calibrate_severity(all_findings)

    # 2. Filter test/mock paths
    all_findings = filter_test_paths(all_findings)
    print(f"[Scanners] After filtering: {len(all_findings)}", file=sys.stderr)

    # 3. Deduplicate
    all_findings = deduplicate_findings(all_findings)
    print(f"[Scanners] After deduplication: {len(all_findings)}", file=sys.stderr)

    return {
        'findings': all_findings,
        'raw_count': raw_count,
        'scanner_results': {s['name']: len(scanner_findings[s['name']]) for s in SCANNERS},
        'timing': scanner_times,
        'scanners_run': scanners_run,
        'scanners_skipped': scanners_skipped,
        'detected_stack': {
            'languages': languages,
            'frameworks': frameworks
        }
    }


def normalize_issue_type(finding: Dict[str, Any]) -> str:
    """
    Normalize finding to a canonical issue type.
    This helps deduplicate similar issues from different scanners.
    E.g., "hardcoded-api-key", "generic-api-key", "api_key_exposed" all become "secret"
    """
    rule_id = finding.get('ruleId', '').lower()
    title = finding.get('title', '').lower()
    category = finding.get('category', '').lower()
    combined = f"{rule_id} {title} {category}"

    # Map to canonical types
    if any(x in combined for x in ['secret', 'api-key', 'api_key', 'apikey', 'password', 'credential', 'token', 'private-key', 'private_key']):
        return 'secret'
    if any(x in combined for x in ['sql-injection', 'sql_injection', 'sqli']):
        return 'sqli'
    if any(x in combined for x in ['xss', 'cross-site', 'innerhtml', 'dangerously']):
        return 'xss'
    if any(x in combined for x in ['command-injection', 'command_injection', 'os-command', 'shell-injection']):
        return 'cmdi'
    if any(x in combined for x in ['path-traversal', 'path_traversal', 'directory-traversal', 'lfi']):
        return 'path-traversal'
    if any(x in combined for x in ['ssrf', 'server-side-request']):
        return 'ssrf'
    if any(x in combined for x in ['open-redirect', 'open_redirect', 'unvalidated-redirect']):
        return 'redirect'
    if any(x in combined for x in ['xxe', 'xml-external']):
        return 'xxe'
    if any(x in combined for x in ['deserialization', 'deserialize', 'pickle', 'yaml.load']):
        return 'deserialization'
    if any(x in combined for x in ['prototype-pollution', 'prototype_pollution']):
        return 'prototype-pollution'
    if any(x in combined for x in ['nosql', 'mongodb-injection']):
        return 'nosqli'
    if any(x in combined for x in ['weak-crypto', 'weak-hash', 'md5', 'sha1', 'des', 'rc4']):
        return 'weak-crypto'
    if any(x in combined for x in ['insecure-cookie', 'cookie', 'session']):
        return 'cookie'
    if any(x in combined for x in ['cors', 'cross-origin']):
        return 'cors'
    if any(x in combined for x in ['csrf', 'cross-site-request']):
        return 'csrf'
    if any(x in combined for x in ['eval', 'code-injection', 'code_injection']):
        return 'code-injection'
    if any(x in combined for x in ['missing-auth', 'no-auth', 'authentication']):
        return 'auth'
    if any(x in combined for x in ['vulnerable', 'cve-', 'dependency', 'outdated']):
        return 'dependency'

    # Default: use simplified rule_id
    return rule_id.split('-')[0] if rule_id else 'unknown'


# ============================================
# FINDING POST-PROCESSING
# Severity calibration and path filtering
# ============================================

# Benchmark mode: Set BENCHMARK_MODE=1 to disable test path filtering
# Useful for validating coverage on security benchmark repos like DeFiVulnLabs
def is_benchmark_mode() -> bool:
    """Check if benchmark mode is enabled (checked at runtime)"""
    return os.environ.get('BENCHMARK_MODE', '').lower() in ('1', 'true', 'yes')

# Rules to demote to INFO (noisy, not security-critical)
DEMOTE_TO_INFO_RULES = [
    'solhint-use-natspec',           # Code style, not security
    'solhint-no-global-import',      # Code style
    'solhint-gas-small-strings',     # Gas optimization, not security
    'solhint-quotes',                # String formatting
    'solhint-visibility-modifier-order',  # Code style
    'solhint-func-order',            # Code style
]

# Path patterns to filter out (test/mock directories)
# Disabled in BENCHMARK_MODE
SKIP_PATH_PATTERNS = [
    '/test/',
    '/tests/',
    '/mock/',
    '/mocks/',
    '/fixture/',
    '/fixtures/',
    '/_test.',
    '.test.',
    '_test.sol',
    'Test.sol',
    '.spec.',
    '/forge-std/',     # Foundry standard library
    '/lib/openzeppelin',  # Known good libraries
]


def calibrate_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Demote noisy rules to INFO severity.
    This reduces their impact on score while keeping them visible.
    """
    demoted_count = 0
    for finding in findings:
        rule_id = finding.get('ruleId', '')
        if rule_id in DEMOTE_TO_INFO_RULES:
            if finding.get('severity', '') != 'info':
                finding['severity'] = 'info'
                finding['demoted'] = True  # Mark as demoted for transparency
                demoted_count += 1

    if demoted_count > 0:
        print(f"[Filter] Demoted {demoted_count} noisy findings to INFO severity", file=sys.stderr)

    return findings


def filter_test_paths(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter out findings from test/mock directories.
    These are expected to contain vulnerable patterns for testing.

    Disabled when BENCHMARK_MODE=1 for validating security benchmark repos.
    """
    if is_benchmark_mode():
        print(f"[Filter] BENCHMARK_MODE enabled - skipping test path filtering", file=sys.stderr)
        return findings

    filtered = []
    skipped_count = 0

    for finding in findings:
        file_path = finding.get('location', {}).get('file', '')

        # Check if file matches any skip pattern
        should_skip = False
        for pattern in SKIP_PATH_PATTERNS:
            if pattern.lower() in file_path.lower():
                should_skip = True
                break

        if should_skip:
            skipped_count += 1
        else:
            filtered.append(finding)

    if skipped_count > 0:
        print(f"[Filter] Filtered out {skipped_count} findings from test/mock paths", file=sys.stderr)

    return filtered


def get_severity_priority(severity: str) -> int:
    """Higher number = higher priority (keep this one)"""
    priorities = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }
    return priorities.get(severity.lower(), 0)


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicates - same issue type at same file:line.

    Strategy:
    1. Group by file + line + normalized issue type
    2. Keep the highest severity finding from each group
    3. Merge scanner sources for better attribution

    This catches:
    - Exact duplicates (same rule, same location)
    - Near-duplicates (different scanners reporting same issue at same location)
    - Similar rules (e.g., "hardcoded-api-key" vs "generic-secret" at same line)
    """
    # Group findings by location + issue type
    location_groups: Dict[str, List[Dict[str, Any]]] = {}

    for finding in findings:
        loc = finding.get('location', {})
        file_path = loc.get('file', '')
        line = loc.get('line', 0)
        issue_type = normalize_issue_type(finding)

        # Key is: file + line + issue_type
        key = f"{file_path}:{line}:{issue_type}"

        if key not in location_groups:
            location_groups[key] = []
        location_groups[key].append(finding)

    # For each group, keep the best finding (highest severity)
    deduplicated = []
    for key, group in location_groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
        else:
            # Sort by severity priority (highest first)
            sorted_group = sorted(group, key=lambda f: get_severity_priority(f.get('severity', 'info')), reverse=True)
            best = sorted_group[0].copy()

            # Add metadata about merged findings
            if len(group) > 1:
                other_rules = [f.get('ruleId', 'unknown') for f in sorted_group[1:]]
                best['mergedFrom'] = other_rules
                best['mergedCount'] = len(group)

            deduplicated.append(best)

    return deduplicated


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate security score from findings"""
    score = 100

    deductions = {
        'critical': 25,
        'high': 10,
        'medium': 5,
        'low': 2,
        'info': 0
    }

    max_deductions = {
        'critical': 100,
        'high': 50,
        'medium': 30,
        'low': 15,
        'info': 0
    }

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1

    for sev in ['critical', 'high', 'medium', 'low']:
        deduction = min(counts[sev] * deductions[sev], max_deductions[sev])
        score -= deduction

    return max(0, min(100, score))


def calculate_grade(score: int) -> str:
    """Calculate letter grade from score"""
    if score >= 90: return 'A'
    if score >= 80: return 'B'
    if score >= 70: return 'C'
    if score >= 60: return 'D'
    return 'F'


def calculate_ship_status(score: int) -> str:
    """Calculate ship status from score"""
    if score >= 90: return 'ship'
    if score >= 70: return 'review'
    if score >= 50: return 'fix'
    return 'danger'


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Vibeship Security Scanner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("repo_url", help="Repository URL to scan")
    parser.add_argument("branch", nargs="?", default="main", help="Branch to scan")
    args = parser.parse_args()
    repo_url = args.repo_url
    branch = args.branch
    if args.verbose:
        print("Verbose mode enabled", file=sys.stderr)

    start_time = datetime.now()
    timing = {}  # Track timing for each phase
    print(f"Starting scan of {repo_url}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, 'repo')

        # Clone phase
        clone_start = datetime.now()
        print(json.dumps({'step': 'clone', 'message': 'Cloning repository...'}), flush=True)
        if not clone_repo(repo_url, repo_dir, branch):
            print(json.dumps({'error': 'Failed to clone repository'}))
            sys.exit(1)
        timing['clone'] = int((datetime.now() - clone_start).total_seconds() * 1000)
        print(f"Clone completed in {timing['clone']}ms", file=sys.stderr)

        # Detect phase
        detect_start = datetime.now()
        print(json.dumps({'step': 'detect', 'message': 'Detecting stack...'}), flush=True)
        stack = detect_stack(repo_dir)
        timing['detect'] = int((datetime.now() - detect_start).total_seconds() * 1000)
        print(f"Detected stack: {stack} in {timing['detect']}ms", file=sys.stderr)

        # Run all scanners using consolidated function
        scan_start = datetime.now()
        print(json.dumps({'step': 'scan', 'message': 'Running security scans in parallel...'}), flush=True)

        scan_result = run_all_scanners(repo_dir, stack)
        all_findings = scan_result['findings']

        timing['scan'] = int((datetime.now() - scan_start).total_seconds() * 1000)
        timing['scanners'] = scan_result['timing']
        print(f"All scans completed in {timing['scan']}ms (parallel)", file=sys.stderr)

        print(json.dumps({'step': 'score', 'message': 'Calculating score...'}), flush=True)
        score = calculate_score(all_findings)
        grade = calculate_grade(score)
        ship_status = calculate_ship_status(score)

        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        timing['total'] = duration_ms

        # Create human-readable duration string
        if duration_ms < 1000:
            duration_human = f"{duration_ms}ms"
        elif duration_ms < 60000:
            duration_human = f"{duration_ms / 1000:.1f}s"
        else:
            minutes = duration_ms // 60000
            seconds = (duration_ms % 60000) / 1000
            duration_human = f"{minutes}m {seconds:.0f}s"

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info')
            counts[sev] = counts.get(sev, 0) + 1

        print(f"\n=== SCAN COMPLETE ===", file=sys.stderr)
        print(f"Total time: {duration_human} ({duration_ms}ms)", file=sys.stderr)
        print(f"  Clone: {timing.get('clone', 0)}ms", file=sys.stderr)
        print(f"  Detect: {timing.get('detect', 0)}ms", file=sys.stderr)
        print(f"  Scan: {timing.get('scan', 0)}ms (parallel)", file=sys.stderr)
        for scanner, ms in timing.get('scanners', {}).items():
            print(f"    - {scanner}: {ms}ms", file=sys.stderr)
        print(f"  Findings: {len(all_findings)} (after dedup)", file=sys.stderr)
        print(f"  Score: {score} ({grade})", file=sys.stderr)
        print(f"=====================\n", file=sys.stderr)

        result = {
            'status': 'complete',
            'score': score,
            'grade': grade,
            'shipStatus': ship_status,
            'summary': counts,
            'stack': stack,
            'findings': all_findings,
            'duration': duration_ms,
            'durationHuman': duration_human,
            'timing': timing
        }

        print(json.dumps({'step': 'complete', 'result': result}), flush=True)


if __name__ == '__main__':
    main()
