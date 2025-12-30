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
]


def clone_repo(url: str, target_dir: str, branch: str = 'main', github_token: str = None) -> bool:
    """Clone a git repository (shallow clone for speed)

    For private repos, uses the GitHub token for authentication.
    URL format with token: https://oauth2:TOKEN@github.com/owner/repo.git
    """
    try:
        clone_url = url
        print(f"[Clone] Starting clone: url={url}, hasToken={bool(github_token)}", file=sys.stderr, flush=True)

        # If we have a GitHub token, inject it into the URL for authenticated cloning
        if github_token and 'github.com' in url:
            # Convert https://github.com/owner/repo to https://oauth2:TOKEN@github.com/owner/repo.git
            clone_url = url.replace('https://github.com/', f'https://oauth2:{github_token}@github.com/')
            if not clone_url.endswith('.git'):
                clone_url += '.git'
            print("[Clone] Using authenticated clone for private repo", file=sys.stderr, flush=True)

        # For logging, mask the token in the URL
        log_url = clone_url
        if github_token:
            log_url = clone_url.replace(github_token, 'TOKEN_HIDDEN')
        print(f"[Clone] Running: git clone --depth 1 --branch {branch} {log_url}", file=sys.stderr, flush=True)

        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--branch', branch, clone_url, target_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            # Mask token in error output
            stderr = result.stderr
            if github_token:
                stderr = stderr.replace(github_token, 'TOKEN_HIDDEN')
            print(f"[Clone] Branch clone failed (code {result.returncode}): {stderr}", file=sys.stderr, flush=True)

            print(f"[Clone] Retrying without branch specification...", file=sys.stderr, flush=True)
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', clone_url, target_dir],
                capture_output=True,
                text=True,
                timeout=120
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

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
            gen_result = subprocess.run(
                ['npm', 'install', '--package-lock-only', '--ignore-scripts'],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            if gen_result.returncode != 0:
                print(f"Could not generate package-lock.json: {gen_result.stderr[:200]}", file=sys.stderr)
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


def run_bandit(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Bandit Python security linter (PyCQA)

    Bandit is a Python security linter that:
    - Detects hardcoded passwords and secrets
    - Finds SQL injection vulnerabilities
    - Identifies command injection (subprocess, os.system)
    - Detects insecure pickle usage
    - Finds weak cryptography usage
    - Identifies assert statements in production code
    """
    findings = []

    # Check for Python files
    has_python = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.venv', '__pycache__', '.git']]
        if any(f.endswith('.py') for f in files):
            has_python = True
            break

    if not has_python:
        print("No Python files found, skipping Bandit", file=sys.stderr)
        return findings

    # Bandit severity mapping
    bandit_severity = {
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
    }

    cmd = [
        'bandit',
        '-r', repo_dir,
        '-f', 'json',
        '-ll',  # Only medium and high severity (skip LOW)
        '--exclude', '.git,node_modules,venv,.venv,__pycache__,test,tests'
    ]

    try:
        print(f"Running Bandit on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Bandit exits with 1 if issues found, which is expected
        print(f"Bandit exit code: {result.returncode}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                for issue in data.get('results', []):
                    severity = bandit_severity.get(issue.get('issue_severity', 'MEDIUM'), 'medium')
                    confidence = issue.get('issue_confidence', 'MEDIUM')

                    # Get relative file path
                    file_path = issue.get('filename', '')
                    if file_path.startswith(repo_dir):
                        file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')

                    line_number = issue.get('line_number', 0)
                    test_id = issue.get('test_id', 'B000')
                    test_name = issue.get('test_name', 'unknown')

                    findings.append({
                        'id': hashlib.md5(f"bandit-{test_id}-{file_path}:{line_number}".encode()).hexdigest()[:12],
                        'ruleId': f"bandit-{test_id}",
                        'severity': severity,
                        'category': 'code',
                        'title': f"[Bandit] {test_name}: {issue.get('issue_text', '')}",
                        'description': f"{issue.get('issue_text', '')} (Confidence: {confidence})",
                        'cwe': f"CWE-{issue.get('issue_cwe', {}).get('id', '0')}" if issue.get('issue_cwe') else None,
                        'location': {
                            'file': file_path,
                            'line': line_number,
                            'column': issue.get('col_offset', 0)
                        },
                        'fix': {
                            'available': False,
                            'template': None
                        },
                        'references': [f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}_{test_name.lower().replace(' ', '_')}.html"],
                        'code_snippet': issue.get('code', '')
                    })

                # Log metrics
                metrics = data.get('metrics', {})
                if metrics:
                    print(f"Bandit scanned {metrics.get('_totals', {}).get('loc', 0)} lines of code", file=sys.stderr)

            except json.JSONDecodeError as e:
                print(f"Bandit JSON parse error: {e}", file=sys.stderr)
                if result.stderr:
                    print(f"Bandit stderr: {result.stderr[:500]}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Bandit timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Bandit not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Bandit error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Bandit found {len(findings)} findings", file=sys.stderr)
    return findings


def run_gosec(repo_dir: str) -> List[Dict[str, Any]]:
    """Run Gosec Go security checker

    Gosec inspects Go source code for security problems:
    - SQL injection
    - Command injection
    - Hardcoded credentials
    - Weak crypto
    - Path traversal
    - Integer overflow
    """
    findings = []

    # Check for Go files
    has_go = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'vendor', '.git']]
        if any(f.endswith('.go') for f in files):
            has_go = True
            break

    if not has_go:
        print("No Go files found, skipping Gosec", file=sys.stderr)
        return findings

    # Check if there's a go.mod file and resolve dependencies if so
    go_mod_path = os.path.join(repo_dir, 'go.mod')
    if os.path.exists(go_mod_path):
        try:
            print("Resolving Go modules for Gosec...", file=sys.stderr)
            subprocess.run(
                ['go', 'mod', 'download'],
                cwd=repo_dir,
                capture_output=True,
                timeout=120
            )
        except Exception as e:
            print(f"Go mod download warning: {e}", file=sys.stderr)

    cmd = [
        'gosec',
        '-fmt', 'json',
        '-quiet',
        '-exclude-generated',  # Skip generated files
        './...'
    ]

    try:
        print(f"Running Gosec on {repo_dir}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Gosec exits with 1 if issues found
        print(f"Gosec exit code: {result.returncode}", file=sys.stderr)

        # Log any stderr for debugging
        if result.stderr:
            print(f"Gosec stderr: {result.stderr[:500]}", file=sys.stderr)

        if result.stdout:
            try:
                data = json.loads(result.stdout)

                for issue in data.get('Issues', []):
                    severity_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
                    severity = severity_map.get(issue.get('severity', 'MEDIUM'), 'medium')

                    file_path = issue.get('file', '')
                    if file_path.startswith(repo_dir):
                        file_path = file_path[len(repo_dir):].lstrip('/').lstrip('\\')

                    findings.append({
                        'id': hashlib.md5(f"gosec-{issue.get('rule_id', '')}-{file_path}:{issue.get('line', 0)}".encode()).hexdigest()[:12],
                        'ruleId': f"gosec-{issue.get('rule_id', 'G000')}",
                        'severity': severity,
                        'category': 'code',
                        'title': f"[Gosec] {issue.get('details', 'Security Issue')}",
                        'description': issue.get('details', ''),
                        'cwe': issue.get('cwe', {}).get('id') if issue.get('cwe') else None,
                        'location': {
                            'file': file_path,
                            'line': int(issue.get('line', 0)),
                            'column': int(issue.get('column', 0))
                        },
                        'snippet': {
                            'code': issue.get('code', ''),
                            'highlightLines': [int(issue.get('line', 0))]
                        },
                        'fix': {
                            'available': False,
                            'template': None
                        },
                        'references': [f"https://securego.io/docs/rules/{issue.get('rule_id', '').lower()}.html"]
                    })

            except json.JSONDecodeError as e:
                print(f"Gosec JSON parse error: {e}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print("Gosec timeout after 300s", file=sys.stderr)
    except FileNotFoundError:
        print("Gosec not installed, skipping", file=sys.stderr)
    except Exception as e:
        print(f"Gosec error: {type(e).__name__}: {e}", file=sys.stderr)

    print(f"Gosec found {len(findings)} findings", file=sys.stderr)
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

    # Check for Solidity files
    has_solidity = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ['node_modules', 'lib', '.git']]
        if any(f.endswith('.sol') for f in files):
            has_solidity = True
            break

    if not has_solidity:
        print("No Solidity files found, skipping Slither", file=sys.stderr)
        return findings

    # Check if this is a Foundry project and compile if so
    foundry_toml = os.path.join(repo_dir, 'foundry.toml')
    if os.path.exists(foundry_toml):
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
            print("Forge not available, Slither may fail on Foundry projects", file=sys.stderr)
        except Exception as e:
            print(f"Forge build error: {e}", file=sys.stderr)

    # Check for Hardhat project
    hardhat_config = os.path.join(repo_dir, 'hardhat.config.js') or os.path.join(repo_dir, 'hardhat.config.ts')
    if os.path.exists(os.path.join(repo_dir, 'hardhat.config.js')) or os.path.exists(os.path.join(repo_dir, 'hardhat.config.ts')):
        try:
            print("Hardhat project detected, installing deps and compiling...", file=sys.stderr)
            subprocess.run(['npm', 'install'], cwd=repo_dir, capture_output=True, timeout=120)
            subprocess.run(['npx', 'hardhat', 'compile'], cwd=repo_dir, capture_output=True, timeout=120)
        except Exception as e:
            print(f"Hardhat setup warning: {e}", file=sys.stderr)

    cmd = [
        'slither',
        repo_dir,
        '--json', '-',
        '--exclude-informational',
        '--exclude-low',  # Focus on medium+ severity
        '--exclude-optimization'
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


# ============================================
# CONSOLIDATED SCANNER ORCHESTRATION
# All scanner execution goes through here
# Adding a new scanner? Just add it to SCANNERS list below!
# ============================================

# Scanner categories for visibility
SCANNER_CATEGORY_UNIVERSAL = 'universal'      # Always runs
SCANNER_CATEGORY_STACK = 'stack-specific'     # Only runs when relevant files detected

def run_all_scanners(repo_dir: str, stack: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run all security scanners in parallel and return combined results.

    This is the SINGLE SOURCE OF TRUTH for scanner execution.
    server.py and scan.py main() both call this function.

    To add a new scanner:
    1. Create run_newscanner() function above
    2. Add entry to SCANNERS list below with metadata
    3. That's it! No other changes needed.

    Args:
        repo_dir: Path to the cloned repository
        stack: Detected stack info (from detect_stack). If None, will be auto-detected.

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
            'name': 'bandit',
            'func': run_bandit,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Python security issues',
            'trigger': '.py files'
        },
        {
            'name': 'gosec',
            'func': run_gosec,
            'args': (repo_dir,),
            'category': SCANNER_CATEGORY_STACK,
            'targets': 'Go security issues',
            'trigger': '.go files'
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
    ]

    # Results storage
    scanner_findings = {s['name']: [] for s in SCANNERS}
    scanner_times = {}
    scanner_start_times = {}
    scanners_run = []
    scanners_skipped = []

    # Log what we detected
    print(f"[Stack] Detected languages: {', '.join(languages) if languages else 'none'}", file=sys.stderr)
    print(f"[Stack] Detected frameworks: {', '.join(frameworks) if frameworks else 'none'}", file=sys.stderr)

    # Show scanner plan
    universal_count = len([s for s in SCANNERS if s['category'] == SCANNER_CATEGORY_UNIVERSAL])
    stack_count = len([s for s in SCANNERS if s['category'] == SCANNER_CATEGORY_STACK])
    print(f"[Scanners] Launching {len(SCANNERS)} scanners in parallel ({universal_count} universal + {stack_count} stack-specific)...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=len(SCANNERS)) as executor:
        # Submit all scanner jobs
        futures = {}
        for scanner in SCANNERS:
            name = scanner['name']
            scanner_start_times[name] = datetime.now()
            future = executor.submit(scanner['func'], *scanner['args'])
            futures[future] = scanner

        # Collect results as they complete
        for future in as_completed(futures):
            scanner = futures[future]
            name = scanner['name']
            scanner_end = datetime.now()
            scanner_times[name] = int((scanner_end - scanner_start_times[name]).total_seconds() * 1000)

            try:
                result = future.result()
                scanner_findings[name] = result

                # Track if scanner actually ran (found files) or was skipped
                # Scanners return [] for both "no findings" and "skipped"
                # We check the log messages to determine if it ran
                if result or scanner['category'] == SCANNER_CATEGORY_UNIVERSAL:
                    scanners_run.append({
                        'name': name,
                        'category': scanner['category'],
                        'targets': scanner['targets'],
                        'findings': len(result),
                        'duration_ms': scanner_times[name]
                    })
                    status = f"✓ {len(result)} findings"
                else:
                    # Stack-specific scanner with 0 findings could be skipped or just clean
                    # For now, track all stack-specific as "run" if they completed without error
                    scanners_run.append({
                        'name': name,
                        'category': scanner['category'],
                        'targets': scanner['targets'],
                        'findings': 0,
                        'duration_ms': scanner_times[name]
                    })
                    status = "✓ clean"

                print(f"[Scanners] {name} ({scanner_times[name]}ms) → {status}", file=sys.stderr)
            except Exception as e:
                print(f"[Scanners] {name} ({scanner_times[name]}ms) → ✗ error: {e}", file=sys.stderr)
                scanners_skipped.append({
                    'name': name,
                    'reason': str(e)
                })

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

    # Deduplicate
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
    if len(sys.argv) < 2:
        print("Usage: scan.py <repo_url> [branch]", file=sys.stderr)
        sys.exit(1)

    repo_url = sys.argv[1]
    branch = sys.argv[2] if len(sys.argv) > 2 else 'main'

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
