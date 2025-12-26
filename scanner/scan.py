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


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicates - same issue at same file:line.
    Strategy: Normalize title (strip, lowercase) + file + line
    This catches both exact duplicates and near-duplicates from similar rules.
    """
    seen = set()
    deduplicated = []

    for finding in findings:
        loc = finding.get('location', {})
        # Normalize title: strip whitespace and lowercase for comparison
        title = finding.get('title', '').strip().lower()
        file_path = loc.get('file', '')
        line = loc.get('line', 0)

        # Key is: normalized_title + file + line
        key = f"{title}:{file_path}:{line}"

        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)

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

        # Run all scanners in PARALLEL for speed optimization
        scan_start = datetime.now()
        print(json.dumps({'step': 'scan', 'message': 'Running security scans in parallel...'}), flush=True)

        opengrep_findings = []
        trivy_findings = []
        gitleaks_findings = []
        retirejs_findings = []
        scanner_times = {}  # Track individual scanner times

        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all scanner jobs with their start times
            scanner_start_times = {}
            futures = {}

            for scanner_name, scanner_func, args in [
                ('opengrep', run_opengrep, (repo_dir, stack.get('languages', []))),
                ('trivy', run_trivy, (repo_dir,)),
                ('gitleaks', run_gitleaks, (repo_dir,)),
                ('retirejs', run_retirejs, (repo_dir,)),
            ]:
                scanner_start_times[scanner_name] = datetime.now()
                future = executor.submit(scanner_func, *args)
                futures[future] = scanner_name

            # Collect results as they complete
            for future in as_completed(futures):
                scanner_name = futures[future]
                scanner_end = datetime.now()
                scanner_times[scanner_name] = int((scanner_end - scanner_start_times[scanner_name]).total_seconds() * 1000)
                try:
                    result = future.result()
                    if scanner_name == 'opengrep':
                        opengrep_findings = result
                    elif scanner_name == 'trivy':
                        trivy_findings = result
                    elif scanner_name == 'gitleaks':
                        gitleaks_findings = result
                    elif scanner_name == 'retirejs':
                        retirejs_findings = result
                    print(f"{scanner_name} completed in {scanner_times[scanner_name]}ms with {len(result)} findings", file=sys.stderr)
                except Exception as e:
                    print(f"{scanner_name} failed in {scanner_times[scanner_name]}ms: {e}", file=sys.stderr)

        timing['scan'] = int((datetime.now() - scan_start).total_seconds() * 1000)
        timing['scanners'] = scanner_times
        print(f"All scans completed in {timing['scan']}ms (parallel)", file=sys.stderr)

        all_findings = opengrep_findings + trivy_findings + gitleaks_findings + retirejs_findings
        print(f"Total raw findings: {len(all_findings)}", file=sys.stderr)

        # Deduplicate findings (multiple rules can flag same line)
        all_findings = deduplicate_findings(all_findings)
        print(f"After deduplication: {len(all_findings)}", file=sys.stderr)

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
