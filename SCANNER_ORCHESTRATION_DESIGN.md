# Smart Scanner Orchestration Design

## Stack Detection → Tool Selection

The scanner should detect the project's tech stack and run ONLY relevant tools.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STACK DETECTION PHASE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Detect files:                                                              │
│  ├── *.sol, foundry.toml, hardhat.config.*  →  SOLIDITY                     │
│  ├── *.py, requirements.txt, pyproject.toml →  PYTHON                       │
│  ├── *.js, *.ts, package.json               →  JAVASCRIPT/TYPESCRIPT        │
│  ├── *.go, go.mod                           →  GO                           │
│  ├── *.rb, Gemfile                          →  RUBY                         │
│  ├── *.java, pom.xml, build.gradle          →  JAVA                         │
│  ├── *.rs, Cargo.toml                       →  RUST                         │
│  ├── *.tf, *.tfvars                         →  TERRAFORM                    │
│  ├── *.yaml (k8s manifests)                 →  KUBERNETES                   │
│  ├── Dockerfile, docker-compose.*           →  DOCKER                       │
│  └── *.php, composer.json                   →  PHP                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TOOL SELECTION MATRIX                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ ALWAYS RUN  │ Gitleaks (secrets in any language)                     │   │
│  │             │ Trivy (dependencies if lockfile exists)                │   │
│  │             │ Opengrep (language-specific rules auto-selected)       │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ SOLIDITY    │ Slither, Mythril, Aderyn, Echidna (if tests exist)     │   │
│  │ DETECTED    │ Foundry tests runner                                   │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ PYTHON      │ Bandit, Safety, Opengrep Python rules                  │   │
│  │ DETECTED    │ pip-audit, OSV-Scanner                                 │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ JAVASCRIPT  │ npm audit, ESLint security, Retire.js                  │   │
│  │ DETECTED    │ OSV-Scanner, Opengrep JS/TS rules                      │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ GO          │ Gosec, Staticcheck, Nancy (deps)                       │   │
│  │ DETECTED    │ govulncheck, Opengrep Go rules                         │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ RUBY        │ Brakeman, Bundler-audit                                │   │
│  │ DETECTED    │ Opengrep Ruby rules                                    │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ JAVA        │ SpotBugs + FindSecBugs, OWASP Dep Check                │   │
│  │ DETECTED    │ Opengrep Java rules                                    │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ RUST        │ cargo-audit, cargo-deny, clippy                        │   │
│  │ DETECTED    │ Opengrep Rust rules                                    │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ TERRAFORM   │ Checkov, tfsec (via Trivy), Terrascan                  │   │
│  │ DETECTED    │ KICS, Opengrep HCL rules                               │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ KUBERNETES  │ Checkov, Kubesec, Polaris, Trivy K8s                   │   │
│  │ DETECTED    │ KICS, Opengrep YAML rules                              │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ DOCKER      │ Hadolint (Dockerfile), Dockle, Trivy image scan        │   │
│  │ DETECTED    │ Checkov Dockerfile policies                            │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────┬────────────────────────────────────────────────────────┐   │
│  │ PHP         │ PHPCS-Security, Psalm (taint), PHPStan                 │   │
│  │ DETECTED    │ Opengrep PHP rules                                     │   │
│  └─────────────┴────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Scan Tiers (User-Selectable Speed vs Depth)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  SCAN TIER: QUICK (Default - 30 seconds)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Opengrep (pattern matching)                                              │
│  • Gitleaks (secrets)                                                       │
│  • Trivy (dependencies only, no container)                                  │
│  • npm audit (if JS)                                                        │
│                                                                             │
│  USE CASE: CI/CD on every commit, quick feedback                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SCAN TIER: STANDARD (2-5 minutes)                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Everything in QUICK                                                      │
│  • Slither (if Solidity)                                                    │
│  • Aderyn (if Solidity)                                                     │
│  • Bandit (if Python)                                                       │
│  • Gosec (if Go)                                                            │
│  • Brakeman (if Ruby)                                                       │
│  • OSV-Scanner (additional deps)                                            │
│  • Checkov (if IaC)                                                         │
│                                                                             │
│  USE CASE: PR reviews, pre-merge checks                                     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SCAN TIER: DEEP (10-30 minutes)                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Everything in STANDARD                                                   │
│  • Mythril (symbolic execution - slow but thorough)                         │
│  • SpotBugs + FindSecBugs (if Java)                                         │
│  • Container image scanning (Trivy, Grype)                                  │
│  • Full IaC analysis (Checkov + KICS + Terrascan)                           │
│                                                                             │
│  USE CASE: Release candidates, security audits, new repos                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SCAN TIER: AUDIT (30+ minutes, may require config)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Everything in DEEP                                                       │
│  • Echidna fuzzing (if Solidity + test properties exist)                    │
│  • Nuclei DAST (if deployed URL provided)                                   │
│  • Halmos formal verification (if specs exist)                              │
│  • CodeQL (semantic analysis)                                               │
│                                                                             │
│  USE CASE: Pre-audit preparation, mainnet launches, enterprise              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation: Stack Detection

```python
def detect_stack(repo_path: str) -> set[str]:
    """Detect project tech stack from file patterns."""
    stack = set()

    patterns = {
        'solidity': ['*.sol', 'foundry.toml', 'hardhat.config.*', 'truffle-config.js'],
        'python': ['*.py', 'requirements.txt', 'pyproject.toml', 'Pipfile'],
        'javascript': ['*.js', '*.jsx', 'package.json'],
        'typescript': ['*.ts', '*.tsx', 'tsconfig.json'],
        'go': ['*.go', 'go.mod', 'go.sum'],
        'ruby': ['*.rb', 'Gemfile', 'Gemfile.lock'],
        'java': ['*.java', 'pom.xml', 'build.gradle', 'build.gradle.kts'],
        'rust': ['*.rs', 'Cargo.toml', 'Cargo.lock'],
        'php': ['*.php', 'composer.json', 'composer.lock'],
        'terraform': ['*.tf', '*.tfvars', 'terraform.tfstate'],
        'kubernetes': ['**/k8s/*.yaml', '**/kubernetes/*.yaml', 'deployment.yaml'],
        'docker': ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'],
        'csharp': ['*.cs', '*.csproj', '*.sln'],
        'swift': ['*.swift', 'Package.swift'],
        'kotlin': ['*.kt', '*.kts'],
    }

    for tech, file_patterns in patterns.items():
        for pattern in file_patterns:
            if glob.glob(f"{repo_path}/**/{pattern}", recursive=True):
                stack.add(tech)
                break

    return stack


def select_tools(stack: set[str], tier: str = 'standard') -> list[str]:
    """Select tools based on detected stack and scan tier."""
    tools = ['opengrep', 'gitleaks', 'trivy']  # Always run

    tier_tools = {
        'quick': [],
        'standard': {
            'solidity': ['slither', 'aderyn'],
            'python': ['bandit', 'safety'],
            'go': ['gosec', 'govulncheck'],
            'ruby': ['brakeman', 'bundler-audit'],
            'javascript': ['npm-audit', 'retire-js'],
            'typescript': ['npm-audit', 'retire-js'],
            'terraform': ['checkov'],
            'kubernetes': ['checkov', 'kubesec'],
            'docker': ['hadolint'],
            'java': [],  # Basic only in standard
            'rust': ['cargo-audit'],
        },
        'deep': {
            'solidity': ['slither', 'aderyn', 'mythril'],
            'python': ['bandit', 'safety', 'osv-scanner'],
            'go': ['gosec', 'govulncheck', 'nancy'],
            'ruby': ['brakeman', 'bundler-audit'],
            'javascript': ['npm-audit', 'retire-js', 'osv-scanner'],
            'typescript': ['npm-audit', 'retire-js', 'osv-scanner'],
            'terraform': ['checkov', 'kics', 'terrascan'],
            'kubernetes': ['checkov', 'kubesec', 'polaris', 'kics'],
            'docker': ['hadolint', 'dockle', 'trivy-image'],
            'java': ['spotbugs', 'findsecbugs', 'owasp-dep-check'],
            'rust': ['cargo-audit', 'cargo-deny'],
            'php': ['phpcs-security', 'psalm'],
        },
        'audit': {
            # Everything in deep + advanced tools
            'solidity': ['slither', 'aderyn', 'mythril', 'echidna', 'halmos'],
            # ... etc
        }
    }

    for tech in stack:
        if tech in tier_tools.get(tier, {}):
            tools.extend(tier_tools[tier][tech])

    return list(set(tools))  # Deduplicate
```

---

## Scan Time Estimates by Tier

| Tier | Small Repo (<100 files) | Medium (100-1000) | Large (1000+) |
|------|------------------------|-------------------|---------------|
| Quick | 10-30 sec | 30-60 sec | 1-3 min |
| Standard | 1-2 min | 2-5 min | 5-10 min |
| Deep | 5-10 min | 10-20 min | 20-60 min |
| Audit | 15-30 min | 30-60 min | 1-3 hours |

---

## API Design

```bash
# Quick scan (default)
curl -X POST https://scanner.vibeship.co/api/scan \
  -d '{"repoUrl": "https://github.com/owner/repo"}'

# Standard scan
curl -X POST https://scanner.vibeship.co/api/scan \
  -d '{"repoUrl": "https://github.com/owner/repo", "tier": "standard"}'

# Deep scan
curl -X POST https://scanner.vibeship.co/api/scan \
  -d '{"repoUrl": "https://github.com/owner/repo", "tier": "deep"}'

# Audit scan with DAST
curl -X POST https://scanner.vibeship.co/api/scan \
  -d '{"repoUrl": "https://github.com/owner/repo", "tier": "audit", "deployedUrl": "https://app.example.com"}'

# Force specific tools
curl -X POST https://scanner.vibeship.co/api/scan \
  -d '{"repoUrl": "https://github.com/owner/repo", "tools": ["opengrep", "slither", "mythril"]}'
```
