# Vibeship Scanner Architecture

## Overview

A modular, parallel-execution scanner architecture supporting 15 languages with isolated rulesets, easy extensibility, and production-ready performance.

---

## Folder Structure

```
vibeship-scanner/
│
├── src/
│   ├── core/                       # Core scanning engine
│   │   ├── scanner.ts              # Main orchestrator
│   │   ├── language-detector.ts    # Auto-detect languages in codebase
│   │   ├── file-walker.ts          # Recursive file discovery
│   │   ├── optimizer.ts            # Scan optimization logic
│   │   └── result-aggregator.ts    # Combine results from workers
│   │
│   ├── workers/                    # Parallel execution workers
│   │   ├── worker-pool.ts          # Worker pool manager
│   │   ├── scan-worker.ts          # Individual worker logic
│   │   └── worker-types.ts         # Shared types
│   │
│   ├── parsers/                    # Language-specific parsing helpers
│   │   ├── base-parser.ts          # Abstract base
│   │   ├── javascript.ts
│   │   ├── python.ts
│   │   ├── solidity.ts
│   │   └── yaml.ts
│   │
│   ├── reporters/                  # Output formatters
│   │   ├── json-reporter.ts
│   │   ├── sarif-reporter.ts       # GitHub/IDE compatible
│   │   ├── html-reporter.ts
│   │   └── cli-reporter.ts
│   │
│   ├── api/                        # HTTP API (for Vibeship platform)
│   │   ├── routes/
│   │   │   ├── scan.ts
│   │   │   ├── results.ts
│   │   │   └── health.ts
│   │   └── server.ts
│   │
│   └── utils/
│       ├── logger.ts
│       ├── cache.ts                # Rule compilation cache
│       └── metrics.ts              # Performance tracking
│
├── rulesets/                       # ALL RULES LIVE HERE
│   │
│   ├── _shared/                    # Cross-language rules
│   │   ├── secrets.yaml            # Generic secret patterns
│   │   ├── urls.yaml               # Localhost, dev URLs
│   │   └── comments.yaml           # TODO/FIXME patterns
│   │
│   ├── _vibe/                      # Vibe-coder specific (your differentiator)
│   │   ├── slopsquatting.yaml      # Hallucinated packages
│   │   ├── ai-patterns.yaml        # Common AI mistakes
│   │   └── placeholder-secrets.yaml
│   │
│   ├── typescript/
│   │   ├── community/              # Pulled from Semgrep/Opengrep
│   │   │   ├── react.yaml
│   │   │   ├── nextjs.yaml
│   │   │   └── express.yaml
│   │   ├── custom/                 # Your additions
│   │   │   └── vibe-ts.yaml
│   │   └── index.yaml              # Manifest: which rules to load
│   │
│   ├── javascript/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── python/
│   │   ├── community/
│   │   │   ├── django.yaml
│   │   │   ├── flask.yaml
│   │   │   ├── fastapi.yaml
│   │   │   └── security.yaml
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── sql/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── go/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── php/
│   │   ├── community/
│   │   │   ├── laravel.yaml
│   │   │   └── wordpress.yaml
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── java/
│   │   ├── community/
│   │   │   └── spring.yaml
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── swift/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── kotlin/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── ruby/
│   │   ├── community/
│   │   │   └── rails.yaml
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── csharp/
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── solidity/                   # Web3
│   │   ├── community/
│   │   │   ├── reentrancy.yaml
│   │   │   ├── access-control.yaml
│   │   │   └── arithmetic.yaml
│   │   ├── custom/
│   │   │   └── vibe-solidity.yaml
│   │   └── index.yaml
│   │
│   ├── dart/                       # Flutter
│   │   ├── community/
│   │   ├── custom/
│   │   └── index.yaml
│   │
│   ├── shell/                      # Bash/Scripts
│   │   ├── community/
│   │   │   └── shellcheck.yaml
│   │   ├── custom/
│   │   │   └── vibe-shell.yaml
│   │   └── index.yaml
│   │
│   └── yaml/                       # Config files
│       ├── community/
│       │   ├── github-actions.yaml
│       │   ├── docker-compose.yaml
│       │   └── kubernetes.yaml
│       ├── custom/
│       └── index.yaml
│
├── config/
│   ├── default.yaml                # Default scan settings
│   ├── languages.yaml              # Language → extension mapping
│   ├── severity-weights.yaml       # Scoring configuration
│   └── optimization.yaml           # ⭐ NEW: Scan optimization settings
│
├── scripts/
│   ├── pull-community-rules.sh     # Fetch latest community rules
│   ├── validate-rules.sh           # Lint all YAML rules
│   └── benchmark.sh                # Performance testing
│
├── tests/
│   ├── fixtures/                   # Sample vulnerable code
│   │   ├── typescript/
│   │   ├── python/
│   │   ├── solidity/
│   │   └── ...
│   ├── unit/
│   └── integration/
│
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yaml
│   └── scanner.dockerfile          # Slim image for workers
│
├── package.json
├── tsconfig.json
└── README.md
```

---

## Key Architecture Decisions

### 1. Ruleset Index Pattern

Each language folder has an `index.yaml` manifest:

```yaml
# rulesets/python/index.yaml
name: python
extensions: [.py, .pyw, .pyi]
includes:
  # Shared rules applied to this language
  - ../_shared/secrets.yaml
  - ../_shared/urls.yaml
  - ../_vibe/slopsquatting.yaml
  - ../_vibe/ai-patterns.yaml
  
  # Community rules
  - community/django.yaml
  - community/flask.yaml
  - community/fastapi.yaml
  - community/security.yaml
  
  # Custom rules
  - custom/vibe-python.yaml

# Optional: exclude specific rule IDs
excludes:
  - python.lang.maintainability.useless-assertion  # Too noisy
```

**Benefits:**
- Add/remove rules without code changes
- Easy to enable/disable per-customer
- Version control friendly

---

### 2. Parallel Worker Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VIBESHIP SCANNER CORE                   │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   File      │  │   Language   │  │    Work Queue     │  │
│  │   Walker    │──│   Detector   │──│  (by language)    │  │
│  └─────────────┘  └──────────────┘  └─────────┬─────────┘  │
└───────────────────────────────────────────────┼─────────────┘
                                                │
                    ┌───────────────────────────┴───────────┐
                    │           WORKER POOL                 │
                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ │
                    │  │Worker 1 │ │Worker 2 │ │Worker N │ │
                    │  │(Python) │ │  (TS)   │ │ (Java)  │ │
                    │  └────┬────┘ └────┬────┘ └────┬────┘ │
                    └───────┼───────────┼───────────┼───────┘
                            │           │           │
                    ┌───────▼───────────▼───────────▼───────┐
                    │          RESULT AGGREGATOR            │
                    │  - Deduplicate                        │
                    │  - Sort by severity                   │
                    │  - Group by file                      │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │             REPORTERS                  │
                    │   JSON │ SARIF │ HTML │ CLI            │
                    └───────────────────────────────────────┘
```

---

### 3. Worker Implementation

```typescript
// src/workers/worker-pool.ts

import { Worker } from 'worker_threads';
import os from 'os';

interface ScanJob {
  files: string[];
  language: string;
  rulesetPath: string;
}

interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  timeMs: number;
}

export class WorkerPool {
  private workers: Worker[] = [];
  private queue: ScanJob[] = [];
  private maxWorkers: number;

  constructor(maxWorkers?: number) {
    // Default: CPU cores - 1 (leave one for main thread)
    this.maxWorkers = maxWorkers || Math.max(1, os.cpus().length - 1);
  }

  async scan(jobs: ScanJob[]): Promise<ScanResult[]> {
    // Group files by language for efficient batching
    const jobsByLanguage = this.groupByLanguage(jobs);
    
    // Create worker for each language (up to maxWorkers)
    const promises = Object.entries(jobsByLanguage).map(
      ([language, files]) => this.runWorker({ language, files, rulesetPath: `rulesets/${language}/index.yaml` })
    );

    return Promise.all(promises);
  }

  private runWorker(job: ScanJob): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const worker = new Worker('./src/workers/scan-worker.js', {
        workerData: job
      });

      worker.on('message', resolve);
      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0) {
          reject(new Error(`Worker exited with code ${code}`));
        }
      });
    });
  }

  private groupByLanguage(jobs: ScanJob[]): Record<string, string[]> {
    // Implementation
  }
}
```

```typescript
// src/workers/scan-worker.ts

import { parentPort, workerData } from 'worker_threads';
import { execSync } from 'child_process';

const { files, language, rulesetPath } = workerData;

async function scan() {
  const startTime = Date.now();
  
  // Write files to temp file for opengrep
  const fileListPath = `/tmp/scan-${process.pid}.txt`;
  fs.writeFileSync(fileListPath, files.join('\n'));

  // Run opengrep with the language-specific ruleset
  const result = execSync(
    `opengrep scan --config ${rulesetPath} --target-file ${fileListPath} --json`,
    { maxBuffer: 50 * 1024 * 1024 } // 50MB buffer for large codebases
  );

  const findings = JSON.parse(result.toString());

  parentPort?.postMessage({
    findings,
    filesScanned: files.length,
    timeMs: Date.now() - startTime
  });
}

scan().catch(err => {
  parentPort?.postMessage({ error: err.message });
});
```

---

### 4. Language Detection

```typescript
// src/core/language-detector.ts

interface LanguageConfig {
  name: string;
  extensions: string[];
  filenames?: string[];  // e.g., "Dockerfile", "Makefile"
  shebangs?: string[];   // e.g., "#!/bin/bash"
}

const LANGUAGES: LanguageConfig[] = [
  // HIGH PRIORITY (deep curation)
  { name: 'typescript', extensions: ['.ts', '.tsx', '.mts', '.cts'] },
  { name: 'javascript', extensions: ['.js', '.jsx', '.mjs', '.cjs'] },
  { name: 'python', extensions: ['.py', '.pyw', '.pyi'] },
  { name: 'sql', extensions: ['.sql'] },
  
  // MEDIUM PRIORITY
  { name: 'go', extensions: ['.go'] },
  { name: 'php', extensions: ['.php', '.phtml', '.php3', '.php4', '.php5'] },
  { name: 'java', extensions: ['.java'] },
  
  // LOWER PRIORITY
  { name: 'swift', extensions: ['.swift'] },
  { name: 'kotlin', extensions: ['.kt', '.kts'] },
  { name: 'ruby', extensions: ['.rb', '.rake', '.gemspec'], filenames: ['Gemfile', 'Rakefile'] },
  { name: 'csharp', extensions: ['.cs', '.csx'] },
  
  // NEW LANGUAGES
  { name: 'solidity', extensions: ['.sol'] },
  { name: 'dart', extensions: ['.dart'] },
  { name: 'shell', extensions: ['.sh', '.bash', '.zsh'], shebangs: ['#!/bin/bash', '#!/bin/sh', '#!/usr/bin/env bash'] },
  { name: 'yaml', extensions: ['.yaml', '.yml'], filenames: ['docker-compose.yml', '.github/workflows/*.yml'] },
];

export function detectLanguage(filePath: string, content?: string): string | null {
  const ext = path.extname(filePath).toLowerCase();
  const filename = path.basename(filePath);
  
  // Check exact filename matches first
  for (const lang of LANGUAGES) {
    if (lang.filenames?.includes(filename)) {
      return lang.name;
    }
  }
  
  // Check extensions
  for (const lang of LANGUAGES) {
    if (lang.extensions.includes(ext)) {
      return lang.name;
    }
  }
  
  // Check shebang if content provided
  if (content) {
    const firstLine = content.split('\n')[0];
    for (const lang of LANGUAGES) {
      if (lang.shebangs?.some(s => firstLine.startsWith(s))) {
        return lang.name;
      }
    }
  }
  
  return null;
}
```

---

### 5. Scan Flow

```typescript
// src/core/scanner.ts

import { WorkerPool } from '../workers/worker-pool';
import { detectLanguage } from './language-detector';
import { walkFiles } from './file-walker';
import { aggregateResults } from './result-aggregator';
import { loadOptimizationConfig } from './optimizer';

interface ScanOptions {
  path: string;
  languages?: string[];      // Filter to specific languages
  severity?: 'INFO' | 'WARNING' | 'ERROR';  // Minimum severity
  excludePaths?: string[];   // Glob patterns to skip
  maxWorkers?: number;
  preset?: 'quick' | 'standard' | 'deep' | 'ci';  // Optimization preset
}

export async function scan(options: ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const optConfig = loadOptimizationConfig(options.preset || 'standard');
  
  // 1. Walk filesystem and group files by language
  const filesByLanguage: Record<string, string[]> = {};
  
  for await (const filePath of walkFiles(options.path, options.excludePaths)) {
    // Skip files based on optimization config
    if (optConfig.skipLargeFiles && fs.statSync(filePath).size > optConfig.maxFileSizeBytes) {
      continue;
    }
    
    const language = detectLanguage(filePath);
    
    if (!language) continue;
    if (options.languages && !options.languages.includes(language)) continue;
    
    filesByLanguage[language] = filesByLanguage[language] || [];
    filesByLanguage[language].push(filePath);
  }
  
  // 2. Create worker pool and run parallel scans
  const pool = new WorkerPool(options.maxWorkers || optConfig.maxWorkers);
  
  const jobs = Object.entries(filesByLanguage).map(([language, files]) => ({
    language,
    files,
    rulesetPath: `rulesets/${language}/index.yaml`
  }));
  
  const results = await pool.scan(jobs);
  
  // 3. Aggregate and filter results
  const report = aggregateResults(results, {
    minSeverity: options.severity
  });
  
  report.metadata = {
    scanTimeMs: Date.now() - startTime,
    filesScanned: Object.values(filesByLanguage).flat().length,
    languagesDetected: Object.keys(filesByLanguage),
    preset: options.preset || 'standard'
  };
  
  return report;
}
```

---

### 6. Rule Compilation Cache

Compiling YAML rules is slow. Cache the compiled rules:

```typescript
// src/utils/cache.ts

import crypto from 'crypto';
import fs from 'fs';

const CACHE_DIR = '.vibeship-cache';

export class RuleCache {
  
  getCompiledRules(rulesetPath: string): CompiledRules | null {
    const hash = this.hashFile(rulesetPath);
    const cachePath = `${CACHE_DIR}/${hash}.json`;
    
    if (fs.existsSync(cachePath)) {
      return JSON.parse(fs.readFileSync(cachePath, 'utf8'));
    }
    
    return null;
  }
  
  setCompiledRules(rulesetPath: string, compiled: CompiledRules): void {
    const hash = this.hashFile(rulesetPath);
    const cachePath = `${CACHE_DIR}/${hash}.json`;
    
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(cachePath, JSON.stringify(compiled));
  }
  
  private hashFile(filePath: string): string {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
  }
}
```

---

## Config Files

### config/languages.yaml

```yaml
# Language configurations and priorities

languages:
  # Tier 1: Deep curation, most rules, priority support
  tier1:
    - typescript
    - javascript  
    - python
    - sql
  
  # Tier 2: Good coverage, community rules
  tier2:
    - go
    - php
    - java
    - solidity
  
  # Tier 3: Basic coverage
  tier3:
    - swift
    - kotlin
    - ruby
    - csharp
    - dart
    - shell
    - yaml

# File extension mappings
extensions:
  typescript: [.ts, .tsx, .mts, .cts]
  javascript: [.js, .jsx, .mjs, .cjs]
  python: [.py, .pyw, .pyi]
  sql: [.sql]
  go: [.go]
  php: [.php, .phtml]
  java: [.java]
  swift: [.swift]
  kotlin: [.kt, .kts]
  ruby: [.rb, .rake]
  csharp: [.cs]
  solidity: [.sol]
  dart: [.dart]
  shell: [.sh, .bash, .zsh]
  yaml: [.yaml, .yml]

# Default exclude patterns
defaultExcludes:
  - node_modules/**
  - vendor/**
  - .git/**
  - dist/**
  - build/**
  - __pycache__/**
  - "*.min.js"
  - "*.bundle.js"
```

### config/severity-weights.yaml

```yaml
# Severity scoring for prioritization

severities:
  ERROR:
    weight: 10
    color: red
    emoji: 🔴
    action: "Must fix before deploy"
    
  WARNING:
    weight: 5
    color: yellow
    emoji: 🟡
    action: "Should fix soon"
    
  INFO:
    weight: 1
    color: blue
    emoji: 🔵
    action: "Consider fixing"

# Category multipliers (boost certain issue types)
categoryMultipliers:
  injection: 1.5          # SQL, command, etc.
  authentication: 1.4
  secrets: 1.3
  supply-chain: 1.5       # Slopsquatting
  misconfiguration: 1.0
  code-quality: 0.8

# Vibe-specific boost (your differentiator gets priority)
vibeRuleBoost: 1.2
```

---

## ⭐ config/optimization.yaml (NEW)

```yaml
# =============================================================================
# VIBESHIP SCANNER - OPTIMIZATION CONFIGURATION
# =============================================================================
# Tune scan performance, resource usage, and accuracy trade-offs
# =============================================================================

# -----------------------------------------------------------------------------
# SCAN PRESETS
# -----------------------------------------------------------------------------
# Use these presets for common scenarios. Override individual settings below.
#
# Usage in code: scan({ preset: 'quick' })
# Usage in CLI:  vibeship scan --preset quick ./src

presets:
  # ⚡ QUICK - Fast feedback during development
  # Best for: Local dev, pre-commit hooks, rapid iteration
  # Trade-off: May miss complex vulnerabilities
  quick:
    maxWorkers: 2
    maxFileSizeKB: 100
    maxFilesPerLanguage: 200
    timeoutSeconds: 30
    ruleCategories:
      - secrets           # Always check for leaked secrets
      - injection         # Critical vulnerabilities
      - supply-chain      # Slopsquatting
    skipCategories:
      - code-quality
      - best-practice
      - maintainability
    severityMinimum: WARNING
    enableCache: true
    incrementalScan: true    # Only scan changed files (requires git)
    skipTests: true          # Skip **/test/**, **/*.test.*, etc.
    skipGenerated: true      # Skip generated code patterns

  # 🎯 STANDARD - Balanced for most use cases (DEFAULT)
  # Best for: Pull request checks, regular scans
  # Trade-off: Good balance of speed and coverage
  standard:
    maxWorkers: 4
    maxFileSizeKB: 500
    maxFilesPerLanguage: 1000
    timeoutSeconds: 120
    ruleCategories: all
    skipCategories:
      - maintainability
    severityMinimum: INFO
    enableCache: true
    incrementalScan: false
    skipTests: false
    skipGenerated: true

  # 🔬 DEEP - Maximum coverage
  # Best for: Security audits, pre-release checks, compliance
  # Trade-off: Slower, more findings (including low-confidence)
  deep:
    maxWorkers: 8
    maxFileSizeKB: 2000
    maxFilesPerLanguage: null  # No limit
    timeoutSeconds: 600
    ruleCategories: all
    skipCategories: []
    severityMinimum: INFO
    enableCache: true
    incrementalScan: false
    skipTests: false
    skipGenerated: false
    enableExperimental: true   # Include experimental/beta rules
    crossFileAnalysis: true    # Track data flow across files

  # 🚀 CI - Optimized for CI/CD pipelines
  # Best for: GitHub Actions, GitLab CI, Jenkins
  # Trade-off: Fail-fast on critical issues, minimal output noise
  ci:
    maxWorkers: 4
    maxFileSizeKB: 500
    maxFilesPerLanguage: 1000
    timeoutSeconds: 180
    ruleCategories:
      - secrets
      - injection
      - authentication
      - supply-chain
      - crypto
    skipCategories:
      - code-quality
      - maintainability
      - best-practice
    severityMinimum: WARNING
    enableCache: true
    incrementalScan: true      # Scan only changed files in PR
    skipTests: true
    skipGenerated: true
    failOnSeverity: ERROR      # Exit code 1 if any ERROR found
    sarifOutput: true          # GitHub code scanning compatible
    suppressDuplicates: true   # Don't report same issue twice

  # 🔒 SECURITY-ONLY - Pure security focus
  # Best for: Security team reviews, penetration testing prep
  security:
    maxWorkers: 6
    maxFileSizeKB: 1000
    maxFilesPerLanguage: null
    timeoutSeconds: 300
    ruleCategories:
      - injection
      - authentication
      - authorization
      - crypto
      - secrets
      - supply-chain
      - xss
      - ssrf
      - deserialization
    skipCategories:
      - code-quality
      - maintainability
      - best-practice
      - performance
    severityMinimum: INFO
    enableCache: true
    crossFileAnalysis: true

# -----------------------------------------------------------------------------
# WORKER & PARALLELISM SETTINGS
# -----------------------------------------------------------------------------

workers:
  # Maximum concurrent workers (0 = auto-detect based on CPU cores)
  maxWorkers: 0
  
  # Workers = min(maxWorkers, cpuCores * cpuMultiplier)
  cpuMultiplier: 0.75
  
  # Memory limit per worker (MB) - worker restarts if exceeded
  memoryLimitMB: 512
  
  # Worker idle timeout - terminate after N seconds of inactivity
  idleTimeoutSeconds: 30
  
  # Batch size: files per worker task
  batchSize: 50
  
  # Strategy for distributing work
  # Options: by-language, by-file-count, round-robin
  distribution: by-language

# -----------------------------------------------------------------------------
# FILE FILTERING
# -----------------------------------------------------------------------------

files:
  # Maximum file size to scan (larger files are skipped)
  maxSizeKB: 500
  
  # Maximum files per language (prevents runaway scans)
  maxPerLanguage: 1000
  
  # Maximum total files (hard limit)
  maxTotal: 10000
  
  # Skip files matching these patterns (in addition to defaultExcludes)
  additionalExcludes:
    - "**/*.min.js"
    - "**/*.min.css"
    - "**/*.bundle.js"
    - "**/*.chunk.js"
    - "**/vendor/**"
    - "**/third_party/**"
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/out/**"
    - "**/__pycache__/**"
    - "**/*.pyc"
    - "**/coverage/**"
    - "**/.nyc_output/**"
    - "**/package-lock.json"
    - "**/yarn.lock"
    - "**/pnpm-lock.yaml"
    - "**/Cargo.lock"
    - "**/poetry.lock"
    - "**/Pipfile.lock"
    - "**/composer.lock"
  
  # Skip test files in quick/CI modes
  testPatterns:
    - "**/*.test.ts"
    - "**/*.test.js"
    - "**/*.spec.ts"
    - "**/*.spec.js"
    - "**/test/**"
    - "**/tests/**"
    - "**/__tests__/**"
    - "**/test_*.py"
    - "**/*_test.py"
    - "**/*_test.go"
  
  # Skip generated code patterns
  generatedPatterns:
    - "**/*.generated.*"
    - "**/*.g.dart"
    - "**/generated/**"
    - "**/*.pb.go"
    - "**/*_pb2.py"
    - "**/prisma/client/**"
    - "**/graphql/generated/**"

# -----------------------------------------------------------------------------
# CACHING
# -----------------------------------------------------------------------------

cache:
  # Enable rule compilation caching
  enabled: true
  
  # Cache directory (relative to project root)
  directory: ".vibeship-cache"
  
  # Cache TTL in hours (0 = never expire)
  ttlHours: 168  # 1 week
  
  # Maximum cache size in MB (LRU eviction)
  maxSizeMB: 100
  
  # Cache scan results for unchanged files
  cacheResults: true
  
  # Use content hash for cache keys (more accurate but slower)
  useContentHash: true

# -----------------------------------------------------------------------------
# INCREMENTAL SCANNING
# -----------------------------------------------------------------------------

incremental:
  # Enable incremental scanning (only scan changed files)
  enabled: false
  
  # Git-based change detection
  git:
    # Compare against this ref (branch, tag, or commit)
    baseRef: "main"
    
    # Include untracked files
    includeUntracked: true
    
    # Include staged files
    includeStaged: true
  
  # File modification time-based (fallback when git unavailable)
  mtime:
    # Only scan files modified in last N hours
    withinHours: 24

# -----------------------------------------------------------------------------
# RULE OPTIMIZATION
# -----------------------------------------------------------------------------

rules:
  # Timeout per rule execution (ms)
  timeoutMs: 5000
  
  # Skip rules that consistently timeout
  skipSlowRules: true
  
  # Threshold for marking a rule as "slow" (ms)
  slowThresholdMs: 2000
  
  # Maximum findings per rule per file (prevents noisy rules from flooding)
  maxFindingsPerRulePerFile: 10
  
  # Maximum total findings per file
  maxFindingsPerFile: 50
  
  # Deduplicate identical findings across rules
  deduplicateFindings: true
  
  # Rule warm-up: pre-compile rules on startup
  precompile: true

# -----------------------------------------------------------------------------
# LANGUAGE-SPECIFIC OPTIMIZATIONS
# -----------------------------------------------------------------------------

languageOptimizations:
  typescript:
    # Parse with TypeScript compiler for better accuracy
    useTypeChecker: false  # Slower but more accurate
    # Skip declaration files
    skipDts: true
  
  javascript:
    # Skip minified files even if under size limit
    detectMinified: true
  
  python:
    # Skip __init__.py files that are just imports
    skipEmptyInits: true
  
  solidity:
    # Include OpenZeppelin patterns
    checkOpenZeppelin: true
  
  yaml:
    # Only scan config files, not data files
    configFilesOnly: true
    configPatterns:
      - "**/docker-compose*.yml"
      - "**/.github/workflows/*.yml"
      - "**/k8s/**/*.yaml"
      - "**/kubernetes/**/*.yaml"
      - "**/helm/**/*.yaml"
      - "**/serverless.yml"
      - "**/cloudformation*.yaml"

# -----------------------------------------------------------------------------
# OUTPUT & REPORTING
# -----------------------------------------------------------------------------

output:
  # Default output format
  format: json  # json, sarif, html, cli
  
  # Pretty print JSON output
  prettyPrint: false
  
  # Include code snippets in findings
  includeSnippets: true
  
  # Snippet context lines (before and after)
  snippetContext: 3
  
  # Group findings by file or by rule
  groupBy: file  # file, rule, severity, category
  
  # Sort order
  sortBy: severity  # severity, file, rule, line
  
  # Maximum findings in output (0 = unlimited)
  maxFindings: 500
  
  # Suppress findings below this confidence
  minConfidence: medium  # low, medium, high

# -----------------------------------------------------------------------------
# TIMEOUTS & LIMITS
# -----------------------------------------------------------------------------

limits:
  # Overall scan timeout (seconds, 0 = unlimited)
  scanTimeoutSeconds: 300
  
  # Per-file timeout (seconds)
  fileTimeoutSeconds: 30
  
  # Per-worker timeout (seconds)
  workerTimeoutSeconds: 120
  
  # Memory limit for entire scan process (MB, 0 = unlimited)
  memoryLimitMB: 4096
  
  # Abort if more than N errors occur
  maxErrors: 100

# -----------------------------------------------------------------------------
# METRICS & TELEMETRY
# -----------------------------------------------------------------------------

metrics:
  # Collect performance metrics
  enabled: true
  
  # Log slow scans (above threshold)
  logSlowScans: true
  slowScanThresholdMs: 30000
  
  # Track rule performance for optimization
  trackRulePerformance: true
  
  # Export metrics (for monitoring systems)
  export:
    enabled: false
    endpoint: null
    format: prometheus  # prometheus, statsd, json

# -----------------------------------------------------------------------------
# ENVIRONMENT-SPECIFIC OVERRIDES
# -----------------------------------------------------------------------------
# These override settings based on VIBESHIP_ENV environment variable

environments:
  development:
    presets.default: quick
    cache.enabled: true
    output.prettyPrint: true
  
  staging:
    presets.default: standard
    cache.enabled: true
  
  production:
    presets.default: ci
    cache.enabled: true
    metrics.enabled: true
  
  audit:
    presets.default: deep
    output.format: sarif
    rules.maxFindingsPerFile: 100
```

---

## Scripts

### scripts/pull-community-rules.sh

```bash
#!/bin/bash
set -e

SEMGREP_RULES_REPO="https://github.com/semgrep/semgrep-rules.git"
TEMP_DIR="/tmp/semgrep-rules-$$"

echo "📦 Pulling latest community rules..."

# Clone semgrep-rules
git clone --depth 1 $SEMGREP_RULES_REPO $TEMP_DIR

# Copy relevant rules to our structure
declare -A LANG_PATHS=(
  ["typescript"]="typescript javascript/react javascript/express"
  ["javascript"]="javascript"
  ["python"]="python"
  ["go"]="go"
  ["php"]="php"
  ["java"]="java"
  ["ruby"]="ruby"
  ["csharp"]="csharp"
  ["swift"]="swift"
  ["kotlin"]="kotlin"
  ["solidity"]="solidity"
  ["yaml"]="yaml"
  ["shell"]="bash"
)

for lang in "${!LANG_PATHS[@]}"; do
  echo "  → $lang"
  mkdir -p "rulesets/$lang/community"
  
  for path in ${LANG_PATHS[$lang]}; do
    if [ -d "$TEMP_DIR/$path" ]; then
      cp -r $TEMP_DIR/$path/* "rulesets/$lang/community/" 2>/dev/null || true
    fi
  done
done

# Cleanup
rm -rf $TEMP_DIR

echo "✅ Community rules updated!"
echo ""
echo "Rule counts:"
for lang in rulesets/*/; do
  count=$(find "$lang" -name "*.yaml" -o -name "*.yml" | wc -l)
  echo "  $(basename $lang): $count files"
done
```

---

## Docker Setup

### docker/Dockerfile

```dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---

FROM node:20-alpine AS runner

# Install opengrep
RUN apk add --no-cache python3 py3-pip git
RUN pip3 install opengrep

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/rulesets ./rulesets
COPY --from=builder /app/config ./config

ENV NODE_ENV=production
ENV MAX_WORKERS=4

EXPOSE 3000

CMD ["node", "dist/api/server.js"]
```

### docker/docker-compose.yaml

```yaml
version: '3.8'

services:
  scanner:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    ports:
      - "3000:3000"
    environment:
      - MAX_WORKERS=4
      - LOG_LEVEL=info
      - CACHE_ENABLED=true
      - VIBESHIP_ENV=production
    volumes:
      - scan-cache:/app/.vibeship-cache
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G

  # Optional: Redis for distributed caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  scan-cache:
```

---

## API Example

```typescript
// src/api/routes/scan.ts

import { Router } from 'express';
import { scan } from '../../core/scanner';
import multer from 'multer';

const router = Router();
const upload = multer({ dest: '/tmp/uploads/' });

// POST /api/scan - Upload and scan a zip/repo
router.post('/', upload.single('file'), async (req, res) => {
  try {
    const { languages, minSeverity, preset } = req.body;
    
    // Extract uploaded file
    const extractPath = await extractUpload(req.file.path);
    
    // Run scan with optimization preset
    const report = await scan({
      path: extractPath,
      languages: languages?.split(','),
      severity: minSeverity || 'INFO',
      preset: preset || 'standard'
    });
    
    // Cleanup
    await fs.rm(extractPath, { recursive: true });
    
    res.json(report);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/scan/github - Scan a GitHub repo
router.post('/github', async (req, res) => {
  const { repoUrl, branch = 'main', preset = 'ci' } = req.body;
  
  // Clone repo to temp dir
  const repoPath = await cloneRepo(repoUrl, branch);
  
  const report = await scan({ 
    path: repoPath,
    preset  // Use CI preset by default for GitHub scans
  });
  
  await fs.rm(repoPath, { recursive: true });
  
  res.json(report);
});

export default router;
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Small project (<100 files) | <5 seconds | Single worker, quick preset |
| Medium project (100-1000 files) | <30 seconds | 2-4 workers, standard preset |
| Large project (1000+ files) | <2 minutes | Max workers, parallel by language |
| Rule compilation | <1 second | Cached after first run |
| Memory per worker | <512MB | Configurable limit |
| Incremental scan (10 files) | <3 seconds | Git-based change detection |

---

## Optimization Preset Comparison

| Preset | Workers | Max File | Timeout | Rules | Best For |
|--------|---------|----------|---------|-------|----------|
| ⚡ quick | 2 | 100KB | 30s | Critical only | Local dev, pre-commit |
| 🎯 standard | 4 | 500KB | 120s | Most rules | PR checks, regular scans |
| 🔬 deep | 8 | 2MB | 600s | All rules | Security audits, releases |
| 🚀 ci | 4 | 500KB | 180s | Security focus | CI/CD pipelines |
| 🔒 security | 6 | 1MB | 300s | Security only | Pentesting prep |

---

## Adding a New Language

1. Create folder: `rulesets/newlang/`
2. Add `index.yaml` manifest
3. Add to `config/languages.yaml`
4. Pull/write community rules
5. Add custom vibe-coder rules
6. Add test fixtures
7. Run `scripts/validate-rules.sh`

That's it. No code changes required.
