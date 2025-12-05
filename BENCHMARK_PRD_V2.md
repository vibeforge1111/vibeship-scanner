# Benchmark System PRD v2 - Simplified

## What Works (Backend)
- `/benchmark/repos` - Returns 7 repos with known vulnerability counts
- `/benchmark/scan-single` - Scans a single repo, returns findings + coverage
- Scanner returns: `detected_vulns`, `missed_vulns`, `coverage`, `findings`

## What We Need (Frontend)

### Core Features Only
1. **Repo List** - Show all 7 benchmark repos with scan buttons
2. **Single Scan** - Click to scan one repo, show progress, display results
3. **Scan All** - Scan all repos sequentially
4. **Coverage Display** - Show detected/total vulns and % for each repo
5. **Overall Stats** - Total coverage across all repos

### Removed (Too Complex/Broken)
- Auto-improve loop (complex, not working)
- Rule generation via Claude API (separate concern)
- Parallel scanning (causes issues)
- Complex modals with findings details
- Gap summary panels
- History tracking

## Simplified Data Flow

```
1. Page loads -> Fetch /benchmark/repos -> Display repo cards
2. Click "Scan" -> POST /api/benchmark/scan -> Poll for result -> Update card
3. Click "Scan All" -> Scan repos one by one sequentially
```

## UI Components

### Repo Card
- Repo name + language badge
- Known vulns count
- Scan button (disabled while scanning)
- After scan: Coverage % (green/yellow/red), detected/missed counts

### Header Stats
- Overall coverage %
- Total detected / Total known

## State (Minimal)
```typescript
repos: BenchmarkRepo[]           // From backend
results: Map<string, ScanResult> // Scan results by repo
scanning: string | null          // Currently scanning repo
scanQueue: string[]              // Repos queued to scan
```

## API Endpoints Used
- `GET /benchmark/repos` - Get repo list
- `POST /api/benchmark/scan` (proxy) -> `POST /benchmark/scan-single` - Scan single repo
