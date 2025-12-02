# Vibeship Scanner - API Specification

## Base URL
- **Production**: `https://scan.vibeship.com/api`
- **Staging**: `https://scan-staging.vibeship.com/api`

## Authentication

### Anonymous Sessions
Anonymous users receive a session token stored in cookies. Limited to 10 scans/month.

### GitHub OAuth
```
GET /auth/github
```
Redirects to GitHub OAuth. Returns JWT token on callback.

### Headers
```
Authorization: Bearer <jwt_token>
X-Session-ID: <anonymous_session_id>
```

---

## Endpoints

### 1. Start Scan

```
POST /api/scan
```

Start a new security scan.

#### Request
```typescript
{
  url: string;           // GitHub/GitLab URL
  type?: 'github' | 'gitlab' | 'url';  // Auto-detected if omitted
  branch?: string;       // Default: 'main'
  deep?: boolean;        // Tier 2 scan (Pro only)
}
```

#### Response (201 Created)
```typescript
{
  scanId: string;        // UUID
  status: 'queued';
  estimatedTime: number; // Seconds
  realtimeChannel: string; // Supabase channel name
}
```

#### Errors
| Code | Message | Cause |
|------|---------|-------|
| 400 | Invalid URL | URL not recognized as valid repo |
| 401 | Auth required | Private repo without GitHub auth |
| 403 | Not authorized | No access to private repo |
| 429 | Rate limit exceeded | Too many scans |

#### Example
```bash
curl -X POST https://scan.vibeship.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/user/repo"}'
```

---

### 2. Get Scan Status/Results

```
GET /api/scan/:id
```

Get current status or completed results of a scan.

#### Response (Pending)
```typescript
{
  id: string;
  status: 'queued' | 'scanning';
  progress: {
    step: string;
    stepNumber: number;
    totalSteps: number;
    message: string;
  };
  estimatedTimeRemaining: number;
}
```

#### Response (Completed)
```typescript
{
  id: string;
  status: 'complete';
  score: number;           // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  shipStatus: 'ship' | 'review' | 'fix' | 'danger';

  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };

  stack: {
    languages: string[];
    frameworks: string[];
    signature: string;
  };

  findings: Finding[];

  benchmarks: {
    stackAverage: number;
    percentile: number;
  };

  tier: 'standard' | 'deep';
  completedAt: string;     // ISO 8601
  duration: number;        // Milliseconds
}
```

#### Finding Type
```typescript
interface Finding {
  id: string;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'code' | 'dependencies' | 'secrets';

  title: string;
  description: string;

  location: {
    file: string;
    line: number;
    column?: number;
  };

  snippet: {
    code: string;
    highlightLines: number[];
  };

  fix: {
    available: boolean;
    template?: string;
    aiGenerated?: boolean;  // Pro only
  };

  references: string[];

  contextNotes?: string;   // e.g., "Found in test file"
}
```

#### Errors
| Code | Message | Cause |
|------|---------|-------|
| 404 | Scan not found | Invalid scan ID |
| 403 | Access denied | Scan belongs to another user |

---

### 3. Get Badge

```
GET /api/badge/:id
```

Generate badge SVG for embedding.

#### Query Parameters
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| style | string | 'flat' | Badge style: flat, flat-square, plastic, for-the-badge |
| label | string | 'vibeship' | Left side label |

#### Response
```
Content-Type: image/svg+xml
Cache-Control: public, max-age=3600
```

Returns SVG badge image.

#### Example
```html
<img src="https://scan.vibeship.com/api/badge/abc123?style=flat" />
```

---

### 4. Submit Feedback

```
POST /api/feedback
```

Submit user feedback on a finding.

#### Request
```typescript
{
  scanId: string;
  findingId: string;
  type: 'true_positive' | 'false_positive' | 'helpful' | 'not_helpful';
  comment?: string;
}
```

#### Response (200 OK)
```typescript
{
  success: true;
  message: 'Feedback recorded';
}
```

---

### 5. List User Scans

```
GET /api/scans
```

Get authenticated user's scan history.

#### Query Parameters
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| page | number | 1 | Page number |
| limit | number | 20 | Items per page (max 100) |
| sort | string | 'desc' | Sort by date: asc, desc |

#### Response
```typescript
{
  scans: ScanSummary[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

interface ScanSummary {
  id: string;
  targetUrl: string;       // Masked for privacy
  score: number;
  grade: string;
  findingCount: number;
  createdAt: string;
}
```

---

### 6. Trigger Rescan

```
POST /api/scan/:id/rescan
```

Trigger a new scan of the same repository.

#### Response (201 Created)
```typescript
{
  newScanId: string;
  previousScanId: string;
  status: 'queued';
}
```

---

### 7. Deep Scan (Pro)

```
POST /api/scan/:id/deep
```

Trigger Tier 2 AI analysis on existing scan.

#### Response (200 OK)
```typescript
{
  status: 'analyzing';
  estimatedTime: number;
}
```

#### Errors
| Code | Message | Cause |
|------|---------|-------|
| 402 | Pro required | User not on Pro tier |
| 400 | Already analyzed | Scan already has Tier 2 |

---

### 8. Generate PDF Report (Pro)

```
GET /api/scan/:id/pdf
```

Generate and download PDF report.

#### Response
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="vibeship-report-{id}.pdf"
```

#### Errors
| Code | Message | Cause |
|------|---------|-------|
| 402 | Pro required | User not on Pro tier |
| 404 | Scan not found | Invalid scan ID |

---

### 9. Get AI Fix (Pro)

```
GET /api/scan/:id/ai-fix
```

Get AI-generated fix for a specific finding.

#### Query Parameters
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| findingId | string | Yes | Finding to generate fix for |

#### Response
```typescript
{
  findingId: string;
  fix: {
    explanation: string;    // Why this fix works
    code: string;           // The fix code
    language: string;       // Syntax highlighting hint
    confidence: number;     // 0-1 confidence score
  };
  cached: boolean;          // Whether this was cached
}
```

#### Errors
| Code | Message | Cause |
|------|---------|-------|
| 402 | Pro required | User not on Pro tier |
| 404 | Finding not found | Invalid finding ID |
| 503 | AI unavailable | Claude API error |

---

## Webhooks

### Trigger.dev Callback

```
POST /api/webhooks/trigger
```

Internal endpoint for Trigger.dev job callbacks.

#### Request Headers
```
X-Trigger-Signature: <signature>
```

#### Request Body
```typescript
{
  jobId: string;
  status: 'success' | 'failed';
  scanId: string;
  result?: ScanResult;
  error?: string;
}
```

---

## Rate Limits

| Tier | Per Hour | Per Day | Per Month |
|------|----------|---------|-----------|
| Anonymous | 3 | 10 | 10 |
| Authenticated | 10 | 50 | - |
| Pro | 50 | 200 | - |

### Rate Limit Headers
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1699234567
```

### Rate Limit Exceeded Response
```typescript
{
  error: 'rate_limit_exceeded',
  message: 'Too many requests',
  retryAfter: 3600,
  upgradeUrl: '/pro'
}
```

---

## Error Response Format

All errors follow this structure:

```typescript
{
  error: string;          // Machine-readable error code
  message: string;        // Human-readable message
  details?: object;       // Additional context
  upgradeUrl?: string;    // If upgrade would resolve
}
```

### Common Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| invalid_request | 400 | Malformed request |
| unauthorized | 401 | Missing or invalid auth |
| forbidden | 403 | No permission |
| not_found | 404 | Resource not found |
| rate_limit_exceeded | 429 | Too many requests |
| internal_error | 500 | Server error |
| ai_unavailable | 503 | Claude API unavailable |

---

## Realtime Updates

Scan progress is delivered via Supabase Realtime.

### Channel
```
scan:{scanId}
```

### Event Types

#### `progress`
```typescript
{
  type: 'progress';
  step: string;
  stepNumber: number;
  totalSteps: number;
  message: string;
}
```

#### `complete`
```typescript
{
  type: 'complete';
  scanId: string;
  score: number;
  grade: string;
}
```

#### `error`
```typescript
{
  type: 'error';
  message: string;
  recoverable: boolean;
}
```

### Client Example (Svelte)
```typescript
import { supabase } from '$lib/supabase';

const channel = supabase
  .channel(`scan:${scanId}`)
  .on('broadcast', { event: 'progress' }, ({ payload }) => {
    progress = payload;
  })
  .on('broadcast', { event: 'complete' }, ({ payload }) => {
    goto(`/scan/${scanId}`);
  })
  .subscribe();
```

---

## TypeScript Types

```typescript
// lib/types/api.ts

export type ScanStatus = 'queued' | 'scanning' | 'complete' | 'failed';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 'code' | 'dependencies' | 'secrets';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export type ShipStatus = 'ship' | 'review' | 'fix' | 'danger';

export type Tier = 'standard' | 'deep';

export interface ScanRequest {
  url: string;
  type?: 'github' | 'gitlab' | 'url';
  branch?: string;
  deep?: boolean;
}

export interface ScanResponse {
  scanId: string;
  status: ScanStatus;
  estimatedTime: number;
  realtimeChannel: string;
}

export interface ScanResult {
  id: string;
  status: 'complete';
  score: number;
  grade: Grade;
  shipStatus: ShipStatus;
  summary: SeverityCounts;
  stack: StackInfo;
  findings: Finding[];
  benchmarks: Benchmarks;
  tier: Tier;
  completedAt: string;
  duration: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface StackInfo {
  languages: string[];
  frameworks: string[];
  signature: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  location: Location;
  snippet: Snippet;
  fix: Fix;
  references: string[];
  contextNotes?: string;
}

export interface Location {
  file: string;
  line: number;
  column?: number;
}

export interface Snippet {
  code: string;
  highlightLines: number[];
}

export interface Fix {
  available: boolean;
  template?: string;
  aiGenerated?: boolean;
}

export interface Benchmarks {
  stackAverage: number;
  percentile: number;
}

export interface FeedbackRequest {
  scanId: string;
  findingId: string;
  type: 'true_positive' | 'false_positive' | 'helpful' | 'not_helpful';
  comment?: string;
}

export interface APIError {
  error: string;
  message: string;
  details?: Record<string, unknown>;
  upgradeUrl?: string;
}
```
