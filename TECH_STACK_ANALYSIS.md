# Tech Stack & Architecture Analysis

## Executive Summary

**Current Status**: Your architecture has several misalignments between design documents and implementation that are causing deployment issues. The tech stack is sound, but the deployment strategy needs refinement.

**Recommendation**: **No major tech stack changes needed** - but deployment architecture needs fixing.

---

## Current Architecture Issues

### 1. **Monorepo Deployment Confusion** ⚠️

**Problem:**
- Single repository contains both SvelteKit webapp and Python scanner service
- Railway is confused about which `railway.json` to use
- Build context conflicts between services

**Current Structure:**
```
vibeship-scanner/
├── railway.json          # For webapp (Nixpacks, Node.js)
├── scanner/
│   ├── Dockerfile        # For scanner (Python)
│   └── railway.json      # Scanner config
└── src/                  # SvelteKit app
```

**Impact:**
- Railway picks wrong config files
- Build failures due to context confusion
- Services can't be deployed independently

---

### 2. **Architecture Document vs Implementation Mismatch** 🔴

**Documented Architecture (ARCHITECTURE.md):**
- Frontend: Vercel Edge (SvelteKit)
- Scanners: Fly.io Machines (ephemeral VMs)
- Orchestration: Trigger.dev
- Database: Supabase
- Cache: Upstash Redis

**Actual Implementation:**
- Frontend: Railway (SvelteKit with adapter-node)
- Scanners: Railway (Python Flask service)
- Orchestration: Direct HTTP calls (no Trigger.dev)
- Database: Supabase ✅
- Cache: Not implemented ❌

**Gap Analysis:**
| Component | Documented | Implemented | Status |
|-----------|-----------|-------------|--------|
| Frontend Hosting | Vercel | Railway | ⚠️ Different |
| Scanner Hosting | Fly.io | Railway | ⚠️ Different |
| Job Queue | Trigger.dev | None | ❌ Missing |
| Caching | Upstash Redis | None | ❌ Missing |

---

### 3. **Service Communication Pattern** ⚠️

**Current Implementation:**
```typescript
// SvelteKit API route calls Python scanner directly
if (SCANNER_API_URL) {
  fetch(`${SCANNER_API_URL}/scan`, { ... })
}
```

**Issues:**
- Direct HTTP dependency (no queue/retry mechanism)
- No error handling for scanner downtime
- Synchronous fire-and-forget pattern
- Missing environment variable configuration

**What's Missing:**
- Job queue system (Trigger.dev as documented)
- Retry logic
- Status polling mechanism
- Webhook callbacks

---

### 4. **Tech Stack Compatibility** ✅

**Good News:** Your tech choices are solid:

| Component | Technology | Rationale | Status |
|-----------|-----------|-----------|--------|
| Frontend | SvelteKit | Modern, fast, SSR-capable | ✅ Excellent |
| Scanner Runtime | Python | Best ecosystem for security tools | ✅ Perfect |
| Database | Supabase (PostgreSQL) | Managed, pgvector support | ✅ Excellent |
| Security Tools | Semgrep, Trivy, Gitleaks | Industry standard | ✅ Perfect |

**No tech stack changes needed** - the tools are right.

---

## Root Cause Analysis

### Why Things Don't Work Together

1. **Railway Monorepo Limitation**
   - Railway expects one service per repository root
   - Having both services causes config conflicts
   - No clear service boundary separation

2. **Missing Orchestration Layer**
   - Architecture calls for Trigger.dev but it's not implemented
   - Direct HTTP calls are fragile
   - No job queue = no retries, no scaling

3. **Deployment Strategy Mismatch**
   - Docs say Fly.io for scanners (ephemeral VMs)
   - Implementation uses Railway (persistent service)
   - Different scaling models

---

## Recommended Solutions

### Option 1: **Separate Repositories** (Recommended for MVP) ⭐

**Structure:**
```
vibeship-scanner-web/     # Separate repo
├── railway.json
└── src/                  # SvelteKit app

vibeship-scanner-api/     # Separate repo  
├── scanner/
│   ├── Dockerfile
│   └── railway.json
└── server.py
```

**Pros:**
- Clear service boundaries
- Independent deployments
- No config conflicts
- Easier CI/CD

**Cons:**
- Two repos to manage
- Code sharing requires packages

**Effort:** Low (just split the repo)

---

### Option 2: **Railway Monorepo with Service Detection** 

**Structure:**
```
vibeship-scanner/
├── .railway/
│   ├── webapp.json      # Service 1 config
│   └── scanner.json     # Service 2 config
├── webapp/              # Move SvelteKit here
└── scanner/             # Keep Python here
```

**Pros:**
- Single repo
- Shared code/types
- Railway can detect services

**Cons:**
- Requires Railway Pro plan (multiple services)
- More complex setup

**Effort:** Medium (restructure + Railway config)

---

### Option 3: **Align with Architecture Doc** (Best Long-term)

**Structure:**
```
vibeship-scanner/
├── webapp/              # SvelteKit → Deploy to Vercel
├── scanner/               # Python → Deploy to Fly.io
└── trigger/              # Trigger.dev jobs
```

**Deployment:**
- Frontend: Vercel (as documented)
- Scanner: Fly.io Machines (ephemeral, as documented)
- Jobs: Trigger.dev (as documented)

**Pros:**
- Matches architecture doc
- Optimal scaling (ephemeral scanners)
- Proper job queue
- Best performance

**Cons:**
- More services to manage
- Higher complexity
- Multiple platforms

**Effort:** High (migrate to Fly.io + add Trigger.dev)

---

## Immediate Fix Recommendations

### Priority 1: Fix Current Deployment (Quick Win)

1. **Separate Railway Services**
   - Create two separate Railway services
   - Point webapp service to root directory
   - Point scanner service to `scanner/` directory
   - Each service uses its own `railway.json`

2. **Environment Variables**
   - Set `SCANNER_API_URL` in webapp service
   - Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in scanner service

3. **Service Communication**
   - Webapp → Scanner: HTTP call (works for now)
   - Add error handling and timeouts
   - Consider adding a simple queue later

**Time:** 30 minutes
**Impact:** High (fixes current issues)

---

### Priority 2: Add Missing Components (Short-term)

1. **Add Job Queue (Trigger.dev)**
   ```typescript
   // Replace direct HTTP call with:
   await trigger.workflows.trigger('scan-repository', {
     scanId,
     repoUrl: url,
     branch: 'main'
   });
   ```

2. **Add Caching (Upstash Redis)**
   - Cache scan results
   - Rate limiting
   - Session storage

3. **Add Error Handling**
   - Retry logic
   - Dead letter queue
   - Status polling

**Time:** 2-3 days
**Impact:** Medium (improves reliability)

---

### Priority 3: Align with Architecture (Long-term)

1. **Migrate Scanner to Fly.io**
   - Ephemeral VMs (better for scanning)
   - Auto-destroy after scan
   - Better cost model

2. **Migrate Frontend to Vercel**
   - Edge functions
   - Better global performance
   - Matches architecture doc

3. **Full Trigger.dev Integration**
   - Workflow orchestration
   - Retries and error handling
   - Webhook callbacks

**Time:** 1-2 weeks
**Impact:** High (optimal architecture)

---

## Tech Stack Assessment

### ✅ Keep These

| Component | Technology | Why Keep |
|-----------|-----------|----------|
| **Frontend Framework** | SvelteKit | Modern, fast, great DX |
| **Database** | Supabase | Managed, pgvector, auth built-in |
| **Security Tools** | Semgrep, Trivy, Gitleaks | Industry standard, best-in-class |
| **Language (Scanner)** | Python | Best ecosystem for security tools |
| **Language (Webapp)** | TypeScript | Type safety, great tooling |

### ⚠️ Consider Changing

| Component | Current | Recommended | Reason |
|-----------|---------|-------------|--------|
| **Frontend Hosting** | Railway | Vercel | Better for SvelteKit, edge functions |
| **Scanner Hosting** | Railway | Fly.io | Ephemeral VMs better for scanning |
| **Job Queue** | None | Trigger.dev | Reliability, retries, scaling |

### ❌ Don't Change

- **No need to change languages** (Python + TypeScript is perfect)
- **No need to change frameworks** (SvelteKit is excellent)
- **No need to change database** (Supabase is ideal)

---

## Decision Matrix

### For MVP (Launch Fast)
**Choose:** Option 1 (Separate Repos) + Priority 1 fixes
- ✅ Fastest to implement
- ✅ Fixes current issues
- ✅ Can iterate later

### For Scale (Production Ready)
**Choose:** Option 3 (Align with Architecture) + All priorities
- ✅ Matches documented architecture
- ✅ Optimal scaling
- ✅ Best performance
- ⚠️ More complex

### For Balance (Recommended)
**Choose:** Option 2 (Railway Monorepo) + Priority 1 & 2
- ✅ Single repo (easier management)
- ✅ Adds job queue (reliability)
- ✅ Can migrate to Fly.io later
- ⚠️ Requires Railway Pro

---

## Action Plan

### Week 1: Fix Current Issues
- [ ] Split into separate Railway services (or fix monorepo config)
- [ ] Set environment variables correctly
- [ ] Test end-to-end scan flow
- [ ] Add error handling to HTTP calls

### Week 2: Add Missing Components
- [ ] Set up Trigger.dev account
- [ ] Replace direct HTTP with Trigger.dev workflows
- [ ] Add Upstash Redis for caching
- [ ] Implement retry logic

### Week 3+: Optimize Architecture
- [ ] Evaluate Fly.io migration (if needed)
- [ ] Consider Vercel migration (if needed)
- [ ] Add monitoring and observability
- [ ] Performance optimization

---

## Conclusion

**Your tech stack is solid** - no major changes needed. The issues are:

1. **Deployment architecture** (monorepo confusion)
2. **Missing orchestration** (no job queue)
3. **Implementation gaps** (Trigger.dev, Redis not implemented)

**Recommendation:** 
- **Short-term:** Fix Railway deployment (separate services or proper monorepo config)
- **Medium-term:** Add Trigger.dev and Redis (as per architecture doc)
- **Long-term:** Consider Fly.io migration for scanners (if scaling becomes an issue)

**No need to change:** Languages, frameworks, or core technologies.




