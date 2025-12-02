# Final Deployment Architecture

## Overview

✅ **Webapp**: Railway (Nixpacks) - Simple, optimized for SvelteKit
✅ **Scanner**: Fly.io (Dockerfile) - Ephemeral VMs, perfect for scanning

This matches your architecture document and is the optimal setup!

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER REQUEST                          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   RAILWAY (Webapp)    │
         │                       │
         │  • SvelteKit          │
         │  • Nixpacks builder  │
         │  • Node.js runtime    │
         └───────────┬───────────┘
                     │
                     │ HTTP POST
                     │ /api/scan
                     ▼
         ┌───────────────────────┐
         │   FLY.IO (Scanner)    │
         │                       │
         │  • Python Flask       │
         │  • Dockerfile         │
         │  • Ephemeral VMs      │
         │  • Auto-start/stop    │
         └───────────┬───────────┘
                     │
                     │ Updates
                     ▼
         ┌───────────────────────┐
         │      SUPABASE          │
         │                       │
         │  • PostgreSQL          │
         │  • Scan results        │
         │  • Progress updates    │
         └───────────────────────┘
```

## Service Details

### Webapp (Railway)

**Location**: Root directory (`/`)
**Builder**: Nixpacks (auto-detects SvelteKit)
**Config**: `railway.json`
**Runtime**: Node.js
**Port**: Railway sets automatically

**Environment Variables:**
- `SCANNER_API_URL` - Fly.io scanner URL
- `SUPABASE_URL` - Supabase project URL
- `SUPABASE_ANON_KEY` - Supabase anon key

**Why Railway + Nixpacks:**
- ✅ Zero configuration
- ✅ Automatic optimizations
- ✅ Perfect for SvelteKit
- ✅ Fast builds

### Scanner (Fly.io)

**Location**: `scanner/` directory
**Builder**: Dockerfile
**Config**: `fly.toml`
**Runtime**: Python + Gunicorn
**Port**: 8080 (internal)

**Environment Variables:**
- `SUPABASE_URL` - Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` - Service role key
- `PORT` - 8080 (set by Fly.io)

**Why Fly.io:**
- ✅ Ephemeral VMs (auto-destroy after scan)
- ✅ Auto-start/stop (cost efficient)
- ✅ Perfect for scanning workloads
- ✅ Matches architecture document

## Setup Checklist

### Railway (Webapp)
- [ ] Create service in Railway dashboard
- [ ] Connect GitHub repo
- [ ] Root directory: `/` (root)
- [ ] Set environment variables:
  - [ ] `SCANNER_API_URL` (from Fly.io)
  - [ ] `SUPABASE_URL`
  - [ ] `SUPABASE_ANON_KEY`
- [ ] Deploy

### Fly.io (Scanner)
- [ ] Install Fly.io CLI
- [ ] Login: `fly auth login`
- [ ] Navigate to `scanner/` directory
- [ ] Launch: `fly launch`
- [ ] Set secrets:
  - [ ] `fly secrets set SUPABASE_URL=...`
  - [ ] `fly secrets set SUPABASE_SERVICE_ROLE_KEY=...`
- [ ] Deploy: `fly deploy`
- [ ] Get URL: `fly status`
- [ ] Update Railway `SCANNER_API_URL`

## File Structure

```
vibeship-scanner/
├── railway.json              # Webapp: Railway config (Nixpacks)
├── package.json              # Webapp: SvelteKit dependencies
├── src/                      # Webapp: Source code
└── scanner/
    ├── Dockerfile            # Scanner: Fly.io build
    ├── fly.toml              # Scanner: Fly.io config
    ├── server.py             # Scanner: Flask API
    ├── scan.py               # Scanner: Scanning logic
    └── requirements.txt      # Scanner: Python deps
```

## Benefits

✅ **No conflicts** - Separate platforms, separate configs
✅ **Optimal for each service** - Railway for webapp, Fly.io for scanner
✅ **Cost efficient** - Fly.io auto-stops when idle
✅ **Scalable** - Both platforms handle scaling automatically
✅ **Matches architecture** - As documented in ARCHITECTURE.md

## Communication Flow

1. **User submits scan** → Webapp (Railway)
2. **Webapp creates record** → Supabase
3. **Webapp triggers scanner** → HTTP POST to Fly.io
4. **Scanner runs scan** → Clones repo, runs tools
5. **Scanner updates results** → Supabase
6. **Webapp reads results** → Supabase (real-time)

## Troubleshooting

### Webapp can't reach scanner
- Verify `SCANNER_API_URL` is set correctly
- Check Fly.io app is running: `fly status`
- Test health endpoint: `curl https://your-app.fly.dev/health`

### Scanner not starting
- Check Fly.io secrets are set: `fly secrets list`
- Check logs: `fly logs`
- First request may take 10-20s (machine starting)

### Build issues
- **Webapp**: Check Railway build logs
- **Scanner**: Check `fly logs` or `fly deploy --verbose`

## Next Steps

1. ✅ Webapp: Railway with Nixpacks (working config restored)
2. ✅ Scanner: Fly.io setup (Dockerfile fixed for Fly.io)
3. Deploy scanner to Fly.io
4. Update webapp `SCANNER_API_URL`
5. Test end-to-end


