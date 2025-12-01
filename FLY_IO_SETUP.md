# Fly.io Scanner Setup Guide

## Overview

**Webapp**: Railway (Nixpacks) - Working configuration ✅
**Scanner**: Fly.io (Dockerfile) - Ephemeral VMs for scanning ✅

This matches your architecture document and is optimal for the scanner service.

## Why Fly.io for Scanner?

✅ **Ephemeral VMs** - Perfect for scan jobs (auto-destroy after use)
✅ **Better cost model** - Pay only when scanning
✅ **Auto-scaling** - Machines start/stop automatically
✅ **Matches architecture** - As documented in ARCHITECTURE.md

## Setup Instructions

### 1. Install Fly.io CLI

```bash
# Windows (PowerShell)
iwr https://fly.io/install.ps1 -useb | iex

# Or download from: https://fly.io/docs/hands-on/install-flyctl/
```

### 2. Login to Fly.io

```bash
fly auth login
```

### 3. Deploy Scanner Service

```bash
cd scanner
fly launch
```

When prompted:
- **App name**: `vibeship-scanner` (or your preferred name)
- **Region**: Choose closest to your users (e.g., `iad`, `sjc`, `lhr`)
- **Postgres**: No (we use Supabase)
- **Redis**: No (optional, can add later)

### 4. Set Environment Variables

```bash
fly secrets set SUPABASE_URL=https://your-project.supabase.co
fly secrets set SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

### 5. Deploy

```bash
fly deploy
```

### 6. Get Scanner URL

```bash
fly status
# Note the hostname, e.g., https://vibeship-scanner.fly.dev
```

### 7. Update Webapp Configuration

In Railway dashboard (webapp service), set:
```
SCANNER_API_URL=https://vibeship-scanner.fly.dev
```

## File Structure

```
vibeship-scanner/
├── railway.json          # Webapp: Railway (Nixpacks)
├── package.json          # Webapp: SvelteKit
└── scanner/
    ├── Dockerfile        # Scanner: Fly.io (fixed paths)
    ├── fly.toml          # Scanner: Fly.io config
    ├── server.py         # Scanner: Flask app
    └── scan.py           # Scanner: Scanning logic
```

## Dockerfile Changes

The Dockerfile has been updated for Fly.io:
- **Before**: `COPY scanner/requirements.txt` (Railway build context)
- **After**: `COPY requirements.txt` (Fly.io build context from scanner/ directory)

Fly.io builds from the `scanner/` directory, so paths are relative to that.

## Configuration Details

### fly.toml
- **Auto-start/stop**: Machines start when requests come in, stop when idle
- **Memory**: 512MB (enough for scanning)
- **CPU**: 1 shared CPU
- **Port**: 8080 (internal), Fly.io handles external routing

### Environment Variables
- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` - Service role key (for writing scan results)
- `PORT` - Set to 8080 (handled by Fly.io)

## Testing

### Test Scanner Locally

```bash
cd scanner
fly proxy 8080:8080
# In another terminal:
curl http://localhost:8080/health
```

### Test from Webapp

The webapp should call:
```
POST https://vibeship-scanner.fly.dev/scan
Body: { scanId, repoUrl, branch }
```

## Monitoring

```bash
# View logs
fly logs

# Check status
fly status

# View metrics
fly dashboard
```

## Benefits

✅ **Cost efficient** - Machines auto-stop when idle
✅ **Scalable** - Auto-starts machines for concurrent scans
✅ **Fast** - Ephemeral VMs start quickly
✅ **Matches architecture** - As documented in ARCHITECTURE.md
✅ **No conflicts** - Separate from Railway webapp

## Troubleshooting

### Build fails
- Check Dockerfile paths (should be relative, not `scanner/`)
- Verify all files are in `scanner/` directory
- Check `fly logs` for errors

### Scanner not responding
- Check `fly status` - machine might be stopped
- First request will start the machine (may take 10-20 seconds)
- Check `fly logs` for errors

### Can't connect from webapp
- Verify `SCANNER_API_URL` is set correctly in Railway
- Check Fly.io app is deployed: `fly status`
- Test health endpoint: `curl https://your-app.fly.dev/health`

## Next Steps

1. Deploy scanner to Fly.io
2. Update `SCANNER_API_URL` in Railway webapp
3. Test end-to-end scan flow
4. Monitor costs (should be very low with auto-stop)

