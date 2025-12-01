# Railway Monorepo Configuration Summary

## What Changed

✅ **Frontend uses Nixpacks** (simpler, better for SvelteKit)
✅ **Scanner uses Dockerfile** (needed for Python + security tools)
✅ **Fixed Railway configuration** - Proper root directory setup

### Before
- Frontend: Nixpacks (Railway auto-detection)
- Scanner: Dockerfile
- **Problem**: Railway confused about which config to use

### After  
- Frontend: `Dockerfile` (root directory)
- Scanner: `scanner/Dockerfile` (scanner directory)
- **Solution**: Both use Dockerfiles, Railway handles them the same way

## Files Created/Modified

1. **`/Dockerfile`** (NEW)
   - Multi-stage build for SvelteKit
   - Builds app with `npm run build`
   - Runs with `node build/index.js`
   - Uses Railway's PORT environment variable

2. **`/.dockerignore`** (NEW)
   - Excludes unnecessary files from Docker build
   - Reduces build time and image size

3. **`/railway.json`** (MODIFIED)
   - Changed from `NIXPACKS` to `Dockerfile` builder
   - Removed `startCommand` (now in Dockerfile CMD)

4. **`/scanner/Dockerfile`** (UNCHANGED)
   - Already using Dockerfile ✅
   - Works perfectly as-is

## How Railway Will Handle This

### Option 1: Two Separate Services (Recommended)

1. **Frontend Service**
   - Root Directory: `/` (root of repo)
   - Detects: `Dockerfile` in root
   - Builds: SvelteKit app
   - Runs: `node build/index.js`

2. **Scanner Service**  
   - Root Directory: `/scanner`
   - Detects: `scanner/Dockerfile`
   - Builds: Python Flask app
   - Runs: `gunicorn` server

### Option 2: Single Service (If Railway Pro)

- Can configure multiple deployments
- Each points to different root directory
- Both use their respective Dockerfiles

## Benefits

✅ **Consistent**: Both services use same build method (Docker)
✅ **Predictable**: Railway handles Dockerfiles the same way
✅ **No Conflicts**: Each service has its own Dockerfile
✅ **Portable**: Can test locally with `docker build` and `docker run`
✅ **Flexible**: Easy to customize each service independently

## Testing Locally

### Frontend
```bash
docker build -t vibeship-webapp .
docker run -p 3000:3000 \
  -e PORT=3000 \
  -e SCANNER_API_URL=http://localhost:8080 \
  -e SUPABASE_URL=your-url \
  -e SUPABASE_ANON_KEY=your-key \
  vibeship-webapp
```

### Scanner
```bash
cd scanner
docker build -t vibeship-scanner .
docker run -p 8080:8080 \
  -e PORT=8080 \
  -e SUPABASE_URL=your-url \
  -e SUPABASE_SERVICE_ROLE_KEY=your-key \
  vibeship-scanner
```

## Next Steps

1. **Commit these changes**
2. **In Railway Dashboard:**
   - Create/update Frontend service → Root: `/`
   - Create/update Scanner service → Root: `/scanner`
3. **Set Environment Variables** (see RAILWAY_SETUP.md)
4. **Deploy and test!**

## Troubleshooting

**If build fails:**
- Check Railway build logs
- Verify Dockerfile syntax
- Ensure all files are committed to git

**If services can't communicate:**
- Verify `SCANNER_API_URL` is set correctly
- Check scanner service is deployed
- Test scanner health: `https://your-scanner.railway.app/health`

**If PORT issues:**
- Railway sets PORT automatically
- Both Dockerfiles use `ENV PORT` as fallback
- CMD should work with Railway's PORT variable

