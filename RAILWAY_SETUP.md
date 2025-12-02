# Railway Monorepo Setup Guide

## Overview

Both services now use Dockerfiles, making Railway handle them consistently:

- **Frontend (Webapp)**: `Dockerfile` in root → SvelteKit app
- **Scanner (API)**: `scanner/Dockerfile` → Python Flask service

## Railway Configuration

### Option 1: Two Separate Railway Services (Recommended)

1. **Create Frontend Service**
   - In Railway dashboard, create new service
   - Connect to your GitHub repo
   - Set **Root Directory**: `/` (root of repo)
   - Railway will detect `Dockerfile` automatically
   - Set environment variables:
     - `SCANNER_API_URL` = URL of scanner service
     - `SUPABASE_URL` = Your Supabase URL
     - `SUPABASE_ANON_KEY` = Your Supabase anon key

2. **Create Scanner Service**
   - In Railway dashboard, create new service
   - Connect to same GitHub repo
   - Set **Root Directory**: `/scanner`
   - Railway will detect `scanner/Dockerfile` automatically
   - Set environment variables:
     - `SUPABASE_URL` = Your Supabase URL
     - `SUPABASE_SERVICE_ROLE_KEY` = Your Supabase service role key
     - `PORT` = 8080 (Railway sets this automatically)

### Option 2: Single Service with Multiple Deployments

If you have Railway Pro, you can use:
- One service with multiple deployments
- Each deployment points to different root directory
- Both use Dockerfiles

## Environment Variables

### Frontend Service
```bash
SCANNER_API_URL=https://your-scanner-service.railway.app
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
```

### Scanner Service
```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
PORT=8080  # Railway sets this automatically
```

## How It Works

1. **Frontend Dockerfile** (`/Dockerfile`)
   - Builds SvelteKit app with `npm run build`
   - Runs Node.js server with `node build`
   - Serves on port 3000 (Railway sets PORT env var)

2. **Scanner Dockerfile** (`/scanner/Dockerfile`)
   - Installs Python dependencies
   - Installs security tools (Semgrep, Trivy, Gitleaks)
   - Runs Flask/Gunicorn server
   - Serves on port 8080

3. **Communication**
   - Frontend calls scanner via `SCANNER_API_URL` environment variable
   - Both services connect to same Supabase database
   - Scanner updates scan results in Supabase
   - Frontend reads results from Supabase

## Benefits of This Approach

✅ **Consistent**: Both services use Dockerfiles
✅ **Predictable**: Railway handles Dockerfiles the same way
✅ **Isolated**: Each service has its own Dockerfile and config
✅ **Flexible**: Easy to update each service independently
✅ **Portable**: Can run locally with `docker build` and `docker run`

## Testing Locally

### Frontend
```bash
docker build -t vibeship-webapp .
docker run -p 3000:3000 \
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
  -e SUPABASE_URL=your-url \
  -e SUPABASE_SERVICE_ROLE_KEY=your-key \
  vibeship-scanner
```

## Troubleshooting

### Railway picks wrong Dockerfile
- Make sure Root Directory is set correctly in Railway service settings
- Frontend: Root = `/`
- Scanner: Root = `/scanner`

### Build fails
- Check that all files are committed to git
- Verify Dockerfile paths are correct
- Check Railway build logs for specific errors

### Services can't communicate
- Verify `SCANNER_API_URL` is set in frontend service
- Check that scanner service is deployed and healthy
- Test scanner health endpoint: `https://your-scanner.railway.app/health`


