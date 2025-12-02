# Railway Monorepo Fix - The Right Way

## The Real Solution

**You were right to question the Dockerfile approach!** 

The issue isn't Nixpacks vs Dockerfile - it's **Railway monorepo configuration**.

## Recommended Setup

### Frontend (Root Directory)
- **Builder**: Nixpacks (Railway auto-detection) ✅
- **Why**: Nixpacks handles SvelteKit perfectly, zero config needed
- **Config**: `railway.json` in root with Nixpacks

### Scanner (Scanner Directory)  
- **Builder**: Dockerfile ✅
- **Why**: Needed for Python + security tools (Semgrep, Trivy, Gitleaks)
- **Config**: `scanner/Dockerfile` + `scanner/railway.json`

## Railway Configuration

### Step 1: Create Two Separate Services

1. **Frontend Service**
   - In Railway dashboard → New Service
   - Connect to GitHub repo
   - **Root Directory**: `/` (leave empty or set to root)
   - Railway will:
     - Detect `railway.json` in root
     - Use Nixpacks (auto-detects Node.js/SvelteKit)
     - Run `npm ci` → `npm run build` → `node build`
   - Environment Variables:
     ```
     SCANNER_API_URL=https://your-scanner-service.railway.app
     SUPABASE_URL=https://your-project.supabase.co
     SUPABASE_ANON_KEY=your-anon-key
     ```

2. **Scanner Service**
   - In Railway dashboard → New Service  
   - Connect to same GitHub repo
   - **Root Directory**: `/scanner` (important!)
   - Railway will:
     - Detect `scanner/Dockerfile`
     - Use Dockerfile builder
     - Build Python container with security tools
   - Environment Variables:
     ```
     SUPABASE_URL=https://your-project.supabase.co
     SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
     PORT=8080  # Railway sets automatically
     ```

## Why This Works

✅ **Frontend uses Nixpacks** - Simple, optimized, zero maintenance
✅ **Scanner uses Dockerfile** - Full control for Python + tools
✅ **No conflicts** - Each service has its own root directory
✅ **Railway handles both** - Detects config based on root directory

## File Structure

```
vibeship-scanner/
├── railway.json          # Frontend: Nixpacks config
├── package.json          # Frontend: SvelteKit
├── src/                  # Frontend: Source code
└── scanner/
    ├── Dockerfile        # Scanner: Python container
    ├── railway.json      # Scanner: Dockerfile config
    └── server.py         # Scanner: Flask app
```

## Key Points

1. **Root Directory is critical** - This tells Railway which service is which
2. **Frontend = Root (`/`)** - Uses Nixpacks from `railway.json`
3. **Scanner = `/scanner`** - Uses Dockerfile from `scanner/Dockerfile`
4. **No conflicts** - Railway treats them as separate services

## Testing

### Frontend (Nixpacks - Railway handles automatically)
- Railway detects `package.json`
- Runs `npm ci`
- Runs `npm run build`  
- Runs `node build` (from startCommand)

### Scanner (Dockerfile)
- Railway detects `scanner/Dockerfile`
- Builds Docker image
- Runs `gunicorn` server

## Benefits

✅ **Simpler** - No Dockerfile maintenance for frontend
✅ **Optimized** - Nixpacks is optimized for Node.js apps
✅ **Flexible** - Scanner still has full Docker control
✅ **No conflicts** - Clear separation via root directories




