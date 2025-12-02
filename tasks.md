# Vibeship Scanner - Tasks

## Completed
- [x] Set up SvelteKit frontend with Supabase integration
- [x] Create scanner service with Semgrep, Trivy, and Gitleaks
- [x] Deploy web app to Railway (Nixpacks)
- [x] Deploy scanner service to Fly.io (Docker)
- [x] Configure Supabase database with scans table
- [x] Fix RLS policies for anonymous access
- [x] Fix supabase/gotrue package compatibility (pinned to v1.0.4)
- [x] Connect web app to scanner API
- [x] End-to-end scan working: clone -> analyze -> results

## Environment Variables

### Railway (Web App)
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `SCANNER_API_URL=https://scanner-empty-field-5676.fly.dev`

### Fly.io (Scanner)
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

## Next Tasks
- [ ] Add scan progress table (`scan_progress`) for real-time updates
- [ ] Improve UI/UX for scan results page
- [ ] Add more detailed findings display
- [ ] Add share/export results feature
- [ ] Add GitHub OAuth for authenticated scans
- [ ] Add support for private repositories
- [ ] Add scan history for users
- [ ] Improve scoring algorithm
- [ ] Add custom Semgrep rules for common frameworks
- [ ] Add rate limiting improvements
- [ ] Deploy production version with custom domain

## URLs
- Local dev: http://localhost:5173
- Scanner API: https://scanner-empty-field-5676.fly.dev
- Scanner health: https://scanner-empty-field-5676.fly.dev/health
