# Vibeship Scanner - Development Tasks

## Phase 1: MVP (Weeks 1-4)

### Week 1: Infrastructure Setup

#### 1.1 Project Initialization
- [ ] Initialize SvelteKit 2.0 project with TypeScript
- [ ] Configure Tailwind CSS 4.0
- [ ] Set up ESLint + Prettier
- [ ] Configure path aliases (`$lib`, `$components`)
- [ ] Create base layout with Vibeship branding

#### 1.2 Supabase Setup
- [ ] Create Supabase project
- [ ] Configure GitHub OAuth provider
- [ ] Create database migrations for core tables:
  - [ ] `scans` table
  - [ ] `scan_progress` table
  - [ ] `rules` table
  - [ ] `learning_signals` table
  - [ ] `fix_templates` table
  - [ ] `stack_benchmarks` table
  - [ ] `badges` table
  - [ ] `rate_limits` table
- [ ] Enable pgvector extension
- [ ] Set up Row Level Security policies
- [ ] Configure Realtime for `scan_progress`

#### 1.3 Upstash Redis Setup
- [ ] Create Upstash Redis instance
- [ ] Implement rate limiting helper functions
- [ ] Set up session storage utilities
- [ ] Create cache wrapper for scan results

#### 1.4 Fly.io Configuration
- [ ] Create Fly.io app for scanner VMs
- [ ] Write Dockerfile with Semgrep, Trivy, Gitleaks
- [ ] Configure fly.toml for ephemeral machines
- [ ] Test machine provisioning and auto-destroy
- [ ] Set up secrets for GitHub token, API keys

#### 1.5 Trigger.dev Setup
- [ ] Create Trigger.dev project
- [ ] Configure webhook endpoint in SvelteKit
- [ ] Create base job structure for scans
- [ ] Implement retry logic and error handling

#### 1.6 CI/CD Pipeline
- [ ] GitHub Actions workflow for lint/type-check
- [ ] GitHub Actions workflow for tests
- [ ] Vercel project connection
- [ ] Preview deployments for PRs
- [ ] Production auto-deploy on main

---

### Week 2: Tier 1 Scanning Pipeline

#### 2.1 Stack Detection
- [ ] Implement `detectStack()` function
- [ ] Support detection for:
  - [ ] Node.js (package.json)
  - [ ] Python (requirements.txt, pyproject.toml)
  - [ ] Go (go.mod)
  - [ ] Rust (Cargo.toml)
  - [ ] Ruby (Gemfile)
- [ ] Generate stack signature string
- [ ] Detect frameworks (Next.js, SvelteKit, Django, etc.)

#### 2.2 Semgrep Integration
- [ ] Create Semgrep rule loader
- [ ] Import community rules for common stacks
- [ ] Create 20+ custom rules for vibe-coded patterns:
  - [ ] Hardcoded API keys
  - [ ] SQL injection in string templates
  - [ ] XSS via innerHTML
  - [ ] Insecure CORS configs
  - [ ] Missing auth checks
- [ ] Implement result normalization
- [ ] Map Semgrep severity to internal severity

#### 2.3 Trivy Integration
- [ ] Install and configure Trivy in scanner VM
- [ ] Run filesystem scan for dependencies
- [ ] Parse vulnerability results
- [ ] Map CVE severity to internal severity
- [ ] Extract license information (for future use)

#### 2.4 Gitleaks Integration
- [ ] Configure Gitleaks with custom patterns
- [ ] Add patterns for:
  - [ ] AWS keys
  - [ ] OpenAI/Anthropic keys
  - [ ] Database URLs
  - [ ] JWT secrets
  - [ ] Stripe keys
  - [ ] Firebase configs
- [ ] Implement entropy-based detection
- [ ] Parse and normalize results

#### 2.5 Result Aggregation
- [ ] Create finding deduplication logic
- [ ] Implement severity normalization across tools
- [ ] Attach file context (lines around finding)
- [ ] Create unified finding structure

#### 2.6 Scoring Algorithm
- [ ] Implement base score calculation (100 - deductions)
- [ ] Apply severity weights:
  - Critical: -25
  - High: -10
  - Medium: -5
  - Low: -2
- [ ] Implement context modifiers:
  - [ ] Test file detection
  - [ ] Example file detection
  - [ ] Main bundle detection
- [ ] Calculate grade (A-F)
- [ ] Determine ship status

#### 2.7 Template Fixes
- [ ] Create fix template structure
- [ ] Write 20+ template fixes for common issues:
  - [ ] SQL injection → parameterized queries
  - [ ] XSS → sanitization
  - [ ] Secrets → environment variables
  - [ ] Dependency CVEs → upgrade commands
- [ ] Stack-specific fix variants (React vs Vue, etc.)

---

### Week 3: Core UI

#### 3.1 Landing Page
- [ ] Hero section with scan input
- [ ] URL validation (GitHub, GitLab)
- [ ] "Quick scan" animation
- [ ] How it works section
- [ ] Trust indicators (open source scanners used)
- [ ] Vibeship CTA banner

#### 3.2 Scan Progress Page
- [ ] Real-time progress subscription (Supabase)
- [ ] Step-by-step progress indicators:
  - [ ] Cloning repository
  - [ ] Detecting stack
  - [ ] Running SAST
  - [ ] Analyzing dependencies
  - [ ] Calculating score
- [ ] Animated progress bar
- [ ] Cancel scan option

#### 3.3 Results Page - Score Display
- [ ] Score reveal animation
- [ ] Grade badge (A-F with color)
- [ ] Ship status indicator
- [ ] Category breakdown:
  - [ ] Code Security
  - [ ] Dependencies
  - [ ] Secrets
- [ ] Stack detected display

#### 3.4 Results Page - Findings List
- [ ] Finding cards with severity badges
- [ ] Collapsible detail sections
- [ ] File location with line numbers
- [ ] Code snippet with syntax highlighting
- [ ] Founder/Developer mode toggle
- [ ] Founder mode explanations
- [ ] Developer mode technical details

#### 3.5 Results Page - Actions
- [ ] "Copy Fix" button per finding
- [ ] "Get Vibeship Help" CTA per finding
- [ ] Share button (Twitter, LinkedIn)
- [ ] Download badge button
- [ ] Email capture modal

#### 3.6 Authentication
- [ ] GitHub OAuth login button
- [ ] Anonymous session creation
- [ ] Session persistence
- [ ] Protected routes (scan history, etc.)

---

### Week 4: Polish & Launch Prep

#### 4.1 Badge Generation
- [ ] SVG badge templates (4 styles):
  - [ ] Flat
  - [ ] Flat-square
  - [ ] Plastic
  - [ ] For-the-badge
- [ ] Dynamic score/grade insertion
- [ ] Badge caching in Redis
- [ ] Badge embed code generator

#### 4.2 Social Sharing
- [ ] Twitter share with score card
- [ ] LinkedIn share
- [ ] Open Graph meta tags
- [ ] Dynamic OG image generation

#### 4.3 Rate Limiting Implementation
- [ ] IP-based rate limiting
- [ ] User-based rate limiting
- [ ] CAPTCHA integration (Cloudflare Turnstile)
- [ ] Abuse detection alerts

#### 4.4 Error Handling
- [ ] Global error boundary
- [ ] Scan failure recovery
- [ ] Timeout handling (90s max)
- [ ] User-friendly error messages
- [ ] Sentry error reporting

#### 4.5 Mobile Responsiveness
- [ ] Responsive landing page
- [ ] Responsive results page
- [ ] Touch-friendly finding cards
- [ ] Mobile navigation

#### 4.6 Cold Start Seeding
- [ ] Script to scan 100 public repos
- [ ] Populate stack_benchmarks table
- [ ] Populate fix_templates with effectiveness
- [ ] Validate Semgrep rules

---

## Phase 2: Experience (Weeks 5-8)

### Week 5: Score Reveal Animation

#### 5.1 Animated Score Counter
- [ ] Count-up animation (0 to final score)
- [ ] Easing functions for smooth animation
- [ ] Color transition based on score
- [ ] Sound effects (optional, toggle)

#### 5.2 Confetti Effect
- [ ] Trigger on scores 80+
- [ ] Multiple confetti styles
- [ ] Performance-optimized particles
- [ ] Mobile-friendly version

#### 5.3 Category Cascade
- [ ] Sequential reveal of categories
- [ ] Individual score animations
- [ ] Icon animations
- [ ] Comparison to community average

### Week 6: Charts & Visualization

#### 6.1 ECharts Integration
- [ ] Lazy load ECharts (~800KB)
- [ ] Create chart wrapper component
- [ ] Responsive chart sizing
- [ ] Dark/light mode support

#### 6.2 Radar Chart
- [ ] Category scores on axes
- [ ] Animated draw-in
- [ ] Community benchmark overlay
- [ ] Interactive tooltips

#### 6.3 Severity Breakdown
- [ ] Donut chart for severity distribution
- [ ] Animated segments
- [ ] Click-to-filter findings

#### 6.4 Historical Trends (Pro)
- [ ] Line chart for score over time
- [ ] Multiple scans comparison
- [ ] Trend indicators (improving/declining)

### Week 7: AI Features (Pro)

#### 7.1 Claude Integration
- [ ] API client setup
- [ ] Model router (Sonnet for analysis, Haiku for classification)
- [ ] Token usage tracking
- [ ] Cost estimation

#### 7.2 AI Explanations
- [ ] Generate founder-mode explanations
- [ ] Generate developer-mode explanations
- [ ] Cache explanations by finding type
- [ ] Rate limit AI calls

#### 7.3 AI Fix Generation
- [ ] Context-aware fix generation
- [ ] Include surrounding code
- [ ] Stack-specific fixes
- [ ] Validate generated code (syntax check)

#### 7.4 Pro Paywall
- [ ] Stripe integration
- [ ] Pro tier creation ($29/mo)
- [ ] Upgrade prompts at strategic moments
- [ ] Feature gating

### Week 8: Reports & Badges

#### 8.1 PDF Report Generation
- [ ] PDF template design
- [ ] Include all findings
- [ ] Executive summary section
- [ ] Recommendations section
- [ ] Vibeship branding

#### 8.2 Badge Verification Pages
- [ ] /badge/[id] verification page
- [ ] Show scan date and score
- [ ] Link to full results (if public)

#### 8.3 Embed Code Generator
- [ ] Markdown embed code
- [ ] HTML embed code
- [ ] Copy-to-clipboard

#### 8.4 Badge Analytics
- [ ] Track badge views
- [ ] Track badge embeds
- [ ] Analytics dashboard (internal)

---

## Phase 3: Intelligence (Weeks 9-12)

### Week 9: Signal Collection

#### 9.1 User Feedback UI
- [ ] "This is accurate" / "False positive" buttons
- [ ] "This helped me" tracking
- [ ] Comment field for feedback
- [ ] Thank you confirmation

#### 9.2 Signal Recording
- [ ] Record to learning_signals table
- [ ] Anonymize before storage
- [ ] Link to rule_id
- [ ] Track signal type

#### 9.3 Fix Tracking
- [ ] Track "Copy Fix" clicks
- [ ] Detect rescan (same repo)
- [ ] Calculate fix success rate
- [ ] Update fix_templates table

### Week 10: Shadow Mode

#### 10.1 Shadow Rule Deployment
- [ ] Rules table with status field
- [ ] Shadow mode runner in scan pipeline
- [ ] Silent match collection
- [ ] No user-visible output for shadow rules

#### 10.2 Validation Dashboard (Internal)
- [ ] List shadow rules
- [ ] Show match samples
- [ ] Calculate precision estimate
- [ ] Manual review workflow

#### 10.3 Rule Promotion
- [ ] Automated precision check (95%+)
- [ ] Promotion approval workflow
- [ ] Version tracking
- [ ] Rollback capability

### Week 11: Pattern Learning

#### 11.1 Code Anonymization
- [ ] Strip string literals
- [ ] Replace variable names
- [ ] Remove comments
- [ ] Generate pattern hash

#### 11.2 Community Benchmarks
- [ ] Weekly benchmark aggregation job
- [ ] Stack-specific averages
- [ ] Top issues by stack
- [ ] Trend analysis

#### 11.3 Fix Effectiveness Ranking
- [ ] Calculate success rates
- [ ] Rank fixes by effectiveness
- [ ] Surface best fixes first
- [ ] A/B test fix variants

### Week 12: Evolution v1

#### 12.1 Daily Evolution Job
- [ ] Trigger.dev scheduled job
- [ ] Analyze shadow mode data
- [ ] Propose rule improvements
- [ ] Log evolution decisions

#### 12.2 Rule Improvement Proposals
- [ ] AI-generated rule refinements
- [ ] Test against known samples
- [ ] Calculate expected precision
- [ ] Queue for review

---

## Phase 4: Scale (Weeks 13-16)

### Week 13-14: Integrations

#### 13.1 GitHub App
- [ ] Create GitHub App
- [ ] Auto-PR for fixes
- [ ] Scan on PR webhook
- [ ] Status checks integration

#### 13.2 CI/CD Integration
- [ ] CLI tool for pipelines
- [ ] GitHub Actions action
- [ ] GitLab CI template
- [ ] Exit code on threshold

#### 13.3 Slack Notifications
- [ ] Slack App setup
- [ ] Scan complete notifications
- [ ] High-severity alerts
- [ ] Daily/weekly digests

### Week 15-16: Enterprise

#### 15.1 Team Accounts
- [ ] Organization model
- [ ] Team member invites
- [ ] Role-based access
- [ ] Shared scan history

#### 15.2 Org-wide Scanning
- [ ] Scan all org repos
- [ ] Aggregate org score
- [ ] Priority queue for enterprise

#### 15.3 Custom Rules
- [ ] Rule editor UI
- [ ] Test rule against sample
- [ ] Deploy to shadow mode
- [ ] Promote to active

---

## Task Priority Matrix

| Priority | Category | Examples |
|----------|----------|----------|
| P0 (Critical) | Core Scanning | Semgrep, Trivy, Gitleaks integration |
| P0 (Critical) | Results Display | Score, findings, fix suggestions |
| P1 (High) | User Experience | Animations, mobile responsive |
| P1 (High) | Security | Rate limiting, abuse prevention |
| P2 (Medium) | Pro Features | AI explanations, PDF reports |
| P2 (Medium) | Intelligence | Shadow mode, pattern learning |
| P3 (Low) | Integrations | GitHub App, Slack |
| P3 (Low) | Enterprise | Teams, custom rules |

---

## Definition of Done

### For Each Feature:
- [ ] Code written and reviewed
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Documentation updated
- [ ] Deployed to staging
- [ ] QA verified
- [ ] Performance acceptable
- [ ] Merged to main

### For Each Phase:
- [ ] All P0 tasks complete
- [ ] All P1 tasks complete or documented
- [ ] E2E test suite passing
- [ ] Security audit passed
- [ ] Load testing passed
- [ ] Documentation complete
