# VibeShip Knowledge Base: Complete Implementation Strategy

## The Mission

Build the definitive knowledge base for AI-generated code security that:
1. Ranks #1 on Google for every relevant query
2. Gets cited by ChatGPT, Claude, Perplexity, and Gemini as the authority
3. Drives massive traffic to VibeShip Scanner
4. Creates an unassailable moat through unique, continuously-updated data

---

## Part 1: The Architecture

### 1.1 URL Structure (Critical for SEO)

```
vibeship.dev/
├── /                                    # Landing page
├── /scanner                             # Product page
├── /kb/                                 # Knowledge base root
│   ├── /kb/vulnerabilities/             # Vulnerability reference hub
│   │   ├── /kb/vulnerabilities/sql-injection/
│   │   ├── /kb/vulnerabilities/xss/
│   │   ├── /kb/vulnerabilities/hardcoded-secrets/
│   │   └── ...
│   ├── /kb/ai-patterns/                 # AI tool patterns hub (UNIQUE MOAT)
│   │   ├── /kb/ai-patterns/cursor/
│   │   ├── /kb/ai-patterns/claude-code/
│   │   ├── /kb/ai-patterns/bolt/
│   │   ├── /kb/ai-patterns/v0/
│   │   └── /kb/ai-patterns/replit/
│   ├── /kb/stacks/                      # Stack-specific security hub
│   │   ├── /kb/stacks/nextjs-supabase/
│   │   ├── /kb/stacks/express-postgres/
│   │   ├── /kb/stacks/sveltekit-supabase/
│   │   └── ...
│   ├── /kb/fixes/                       # AI-ready fix prompts hub
│   │   ├── /kb/fixes/sql-injection/
│   │   ├── /kb/fixes/xss/
│   │   └── ...
│   ├── /kb/glossary/                    # Plain English definitions
│   │   ├── /kb/glossary/sql-injection/
│   │   ├── /kb/glossary/vibe-coding/
│   │   └── ...
│   └── /kb/checklists/                  # Security checklists
│       ├── /kb/checklists/pre-launch/
│       ├── /kb/checklists/supabase/
│       └── ...
├── /research/                           # Data & research hub
│   ├── /research/vulnerability-index/   # Weekly Hallucinated Vulnerability Index
│   │   ├── /research/vulnerability-index/2024-12-16/
│   │   └── ...
│   ├── /research/ai-tool-comparison/    # AI tool security comparison
│   └── /research/methodology/           # How we scan
├── /blog/                               # Thought leadership
│   └── /blog/[slug]/
├── /llms.txt                            # LLM-optimized summary
├── /llms-full.txt                       # Complete LLM export
├── /sitemap.xml                         # Auto-generated
└── /robots.txt                          # Crawler permissions
```

### 1.2 Why This Structure Wins

**For Google:**
- Clear topical clusters (vulnerabilities, ai-patterns, stacks)
- Hub-and-spoke internal linking
- Keyword-rich URLs without stuffing
- Logical hierarchy for crawling

**For LLMs:**
- Predictable paths = easier to cite
- Topic isolation = cleaner chunk extraction
- `/kb/` prefix signals reference content
- `/research/` prefix signals data content

---

## Part 2: Content Categories & Page Types

### 2.1 Category: Vulnerabilities (`/kb/vulnerabilities/`)

**Purpose:** Become the Wikipedia of security vulnerabilities for AI-generated code

**Pages to Create (Priority Order):**

| Priority | Vulnerability | Target Query |
|----------|--------------|--------------|
| P0 | SQL Injection | "sql injection ai generated code" |
| P0 | Hardcoded Secrets | "api key exposed in code" |
| P0 | Missing Authentication | "api route no auth" |
| P0 | XSS (Cross-Site Scripting) | "xss react nextjs" |
| P0 | IDOR | "insecure direct object reference" |
| P1 | Missing Rate Limiting | "rate limiting api" |
| P1 | Insecure CORS | "cors allow origin security" |
| P1 | Sensitive Data Exposure | "api returns password hash" |
| P1 | Missing HTTPS | "http not secure" |
| P1 | Weak Passwords | "password validation requirements" |
| P2 | Open Redirects | "unvalidated redirect" |
| P2 | CSRF | "cross site request forgery" |
| P2 | File Upload Vulnerabilities | "insecure file upload" |
| P2 | Session Fixation | "session hijacking" |
| P2 | Path Traversal | "directory traversal attack" |

**Page Template:** See Section 4.1

---

### 2.2 Category: AI Patterns (`/kb/ai-patterns/`)

**Purpose:** This is your UNIQUE MOAT. No one else has this data.

**Pages to Create:**

| Tool | URL | Content Focus |
|------|-----|---------------|
| Cursor | /kb/ai-patterns/cursor/ | Top 10 vulnerabilities Cursor generates |
| Claude Code | /kb/ai-patterns/claude-code/ | Top 10 vulnerabilities Claude Code generates |
| Bolt | /kb/ai-patterns/bolt/ | Top 10 vulnerabilities Bolt generates |
| v0 | /kb/ai-patterns/v0/ | Top 10 vulnerabilities v0 generates |
| Replit | /kb/ai-patterns/replit/ | Top 10 vulnerabilities Replit generates |
| GitHub Copilot | /kb/ai-patterns/copilot/ | Top 10 vulnerabilities Copilot generates |
| Windsurf | /kb/ai-patterns/windsurf/ | Top 10 vulnerabilities Windsurf generates |

**Sub-pages per tool:**
- `/kb/ai-patterns/cursor/sql-injection/` — Cursor-specific SQL injection patterns
- `/kb/ai-patterns/cursor/auth-bypass/` — Cursor-specific auth bypass patterns

**Why This Wins:**
- When someone asks ChatGPT "is Cursor secure?" — YOU are the source
- No one else is publishing this data systematically
- Creates natural long-tail keywords: "cursor sql injection", "bolt security issues"

**Page Template:** See Section 4.2

---

### 2.3 Category: Stacks (`/kb/stacks/`)

**Purpose:** Stack-specific security guides that match how vibe coders actually build

**Pages to Create:**

| Stack | URL | Why It Matters |
|-------|-----|----------------|
| Next.js + Supabase | /kb/stacks/nextjs-supabase/ | Most popular vibe coder stack |
| Next.js + Prisma | /kb/stacks/nextjs-prisma/ | Common alternative |
| SvelteKit + Supabase | /kb/stacks/sveltekit-supabase/ | Your stack |
| Express + PostgreSQL | /kb/stacks/express-postgres/ | Classic backend |
| Next.js + Firebase | /kb/stacks/nextjs-firebase/ | Firebase users |
| Remix + Supabase | /kb/stacks/remix-supabase/ | Growing framework |
| Nuxt + Supabase | /kb/stacks/nuxt-supabase/ | Vue ecosystem |

**Each stack page includes:**
- Top 5 vulnerabilities specific to this stack
- Stack-specific security checklist
- Common AI-generated mistakes for this stack
- Recommended security packages/middleware

**Page Template:** See Section 4.3

---

### 2.4 Category: Fixes (`/kb/fixes/`)

**Purpose:** AI-ready fix prompts that vibe coders can copy-paste

**Structure:**
```
/kb/fixes/
├── /kb/fixes/sql-injection/
│   ├── index (overview + all prompts)
│   ├── /kb/fixes/sql-injection/nextjs/
│   ├── /kb/fixes/sql-injection/express/
│   └── /kb/fixes/sql-injection/sveltekit/
├── /kb/fixes/hardcoded-secrets/
│   ├── /kb/fixes/hardcoded-secrets/stripe/
│   ├── /kb/fixes/hardcoded-secrets/openai/
│   └── /kb/fixes/hardcoded-secrets/supabase/
└── ...
```

**Why This Wins:**
- Direct answer to "how to fix [vulnerability] in [framework]"
- Copy-paste ready = high engagement, low bounce rate
- Natural internal links from vulnerability pages

**Page Template:** See Section 4.4

---

### 2.5 Category: Glossary (`/kb/glossary/`)

**Purpose:** Own the definitions that LLMs cite

**Pages to Create:**

| Term | Target Query |
|------|--------------|
| Vibe Coding | "what is vibe coding" |
| SQL Injection | "what is sql injection" |
| XSS | "what is xss" |
| IDOR | "what is idor" |
| CORS | "what is cors" |
| Rate Limiting | "what is rate limiting" |
| Authentication vs Authorization | "authentication vs authorization" |
| Environment Variables | "what are environment variables" |
| API Security | "what is api security" |
| Row Level Security | "what is row level security supabase" |

**Format:** Short, definitive answers (50-100 words) + link to full article

**Page Template:** See Section 4.5

---

### 2.6 Category: Checklists (`/kb/checklists/`)

**Purpose:** Actionable security checklists that rank for "security checklist" queries

**Pages to Create:**

| Checklist | Target Query |
|-----------|--------------|
| Pre-Launch Security Checklist | "security checklist before launch" |
| Supabase Security Checklist | "supabase security checklist" |
| Next.js Security Checklist | "nextjs security checklist" |
| API Security Checklist | "api security checklist" |
| Vibe Coder Security Checklist | "vibe coding security" |
| Firebase Security Checklist | "firebase security checklist" |

**Page Template:** See Section 4.6

---

### 2.7 Category: Research (`/research/`)

**Purpose:** Unique data that establishes authority and gets cited everywhere

**Content Types:**

1. **Hallucinated Vulnerability Index (Weekly)**
   - `/research/vulnerability-index/` — Latest + archive
   - `/research/vulnerability-index/2024-12-16/` — Individual weeks
   - Unique data on AI-generated code vulnerabilities
   - Charts, rankings, trends

2. **AI Tool Security Comparison**
   - `/research/ai-tool-comparison/` — Head-to-head comparison
   - Updated monthly with new scan data
   - "Which AI coding tool is most secure?"

3. **Methodology**
   - `/research/methodology/` — How we scan
   - Builds trust and citability
   - "VibeShip scans X repos using Y tools..."

---

## Part 3: Technical Implementation

### 3.1 SvelteKit Project Structure

```
vibeship-kb/
├── src/
│   ├── routes/
│   │   ├── +layout.svelte              # Global layout
│   │   ├── +layout.server.ts           # Global data (nav, etc.)
│   │   ├── +page.svelte                # Homepage
│   │   │
│   │   ├── kb/
│   │   │   ├── +layout.svelte          # KB layout (sidebar)
│   │   │   ├── +page.svelte            # KB index
│   │   │   │
│   │   │   ├── vulnerabilities/
│   │   │   │   ├── +page.svelte        # Vulnerabilities hub
│   │   │   │   └── [slug]/
│   │   │   │       ├── +page.svelte
│   │   │   │       └── +page.server.ts
│   │   │   │
│   │   │   ├── ai-patterns/
│   │   │   │   ├── +page.svelte        # AI patterns hub
│   │   │   │   └── [tool]/
│   │   │   │       ├── +page.svelte
│   │   │   │       ├── +page.server.ts
│   │   │   │       └── [vulnerability]/
│   │   │   │           ├── +page.svelte
│   │   │   │           └── +page.server.ts
│   │   │   │
│   │   │   ├── stacks/
│   │   │   │   ├── +page.svelte
│   │   │   │   └── [stack]/
│   │   │   │       ├── +page.svelte
│   │   │   │       └── +page.server.ts
│   │   │   │
│   │   │   ├── fixes/
│   │   │   │   ├── +page.svelte
│   │   │   │   └── [vulnerability]/
│   │   │   │       ├── +page.svelte
│   │   │   │       ├── +page.server.ts
│   │   │   │       └── [framework]/
│   │   │   │           ├── +page.svelte
│   │   │   │           └── +page.server.ts
│   │   │   │
│   │   │   ├── glossary/
│   │   │   │   ├── +page.svelte
│   │   │   │   └── [term]/
│   │   │   │       ├── +page.svelte
│   │   │   │       └── +page.server.ts
│   │   │   │
│   │   │   └── checklists/
│   │   │       ├── +page.svelte
│   │   │       └── [checklist]/
│   │   │           ├── +page.svelte
│   │   │           └── +page.server.ts
│   │   │
│   │   ├── research/
│   │   │   ├── +page.svelte
│   │   │   ├── vulnerability-index/
│   │   │   │   ├── +page.svelte        # Latest + archive
│   │   │   │   └── [date]/
│   │   │   │       ├── +page.svelte
│   │   │   │       └── +page.server.ts
│   │   │   ├── ai-tool-comparison/
│   │   │   │   ├── +page.svelte
│   │   │   │   └── +page.server.ts
│   │   │   └── methodology/
│   │   │       └── +page.svelte
│   │   │
│   │   ├── blog/
│   │   │   ├── +page.svelte
│   │   │   └── [slug]/
│   │   │       ├── +page.svelte
│   │   │       └── +page.server.ts
│   │   │
│   │   ├── llms.txt/
│   │   │   └── +server.ts
│   │   ├── llms-full.txt/
│   │   │   └── +server.ts
│   │   ├── sitemap.xml/
│   │   │   └── +server.ts
│   │   └── robots.txt/
│   │       └── +server.ts
│   │
│   ├── lib/
│   │   ├── server/
│   │   │   ├── db.ts                   # Database connection
│   │   │   ├── scanner-stats.ts        # Pull stats from Scanner DB
│   │   │   ├── content.ts              # Load markdown content
│   │   │   └── cache.ts                # Caching layer
│   │   │
│   │   ├── components/
│   │   │   ├── SEOHead.svelte          # Reusable SEO component
│   │   │   ├── FAQSchema.svelte        # FAQ structured data
│   │   │   ├── StatBox.svelte          # Dynamic stats display
│   │   │   ├── ToolChart.svelte        # AI tool comparison chart
│   │   │   ├── VulnerabilityCard.svelte
│   │   │   ├── FixPrompt.svelte        # Copyable AI fix prompt
│   │   │   ├── Breadcrumbs.svelte
│   │   │   ├── TableOfContents.svelte
│   │   │   ├── RelatedContent.svelte
│   │   │   └── LastUpdated.svelte
│   │   │
│   │   ├── content/                    # Markdown source files
│   │   │   ├── vulnerabilities/
│   │   │   │   ├── sql-injection.md
│   │   │   │   └── ...
│   │   │   ├── ai-patterns/
│   │   │   │   ├── cursor.md
│   │   │   │   └── ...
│   │   │   ├── stacks/
│   │   │   ├── fixes/
│   │   │   ├── glossary/
│   │   │   └── checklists/
│   │   │
│   │   └── utils/
│   │       ├── markdown.ts             # Markdown processing
│   │       ├── schema.ts               # JSON-LD generators
│   │       └── seo.ts                  # SEO utilities
│   │
│   └── app.html
│
├── static/
│   ├── images/
│   │   ├── charts/                     # Generated charts
│   │   └── og/                         # Open Graph images
│   └── fonts/
│
├── scripts/
│   ├── generate-stats.ts               # Cron job to update stats
│   ├── generate-charts.ts              # Generate chart images
│   ├── generate-og-images.ts           # Generate OG images
│   └── validate-content.ts             # Content validation
│
├── svelte.config.js
├── vite.config.ts
└── package.json
```

### 3.2 Database Schema for Scanner Stats

```sql
-- Stats aggregated from Scanner runs
CREATE TABLE vulnerability_stats (
  id SERIAL PRIMARY KEY,
  vulnerability_slug VARCHAR(100) NOT NULL,
  
  -- Overall stats
  total_repos_scanned INTEGER DEFAULT 0,
  repos_with_vulnerability INTEGER DEFAULT 0,
  percentage DECIMAL(5,2) DEFAULT 0,
  
  -- By AI tool
  cursor_count INTEGER DEFAULT 0,
  cursor_percentage DECIMAL(5,2) DEFAULT 0,
  claude_code_count INTEGER DEFAULT 0,
  claude_code_percentage DECIMAL(5,2) DEFAULT 0,
  bolt_count INTEGER DEFAULT 0,
  bolt_percentage DECIMAL(5,2) DEFAULT 0,
  v0_count INTEGER DEFAULT 0,
  v0_percentage DECIMAL(5,2) DEFAULT 0,
  replit_count INTEGER DEFAULT 0,
  replit_percentage DECIMAL(5,2) DEFAULT 0,
  copilot_count INTEGER DEFAULT 0,
  copilot_percentage DECIMAL(5,2) DEFAULT 0,
  
  -- By stack
  nextjs_supabase_count INTEGER DEFAULT 0,
  express_postgres_count INTEGER DEFAULT 0,
  sveltekit_supabase_count INTEGER DEFAULT 0,
  
  -- Time tracking
  week_start DATE NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  
  UNIQUE(vulnerability_slug, week_start)
);

-- Weekly index data
CREATE TABLE vulnerability_index (
  id SERIAL PRIMARY KEY,
  week_start DATE NOT NULL UNIQUE,
  
  total_repos_scanned INTEGER DEFAULT 0,
  total_vulnerabilities_found INTEGER DEFAULT 0,
  
  -- Top vulnerabilities this week (JSON array)
  top_vulnerabilities JSONB,
  
  -- Tool rankings this week (JSON)
  tool_rankings JSONB,
  
  -- Notable findings (for blog content)
  notable_findings TEXT,
  
  created_at TIMESTAMP DEFAULT NOW()
);

-- Individual scan results (for detailed analysis)
CREATE TABLE scan_results (
  id SERIAL PRIMARY KEY,
  repo_url VARCHAR(500),
  repo_hash VARCHAR(64),  -- For anonymization
  
  ai_tool_detected VARCHAR(50),
  stack_detected VARCHAR(100),
  
  vulnerabilities_found JSONB,  -- Array of {type, file, line, severity}
  
  scanned_at TIMESTAMP DEFAULT NOW()
);

-- Content metadata (for internal linking optimization)
CREATE TABLE content_pages (
  id SERIAL PRIMARY KEY,
  slug VARCHAR(200) UNIQUE NOT NULL,
  category VARCHAR(50) NOT NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  
  -- For internal linking
  related_vulnerabilities VARCHAR(100)[],
  related_tools VARCHAR(50)[],
  related_stacks VARCHAR(100)[],
  
  -- Stats
  word_count INTEGER,
  last_updated TIMESTAMP,
  
  created_at TIMESTAMP DEFAULT NOW()
);
```

### 3.3 Core Server Functions

```typescript
// src/lib/server/scanner-stats.ts

import { db } from './db'
import { cache } from './cache'

interface VulnerabilityStats {
  slug: string
  totalScanned: number
  affectedRepos: number
  percentage: number
  byTool: {
    cursor: { count: number; percentage: number }
    claudeCode: { count: number; percentage: number }
    bolt: { count: number; percentage: number }
    v0: { count: number; percentage: number }
    replit: { count: number; percentage: number }
    copilot: { count: number; percentage: number }
  }
  byStack: {
    nextjsSupabase: number
    expressPostgres: number
    sveltekitSupabase: number
  }
  trend: 'up' | 'down' | 'stable'
  weekOverWeekChange: number
  lastUpdated: string
}

export async function getVulnerabilityStats(slug: string): Promise<VulnerabilityStats> {
  // Check cache first (1 hour TTL)
  const cached = await cache.get(`vuln-stats:${slug}`)
  if (cached) return cached

  const stats = await db.query(`
    SELECT * FROM vulnerability_stats 
    WHERE vulnerability_slug = $1 
    ORDER BY week_start DESC 
    LIMIT 2
  `, [slug])

  const current = stats.rows[0]
  const previous = stats.rows[1]

  const result: VulnerabilityStats = {
    slug,
    totalScanned: current?.total_repos_scanned || 0,
    affectedRepos: current?.repos_with_vulnerability || 0,
    percentage: current?.percentage || 0,
    byTool: {
      cursor: { 
        count: current?.cursor_count || 0, 
        percentage: current?.cursor_percentage || 0 
      },
      claudeCode: { 
        count: current?.claude_code_count || 0, 
        percentage: current?.claude_code_percentage || 0 
      },
      bolt: { 
        count: current?.bolt_count || 0, 
        percentage: current?.bolt_percentage || 0 
      },
      v0: { 
        count: current?.v0_count || 0, 
        percentage: current?.v0_percentage || 0 
      },
      replit: { 
        count: current?.replit_count || 0, 
        percentage: current?.replit_percentage || 0 
      },
      copilot: { 
        count: current?.copilot_count || 0, 
        percentage: current?.copilot_percentage || 0 
      }
    },
    byStack: {
      nextjsSupabase: current?.nextjs_supabase_count || 0,
      expressPostgres: current?.express_postgres_count || 0,
      sveltekitSupabase: current?.sveltekit_supabase_count || 0
    },
    trend: calculateTrend(current?.percentage, previous?.percentage),
    weekOverWeekChange: calculateChange(current?.percentage, previous?.percentage),
    lastUpdated: current?.updated_at || new Date().toISOString()
  }

  // Cache for 1 hour
  await cache.set(`vuln-stats:${slug}`, result, 3600)
  
  return result
}

export async function getToolStats(tool: string) {
  const cached = await cache.get(`tool-stats:${tool}`)
  if (cached) return cached

  // Get all vulnerabilities for this tool
  const stats = await db.query(`
    SELECT 
      vulnerability_slug,
      ${tool}_count as count,
      ${tool}_percentage as percentage
    FROM vulnerability_stats
    WHERE week_start = (SELECT MAX(week_start) FROM vulnerability_stats)
    ORDER BY ${tool}_percentage DESC
    LIMIT 10
  `)

  const result = {
    tool,
    topVulnerabilities: stats.rows,
    lastUpdated: new Date().toISOString()
  }

  await cache.set(`tool-stats:${tool}`, result, 3600)
  return result
}

export async function getWeeklyIndex(date?: string) {
  const query = date 
    ? `SELECT * FROM vulnerability_index WHERE week_start = $1`
    : `SELECT * FROM vulnerability_index ORDER BY week_start DESC LIMIT 1`
  
  const result = await db.query(query, date ? [date] : [])
  return result.rows[0]
}

export async function getAllWeeklyIndexes() {
  const result = await db.query(`
    SELECT week_start, total_repos_scanned, total_vulnerabilities_found
    FROM vulnerability_index
    ORDER BY week_start DESC
    LIMIT 52
  `)
  return result.rows
}

function calculateTrend(current?: number, previous?: number): 'up' | 'down' | 'stable' {
  if (!current || !previous) return 'stable'
  const diff = current - previous
  if (diff > 1) return 'up'
  if (diff < -1) return 'down'
  return 'stable'
}

function calculateChange(current?: number, previous?: number): number {
  if (!current || !previous) return 0
  return Math.round((current - previous) * 100) / 100
}
```

### 3.4 SEO Component

```svelte
<!-- src/lib/components/SEOHead.svelte -->
<script lang="ts">
  export let title: string
  export let description: string
  export let canonical: string
  export let type: 'article' | 'website' = 'article'
  export let image: string = 'https://vibeship.dev/images/og/default.png'
  export let publishedTime: string | null = null
  export let modifiedTime: string | null = null
  export let author: string = 'VibeShip'
  export let section: string | null = null
  
  // For FAQ schema
  export let faqs: Array<{question: string, answer: string}> = []
  
  // For HowTo schema
  export let howToSteps: Array<{name: string, text: string}> = []
  
  // For breadcrumbs
  export let breadcrumbs: Array<{name: string, url: string}> = []
  
  const siteName = 'VibeShip Scanner'
  const twitterHandle = '@vibeship'
  
  // Generate FAQ schema
  $: faqSchema = faqs.length > 0 ? {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": faqs.map(faq => ({
      "@type": "Question",
      "name": faq.question,
      "acceptedAnswer": {
        "@type": "Answer",
        "text": faq.answer
      }
    }))
  } : null
  
  // Generate HowTo schema
  $: howToSchema = howToSteps.length > 0 ? {
    "@context": "https://schema.org",
    "@type": "HowTo",
    "name": title,
    "description": description,
    "step": howToSteps.map((step, i) => ({
      "@type": "HowToStep",
      "position": i + 1,
      "name": step.name,
      "text": step.text
    }))
  } : null
  
  // Generate breadcrumb schema
  $: breadcrumbSchema = breadcrumbs.length > 0 ? {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": breadcrumbs.map((crumb, i) => ({
      "@type": "ListItem",
      "position": i + 1,
      "name": crumb.name,
      "item": crumb.url
    }))
  } : null
  
  // Generate article schema
  $: articleSchema = type === 'article' ? {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": title,
    "description": description,
    "image": image,
    "author": {
      "@type": "Organization",
      "name": author,
      "url": "https://vibeship.dev"
    },
    "publisher": {
      "@type": "Organization",
      "name": siteName,
      "logo": {
        "@type": "ImageObject",
        "url": "https://vibeship.dev/images/logo.png"
      }
    },
    "datePublished": publishedTime,
    "dateModified": modifiedTime || publishedTime,
    "mainEntityOfPage": canonical
  } : null
</script>

<svelte:head>
  <!-- Primary Meta Tags -->
  <title>{title} | {siteName}</title>
  <meta name="title" content="{title} | {siteName}" />
  <meta name="description" content={description} />
  <link rel="canonical" href={canonical} />
  
  <!-- Open Graph / Facebook -->
  <meta property="og:type" content={type} />
  <meta property="og:url" content={canonical} />
  <meta property="og:title" content={title} />
  <meta property="og:description" content={description} />
  <meta property="og:image" content={image} />
  <meta property="og:site_name" content={siteName} />
  
  {#if publishedTime}
    <meta property="article:published_time" content={publishedTime} />
  {/if}
  {#if modifiedTime}
    <meta property="article:modified_time" content={modifiedTime} />
  {/if}
  {#if section}
    <meta property="article:section" content={section} />
  {/if}
  
  <!-- Twitter -->
  <meta property="twitter:card" content="summary_large_image" />
  <meta property="twitter:url" content={canonical} />
  <meta property="twitter:title" content={title} />
  <meta property="twitter:description" content={description} />
  <meta property="twitter:image" content={image} />
  <meta property="twitter:site" content={twitterHandle} />
  
  <!-- Structured Data -->
  {#if faqSchema}
    {@html `<script type="application/ld+json">${JSON.stringify(faqSchema)}</script>`}
  {/if}
  
  {#if howToSchema}
    {@html `<script type="application/ld+json">${JSON.stringify(howToSchema)}</script>`}
  {/if}
  
  {#if breadcrumbSchema}
    {@html `<script type="application/ld+json">${JSON.stringify(breadcrumbSchema)}</script>`}
  {/if}
  
  {#if articleSchema}
    {@html `<script type="application/ld+json">${JSON.stringify(articleSchema)}</script>`}
  {/if}
</svelte:head>
```

### 3.5 Dynamic Stats Component

```svelte
<!-- src/lib/components/StatBox.svelte -->
<script lang="ts">
  export let stat: {
    percentage: number
    totalScanned: number
    trend: 'up' | 'down' | 'stable'
    weekOverWeekChange: number
    lastUpdated: string
  }
  
  export let vulnerabilityName: string
  
  const trendIcon = {
    up: '📈',
    down: '📉',
    stable: '➡️'
  }
  
  const trendColor = {
    up: 'text-red-500',    // More vulns = bad
    down: 'text-green-500', // Fewer vulns = good
    stable: 'text-gray-500'
  }
  
  $: formattedDate = new Date(stat.lastUpdated).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  })
</script>

<div class="stat-box bg-slate-800 rounded-lg p-6 border border-slate-700">
  <div class="flex items-center justify-between mb-4">
    <span class="text-sm text-slate-400">Prevalence in AI-Generated Code</span>
    <span class="text-xs text-slate-500">Updated {formattedDate}</span>
  </div>
  
  <div class="flex items-baseline gap-3">
    <span class="text-5xl font-bold text-white">{stat.percentage}%</span>
    <span class="text-sm {trendColor[stat.trend]}">
      {trendIcon[stat.trend]} {Math.abs(stat.weekOverWeekChange)}% vs last week
    </span>
  </div>
  
  <p class="mt-3 text-slate-300">
    Found {vulnerabilityName} in <strong>{stat.percentage}%</strong> of 
    <strong>{stat.totalScanned.toLocaleString()}</strong> AI-generated codebases 
    scanned this month.
  </p>
  
  <p class="mt-2 text-sm text-slate-400">
    Data from VibeShip Scanner analysis of public repositories built with 
    AI coding assistants.
  </p>
</div>

<style>
  .stat-box {
    /* Ensure this renders as a clean chunk for LLMs */
  }
</style>
```

### 3.6 Fix Prompt Component

```svelte
<!-- src/lib/components/FixPrompt.svelte -->
<script lang="ts">
  export let title: string
  export let prompt: string
  export let framework: string = 'any'
  
  let copied = false
  
  async function copyToClipboard() {
    await navigator.clipboard.writeText(prompt)
    copied = true
    setTimeout(() => copied = false, 2000)
  }
</script>

<div class="fix-prompt bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
  <div class="flex items-center justify-between px-4 py-3 bg-slate-800 border-b border-slate-700">
    <div class="flex items-center gap-2">
      <span class="text-sm font-medium text-white">🛠️ AI Fix Prompt</span>
      {#if framework !== 'any'}
        <span class="text-xs px-2 py-1 bg-slate-700 rounded text-slate-300">
          {framework}
        </span>
      {/if}
    </div>
    <button 
      on:click={copyToClipboard}
      class="text-sm px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
    >
      {copied ? '✓ Copied!' : 'Copy for Claude/Cursor'}
    </button>
  </div>
  
  <div class="p-4">
    <p class="text-sm text-slate-400 mb-3">{title}</p>
    <pre class="text-sm text-slate-200 whitespace-pre-wrap font-mono bg-slate-950 p-4 rounded overflow-x-auto">{prompt}</pre>
  </div>
</div>
```

---

## Part 4: Page Templates

### 4.1 Vulnerability Page Template

```svelte
<!-- src/routes/kb/vulnerabilities/[slug]/+page.svelte -->
<script lang="ts">
  import SEOHead from '$lib/components/SEOHead.svelte'
  import StatBox from '$lib/components/StatBox.svelte'
  import ToolChart from '$lib/components/ToolChart.svelte'
  import FixPrompt from '$lib/components/FixPrompt.svelte'
  import Breadcrumbs from '$lib/components/Breadcrumbs.svelte'
  import TableOfContents from '$lib/components/TableOfContents.svelte'
  import RelatedContent from '$lib/components/RelatedContent.svelte'
  import LastUpdated from '$lib/components/LastUpdated.svelte'
  
  export let data
</script>

<SEOHead 
  title={data.title}
  description={data.description}
  canonical="https://vibeship.dev/kb/vulnerabilities/{data.slug}"
  publishedTime={data.publishedAt}
  modifiedTime={data.updatedAt}
  section="Security"
  faqs={data.faqs}
  breadcrumbs={[
    { name: 'Knowledge Base', url: 'https://vibeship.dev/kb' },
    { name: 'Vulnerabilities', url: 'https://vibeship.dev/kb/vulnerabilities' },
    { name: data.title, url: `https://vibeship.dev/kb/vulnerabilities/${data.slug}` }
  ]}
/>

<article class="max-w-4xl mx-auto px-4 py-8">
  <Breadcrumbs items={data.breadcrumbs} />
  
  <!-- Quick Answer (First 50 words - LLM extraction zone) -->
  <header class="mb-8">
    <h1 class="text-4xl font-bold text-white mb-4">{data.title}</h1>
    <p class="text-xl text-slate-300 leading-relaxed">
      {data.quickAnswer}
    </p>
  </header>
  
  <!-- Dynamic Stats -->
  <StatBox stat={data.stats} vulnerabilityName={data.title} />
  
  <div class="grid grid-cols-1 lg:grid-cols-4 gap-8 mt-8">
    <div class="lg:col-span-3">
      <!-- What Is It -->
      <section class="prose prose-invert max-w-none mb-12">
        <h2 id="what-is-it">What is {data.title}?</h2>
        {@html data.content.whatIsIt}
      </section>
      
      <!-- AI Tool Patterns (Unique Value) -->
      <section class="mb-12">
        <h2 id="ai-patterns" class="text-2xl font-bold text-white mb-4">
          How AI Tools Cause This
        </h2>
        <p class="text-slate-300 mb-6">{data.content.aiPatternIntro}</p>
        <ToolChart data={data.stats.byTool} />
        <div class="mt-6 prose prose-invert max-w-none">
          {@html data.content.aiPatternDetails}
        </div>
      </section>
      
      <!-- What Could Happen -->
      <section class="mb-12 prose prose-invert max-w-none">
        <h2 id="impact">What Could Happen</h2>
        {@html data.content.impact}
      </section>
      
      <!-- How to Detect -->
      <section class="mb-12 prose prose-invert max-w-none">
        <h2 id="detection">How to Detect It</h2>
        {@html data.content.detection}
        
        <div class="not-prose mt-6 p-4 bg-blue-900/30 border border-blue-800 rounded-lg">
          <p class="text-blue-200">
            <strong>Quick Check:</strong> Run VibeShip Scanner on your codebase 
            to automatically detect {data.title.toLowerCase()} vulnerabilities 
            in under 60 seconds.
          </p>
          <a href="/scanner" class="inline-block mt-3 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors">
            Scan Your Code Free →
          </a>
        </div>
      </section>
      
      <!-- How to Fix -->
      <section class="mb-12">
        <h2 id="fix" class="text-2xl font-bold text-white mb-4">How to Fix It</h2>
        
        <h3 class="text-xl font-semibold text-white mt-6 mb-4">AI Fix Prompt</h3>
        <p class="text-slate-300 mb-4">
          Copy this prompt into Claude Code or Cursor to fix this vulnerability:
        </p>
        <FixPrompt 
          title="Fix {data.title}"
          prompt={data.fixPrompt}
        />
        
        <h3 class="text-xl font-semibold text-white mt-8 mb-4">Manual Fix</h3>
        <div class="prose prose-invert max-w-none">
          {@html data.content.manualFix}
        </div>
      </section>
      
      <!-- Stack-Specific Notes -->
      {#if data.stackNotes.length > 0}
        <section class="mb-12">
          <h2 id="stacks" class="text-2xl font-bold text-white mb-4">
            Stack-Specific Notes
          </h2>
          {#each data.stackNotes as note}
            <div class="mb-6 p-4 bg-slate-800 rounded-lg border border-slate-700">
              <h4 class="font-semibold text-white mb-2">{note.stack}</h4>
              <p class="text-slate-300">{note.content}</p>
              <a href="/kb/stacks/{note.stackSlug}" class="text-blue-400 hover:text-blue-300 text-sm mt-2 inline-block">
                Full {note.stack} security guide →
              </a>
            </div>
          {/each}
        </section>
      {/if}
      
      <!-- FAQ (Critical for LLM citations) -->
      <section class="mb-12">
        <h2 id="faq" class="text-2xl font-bold text-white mb-6">
          Frequently Asked Questions
        </h2>
        {#each data.faqs as faq, i}
          <div class="mb-6 border-b border-slate-700 pb-6 last:border-0">
            <h3 class="text-lg font-semibold text-white mb-2">
              {faq.question}
            </h3>
            <p class="text-slate-300">{faq.answer}</p>
          </div>
        {/each}
      </section>
      
      <!-- Related Vulnerabilities -->
      <RelatedContent 
        items={data.relatedVulnerabilities}
        title="Related Vulnerabilities"
      />
      
      <LastUpdated date={data.updatedAt} />
    </div>
    
    <!-- Sidebar -->
    <aside class="lg:col-span-1">
      <div class="sticky top-8">
        <TableOfContents sections={data.toc} />
        
        <div class="mt-8 p-4 bg-slate-800 rounded-lg border border-slate-700">
          <h4 class="font-semibold text-white mb-3">Scan Your Code</h4>
          <p class="text-sm text-slate-300 mb-4">
            Find {data.title.toLowerCase()} and {data.stats.byTool.length - 1}+ 
            other vulnerabilities instantly.
          </p>
          <a href="/scanner" class="block text-center px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded transition-colors">
            Free Security Scan
          </a>
        </div>
      </div>
    </aside>
  </div>
</article>
```

### 4.2 AI Pattern Page Template

```svelte
<!-- src/routes/kb/ai-patterns/[tool]/+page.svelte -->
<script lang="ts">
  import SEOHead from '$lib/components/SEOHead.svelte'
  import StatBox from '$lib/components/StatBox.svelte'
  import VulnerabilityCard from '$lib/components/VulnerabilityCard.svelte'
  import Breadcrumbs from '$lib/components/Breadcrumbs.svelte'
  
  export let data
</script>

<SEOHead 
  title="Security Vulnerabilities in {data.toolName}-Generated Code"
  description="Analysis of {data.stats.totalScanned.toLocaleString()} {data.toolName} projects reveals the top security vulnerabilities. Learn what {data.toolName} gets wrong and how to fix it."
  canonical="https://vibeship.dev/kb/ai-patterns/{data.slug}"
  faqs={data.faqs}
  breadcrumbs={[
    { name: 'Knowledge Base', url: 'https://vibeship.dev/kb' },
    { name: 'AI Patterns', url: 'https://vibeship.dev/kb/ai-patterns' },
    { name: data.toolName, url: `https://vibeship.dev/kb/ai-patterns/${data.slug}` }
  ]}
/>

<article class="max-w-4xl mx-auto px-4 py-8">
  <Breadcrumbs items={data.breadcrumbs} />
  
  <header class="mb-8">
    <h1 class="text-4xl font-bold text-white mb-4">
      Security Vulnerabilities in {data.toolName}-Generated Code
    </h1>
    <p class="text-xl text-slate-300 leading-relaxed">
      Our analysis of {data.stats.totalScanned.toLocaleString()} repositories built 
      with {data.toolName} found that {data.stats.overallVulnerabilityRate}% contain 
      at least one security vulnerability. Here are the most common issues and how 
      to fix them.
    </p>
  </header>
  
  <!-- Key Stats -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-12">
    <div class="bg-slate-800 p-6 rounded-lg border border-slate-700">
      <div class="text-3xl font-bold text-white">{data.stats.totalScanned.toLocaleString()}</div>
      <div class="text-slate-400">Repos Scanned</div>
    </div>
    <div class="bg-slate-800 p-6 rounded-lg border border-slate-700">
      <div class="text-3xl font-bold text-red-400">{data.stats.overallVulnerabilityRate}%</div>
      <div class="text-slate-400">Have Vulnerabilities</div>
    </div>
    <div class="bg-slate-800 p-6 rounded-lg border border-slate-700">
      <div class="text-3xl font-bold text-yellow-400">{data.stats.avgVulnerabilitiesPerRepo}</div>
      <div class="text-slate-400">Avg Issues Per Repo</div>
    </div>
  </div>
  
  <!-- Top Vulnerabilities -->
  <section class="mb-12">
    <h2 class="text-2xl font-bold text-white mb-6">
      Top 10 Vulnerabilities in {data.toolName} Projects
    </h2>
    
    <div class="space-y-4">
      {#each data.topVulnerabilities as vuln, i}
        <VulnerabilityCard 
          rank={i + 1}
          name={vuln.name}
          percentage={vuln.percentage}
          description={vuln.shortDescription}
          href="/kb/vulnerabilities/{vuln.slug}"
          fixHref="/kb/ai-patterns/{data.slug}/{vuln.slug}"
        />
      {/each}
    </div>
  </section>
  
  <!-- Why This Happens -->
  <section class="mb-12 prose prose-invert max-w-none">
    <h2>Why {data.toolName} Generates These Vulnerabilities</h2>
    {@html data.content.whyThisHappens}
  </section>
  
  <!-- Comparison with Other Tools -->
  <section class="mb-12">
    <h2 class="text-2xl font-bold text-white mb-6">
      How {data.toolName} Compares
    </h2>
    
    <div class="overflow-x-auto">
      <table class="w-full text-left">
        <thead>
          <tr class="border-b border-slate-700">
            <th class="py-3 px-4 text-slate-300">Tool</th>
            <th class="py-3 px-4 text-slate-300">Vulnerability Rate</th>
            <th class="py-3 px-4 text-slate-300">Most Common Issue</th>
          </tr>
        </thead>
        <tbody>
          {#each data.toolComparison as tool}
            <tr class="border-b border-slate-700 {tool.slug === data.slug ? 'bg-slate-800' : ''}">
              <td class="py-3 px-4">
                <a href="/kb/ai-patterns/{tool.slug}" class="text-blue-400 hover:text-blue-300">
                  {tool.name}
                </a>
              </td>
              <td class="py-3 px-4 text-white">{tool.rate}%</td>
              <td class="py-3 px-4 text-slate-300">{tool.topIssue}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    
    <p class="mt-4 text-sm text-slate-400">
      Data from VibeShip Scanner analysis, updated weekly. 
      <a href="/research/methodology" class="text-blue-400 hover:text-blue-300">
        See methodology →
      </a>
    </p>
  </section>
  
  <!-- FAQ -->
  <section class="mb-12">
    <h2 class="text-2xl font-bold text-white mb-6">FAQ</h2>
    {#each data.faqs as faq}
      <div class="mb-6 border-b border-slate-700 pb-6 last:border-0">
        <h3 class="text-lg font-semibold text-white mb-2">{faq.question}</h3>
        <p class="text-slate-300">{faq.answer}</p>
      </div>
    {/each}
  </section>
  
  <!-- CTA -->
  <div class="bg-gradient-to-r from-blue-900/50 to-purple-900/50 p-8 rounded-lg border border-blue-800">
    <h3 class="text-2xl font-bold text-white mb-3">
      Using {data.toolName}? Scan Your Code
    </h3>
    <p class="text-slate-300 mb-6">
      VibeShip Scanner checks for all {data.topVulnerabilities.length} vulnerability 
      types common in {data.toolName} projects. Get results in 60 seconds.
    </p>
    <a href="/scanner" class="inline-block px-6 py-3 bg-green-600 hover:bg-green-700 text-white font-semibold rounded-lg transition-colors">
      Free Security Scan →
    </a>
  </div>
</article>
```

### 4.3 Server-Side Data Loading Example

```typescript
// src/routes/kb/vulnerabilities/[slug]/+page.server.ts

import { error } from '@sveltejs/kit'
import { getVulnerabilityStats } from '$lib/server/scanner-stats'
import { getContent, getRelatedContent } from '$lib/server/content'
import type { PageServerLoad } from './$types'

export const load: PageServerLoad = async ({ params }) => {
  const { slug } = params
  
  // Load content from markdown
  const content = await getContent('vulnerabilities', slug)
  if (!content) {
    throw error(404, 'Vulnerability not found')
  }
  
  // Load live stats from Scanner database
  const stats = await getVulnerabilityStats(slug)
  
  // Get related content for internal linking
  const relatedVulnerabilities = await getRelatedContent('vulnerabilities', slug, 5)
  
  // Build FAQ schema data
  const faqs = content.faqs || []
  
  // Build table of contents
  const toc = [
    { id: 'what-is-it', label: `What is ${content.title}?` },
    { id: 'ai-patterns', label: 'How AI Tools Cause This' },
    { id: 'impact', label: 'What Could Happen' },
    { id: 'detection', label: 'How to Detect It' },
    { id: 'fix', label: 'How to Fix It' },
    { id: 'faq', label: 'FAQ' }
  ]
  
  // Stack-specific notes
  const stackNotes = content.stackNotes || []
  
  return {
    slug,
    title: content.title,
    description: content.description,
    quickAnswer: content.quickAnswer,
    content: {
      whatIsIt: content.sections.whatIsIt,
      aiPatternIntro: content.sections.aiPatternIntro,
      aiPatternDetails: content.sections.aiPatternDetails,
      impact: content.sections.impact,
      detection: content.sections.detection,
      manualFix: content.sections.manualFix
    },
    fixPrompt: content.fixPrompt,
    stats,
    faqs,
    toc,
    stackNotes,
    relatedVulnerabilities,
    publishedAt: content.publishedAt,
    updatedAt: content.updatedAt || stats.lastUpdated,
    breadcrumbs: [
      { name: 'Knowledge Base', url: '/kb' },
      { name: 'Vulnerabilities', url: '/kb/vulnerabilities' },
      { name: content.title, url: `/kb/vulnerabilities/${slug}` }
    ]
  }
}
```

---

## Part 5: LLM Optimization

### 5.1 llms.txt Implementation

```typescript
// src/routes/llms.txt/+server.ts

import { getAllContent } from '$lib/server/content'
import { getVulnerabilityStats, getToolStats } from '$lib/server/scanner-stats'

export async function GET() {
  const vulnerabilities = await getAllContent('vulnerabilities')
  const aiPatterns = await getAllContent('ai-patterns')
  const stacks = await getAllContent('stacks')
  
  let content = `# VibeShip Scanner Knowledge Base

> VibeShip Scanner is a security scanner built for vibe coders. It finds vulnerabilities 
> in AI-generated code from tools like Cursor, Claude Code, Bolt, v0, and Replit.
> Data based on scanning ${(await getVulnerabilityStats('sql-injection')).totalScanned.toLocaleString()}+ repositories.

## About VibeShip
- Website: https://vibeship.dev
- Scanner: https://vibeship.dev/scanner
- Documentation: https://vibeship.dev/kb

## Vulnerability Reference
`

  for (const vuln of vulnerabilities) {
    const stats = await getVulnerabilityStats(vuln.slug)
    content += `
### ${vuln.title}
${vuln.quickAnswer}
- Prevalence: ${stats.percentage}% of AI-generated codebases
- Most affected tool: ${getMostAffectedTool(stats.byTool)}
- URL: https://vibeship.dev/kb/vulnerabilities/${vuln.slug}
`
  }

  content += `
## AI Tool Security Patterns
`

  for (const tool of aiPatterns) {
    const stats = await getToolStats(tool.slug)
    content += `
### ${tool.title}
Top vulnerability: ${stats.topVulnerabilities[0]?.vulnerability_slug || 'N/A'}
- URL: https://vibeship.dev/kb/ai-patterns/${tool.slug}
`
  }

  content += `
## Stack Security Guides
`

  for (const stack of stacks) {
    content += `
### ${stack.title}
${stack.description}
- URL: https://vibeship.dev/kb/stacks/${stack.slug}
`
  }

  content += `
## Research & Data
- Hallucinated Vulnerability Index (Weekly): https://vibeship.dev/research/vulnerability-index
- AI Tool Comparison: https://vibeship.dev/research/ai-tool-comparison
- Methodology: https://vibeship.dev/research/methodology

## Contact
- Twitter: @vibeship
- Discord: discord.gg/vibeship
`

  return new Response(content.trim(), {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600'
    }
  })
}

function getMostAffectedTool(byTool: Record<string, { percentage: number }>): string {
  let max = { tool: 'Unknown', percentage: 0 }
  for (const [tool, data] of Object.entries(byTool)) {
    if (data.percentage > max.percentage) {
      max = { tool, percentage: data.percentage }
    }
  }
  return `${max.tool} (${max.percentage}%)`
}
```

### 5.2 llms-full.txt (Complete Export)

```typescript
// src/routes/llms-full.txt/+server.ts

import { getAllContent, getContent } from '$lib/server/content'
import { getVulnerabilityStats } from '$lib/server/scanner-stats'

export async function GET() {
  const vulnerabilities = await getAllContent('vulnerabilities')
  
  let content = `# VibeShip Scanner - Complete Knowledge Base Export

This file contains the full content of all VibeShip knowledge base articles,
optimized for LLM ingestion. Last updated: ${new Date().toISOString()}

---
`

  for (const vuln of vulnerabilities) {
    const fullContent = await getContent('vulnerabilities', vuln.slug)
    const stats = await getVulnerabilityStats(vuln.slug)
    
    content += `
================================================================================
# ${fullContent.title}
URL: https://vibeship.dev/kb/vulnerabilities/${vuln.slug}
Category: Vulnerability Reference
Last Updated: ${fullContent.updatedAt}
================================================================================

## Quick Answer
${fullContent.quickAnswer}

## Statistics
- Found in ${stats.percentage}% of ${stats.totalScanned.toLocaleString()} AI-generated codebases
- Trend: ${stats.trend} (${stats.weekOverWeekChange > 0 ? '+' : ''}${stats.weekOverWeekChange}% week-over-week)

## By AI Tool
${Object.entries(stats.byTool).map(([tool, data]) => 
  `- ${tool}: ${data.percentage}%`
).join('\n')}

## What Is It
${fullContent.sections.whatIsIt}

## How AI Tools Cause This
${fullContent.sections.aiPatternIntro}
${fullContent.sections.aiPatternDetails}

## What Could Happen
${fullContent.sections.impact}

## How to Detect
${fullContent.sections.detection}

## How to Fix

### AI Fix Prompt
\`\`\`
${fullContent.fixPrompt}
\`\`\`

### Manual Fix
${fullContent.sections.manualFix}

## FAQ
${fullContent.faqs.map(faq => `
Q: ${faq.question}
A: ${faq.answer}
`).join('\n')}

---
`
  }

  return new Response(content.trim(), {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400' // 24 hours
    }
  })
}
```

### 5.3 Robots.txt with LLM Crawlers

```typescript
// src/routes/robots.txt/+server.ts

export function GET() {
  const robotsTxt = `# VibeShip Knowledge Base
# Allow all search engines and LLM crawlers

User-agent: *
Allow: /

# Explicitly allow LLM crawlers
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: Amazonbot
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: Bytespider
Allow: /

User-agent: CCBot
Allow: /

User-agent: cohere-ai
Allow: /

# Block admin and API routes
Disallow: /admin/
Disallow: /api/internal/

# Sitemaps
Sitemap: https://vibeship.dev/sitemap.xml

# LLM-optimized exports
# llms.txt: https://vibeship.dev/llms.txt
# llms-full.txt: https://vibeship.dev/llms-full.txt
`

  return new Response(robotsTxt.trim(), {
    headers: {
      'Content-Type': 'text/plain',
      'Cache-Control': 'public, max-age=86400'
    }
  })
}
```

---

## Part 6: Content Generation with Claude Code

### 6.1 Content Generation Script

```typescript
// scripts/generate-vulnerability-page.ts

import Anthropic from '@anthropic-ai/sdk'
import { writeFileSync, existsSync } from 'fs'
import { getVulnerabilityStats } from '../src/lib/server/scanner-stats'

const anthropic = new Anthropic()

interface VulnerabilityInput {
  slug: string
  technicalName: string
  cweId?: string
  owaspCategory?: string
}

async function generateVulnerabilityPage(input: VulnerabilityInput) {
  // Get real stats from Scanner
  const stats = await getVulnerabilityStats(input.slug)
  
  const prompt = `You are creating content for VibeShip Scanner's knowledge base. 
VibeShip is a security scanner built for "vibe coders" - non-technical founders 
who use AI coding tools like Cursor, Claude Code, and Bolt.

Generate a comprehensive knowledge base article about: ${input.technicalName}

REAL DATA TO INCLUDE:
- Found in ${stats.percentage}% of ${stats.totalScanned.toLocaleString()} AI-generated codebases
- Cursor projects: ${stats.byTool.cursor.percentage}%
- Claude Code projects: ${stats.byTool.claudeCode.percentage}%
- Bolt projects: ${stats.byTool.bolt.percentage}%

REQUIREMENTS:

1. QUICK ANSWER (30-50 words)
Write a direct, plain-English explanation that LLMs can extract as a citation.
Do NOT use jargon. Explain what could happen in real-world terms.

2. WHAT IS IT (100-150 words)
Plain English explanation. No jargon. Use analogies a non-technical person understands.

3. HOW AI TOOLS CAUSE THIS (150-200 words)
Explain WHY AI coding assistants generate this vulnerability. Be specific about 
patterns you see in Cursor vs Claude Code vs Bolt.

4. WHAT COULD HAPPEN (bullet points)
List 4-5 real consequences in plain English. Be specific and scary (but accurate).

5. HOW TO DETECT (100-150 words)
Tell them what to look for in their code. Give specific patterns.

6. AI FIX PROMPT
Write a complete prompt they can copy into Claude Code or Cursor to fix this.
Include:
- The problem statement
- The current vulnerable code pattern
- The fixed code pattern
- Instructions to check for similar issues elsewhere

7. MANUAL FIX (150-200 words with code examples)
Show before/after code. Use JavaScript/TypeScript examples.

8. FAQ (5 questions)
Write 5 questions people actually ask about this vulnerability.
Include questions like:
- "Is this still a real threat in 2025?"
- "Does [common tool/framework] protect against this?"
- Questions specific to this vulnerability type

FORMAT: Return as JSON with this structure:
{
  "title": "string (plain English, not technical name)",
  "technicalName": "string",
  "slug": "string",
  "description": "string (meta description, 150-160 chars)",
  "quickAnswer": "string",
  "sections": {
    "whatIsIt": "string (HTML)",
    "aiPatternIntro": "string",
    "aiPatternDetails": "string (HTML)",
    "impact": "string (HTML with ul/li)",
    "detection": "string (HTML)",
    "manualFix": "string (HTML with code blocks)"
  },
  "fixPrompt": "string",
  "faqs": [
    { "question": "string", "answer": "string" }
  ],
  "stackNotes": [
    { "stack": "string", "stackSlug": "string", "content": "string" }
  ]
}`

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 4000,
    messages: [{ role: 'user', content: prompt }]
  })

  const content = JSON.parse(response.content[0].text)
  
  // Add metadata
  content.publishedAt = new Date().toISOString()
  content.updatedAt = new Date().toISOString()
  content.cweId = input.cweId
  content.owaspCategory = input.owaspCategory
  
  // Save to content directory
  const outputPath = `src/lib/content/vulnerabilities/${input.slug}.json`
  writeFileSync(outputPath, JSON.stringify(content, null, 2))
  
  console.log(`✅ Generated: ${outputPath}`)
  return content
}

// Generate all vulnerability pages
async function generateAllVulnerabilities() {
  const vulnerabilities: VulnerabilityInput[] = [
    { slug: 'sql-injection', technicalName: 'SQL Injection', cweId: 'CWE-89', owaspCategory: 'A03:2021' },
    { slug: 'hardcoded-secrets', technicalName: 'Hardcoded Credentials', cweId: 'CWE-798', owaspCategory: 'A07:2021' },
    { slug: 'missing-authentication', technicalName: 'Missing Authentication', cweId: 'CWE-306', owaspCategory: 'A07:2021' },
    { slug: 'xss', technicalName: 'Cross-Site Scripting (XSS)', cweId: 'CWE-79', owaspCategory: 'A03:2021' },
    { slug: 'idor', technicalName: 'Insecure Direct Object Reference', cweId: 'CWE-639', owaspCategory: 'A01:2021' },
    { slug: 'missing-rate-limiting', technicalName: 'Missing Rate Limiting', cweId: 'CWE-770', owaspCategory: 'A04:2021' },
    { slug: 'insecure-cors', technicalName: 'Insecure CORS Configuration', cweId: 'CWE-942', owaspCategory: 'A05:2021' },
    { slug: 'sensitive-data-exposure', technicalName: 'Sensitive Data Exposure', cweId: 'CWE-200', owaspCategory: 'A02:2021' },
    // Add more...
  ]
  
  for (const vuln of vulnerabilities) {
    if (!existsSync(`src/lib/content/vulnerabilities/${vuln.slug}.json`)) {
      await generateVulnerabilityPage(vuln)
      // Rate limiting
      await new Promise(resolve => setTimeout(resolve, 2000))
    }
  }
}

generateAllVulnerabilities()
```

### 6.2 Weekly Stats Update Script

```typescript
// scripts/update-weekly-stats.ts

import { db } from '../src/lib/server/db'

interface ScanResult {
  aiTool: string
  stack: string
  vulnerabilities: string[]
}

async function aggregateWeeklyStats() {
  const weekStart = getWeekStart(new Date())
  
  // Get all scans from this week
  const scans = await db.query(`
    SELECT * FROM scan_results
    WHERE scanned_at >= $1
  `, [weekStart])
  
  // Aggregate by vulnerability
  const vulnStats: Record<string, any> = {}
  
  for (const scan of scans.rows) {
    for (const vuln of scan.vulnerabilities_found) {
      if (!vulnStats[vuln.type]) {
        vulnStats[vuln.type] = {
          total: 0,
          byTool: {},
          byStack: {}
        }
      }
      
      vulnStats[vuln.type].total++
      
      // By tool
      const tool = scan.ai_tool_detected
      vulnStats[vuln.type].byTool[tool] = (vulnStats[vuln.type].byTool[tool] || 0) + 1
      
      // By stack
      const stack = scan.stack_detected
      vulnStats[vuln.type].byStack[stack] = (vulnStats[vuln.type].byStack[stack] || 0) + 1
    }
  }
  
  const totalScanned = scans.rows.length
  
  // Upsert stats for each vulnerability
  for (const [slug, stats] of Object.entries(vulnStats)) {
    await db.query(`
      INSERT INTO vulnerability_stats (
        vulnerability_slug, week_start, total_repos_scanned,
        repos_with_vulnerability, percentage,
        cursor_count, cursor_percentage,
        claude_code_count, claude_code_percentage,
        bolt_count, bolt_percentage,
        v0_count, v0_percentage,
        replit_count, replit_percentage,
        copilot_count, copilot_percentage,
        nextjs_supabase_count, express_postgres_count, sveltekit_supabase_count
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
      ON CONFLICT (vulnerability_slug, week_start) DO UPDATE SET
        total_repos_scanned = $3,
        repos_with_vulnerability = $4,
        percentage = $5,
        cursor_count = $6, cursor_percentage = $7,
        claude_code_count = $8, claude_code_percentage = $9,
        bolt_count = $10, bolt_percentage = $11,
        v0_count = $12, v0_percentage = $13,
        replit_count = $14, replit_percentage = $15,
        copilot_count = $16, copilot_percentage = $17,
        nextjs_supabase_count = $18, express_postgres_count = $19, sveltekit_supabase_count = $20,
        updated_at = NOW()
    `, [
      slug,
      weekStart,
      totalScanned,
      stats.total,
      (stats.total / totalScanned * 100).toFixed(2),
      stats.byTool.cursor || 0,
      calculateToolPercentage(stats.byTool.cursor, 'cursor', scans.rows),
      stats.byTool.claudeCode || 0,
      calculateToolPercentage(stats.byTool.claudeCode, 'claudeCode', scans.rows),
      stats.byTool.bolt || 0,
      calculateToolPercentage(stats.byTool.bolt, 'bolt', scans.rows),
      stats.byTool.v0 || 0,
      calculateToolPercentage(stats.byTool.v0, 'v0', scans.rows),
      stats.byTool.replit || 0,
      calculateToolPercentage(stats.byTool.replit, 'replit', scans.rows),
      stats.byTool.copilot || 0,
      calculateToolPercentage(stats.byTool.copilot, 'copilot', scans.rows),
      stats.byStack['nextjs-supabase'] || 0,
      stats.byStack['express-postgres'] || 0,
      stats.byStack['sveltekit-supabase'] || 0
    ])
  }
  
  console.log(`✅ Updated stats for week of ${weekStart}`)
}

function getWeekStart(date: Date): string {
  const d = new Date(date)
  d.setDate(d.getDate() - d.getDay())
  return d.toISOString().split('T')[0]
}

function calculateToolPercentage(count: number, tool: string, scans: any[]): number {
  const toolScans = scans.filter(s => s.ai_tool_detected === tool).length
  if (toolScans === 0) return 0
  return Math.round(count / toolScans * 100 * 100) / 100
}

aggregateWeeklyStats()
```

---

## Part 7: Implementation Roadmap

### Week 1: Foundation
- [ ] Set up SvelteKit project with folder structure
- [ ] Create database schema and connect to Scanner DB
- [ ] Implement core server functions (scanner-stats.ts)
- [ ] Build SEO component with schema support
- [ ] Create robots.txt and sitemap.xml endpoints

### Week 2: Core Pages
- [ ] Build vulnerability page template
- [ ] Generate first 5 vulnerability pages with Claude Code
- [ ] Implement StatBox and ToolChart components
- [ ] Add FixPrompt component with copy functionality
- [ ] Create llms.txt endpoint

### Week 3: AI Patterns (Your Moat)
- [ ] Build AI pattern page template
- [ ] Generate pages for Cursor, Claude Code, Bolt
- [ ] Connect tool comparison data
- [ ] Add cross-linking between vulnerabilities and tools

### Week 4: Stacks & Fixes
- [ ] Build stack page template
- [ ] Generate Next.js + Supabase security guide
- [ ] Create fix prompt library
- [ ] Build framework-specific fix pages

### Week 5: Research Section
- [ ] Build Hallucinated Vulnerability Index page
- [ ] Create weekly index generation script
- [ ] Build methodology page
- [ ] Set up automated stats update cron job

### Week 6: Polish & Launch
- [ ] Add breadcrumbs and internal linking
- [ ] Generate OG images for all pages
- [ ] Performance optimization (caching, static generation)
- [ ] Submit sitemap to Google Search Console
- [ ] Test LLM citations (ask ChatGPT, Claude, Perplexity)

---

## Part 8: Success Metrics

### SEO Metrics (Track Weekly)
- Organic traffic to /kb/* pages
- Keyword rankings for target queries
- Pages indexed in Google
- Core Web Vitals scores
- Backlinks to knowledge base

### LLM Metrics (Track Weekly)
- Manual testing: Does ChatGPT cite VibeShip?
- Manual testing: Does Claude cite VibeShip?
- Manual testing: Does Perplexity cite VibeShip?
- Referral traffic from chat.openai.com, claude.ai, perplexity.ai

### Business Metrics
- KB → Scanner conversion rate
- Time on page
- Pages per session
- Free scan signups from KB

---

## Appendix: Quick Reference

### Target Queries by Category

**Vulnerabilities:**
- "sql injection ai generated code"
- "xss react nextjs"
- "api key exposed in code"
- "missing authentication api"

**AI Patterns:**
- "cursor security issues"
- "is cursor safe"
- "claude code vulnerabilities"
- "bolt security problems"

**Stacks:**
- "nextjs supabase security"
- "supabase security checklist"
- "express api security"

**General:**
- "vibe coding security"
- "ai generated code security"
- "security scanner for ai code"

### Internal Linking Strategy

Every page should link to:
1. Parent hub page (breadcrumbs)
2. 3-5 related pages in same category
3. 1-2 pages in different categories (cross-pollination)
4. Scanner product page (CTA)
5. Relevant fix prompt page

### Content Update Schedule

| Content Type | Update Frequency |
|--------------|------------------|
| Vulnerability stats | Weekly (automated) |
| Vulnerability content | Monthly (review) |
| AI pattern stats | Weekly (automated) |
| AI pattern content | Monthly (review) |
| Stack guides | Quarterly |
| Vulnerability Index | Weekly |
| llms.txt | Daily (automated) |
