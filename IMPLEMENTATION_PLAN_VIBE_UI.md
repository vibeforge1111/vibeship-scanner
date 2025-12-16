# Implementation Plan: Vibe-Coder Friendly Scanner Output

## Overview

Transform Vibeship Scanner from "security tool output" to "builder-friendly guidance" following the vibeship-scanner-guidelines.md principles. The core philosophy: **AI/LLMs should be able to fix problems with the prompts we provide.**

---

## Phase 1: Data Layer - Enhanced Finding Structure

### 1.1 Create New AI Fix Prompt Generator (`src/lib/aiFixPrompts.ts`)

**Purpose:** Generate copy-paste ready prompts that actually work with Claude/Cursor/GPT.

```typescript
export interface AIFixPrompt {
  // The main prompt - designed to be copy-pasted into AI tools
  prompt: string;

  // Context for the AI
  context: {
    file: string;
    line?: number;
    language: string;
    framework?: string;
  };

  // What's in the prompt
  includes: {
    currentCode: boolean;    // Shows the vulnerable code
    fixedCode: boolean;      // Shows the safe version
    scopeCheck: boolean;     // Asks AI to find similar issues
    verification: boolean;   // Asks AI to confirm fix
  };
}

// Templates by vulnerability type
export const aiPromptTemplates = {
  'sql-injection': (finding) => `
Fix the SQL injection vulnerability in ${finding.location.file}${finding.location.line ? ` at line ${finding.location.line}` : ''}.

The current code does this:
\`\`\`${finding.language || 'javascript'}
${finding.snippet?.code || '// Code not available - check the file'}
\`\`\`

Replace it with a parameterized query:
\`\`\`${finding.language || 'javascript'}
// Use parameterized queries instead of string concatenation
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
// Or with Prisma: prisma.user.findUnique({ where: { id } })
\`\`\`

After fixing this:
1. Search the entire codebase for similar patterns: string concatenation in database queries
2. Fix any other instances you find
3. List all files you modified
4. Show me the complete updated function when done
`,

  'xss': (finding) => `
Fix the XSS vulnerability in ${finding.location.file}${finding.location.line ? ` at line ${finding.location.line}` : ''}.

User input is being rendered without sanitization:
\`\`\`${finding.language || 'javascript'}
${finding.snippet?.code || '// Code not available - check the file'}
\`\`\`

Fix options:

1. For plain text (most common):
\`\`\`javascript
element.textContent = userInput;  // Safe - treats as text
\`\`\`

2. If you need HTML rendering:
\`\`\`javascript
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

3. For React:
\`\`\`jsx
// Safe by default
<div>{userInput}</div>

// If you MUST use dangerouslySetInnerHTML:
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
\`\`\`

After fixing:
1. Check for other uses of innerHTML or dangerouslySetInnerHTML in this file
2. Install DOMPurify if needed: npm install dompurify
3. Show me the updated code
`,

  'hardcoded-secret': (finding) => `
Remove the hardcoded secret from ${finding.location.file}${finding.location.line ? ` at line ${finding.location.line}` : ''}.

Current code has exposed credentials:
\`\`\`${finding.language || 'javascript'}
${finding.snippet?.code || '// Secret detected in this file'}
\`\`\`

Fix this by:

1. Create or update your .env file:
\`\`\`
# .env (add to .gitignore!)
${finding.secretType || 'API_KEY'}=your-secret-here
\`\`\`

2. Update the code to use environment variable:
\`\`\`javascript
// For Node.js
const secret = process.env.${finding.secretType || 'API_KEY'};

// For Next.js (client-side needs NEXT_PUBLIC_ prefix for non-sensitive)
const apiUrl = process.env.NEXT_PUBLIC_API_URL;

// For Vite
const apiKey = import.meta.env.VITE_API_KEY;
\`\`\`

3. Add .env to .gitignore if not already there

IMPORTANT:
- If this secret was already committed to git, it's exposed in history. Rotate it immediately.
- Search for other hardcoded secrets: API keys, passwords, tokens, connection strings
- Show me all the changes you made
`,

  // ... more templates for each vulnerability type
};
```

### 1.2 Update Finding Interface (`src/lib/types.ts`)

Add vibe-coder fields while preserving security metadata:

```typescript
export interface Finding {
  // Existing fields (keep these)
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  ruleId: string;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  snippet?: {
    code: string;
    startLine?: number;
  };

  // Security metadata (keep for experts, show in collapsed view)
  metadata?: {
    cwe?: string;
    cvss?: number;
    owasp?: string;
    references?: string[];
  };

  // NEW: Vibe-coder friendly fields
  vibeOutput: {
    // Plain English headline (no jargon)
    headline: string;          // "Someone could delete your entire database"

    // What could actually happen (real consequences)
    consequences: string[];    // ["All user data could be deleted", "Passwords could be stolen"]

    // Severity in human terms
    urgency: {
      label: string;           // "Fix Before You Ship" | "Fix This Week" | etc.
      emoji: string;           // "🔴" | "🟠" | "🟡" | "🟢" | "💡"
      description: string;     // "Your app is hackable right now"
    };

    // The AI fix prompt - THE MOST IMPORTANT PART
    aiPrompt: string;          // Full copy-paste ready prompt for Claude/Cursor

    // Optional: context about AI tools making this mistake
    aiToolContext?: string;    // "This is a common Cursor pattern - it often..."
  };
}
```

---

## Phase 2: UI Redesign - Mobile-First Clean Cards

### 2.1 New Finding Card Component (`src/lib/components/FindingCard.svelte`)

**Design principles:**
- Mobile-first, single column
- No confusing nested accordions
- Clear visual hierarchy
- One-tap copy for AI prompt
- Security details available but not prominent

```svelte
<script lang="ts">
  import { slide } from 'svelte/transition';

  export let finding: Finding;
  export let isExpanded = false;

  let copied = false;

  function copyAIPrompt() {
    navigator.clipboard.writeText(finding.vibeOutput.aiPrompt);
    copied = true;
    setTimeout(() => copied = false, 2000);
  }
</script>

<article class="finding-card" class:expanded={isExpanded}>
  <!-- Header - Always visible -->
  <button class="card-header" on:click={() => isExpanded = !isExpanded}>
    <div class="urgency-badge {finding.vibeOutput.urgency.label.toLowerCase().replace(/ /g, '-')}">
      <span class="emoji">{finding.vibeOutput.urgency.emoji}</span>
      <span class="label">{finding.vibeOutput.urgency.label}</span>
    </div>

    <h3 class="headline">{finding.vibeOutput.headline}</h3>

    <div class="location">
      <code>{finding.location.file}{finding.location.line ? `:${finding.location.line}` : ''}</code>
    </div>

    <span class="expand-icon" class:rotated={isExpanded}>▼</span>
  </button>

  <!-- Expanded Content -->
  {#if isExpanded}
    <div class="card-content" transition:slide>
      <!-- What Could Happen -->
      <section class="consequences">
        <h4>💥 What Could Happen</h4>
        <ul>
          {#each finding.vibeOutput.consequences as consequence}
            <li>{consequence}</li>
          {/each}
        </ul>
      </section>

      <!-- The Fix - Most Important -->
      <section class="ai-fix">
        <div class="fix-header">
          <h4>🛠️ Copy this into Claude / Cursor</h4>
          <button class="copy-btn" on:click={copyAIPrompt}>
            {copied ? '✓ Copied!' : 'Copy Prompt'}
          </button>
        </div>
        <pre class="prompt-preview"><code>{finding.vibeOutput.aiPrompt}</code></pre>
      </section>

      <!-- Code Context (if available) -->
      {#if finding.snippet?.code}
        <section class="code-context">
          <h4>📍 The Vulnerable Code</h4>
          <pre><code>{finding.snippet.code}</code></pre>
        </section>
      {/if}

      <!-- Security Details (collapsed by default) -->
      <details class="security-details">
        <summary>🔒 Technical Details</summary>
        <div class="tech-content">
          {#if finding.metadata?.cwe}
            <span class="tag">{finding.metadata.cwe}</span>
          {/if}
          {#if finding.metadata?.cvss}
            <span class="tag">CVSS: {finding.metadata.cvss}</span>
          {/if}
          {#if finding.metadata?.owasp}
            <span class="tag">{finding.metadata.owasp}</span>
          {/if}
          <p class="category">Category: {finding.category}</p>
          {#if finding.metadata?.references?.length}
            <a href={finding.metadata.references[0]} target="_blank" rel="noopener">
              Learn more →
            </a>
          {/if}
        </div>
      </details>
    </div>
  {/if}
</article>
```

### 2.2 New Styles - Clean, Mobile-First

```css
.finding-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 1rem;
  overflow: hidden;
  transition: all 0.2s ease;
}

.finding-card:hover {
  border-color: var(--border-hover);
}

.card-header {
  width: 100%;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  text-align: left;
  background: transparent;
  border: none;
  cursor: pointer;
}

.urgency-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.85rem;
  font-weight: 600;
  width: fit-content;
}

.urgency-badge.fix-before-you-ship {
  background: rgba(255, 77, 77, 0.15);
  color: #ff4d4d;
}

.urgency-badge.fix-this-week {
  background: rgba(255, 176, 32, 0.15);
  color: #ffb020;
}

.urgency-badge.fix-when-you-can {
  background: rgba(255, 193, 7, 0.15);
  color: #ffc107;
}

.urgency-badge.nice-to-fix {
  background: rgba(46, 204, 113, 0.15);
  color: #2ecc71;
}

.urgency-badge.pro-tip {
  background: rgba(51, 153, 255, 0.15);
  color: #3399ff;
}

.headline {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
  line-height: 1.4;
}

.location code {
  font-size: 0.8rem;
  color: var(--text-tertiary);
  background: var(--bg-tertiary);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
}

/* Expanded content */
.card-content {
  padding: 0 1rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.consequences {
  background: rgba(255, 77, 77, 0.05);
  border-left: 3px solid var(--red);
  padding: 1rem;
  border-radius: 0 8px 8px 0;
}

.consequences h4 {
  margin: 0 0 0.5rem;
  font-size: 0.9rem;
}

.consequences ul {
  margin: 0;
  padding-left: 1.25rem;
}

.consequences li {
  margin-bottom: 0.25rem;
  color: var(--text-secondary);
}

/* AI Fix Section - THE STAR */
.ai-fix {
  background: linear-gradient(135deg, rgba(157, 140, 255, 0.1), rgba(51, 153, 255, 0.1));
  border: 1px solid rgba(157, 140, 255, 0.3);
  border-radius: 12px;
  padding: 1rem;
}

.fix-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.fix-header h4 {
  margin: 0;
  font-size: 0.95rem;
}

.copy-btn {
  background: var(--purple);
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}

.copy-btn:hover {
  background: var(--purple-light);
}

.prompt-preview {
  background: var(--bg-primary);
  border-radius: 8px;
  padding: 1rem;
  font-size: 0.85rem;
  max-height: 200px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

/* Mobile optimizations */
@media (max-width: 640px) {
  .card-header {
    padding: 0.875rem;
  }

  .headline {
    font-size: 1rem;
  }

  .copy-btn {
    padding: 0.625rem 1.25rem;
    font-size: 0.95rem;
  }
}
```

---

## Phase 3: Transform Function - Security → Vibe Output

### 3.1 Create Transformer (`src/lib/vibeTransformer.ts`)

```typescript
import { aiPromptTemplates } from './aiFixPrompts';

// Maps security severity to vibe urgency
const severityToUrgency = {
  critical: {
    label: 'Fix Before You Ship',
    emoji: '🔴',
    description: 'Your app is hackable right now'
  },
  high: {
    label: 'Fix This Week',
    emoji: '🟠',
    description: 'Real risk if anyone looks'
  },
  medium: {
    label: 'Fix When You Can',
    emoji: '🟡',
    description: 'Not urgent but don\'t ignore'
  },
  low: {
    label: 'Nice to Fix',
    emoji: '🟢',
    description: 'Good practice, low actual risk'
  },
  info: {
    label: 'Pro Tip',
    emoji: '💡',
    description: 'Not a vulnerability, just advice'
  }
};

// Maps vulnerability types to plain English headlines
const headlineMap: Record<string, (finding: any) => string> = {
  'sql-injection': () => 'Someone could delete your entire database',
  'sql_injection': () => 'Someone could delete your entire database',
  'xss': () => 'Attackers can run code in your users\' browsers',
  'cross-site': () => 'Attackers can run code in your users\' browsers',
  'hardcoded-secret': () => 'Your passwords are visible in the code',
  'hardcoded_secret': () => 'Your passwords are visible in the code',
  'hardcoded_credential': () => 'Your passwords are visible in the code',
  'api_key': () => 'API key exposed - anyone can use your services',
  'command-injection': () => 'Attackers can run any command on your server',
  'command_injection': () => 'Attackers can run any command on your server',
  'path-traversal': () => 'Hackers can read any file on your server',
  'path_traversal': () => 'Hackers can read any file on your server',
  'ssrf': () => 'Your server can be tricked into attacking other systems',
  'missing-auth': () => 'Anyone can access this without logging in',
  'missing_auth': () => 'Anyone can access this without logging in',
  'open-redirect': () => 'Your site can trick users into visiting malicious sites',
  'open_redirect': () => 'Your site can trick users into visiting malicious sites',
  'csrf': () => 'Hackers can trick users into doing things they didn\'t mean to',
  'idor': () => 'Users can access other users\' data by changing IDs',
  'weak_hash': () => 'Your "encryption" can be cracked easily',
  'weak_crypto': () => 'Your "encryption" can be cracked easily',
  'eval': () => 'Attackers can run any code they want in your app',
  'prototype-pollution': () => 'Attackers can modify how JavaScript works in your app',
  'session': () => 'User sessions can be hijacked',
  'cookie': () => 'Session cookies aren\'t properly protected'
};

// Maps vulnerability types to consequences
const consequencesMap: Record<string, string[]> = {
  'sql-injection': [
    'All your user data could be deleted',
    'Attackers could steal email addresses and passwords',
    'Your entire database could be downloaded'
  ],
  'xss': [
    'Attackers can steal user sessions and log in as them',
    'Malicious scripts can steal passwords and credit cards',
    'Your users\' browsers could be used to attack others'
  ],
  'hardcoded-secret': [
    'Anyone who sees your code has your API keys',
    'Attackers can use your services and run up your bill',
    'If it\'s a database password, they own your data'
  ],
  'command-injection': [
    'Attackers get full control of your server',
    'They can read any file, including .env and secrets',
    'Your server could be used to attack other systems'
  ],
  // ... more mappings
};

export function transformToVibeOutput(finding: any): Finding {
  const ruleId = finding.ruleId?.toLowerCase() || '';
  const category = finding.category?.toLowerCase() || '';
  const title = finding.title?.toLowerCase() || '';
  const searchKey = `${ruleId} ${category} ${title}`;

  // Find the matching headline
  let headline = finding.title; // Default to original title
  for (const [key, generator] of Object.entries(headlineMap)) {
    if (searchKey.includes(key)) {
      headline = generator(finding);
      break;
    }
  }

  // Find consequences
  let consequences = ['Review this code and apply the recommended fix'];
  for (const [key, items] of Object.entries(consequencesMap)) {
    if (searchKey.includes(key)) {
      consequences = items;
      break;
    }
  }

  // Generate AI prompt
  let aiPrompt = generateDefaultPrompt(finding);
  for (const [key, generator] of Object.entries(aiPromptTemplates)) {
    if (searchKey.includes(key)) {
      aiPrompt = generator(finding);
      break;
    }
  }

  return {
    ...finding,
    vibeOutput: {
      headline,
      consequences,
      urgency: severityToUrgency[finding.severity] || severityToUrgency.info,
      aiPrompt
    }
  };
}

function generateDefaultPrompt(finding: any): string {
  return `
Fix the security issue in ${finding.location?.file || 'the codebase'}${finding.location?.line ? ` at line ${finding.location.line}` : ''}.

Issue: ${finding.title}
Category: ${finding.category}

${finding.snippet?.code ? `Current code:
\`\`\`
${finding.snippet.code}
\`\`\`` : ''}

Please:
1. Identify the security vulnerability
2. Show me the fixed code
3. Check if there are similar issues elsewhere in the file
4. Explain what you changed and why
`;
}
```

---

## Phase 4: Summary Section Redesign

### 4.1 Production Readiness Score Component

```svelte
<script lang="ts">
  export let results: ScanResults;

  const criticalCount = results.summary?.critical || 0;
  const highCount = results.summary?.high || 0;

  // Generate master fix prompt for all critical issues
  $: masterPrompt = generateMasterPrompt(results.findings);
</script>

<div class="readiness-score">
  <div class="score-header">
    <h2>Production Readiness</h2>
    <div class="score-badge {results.grade}">
      <span class="score">{results.score}/100</span>
      <span class="status">{getShipStatus(results)}</span>
    </div>
  </div>

  {#if criticalCount > 0 || highCount > 0}
    <div class="quick-fix-section">
      <h3>🚀 Get to Green Fast</h3>
      <p>Copy this into Claude / Cursor to fix all critical issues:</p>

      <div class="master-prompt">
        <button class="copy-all-btn" on:click={() => copyToClipboard(masterPrompt)}>
          Copy All Fixes
        </button>
        <pre><code>{masterPrompt}</code></pre>
      </div>
    </div>
  {/if}
</div>
```

---

## Phase 5: Backend - Add Vibe Data to Scan Results

### 5.1 Update Scanner Output Processing (`scanner/scan.py`)

The Python scanner already outputs findings. We need to add vibe-coder fields either:

**Option A:** In Python (faster, processed once)
**Option B:** In Frontend (more flexible, easier to iterate)

**Recommendation:** Option B - Transform in frontend for now, move to backend later.

### 5.2 Update Scan Results Page

In `+page.svelte`, transform findings on load:

```typescript
import { transformToVibeOutput } from '$lib/vibeTransformer';

// In the fetchScan function, after getting results:
if (data.status === 'complete') {
  const transformedFindings = (data.findings || []).map(transformToVibeOutput);
  results = {
    ...data,
    findings: transformedFindings
  };
}
```

---

## Implementation Order

### Sprint 1: Core Transform (Day 1-2)
1. ✅ Create `src/lib/vibeTransformer.ts`
2. ✅ Create `src/lib/aiFixPrompts.ts` with 15 most common vulnerability types
3. ✅ Update type definitions
4. ✅ Wire up transformer in scan results page

### Sprint 2: UI Components (Day 2-3)
1. ✅ Create new `FindingCard.svelte` component
2. ✅ Add mobile-first styles
3. ✅ Replace accordion in main page with new cards
4. ✅ Test on mobile devices

### Sprint 3: AI Prompts Deep Dive (Day 3-4)
1. ✅ Test prompts with actual Claude/Cursor
2. ✅ Refine prompts based on AI responses
3. ✅ Add context about stack (Next.js, Svelte, etc.)
4. ✅ Add prompts for remaining vulnerability types

### Sprint 4: Summary & Polish (Day 4-5)
1. ✅ Add master fix prompt for all critical issues
2. ✅ Update readiness score section
3. ✅ Add "Need Help?" section with VibeShip CTA
4. ✅ Final testing and polish

---

## AI Prompt Design Principles

### What Makes a Good AI Fix Prompt

1. **Specific location** - File and line number
2. **Show the problem** - Include the vulnerable code
3. **Show the solution** - Include fixed code example
4. **Scope expansion** - Ask AI to check for similar issues
5. **Verification** - Ask AI to confirm the fix works
6. **Framework-aware** - Use patterns for their specific framework

### Example of a GREAT Prompt

```
Fix the SQL injection vulnerability in src/api/users.ts at line 47.

The current code does this:
```typescript
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`)
```

Replace it with a parameterized query:
```typescript
const user = await db.query('SELECT * FROM users WHERE id = $1', [userId])
```

After fixing this:
1. Search for similar patterns in src/api/ - any string concatenation in queries
2. Fix any other instances you find
3. List all files you modified
4. Show me the complete updated function when done
```

### Example of a BAD Prompt

```
Fix SQL injection in users.ts
```

Why it's bad:
- No line number
- No current code
- No fix example
- No scope check
- AI has to guess everything

---

## Testing Checklist

- [ ] AI prompts work in Claude Code
- [ ] AI prompts work in Cursor
- [ ] AI prompts work in ChatGPT
- [ ] Mobile layout looks good
- [ ] Copy button works on all browsers
- [ ] Security metadata still accessible
- [ ] No regression in existing functionality
- [ ] Performance acceptable with many findings

---

## Future Enhancements

1. **Stack detection** - Customize prompts for detected framework
2. **Git integration** - Show which commit introduced the issue
3. **Learning mode** - Explain WHY the fix works
4. **Batch fix** - One prompt to fix all issues of same type
5. **AI tool detection** - Show which AI tool commonly makes this mistake
