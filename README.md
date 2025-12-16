# Vibeship Scanner

A security scanning tool designed for vibe coders. Analyzes GitHub repositories for vulnerabilities and generates AI-ready fix prompts.

## Features

- **Multi-Scanner Analysis**: Combines Opengrep (SAST), Trivy (dependency scanning), Gitleaks (secret detection), and npm audit
- **AI-Ready Fix Prompts**: Every finding includes a copy-paste prompt for Claude, Cursor, or ChatGPT
- **Vibe-Friendly Output**: Plain English explanations instead of security jargon
- **Master Fix Prompt**: One prompt to fix all issues systematically
- **100+ Vulnerability Patterns**: SQL injection, XSS, SSRF, secrets, auth issues, and more

## Tech Stack

- **Frontend**: SvelteKit, TypeScript
- **Backend**: Python (Flask), deployed on Fly.io
- **Database**: Supabase
- **Scanners**: Opengrep, Trivy, Gitleaks, npm audit

## Getting Started

### Prerequisites

- Node.js 18+
- npm or pnpm

### Installation

```bash
# Clone the repository
git clone https://github.com/vibeforge1111/vibeship-scanner.git
cd vibeship-scanner

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your Supabase credentials

# Start development server
npm run dev
```

### Environment Variables

```
PUBLIC_SUPABASE_URL=your_supabase_url
PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

## Usage

1. Visit the app at `http://localhost:5173`
2. Enter a GitHub repository URL
3. Wait for the scan to complete
4. Review findings with AI-ready fix prompts
5. Copy the master prompt to fix all issues at once

## Scanner Rules

The scanner includes 100+ custom security rules covering:

- **Injection**: SQL, NoSQL, Command, Template (SSTI)
- **XSS**: DOM, Stored, React, Vue, Svelte, Angular, jQuery
- **Authentication**: Missing auth, IDOR, session issues
- **Cryptography**: Weak hashes, insecure ciphers, hardcoded keys
- **Secrets**: API keys, passwords, tokens in code
- **Configuration**: Debug mode, CORS, security headers

## API

### Trigger a Scan

```bash
curl -X POST https://scanner-empty-field-5676.fly.dev/scan \
  -H "Content-Type: application/json" \
  -d '{"scanId": "uuid", "repoUrl": "https://github.com/owner/repo"}'
```

### View Results

Results are available at:
- Production: `https://vibeship.co/scan/{scanId}`
- Local: `http://localhost:5173/scan/{scanId}`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Adding New Rules

1. Add rules to `scanner/rules/{language}.yaml`
2. Validate: `opengrep --validate -f scanner/rules/`
3. Add corresponding fix hints in `src/lib/aiFixPrompts.ts`
4. Deploy scanner: `cd scanner && fly deploy --remote-only`

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Links

- **Live App**: [vibeship.co](https://vibeship.co)
- **GitHub**: [github.com/vibeforge1111/vibeship-scanner](https://github.com/vibeforge1111/vibeship-scanner)
