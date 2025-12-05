import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import Anthropic from '@anthropic-ai/sdk';
import { ANTHROPIC_API_KEY } from '$env/static/private';

const anthropic = new Anthropic({
	apiKey: ANTHROPIC_API_KEY
});

interface Gap {
	repo: string;
	repoName: string;
	vulnId: string;
	vulnType?: string;
	description?: string;
	file?: string;
	language?: string;
}

interface GeneratedRule {
	id: string;
	language: string;
	yaml: string;
	vulnId: string;
	confidence: 'high' | 'medium' | 'low';
}

export const POST: RequestHandler = async ({ request }) => {
	try {
		const body = await request.json();
		const gaps: Gap[] = body.gaps || [];

		if (gaps.length === 0) {
			return json({ rules: [], message: 'No gaps to process' });
		}

		// Group gaps by language for efficient rule generation
		const gapsByLanguage: Record<string, Gap[]> = {};
		for (const gap of gaps) {
			const lang = gap.language || 'javascript';
			if (!gapsByLanguage[lang]) gapsByLanguage[lang] = [];
			gapsByLanguage[lang].push(gap);
		}

		const generatedRules: GeneratedRule[] = [];

		for (const [language, langGaps] of Object.entries(gapsByLanguage)) {
			// Create a prompt for Claude to generate Semgrep rules
			const gapDescriptions = langGaps
				.map(
					(g, i) =>
						`${i + 1}. Vulnerability ID: ${g.vulnId}
   Type: ${g.vulnType || 'unknown'}
   Description: ${g.description || 'Security vulnerability'}
   File pattern: ${g.file || 'N/A'}
   Repo: ${g.repoName}`
				)
				.join('\n\n');

			const prompt = `You are a security expert generating Semgrep rules to detect vulnerabilities.

Generate Semgrep rules for the following ${language} vulnerabilities that our scanner is currently missing:

${gapDescriptions}

For each vulnerability, generate a Semgrep rule in YAML format. Follow these guidelines:
1. Use pattern, pattern-either, or pattern-regex as appropriate
2. Include a clear message explaining the vulnerability
3. Set appropriate severity (ERROR for critical/high, WARNING for medium, INFO for low)
4. Add relevant metadata tags
5. Make patterns specific enough to avoid false positives but general enough to catch variants

Respond with a JSON array where each element has:
- id: rule ID (use format: "vibeship-{vulnId}")
- yaml: the complete Semgrep rule YAML
- vulnId: the original vulnerability ID this rule addresses
- confidence: "high", "medium", or "low" based on how confident you are the rule will work

Example response format:
[
  {
    "id": "vibeship-sqli-login",
    "yaml": "rules:\\n  - id: vibeship-sqli-login\\n    message: SQL injection detected...",
    "vulnId": "sqli-login",
    "confidence": "high"
  }
]

Generate rules for all ${langGaps.length} vulnerabilities listed above.`;

			try {
				const response = await anthropic.messages.create({
					model: 'claude-sonnet-4-20250514',
					max_tokens: 4096,
					messages: [
						{
							role: 'user',
							content: prompt
						}
					]
				});

				// Extract the text response
				const textContent = response.content.find((c) => c.type === 'text');
				if (textContent && textContent.type === 'text') {
					// Parse the JSON from the response
					const jsonMatch = textContent.text.match(/\[[\s\S]*\]/);
					if (jsonMatch) {
						const rules = JSON.parse(jsonMatch[0]);
						for (const rule of rules) {
							generatedRules.push({
								...rule,
								language
							});
						}
					}
				}
			} catch (apiError) {
				console.error(`Error generating rules for ${language}:`, apiError);
			}
		}

		return json({
			rules: generatedRules,
			message: `Generated ${generatedRules.length} rules for ${gaps.length} gaps`
		});
	} catch (error) {
		console.error('Rule generation error:', error);
		return json({ error: 'Failed to generate rules', rules: [] }, { status: 500 });
	}
};
