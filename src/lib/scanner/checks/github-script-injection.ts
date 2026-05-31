import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';
import { DANGEROUS_CONTEXT_PATTERNS, DANGEROUS_CONTEXTS } from '../data/dangerous-contexts';

/**
 * injection/github-script
 *
 * Detects `actions/github-script` steps whose inline `script:` body
 * interpolates an attacker-controllable `${{ github.event.* }}` value
 * directly into the JavaScript. This is a distinct injection sink from
 * shell `run:` injection: the value lands inside a JS string literal, and
 * a payload like `"); maliciousCode(); ("` breaks out and runs arbitrary
 * JavaScript in the runner with the workflow's `GITHUB_TOKEN`. The
 * Ultralytics 2024 compromise used exactly this, via a crafted branch
 * name. The safe pattern passes the value through `env:` and reads
 * `process.env`.
 */

// Match a full ${{ ... }} expression (brace-aware so format('{0}', ...) is
// captured); callers filter for attacker-controlled contexts.
const EVENT_EXPR = /\$\{\{(?:[^}]|\}(?!\}))*\}\}/g;

function getGithubScriptSteps(parsed: Record<string, unknown>): Array<{ script: string; jobId: string; idx: number }> {
  const out: Array<{ script: string; jobId: string; idx: number }> = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const steps = (jobDef as Record<string, unknown>)['steps'];
    if (!Array.isArray(steps)) continue;
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!step || typeof step !== 'object') continue;
      const uses = (step as Record<string, unknown>)['uses'];
      if (typeof uses !== 'string' || !uses.startsWith('actions/github-script')) continue;
      const withBlock = (step as Record<string, unknown>)['with'];
      if (!withBlock || typeof withBlock !== 'object') continue;
      const script = (withBlock as Record<string, unknown>)['script'];
      if (typeof script === 'string') out.push({ script, jobId, idx: i });
    }
  }
  return out;
}

export const githubScriptInjectionCheck: CheckDefinition = {
  id: 'injection/github-script',
  name: 'Untrusted input in actions/github-script',
  description:
    'Detects attacker-controllable github.event.* expressions interpolated directly into an actions/github-script body.',
  category: 'injection',
  severity: 'critical',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const { script, jobId, idx } of getGithubScriptSteps(workflow.parsed)) {
        const matches = script.match(EVENT_EXPR);
        if (!matches) continue;

        for (const rawMatch of matches) {
          // Normalize bracket notation (github.event['pull_request']['title'])
          // to dot notation so it is classified like the common form.
          const match = rawMatch.replace(/\[\s*['"]([A-Za-z0-9_-]+)['"]\s*\]/g, '.$1');

          // Flag only known attacker-controlled contexts (issue/PR title & body,
          // comment body, github.head_ref — the Ultralytics branch-name vector,
          // etc.). Constrained/trusted fields (base.sha, numbers, logins) are
          // not injection sources here.
          const dangerous =
            DANGEROUS_CONTEXTS.some((c) => !c.includes('*') && match.includes(c)) ||
            DANGEROUS_CONTEXT_PATTERNS.some((p) => {
              p.lastIndex = 0;
              return p.test(match);
            });
          if (!dangerous) continue;

          findings.push({
            checkId: 'injection/github-script',
            severity: 'critical',
            category: 'injection',
            title: `Untrusted input in github-script: ${match}`,
            description:
              `Workflow "${workflow.name}" job "${jobId}" step ${idx + 1} interpolates \`${match}\` directly into an \`actions/github-script\` body. ` +
              'The value is placed inside the executed JavaScript, where it can break out of its string literal.',
            risk:
              'Unlike shell injection, this runs inside the github-script JS context with the `GITHUB_TOKEN` already authenticated via the `github` client. ' +
              'A crafted PR title, body, comment, or branch name can execute arbitrary JavaScript: read secrets, push commits, or call the GitHub API with the workflow\'s permissions. This was the mechanism of the Ultralytics 2024 supply chain compromise.',
            remediation:
              'Pass untrusted values through `env:` and read them from `process.env` inside the script:\n\n' +
              '```yaml\n' +
              '- uses: actions/github-script@v7\n' +
              '  env:\n' +
              '    TITLE: ${{ github.event.pull_request.title }}\n' +
              '  with:\n' +
              '    script: |\n' +
              '      const title = process.env.TITLE   // safe: never parsed as code\n' +
              '      core.info(title)\n' +
              '```',
            file: workflow.path,
            line: findLineNumber(workflow.content, match),
            evidence: match,
          });
          break; // one finding per script step
        }
      }
    }

    return findings;
  },
};
