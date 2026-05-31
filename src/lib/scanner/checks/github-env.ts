import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';
import { DANGEROUS_CONTEXT_PATTERNS, DANGEROUS_CONTEXTS } from '../data/dangerous-contexts';

/**
 * injection/github-env
 *
 * Detects run: steps that write a known attacker-controlled context into
 * $GITHUB_ENV or $GITHUB_PATH. Writing untrusted data to GITHUB_ENV lets an
 * attacker set environment variables consumed by LATER steps (LD_PRELOAD,
 * NODE_OPTIONS, BASH_ENV, ...) or prepend a malicious directory to PATH via
 * GITHUB_PATH. This is the "environment injection" variant of expression
 * injection and survives even when the immediate run block looks benign,
 * because the payload detonates in a different step.
 *
 * Precision model: only the curated attacker-controlled contexts
 * (DANGEROUS_CONTEXTS: issue/PR title & body, comment body, head_ref, commit
 * messages, ...) are treated as injection sources. Constrained or trusted
 * fields (base.sha, repository.default_branch, run numbers, logins) are not
 * flagged, and the untrusted expression must appear on the env-write line
 * itself.
 */

const GITHUB_ENV_WRITE =
  /(?:>>?|\|\s*tee(?:\s+-a)?)\s*"?\$\{?\s*(?:GITHUB_ENV|GITHUB_PATH)\s*\}?"?/;

// Match a full ${{ ... }} expression, allowing single `}` inside (e.g.
// format('{0}-{1}', ...)) by only stopping at a literal `}}`.
const EXPRESSION = /\$\{\{(?:[^}]|\}(?!\}))*\}\}/g;

function lineWritesToGithubEnv(line: string): boolean {
  return GITHUB_ENV_WRITE.test(line);
}

/**
 * True if the expression references a known attacker-controlled context.
 * Normalizes bracket notation to dot notation, and substring-matches the
 * non-glob contexts (brace-agnostic, so it still fires inside expressions
 * containing `}` like format('{0}', ...) where the `[^}]`-based patterns
 * cannot).
 */
function isDangerousExpression(rawExpr: string): boolean {
  const expr = rawExpr.replace(/\[\s*['"]([A-Za-z0-9_-]+)['"]\s*\]/g, '.$1');
  if (DANGEROUS_CONTEXTS.some((c) => !c.includes('*') && expr.includes(c))) return true;
  return DANGEROUS_CONTEXT_PATTERNS.some((p) => {
    p.lastIndex = 0;
    return p.test(expr);
  });
}

interface RunStep {
  run: string;
  jobId: string;
  stepIndex: number;
  stepName?: string;
}

function getRunSteps(parsed: Record<string, unknown>): RunStep[] {
  const out: RunStep[] = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    const job = jobDef as Record<string, unknown>;
    const steps = job?.['steps'];
    if (!Array.isArray(steps)) continue;
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!step || typeof step !== 'object') continue;
      const run = (step as Record<string, unknown>)['run'];
      if (typeof run !== 'string') continue;
      out.push({
        run,
        jobId,
        stepIndex: i,
        stepName:
          typeof (step as Record<string, unknown>)['name'] === 'string'
            ? ((step as Record<string, unknown>)['name'] as string)
            : undefined,
      });
    }
  }
  return out;
}

export const githubEnvCheck: CheckDefinition = {
  id: 'injection/github-env',
  name: 'Environment injection via GITHUB_ENV / GITHUB_PATH',
  description:
    'Detects run blocks that write attacker-controlled contexts into $GITHUB_ENV or $GITHUB_PATH, allowing environment-variable injection that detonates in later steps.',
  category: 'injection',
  severity: 'critical',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const step of getRunSteps(workflow.parsed)) {
        // Merge shell line-continuations so a `... \<newline> >> $GITHUB_ENV`
        // is analyzed as one logical line (source and sink stay together).
        const lines = step.run.replace(/\\\r?\n/g, ' ').split('\n');

        let offending: { line: string; expr: string } | null = null;
        for (const line of lines) {
          if (!lineWritesToGithubEnv(line)) continue;
          const exprs = line.match(EXPRESSION) ?? [];
          const dangerous = exprs.find((e) => isDangerousExpression(e));
          if (!dangerous) continue;
          offending = { line: line.trim(), expr: dangerous };
          break;
        }
        if (!offending) continue;

        const writeLine = offending.line;
        const target = /GITHUB_PATH/.test(writeLine) ? '$GITHUB_PATH' : '$GITHUB_ENV';
        const stepLabel = step.stepName
          ? `step "${step.stepName}"`
          : `step ${step.stepIndex + 1}`;

        findings.push({
          checkId: 'injection/github-env',
          severity: 'critical',
          category: 'injection',
          title: `Untrusted value written to ${target} in job "${step.jobId}"`,
          description:
            `Job \`${step.jobId}\`, ${stepLabel} writes an attacker-controlled expression (${offending.expr}) into ${target}. ` +
            `Values written to ${target} become environment variables (or PATH entries) for every subsequent step in the job. ` +
            `An attacker who controls the interpolated value can set dangerous variables such as \`LD_PRELOAD\`, \`NODE_OPTIONS\`, or \`BASH_ENV\`, or hijack PATH, to execute code in a later step that looks harmless.`,
          risk:
            'GITHUB_ENV / GITHUB_PATH injection is a code-execution primitive even when the writing step does not itself run the attacker input. ' +
            'The injected variable is inherited by later steps and by tools they invoke. This is how several real Actions pwn-request chains escalated from a benign-looking echo to full runner compromise.',
          remediation:
            'Never write raw untrusted expressions to GITHUB_ENV/GITHUB_PATH. Route the value through a quoted intermediate environment variable and validate it first:\n\n' +
            '```yaml\n' +
            '# Vulnerable:\n' +
            '- run: echo "TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"\n\n' +
            '# Safer: bind to an env var, then write a sanitized value\n' +
            '- env:\n' +
            '    TITLE: ${{ github.event.issue.title }}\n' +
            '  run: |\n' +
            '    clean=$(printf \'%s\' "$TITLE" | tr -cd \'[:alnum:]_- \')\n' +
            '    echo "TITLE=$clean" >> "$GITHUB_ENV"\n' +
            '```\n\n' +
            'Best of all, avoid persisting untrusted input across steps entirely.',
          file: workflow.path,
          line: findLineNumber(workflow.content, writeLine),
          evidence: `${writeLine} | expression: ${offending.expr}`,
        });
      }
    }

    return findings;
  },
};
