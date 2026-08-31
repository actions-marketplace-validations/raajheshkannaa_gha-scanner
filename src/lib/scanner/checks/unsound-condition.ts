import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * triggers/unsound-condition
 *
 * Detects `if:` conditions that are silently always-true. GitHub treats an
 * `if:` value as a real boolean ONLY when the entire value is a single
 * `${{ ... }}` expression with nothing else around it. A block scalar
 * (`|` or `>`) appends a trailing newline, and any leading/trailing text
 * or a second expression turns the value into a non-empty STRING, which
 * Actions evaluates as truthy. The gate then runs unconditionally.
 *
 * This is the "if-always-true" gate bypass: a security condition such as
 * `if: github.actor == 'dependabot[bot]'` wrapped in a block scalar passes
 * for everyone.
 */

function isUnsound(s: string): boolean {
  if (!s.includes('${{')) return false; // bare conditions are auto-wrapped and sound
  const m = s.match(/\$\{\{[\s\S]*\}\}/); // first '${{' to last '}}'
  if (!m || m.index === undefined) return false; // no closing fence; malformed, skip
  const prefix = s.slice(0, m.index);
  const suffix = s.slice(m.index + m[0].length);
  if (prefix.length > 0 || suffix.length > 0) return true; // extra content (incl. newline)
  const exprCount = (s.match(/\$\{\{/g) ?? []).length;
  return exprCount > 1; // multiple concatenated expressions are also a string
}

interface Cond {
  expr: string;
  where: string;
}

function collectConditions(parsed: Record<string, unknown>): Cond[] {
  const out: Cond[] = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const job = jobDef as Record<string, unknown>;
    if (typeof job['if'] === 'string') out.push({ expr: job['if'], where: `job "${jobId}"` });
    const steps = job['steps'];
    if (Array.isArray(steps)) {
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        if (step && typeof step === 'object' && typeof (step as Record<string, unknown>)['if'] === 'string') {
          out.push({ expr: (step as Record<string, unknown>)['if'] as string, where: `job "${jobId}" step ${i + 1}` });
        }
      }
    }
  }
  return out;
}

export const unsoundConditionCheck: CheckDefinition = {
  id: 'triggers/unsound-condition',
  name: 'Always-true if: condition',
  description:
    'Detects if: conditions that GitHub evaluates as a truthy string instead of a boolean (block scalars, trailing newlines, surrounding text), silently disabling the gate.',
  category: 'dangerous-triggers',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const cond of collectConditions(workflow.parsed)) {
        if (!isUnsound(cond.expr)) continue;

        const oneLine = cond.expr.replace(/\s+/g, ' ').trim();
        findings.push({
          checkId: 'triggers/unsound-condition',
          severity: 'high',
          category: 'dangerous-triggers',
          title: `Always-true condition on ${cond.where}`,
          description:
            `Workflow "${workflow.name}" has an \`if:\` on ${cond.where} that is not a single bare \`${'${{ ... }}'}\` expression. ` +
            'GitHub Actions treats it as a non-empty string, which is always truthy, so the condition never blocks anything.',
          risk:
            'A condition meant as a security gate (actor check, fork check, branch check) that always evaluates true runs for every trigger, including attacker-controlled ones. ' +
            'This commonly happens when the condition is written as a YAML block scalar (`|` or `>`), which appends a trailing newline, or when text is placed around the expression.',
          remediation:
            'Write the condition as a single inline expression with nothing around it:\n\n' +
            '```yaml\n' +
            '# Unsound (block scalar adds a trailing newline -> always true):\n' +
            'if: >\n' +
            "  ${{ github.actor == 'dependabot[bot]' }}\n\n" +
            '# Sound:\n' +
            "if: ${{ github.actor == 'dependabot[bot]' }}\n" +
            '# or, equivalently, the unfenced form:\n' +
            "if: github.actor == 'dependabot[bot]'\n" +
            '```',
          file: workflow.path,
          line: findLineNumber(workflow.content, oneLine.slice(0, 30)) ?? findLineNumber(workflow.content, 'if:'),
          evidence: `if: ${oneLine}`,
        });
      }
    }

    return findings;
  },
};
