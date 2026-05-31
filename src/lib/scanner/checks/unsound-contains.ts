import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * triggers/unsound-contains
 *
 * Detects `contains('a b c', <user-controllable>)` used as an allowlist
 * inside an `if:` gate. `contains(string, item)` does a SUBSTRING match,
 * not set membership, and the first argument is a flat string. So
 * `contains('refs/heads/main refs/heads/dev', github.ref)` returns true for
 * any ref that is a substring of that haystack (e.g. `refs/heads/d`), and an
 * attacker who controls the second argument can satisfy the gate with a
 * crafted value. The sound form uses a JSON array.
 *
 * Scoped to `if:` conditions so that example strings, step names, and
 * comments containing `contains(...)` are not flagged.
 */

// First arg is a quoted string literal; second arg is a user-controllable
// context. github.sha and env.* are excluded: they are not inherently
// attacker-controlled in the relevant trigger contexts.
const CONTROLLABLE =
  '(?:github\\.(?:actor|triggering_actor|base_ref|head_ref|ref|ref_name)|github\\.event\\.[A-Za-z0-9_.]+|inputs\\.[A-Za-z0-9_-]+)';
const UNSOUND_CONTAINS = new RegExp(
  `contains\\(\\s*['"][^'"]*['"]\\s*,\\s*(${CONTROLLABLE})\\s*\\)`,
  'g'
);

// Constrained scalar event fields are not attacker-controlled; a contains()
// over these is not the bypass this check targets.
const SAFE_EVENT_SCALARS = [
  'github.event.number',
  'github.event.action',
  'github.event.pull_request.number',
  'github.event.issue.number',
];

function ifToString(value: unknown): string | null {
  if (typeof value === 'string') return value;
  return null;
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
    const jobIf = ifToString(job['if']);
    if (jobIf) out.push({ expr: jobIf, where: `job "${jobId}"` });
    const steps = job['steps'];
    if (Array.isArray(steps)) {
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        if (step && typeof step === 'object') {
          const stepIf = ifToString((step as Record<string, unknown>)['if']);
          if (stepIf) out.push({ expr: stepIf, where: `job "${jobId}" step ${i + 1}` });
        }
      }
    }
  }
  return out;
}

export const unsoundContainsCheck: CheckDefinition = {
  id: 'triggers/unsound-contains',
  name: 'Unsound contains() allowlist',
  description:
    "Detects contains('string literal', user-controllable) in an if: gate, where substring matching makes the gate bypassable.",
  category: 'dangerous-triggers',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const cond of collectConditions(workflow.parsed)) {
        UNSOUND_CONTAINS.lastIndex = 0;
        let evidence: string | null = null;
        let m: RegExpExecArray | null;
        while ((m = UNSOUND_CONTAINS.exec(cond.expr)) !== null) {
          if (SAFE_EVENT_SCALARS.includes(m[1])) continue; // safe scalar arg
          evidence = m[0];
          break;
        }
        if (!evidence) continue;

        findings.push({
          checkId: 'triggers/unsound-contains',
          severity: 'high',
          category: 'dangerous-triggers',
          title: `Bypassable contains() allowlist on ${cond.where}`,
          description:
            `Workflow "${workflow.name}" uses \`${evidence}\` as an allowlist in the \`if:\` on ${cond.where}. ` +
            '`contains()` over a string literal is a substring test, not membership, and the second argument is attacker-influenceable.',
          risk:
            'Because `contains(\'a b c\', x)` matches when `x` is any substring of the haystack, an attacker who controls the second argument (a ref name, branch, input, or event field) can craft a value that passes the gate it was never meant to pass. ' +
            'Used on a privileged trigger, this bypasses the intended branch/actor allowlist.',
          remediation:
            'Use a JSON array so the check is true set membership:\n\n' +
            '```yaml\n' +
            '# Unsound (substring match):\n' +
            "if: contains('refs/heads/main refs/heads/dev', github.ref)\n\n" +
            '# Sound (array membership):\n' +
            "if: contains(fromJSON('[\"refs/heads/main\",\"refs/heads/dev\"]'), github.ref)\n" +
            '```',
          file: workflow.path,
          line: findLineNumber(workflow.content, evidence) ?? findLineNumber(workflow.content, 'contains('),
          evidence,
        });
      }
    }

    return findings;
  },
};
