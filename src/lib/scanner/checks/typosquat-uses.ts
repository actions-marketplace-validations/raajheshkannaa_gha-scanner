import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';
import { POPULAR_ACTIONS } from '../data/popular-actions';

/**
 * supply-chain/typosquat-uses
 *
 * Detects `uses:` references that are a tiny edit-distance away from a
 * popular action but not an exact match — the classic typosquat shape
 * (`actons/checkout`, `actions/checkuot`, `aws-actions/configure-aws-credential`).
 * A typosquatted action under attacker control runs with the workflow's
 * permissions and secrets.
 *
 * This is OFFLINE and corpus-based: it cannot confirm the look-alike repo
 * actually exists, so findings are framed for human verification and use
 * conservative distance thresholds to limit false positives.
 */

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const prev = new Array(n + 1);
  const curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }
  return prev[n];
}

function parseActionRef(uses: string): { actionPath: string; ref: string } | null {
  const trimmed = uses.trim();
  if (trimmed.startsWith('./') || trimmed.startsWith('../') || trimmed.startsWith('docker://')) return null;
  if (trimmed.includes('.github/workflows/')) return null;
  const at = trimmed.indexOf('@');
  const actionPath = at === -1 ? trimmed : trimmed.slice(0, at);
  const ref = at === -1 ? '' : trimmed.slice(at + 1);
  // Normalize owner/repo (drop any subpath like owner/repo/sub)
  const parts = actionPath.split('/');
  if (parts.length < 2) return null;
  return { actionPath: `${parts[0]}/${parts[1]}`.toLowerCase(), ref };
}

function nearestPopular(actionPath: string): { match: string; distance: number } | null {
  let best: { match: string; distance: number } | null = null;
  for (const popular of POPULAR_ACTIONS) {
    if (popular === actionPath) return null; // exact match: legitimate
    const d = levenshtein(actionPath, popular);
    if (best === null || d < best.distance) best = { match: popular, distance: d };
  }
  return best;
}

export const typosquatUsesCheck: CheckDefinition = {
  id: 'supply-chain/typosquat-uses',
  name: 'Possible typosquatted action',
  description:
    'Detects uses: references that closely resemble a popular action but are not an exact match, a common typosquatting pattern.',
  category: 'supply-chain',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];
    const reported = new Set<string>();

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;
      const jobs = workflow.parsed['jobs'];
      if (!jobs || typeof jobs !== 'object') continue;

      for (const jobDef of Object.values(jobs as Record<string, unknown>)) {
        if (!jobDef || typeof jobDef !== 'object') continue;
        const steps = (jobDef as Record<string, unknown>)['steps'];
        if (!Array.isArray(steps)) continue;

        for (const step of steps) {
          if (!step || typeof step !== 'object') continue;
          const uses = (step as Record<string, unknown>)['uses'];
          if (typeof uses !== 'string') continue;

          const parsed = parseActionRef(uses);
          if (!parsed) continue;

          const nearest = nearestPopular(parsed.actionPath);
          if (!nearest) continue;

          // Conservative thresholds: distance 1, or distance 2 on longer names.
          const isSuspect =
            nearest.distance === 1 ||
            (nearest.distance === 2 && parsed.actionPath.length >= 12);
          if (!isSuspect) continue;

          const dedupe = `${workflow.path}:${parsed.actionPath}`;
          if (reported.has(dedupe)) continue;
          reported.add(dedupe);

          findings.push({
            checkId: 'supply-chain/typosquat-uses',
            severity: 'high',
            category: 'supply-chain',
            title: `Possible typosquat: ${parsed.actionPath} resembles ${nearest.match}`,
            description:
              `Workflow "${workflow.name}" uses \`${parsed.actionPath}\`, which differs from the popular action \`${nearest.match}\` by only ${nearest.distance} character${nearest.distance === 1 ? '' : 's'}. ` +
              'This is the shape of a typosquatted action. Verify it is the action you intended.',
            risk:
              'A typosquatted action under an attacker\'s control executes inside your workflow with its permissions, the GITHUB_TOKEN, and any secrets passed to it. ' +
              'Supply chain actors register look-alike names specifically to catch these typos.',
            remediation:
              `Confirm the correct owner/repo and pin it by commit SHA:\n\n` +
              '```yaml\n' +
              `# If you meant ${nearest.match}:\n` +
              `uses: ${nearest.match}@<full-40-char-sha>  # vX.Y.Z\n` +
              '```\n\n' +
              'If `' + parsed.actionPath + '` is genuinely the action you want, suppress this finding:\n' +
              '`# gha-scanner-ignore: supply-chain/typosquat-uses`',
            file: workflow.path,
            line: findLineNumber(workflow.content, uses),
            evidence: `uses: ${uses} (distance ${nearest.distance} from ${nearest.match})`,
          });
        }
      }
    }

    return findings;
  },
};
