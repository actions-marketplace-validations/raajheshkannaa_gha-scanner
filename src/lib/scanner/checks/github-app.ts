import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * permissions/github-app-token
 *
 * Detects risky use of `actions/create-github-app-token`. App
 * installation tokens are powerful, short-lived credentials. Three
 * patterns widen their blast radius:
 *   1. `skip-token-revoke: true` — the token is not revoked at job end,
 *      so it stays valid for its full ~1h lifetime even after the job.
 *   2. `owner:` set without `repositories:` — the token is scoped to ALL
 *      repos in the owner/org, not just the ones needed.
 *   3. no `permission-*` inputs — the token gets every permission granted
 *      to the app installation, instead of a minimal set.
 */

function getSteps(parsed: Record<string, unknown>): Array<{ step: Record<string, unknown>; jobId: string }> {
  const out: Array<{ step: Record<string, unknown>; jobId: string }> = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const steps = (jobDef as Record<string, unknown>)['steps'];
    if (!Array.isArray(steps)) continue;
    for (const step of steps) {
      if (step && typeof step === 'object') out.push({ step: step as Record<string, unknown>, jobId });
    }
  }
  return out;
}

export const githubAppTokenCheck: CheckDefinition = {
  id: 'permissions/github-app-token',
  name: 'Over-scoped GitHub App token',
  description:
    'Detects actions/create-github-app-token usage that skips token revocation, omits repository scoping, or requests all installation permissions.',
  category: 'permissions',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const { step, jobId } of getSteps(workflow.parsed)) {
        const uses = typeof step['uses'] === 'string' ? step['uses'] : '';
        if (!uses.startsWith('actions/create-github-app-token')) continue;

        const withBlock =
          step['with'] && typeof step['with'] === 'object'
            ? (step['with'] as Record<string, unknown>)
            : {};

        const issues: string[] = [];

        const skipRevoke = withBlock['skip-token-revoke'];
        if (skipRevoke === true || skipRevoke === 'true') {
          issues.push('`skip-token-revoke: true` keeps the token valid after the job ends');
        }

        const hasOwner = 'owner' in withBlock && String(withBlock['owner'] ?? '').trim() !== '';
        const hasRepos = 'repositories' in withBlock && String(withBlock['repositories'] ?? '').trim() !== '';
        if (hasOwner && !hasRepos) {
          issues.push('`owner` is set without `repositories`, scoping the token to every repo in the owner');
        }

        const hasPermissionScope = Object.keys(withBlock).some((k) => k.startsWith('permission-'));
        if (!hasPermissionScope) {
          issues.push('no `permission-*` inputs, so the token gets all of the app installation\'s permissions');
        }

        if (issues.length === 0) continue;

        findings.push({
          checkId: 'permissions/github-app-token',
          severity: 'high',
          category: 'permissions',
          title: `Over-scoped GitHub App token in job "${jobId}"`,
          description:
            `Workflow "${workflow.name}" mints a GitHub App installation token in job "${jobId}" with weakened scoping: ` +
            issues.map((i) => `\n- ${i}`).join(''),
          risk:
            'App installation tokens can act across repositories with the app\'s permissions. ' +
            'A token that is broadly scoped, fully permissioned, or left un-revoked is a high-value target: any later compromised step (or a leaked log) can reuse it to push code, publish packages, or modify settings across the org for the remainder of its lifetime.',
          remediation:
            'Mint the narrowest token the job needs and let it revoke at job end:\n\n' +
            '```yaml\n' +
            '- uses: actions/create-github-app-token@v2\n' +
            '  with:\n' +
            '    app-id: ${{ vars.APP_ID }}\n' +
            '    private-key: ${{ secrets.APP_PRIVATE_KEY }}\n' +
            '    repositories: this-repo            # scope to specific repos\n' +
            '    permission-contents: write          # request only needed scopes\n' +
            '    permission-pull-requests: write\n' +
            '    # leave skip-token-revoke unset (defaults to revoking)\n' +
            '```',
          file: workflow.path,
          line: findLineNumber(workflow.content, 'create-github-app-token'),
          evidence: `job "${jobId}": ${issues.length} app-token scoping issue(s)`,
        });
      }
    }

    return findings;
  },
};
