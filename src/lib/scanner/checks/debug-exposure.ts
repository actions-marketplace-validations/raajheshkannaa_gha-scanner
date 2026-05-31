import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * secrets/debug-exposure
 *
 * Detects interactive remote-debug sessions opened from a committed
 * workflow, specifically `mxschmitt/action-tmate` (and forks). action-tmate
 * opens an interactive SSH/web session into the runner while the job's
 * secrets are loaded into the environment, which is a live shell with the
 * job's credentials. Committed (non-conditional) tmate steps run on normal
 * pushes, not just when a maintainer is actively debugging.
 *
 * Scope note: this check deliberately does NOT flag `env`/`printenv` dumps
 * (GitHub masks registered secrets in logs, so those are weaker signal and
 * noisy) nor `ACTIONS_STEP_DEBUG` in a workflow `env:` block (that variable
 * only enables debug logging when set as a repository/org secret or
 * variable, not via workflow env, so flagging it there would be incorrect).
 */

const TMATE_RE = /(?:^|\/)action-tmate/;

function getSteps(parsed: Record<string, unknown>): Array<{ uses: string; jobId: string }> {
  const out: Array<{ uses: string; jobId: string }> = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const steps = (jobDef as Record<string, unknown>)['steps'];
    if (!Array.isArray(steps)) continue;
    for (const step of steps) {
      if (step && typeof step === 'object' && typeof (step as Record<string, unknown>)['uses'] === 'string') {
        out.push({ uses: (step as Record<string, unknown>)['uses'] as string, jobId });
      }
    }
  }
  return out;
}

export const debugExposureCheck: CheckDefinition = {
  id: 'secrets/debug-exposure',
  name: 'Interactive debug session exposure',
  description:
    'Detects committed action-tmate steps, which open an interactive shell into the runner with the job\'s secrets loaded.',
  category: 'secrets-exposure',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const { uses, jobId } of getSteps(workflow.parsed)) {
        if (!TMATE_RE.test(uses)) continue;

        findings.push({
          checkId: 'secrets/debug-exposure',
          severity: 'medium',
          category: 'secrets-exposure',
          title: `Interactive tmate debug session in job "${jobId}"`,
          description:
            `Workflow "${workflow.name}" runs \`${uses}\`, which opens an interactive SSH/web session into the runner with the job's secrets available.`,
          risk:
            'action-tmate pauses the job and exposes a live shell on the runner while secrets and the GITHUB_TOKEN are loaded. ' +
            'A committed (non-conditional) tmate step means anyone who can read the session details, or trigger the workflow, can reach that shell. On untrusted triggers it is a direct path to the job\'s credentials.',
          remediation:
            'Remove tmate from committed workflows. If you need it for ad-hoc debugging, gate it behind a manual dispatch input and restrict access to the actor:\n\n' +
            '```yaml\n' +
            "- if: ${{ github.event_name == 'workflow_dispatch' && inputs.debug }}\n" +
            '  uses: mxschmitt/action-tmate@v3\n' +
            '  with:\n' +
            '    limit-access-to-actor: true\n' +
            '```\n\n' +
            'Never run it on untrusted triggers (pull_request_target, fork pull_request).',
          file: workflow.path,
          line: findLineNumber(workflow.content, uses),
          evidence: `uses: ${uses}`,
        });
      }
    }

    return findings;
  },
};
