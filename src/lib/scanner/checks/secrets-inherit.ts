import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * secrets/secrets-inherit
 *
 * Detects reusable-workflow calls that pass `secrets: inherit`. This
 * forwards EVERY secret available to the calling workflow to the called
 * workflow, regardless of what the callee actually needs. If the called
 * workflow (or any action it runs) is compromised or simply
 * over-permissioned, the full secret set is exposed. The least-privilege
 * pattern is to pass only the named secrets the callee requires.
 */

function getJobs(parsed: Record<string, unknown>): [string, Record<string, unknown>][] {
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];
  return Object.entries(jobs as Record<string, unknown>).filter(
    (entry): entry is [string, Record<string, unknown>] =>
      typeof entry[1] === 'object' && entry[1] !== null
  );
}

export const secretsInheritCheck: CheckDefinition = {
  id: 'secrets/secrets-inherit',
  name: 'Reusable workflow called with secrets: inherit',
  description:
    'Detects reusable workflow calls using `secrets: inherit`, which forwards all of the caller\'s secrets to the callee instead of only what it needs.',
  category: 'secrets-exposure',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const [jobId, job] of getJobs(workflow.parsed)) {
        const uses = job['uses'];
        if (typeof uses !== 'string') continue; // only reusable-workflow-call jobs

        const secrets = job['secrets'];
        if (secrets !== 'inherit') continue;

        findings.push({
          checkId: 'secrets/secrets-inherit',
          severity: 'medium',
          category: 'secrets-exposure',
          title: `Job "${jobId}" calls a reusable workflow with secrets: inherit`,
          description:
            `Workflow "${workflow.name}" job "${jobId}" calls \`${uses}\` with \`secrets: inherit\`. ` +
            'Every secret available to this workflow is forwarded to the called workflow, including secrets it does not use.',
          risk:
            'A compromised or over-permissioned reusable workflow (or any third-party action it runs) receives the entire secret set, not just what it needs. ' +
            'This widens the blast radius of a callee compromise from one credential to all of them, and it obscures which secrets actually flow where.',
          remediation:
            'Pass only the named secrets the callee requires:\n\n' +
            '```yaml\n' +
            'jobs:\n' +
            `  ${jobId}:\n` +
            `    uses: ${uses}\n` +
            '    secrets:\n' +
            '      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n' +
            '      # only the secrets this workflow actually needs\n' +
            '```\n\n' +
            'Reserve `secrets: inherit` for trusted, same-repo reusable workflows where forwarding everything is intentional.',
          file: workflow.path,
          line: findLineNumber(workflow.content, `${jobId}:`),
          evidence: `job "${jobId}" uses: ${uses} with secrets: inherit`,
        });
      }
    }

    return findings;
  },
};
