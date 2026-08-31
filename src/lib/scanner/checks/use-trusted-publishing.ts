import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * permissions/use-trusted-publishing
 *
 * Informational: detects package publishing that uses a long-lived API
 * token instead of OIDC "trusted publishing". Trusted publishing
 * exchanges a short-lived, workflow-scoped OIDC token for the publish,
 * removing the standing secret entirely (no token to leak, rotate, or
 * exfiltrate).
 */

interface JobView {
  jobId: string;
  job: Record<string, unknown>;
  steps: Record<string, unknown>[];
  hasIdTokenWrite: boolean;
}

function jobHasIdToken(perms: unknown): boolean {
  if (perms === 'write-all') return true;
  if (perms && typeof perms === 'object') {
    return (perms as Record<string, unknown>)['id-token'] === 'write';
  }
  return false;
}

function getJobs(parsed: Record<string, unknown>): JobView[] {
  const out: JobView[] = [];
  const workflowIdToken = jobHasIdToken(parsed['permissions']);
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const job = jobDef as Record<string, unknown>;
    const stepsRaw = job['steps'];
    const steps = Array.isArray(stepsRaw)
      ? stepsRaw.filter((s): s is Record<string, unknown> => !!s && typeof s === 'object')
      : [];
    out.push({
      jobId,
      job,
      steps,
      hasIdTokenWrite: workflowIdToken || jobHasIdToken(job['permissions']),
    });
  }
  return out;
}

const RUN_PUBLISH = [
  /\b(?:npm|pnpm|yarn|bun)\s+publish(?=\s|$)/,
  /\byarn\s+npm\s+publish(?=\s|$)/,
  /\btwine\s+upload(?=\s|$)/,
  /\b(?:uv|poetry|hatch|pdm)\s+publish(?=\s|$)/,
  /\bgem\s+push(?=\s|$)/,
  /\bcargo\s+publish(?!\s+(?:--dry-run|-n))/,
  /\bdotnet\s+nuget\s+push(?=\s|$)/,
  /\bnuget\s+push(?=\s|$)/,
];

export const useTrustedPublishingCheck: CheckDefinition = {
  id: 'permissions/use-trusted-publishing',
  name: 'Token-based publishing instead of trusted publishing',
  description:
    'Detects package publishing via a long-lived API token where OIDC trusted publishing is available.',
  category: 'permissions',
  severity: 'info',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const view of getJobs(workflow.parsed)) {
        let signal: string | null = null;

        for (const step of view.steps) {
          const uses = typeof step['uses'] === 'string' ? step['uses'] : '';
          const withBlock =
            step['with'] && typeof step['with'] === 'object'
              ? (step['with'] as Record<string, unknown>)
              : {};
          const run = typeof step['run'] === 'string' ? step['run'] : '';

          // pypa/gh-action-pypi-publish with an explicit password = token publishing
          if (uses.startsWith('pypa/gh-action-pypi-publish') && 'password' in withBlock) {
            signal = 'pypa/gh-action-pypi-publish with a password input';
            break;
          }
          // Command-line publish without OIDC. We require an actual publish
          // command (not just a registry-url setup step, which is also used for
          // private-package installs) to avoid false positives, and skip
          // dry-run invocations which do not actually publish.
          if (run) {
            for (const line of run.split('\n')) {
              if (/--dry-run\b|(?:^|\s)-n\b/.test(line)) continue;
              const re = RUN_PUBLISH.find((r) => r.test(line));
              if (re) {
                signal = `run: ${line.match(re)?.[0]}`;
                break;
              }
            }
            if (signal) break;
          }
        }

        // Only emit when there is no id-token: write (i.e. not already on OIDC).
        if (!signal || view.hasIdTokenWrite) continue;

        findings.push({
          checkId: 'permissions/use-trusted-publishing',
          severity: 'info',
          category: 'permissions',
          title: `Job "${view.jobId}" publishes with a token instead of trusted publishing`,
          description:
            `Workflow "${workflow.name}" job "${view.jobId}" publishes a package using a stored credential (${signal}) rather than OIDC trusted publishing.`,
          risk:
            'A long-lived publish token is a standing secret: it can be leaked from logs, a compromised action, or a misconfigured artifact, and it stays valid until manually rotated. ' +
            'Trusted publishing removes the secret entirely by minting a short-lived, workflow-scoped OIDC token at publish time, which is the credential design npm, PyPI, RubyGems, and crates.io now recommend.',
          remediation:
            'Adopt OIDC trusted publishing for the registry and drop the stored token:\n\n' +
            '```yaml\n' +
            '  publish:\n' +
            '    runs-on: ubuntu-latest\n' +
            '    environment: release\n' +
            '    permissions:\n' +
            '      id-token: write   # mint the OIDC token\n' +
            '      contents: read\n' +
            '    steps:\n' +
            '      - uses: pypa/gh-action-pypi-publish@release/v1   # no password: needed\n' +
            '```\n\n' +
            'Configure the trusted publisher in the registry settings (PyPI, npm, RubyGems, crates.io) to bind it to this repo and workflow.',
          file: workflow.path,
          line: findLineNumber(workflow.content, `${view.jobId}:`),
          evidence: `job "${view.jobId}": ${signal}; no id-token: write`,
        });
      }
    }

    return findings;
  },
};
