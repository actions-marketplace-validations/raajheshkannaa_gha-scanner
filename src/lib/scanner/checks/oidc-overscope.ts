import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * permissions/oidc-overscope
 *
 * Detects workflows that issue OIDC tokens (id-token: write) without
 * adequate scope controls. The May 2026 TanStack publish path exploited
 * an `id-token: write` job that had no `environment:` protection — the
 * attacker's poisoned cache ran in the same job as the trusted publish
 * step and exfiltrated the OIDC token to publish via npm trusted
 * publishing.
 *
 * This is a WORKFLOW-YAML-ONLY heuristic. It does NOT query the GitHub
 * API for environment reviewer configuration; findings explicitly tell
 * the user that environment presence is checked but reviewer enforcement
 * must be verified out-of-band in the GitHub UI.
 *
 * Three rules:
 *   1. Workflow-scope `id-token: write` → HIGH. id-token should be
 *      scoped to the specific publish job, not the whole workflow.
 *   2. Job with `id-token: write` and no `environment:` → HIGH. Without
 *      an environment gate, any compromised step in the job can call
 *      `actions/github-script` to mint OIDC tokens or read them from
 *      env vars set by sibling steps. Environment protection (with
 *      required reviewers) is the platform's only built-in defense.
 *   3. Trusted-publishing pattern (id-token: write + npm/pnpm/yarn
 *      publish OR setup-node with registry-url, OR PyPI publish, OR
 *      configure-aws-credentials) without environment → CRITICAL.
 *      This is the May 11 vector unprotected.
 *
 * Reusable workflows (`on: workflow_call` only) are skipped — they
 * inherit environment protection from the calling workflow.
 */

interface JobView {
  name: string;
  raw: Record<string, unknown>;
  permissions: unknown;
  hasIdTokenWrite: boolean;
  environment: unknown;
  steps: Array<Record<string, unknown>>;
}

function getJobs(parsed: Record<string, unknown>): JobView[] {
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];
  const out: JobView[] = [];
  for (const [name, raw] of Object.entries(jobs as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object') continue;
    const job = raw as Record<string, unknown>;
    const perms = job['permissions'];
    const hasIdToken =
      perms === 'write-all' ||
      (typeof perms === 'object' && perms !== null && (perms as Record<string, unknown>)['id-token'] === 'write');
    const stepsRaw = job['steps'];
    const steps = Array.isArray(stepsRaw)
      ? stepsRaw.filter((s): s is Record<string, unknown> => !!s && typeof s === 'object')
      : [];
    out.push({
      name,
      raw: job,
      permissions: perms,
      hasIdTokenWrite: hasIdToken,
      environment: job['environment'],
      steps,
    });
  }
  return out;
}

function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

function isReusableOnly(triggers: string[]): boolean {
  return triggers.length === 1 && triggers[0] === 'workflow_call';
}

function workflowScopePermissions(parsed: Record<string, unknown>): unknown {
  return parsed['permissions'];
}

function workflowScopeHasIdToken(parsed: Record<string, unknown>): boolean {
  const perms = workflowScopePermissions(parsed);
  if (perms === 'write-all') return true;
  if (typeof perms === 'object' && perms !== null) {
    return (perms as Record<string, unknown>)['id-token'] === 'write';
  }
  return false;
}

/**
 * Detect whether a job looks like a "trusted publishing" job: a step
 * that publishes packages to a registry that uses OIDC federation
 * (npm, PyPI, etc.) OR a step that exchanges the OIDC token for cloud
 * credentials (AWS, GCP, Azure).
 *
 * This is intentionally a publish-shape detector, not a generic OIDC
 * consumer detector. It is the trigger for rule 3's CRITICAL severity.
 */
export interface PublishSignal {
  matched: boolean;
  signal: string;
}

export function detectPublishingPattern(job: JobView): PublishSignal {
  // First pass: collect direct publish/cloud-auth signals AND track whether
  // setup-node with registry-url appeared (only counted if a publish command
  // also exists in the same job — setup-node alone is used legitimately for
  // scoped installs and is not a publish indicator by itself).
  let setupNodeRegistry: string | null = null;

  for (const step of job.steps) {
    const uses = typeof step['uses'] === 'string' ? step['uses'] : '';
    const run = typeof step['run'] === 'string' ? step['run'] : '';
    const withBlock =
      typeof step['with'] === 'object' && step['with'] !== null
        ? (step['with'] as Record<string, unknown>)
        : {};

    // Track setup-node + registry-url; only count it as a publishing signal
    // if a publish command also appears in the same job.
    if (uses.startsWith('actions/setup-node') && typeof withBlock['registry-url'] === 'string') {
      setupNodeRegistry = String(withBlock['registry-url']);
    }

    // pypa/gh-action-pypi-publish (PyPI trusted publishing) — direct signal
    if (uses.startsWith('pypa/gh-action-pypi-publish')) {
      return { matched: true, signal: `uses: ${uses}` };
    }

    // OIDC → cloud credential exchange — direct signal
    if (uses.startsWith('aws-actions/configure-aws-credentials')) {
      return { matched: true, signal: `uses: ${uses} (OIDC → AWS credentials)` };
    }
    if (uses.startsWith('google-github-actions/auth')) {
      return { matched: true, signal: `uses: ${uses} (OIDC → GCP credentials)` };
    }
    if (uses.startsWith('azure/login')) {
      return { matched: true, signal: `uses: ${uses} (OIDC → Azure credentials)` };
    }

    // Direct publish commands in run blocks.
    // Covers: npm publish, pnpm publish, yarn publish (classic), yarn npm publish (Berry).
    // Lookahead `(?=\s|$)` prevents matching hyphenated names like
    // `publish-package` because `\b` fires before `-`.
    if (/\byarn\s+npm\s+publish(?=\s|$)/.test(run)) {
      return { matched: true, signal: 'run: yarn npm publish' };
    }
    if (/\b(?:npm|pnpm|yarn)\s+publish(?=\s|$)/.test(run)) {
      const cmd = run.match(/\b(?:npm|pnpm|yarn)\s+publish(?=\s|$)[^\n]*/)?.[0] ?? 'npm publish';
      return { matched: true, signal: `run: ${cmd}` };
    }
    if (/\btwine\s+upload(?=\s|$)/.test(run) || /\b(?:python|python3)\s+-m\s+twine\s+upload(?=\s|$)/.test(run)) {
      return { matched: true, signal: 'run: twine upload' };
    }
    if (/\b(?:cargo)\s+publish(?=\s|$)/.test(run)) {
      return { matched: true, signal: 'run: cargo publish' };
    }
    if (/\bgem\s+push(?=\s|$)/.test(run)) {
      return { matched: true, signal: 'run: gem push' };
    }
  }

  // Fallback: setup-node + registry-url, IF the same job ALSO contains a
  // publish-shaped command (not just any npm/pnpm/yarn invocation). This
  // covers the May 11 vector when the publish is hidden behind a script
  // that the run step calls, but rejects scoped-install patterns like
  // `npm ci`, `npm test`, `yarn install` which do not publish.
  //
  // Publish indicators in this fallback:
  //   - Direct verbs: `npm publish`, `pnpm publish`, `yarn publish`, `yarn npm publish`
  //   - Scripts named `release`, `publish`, or `release-*`: `npm run publish`,
  //     `npm run release`, `pnpm release`, etc.
  if (setupNodeRegistry) {
    const publishVerbRe = /\b(?:npm|pnpm|yarn)(?:\s+npm)?\s+publish(?=\s|$)/;
    // Scripts: end is either whitespace/EOL OR a `:`/`-` suffix segment.
    const publishScriptRe = /\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:publish|release)(?:[:-][a-z0-9-]+)?(?=\s|$)/i;
    for (const step of job.steps) {
      const run = typeof step['run'] === 'string' ? step['run'] : '';
      if (publishVerbRe.test(run) || publishScriptRe.test(run)) {
        const match = run.match(publishVerbRe)?.[0] ?? run.match(publishScriptRe)?.[0] ?? 'publish';
        return {
          matched: true,
          signal: `actions/setup-node with registry-url (${setupNodeRegistry}) + ${match} in same job`,
        };
      }
    }
  }

  return { matched: false, signal: '' };
}

const ENV_VERIFY_NOTE =
  '\n\n**Verifying environment protection (out-of-band):** This check only confirms that an `environment:` is referenced in the workflow YAML. ' +
  'It does NOT verify reviewer configuration. To check whether the environment actually requires reviewers, branch protection, or wait timers, open ' +
  'Settings > Environments > [environment-name] in the GitHub UI, or query the REST API: ' +
  '`gh api /repos/{owner}/{repo}/environments/{environment-name}`.';

export const oidcOverscopeCheck: CheckDefinition = {
  id: 'permissions/oidc-overscope',
  name: 'OIDC Token Issuance Overscope',
  description:
    'Detects workflows that grant id-token: write without adequate scope controls. This is the May 2026 TanStack/Mini Shai-Hulud publish-vector exposure.',
  category: 'permissions',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];
    const reported = new Set<string>();

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;
      const triggers = getTriggers(workflow.parsed);
      if (isReusableOnly(triggers)) continue;

      // --- Rule 1: workflow-scope id-token: write ---
      if (workflowScopeHasIdToken(workflow.parsed)) {
        const dedupeKey = `r1:${workflow.path}`;
        if (!reported.has(dedupeKey)) {
          reported.add(dedupeKey);
          findings.push({
            checkId: 'permissions/oidc-overscope',
            severity: 'high',
            category: 'permissions',
            title: 'OIDC id-token: write granted at workflow scope',
            description:
              `Workflow "${workflow.name}" grants \`id-token: write\` at the workflow level. ` +
              `Every job in the workflow can mint OIDC tokens, even jobs that do not publish or exchange for cloud credentials. ` +
              `This widens the attack surface: any compromised step in any job can request an OIDC token.`,
            risk:
              'OIDC tokens are bearer credentials. Workflow-scope `id-token: write` means a compromised step in any job — test runners, linters, third-party actions — can mint a token. ' +
              'The minimum-privilege practice is to scope `id-token: write` to the single job that performs the publish or cloud auth.',
            remediation:
              'Move `id-token: write` from workflow scope to the specific job that needs it:\n\n' +
              '```yaml\n' +
              '# Instead of:\n' +
              'permissions:\n' +
              '  id-token: write   # <- too broad\n' +
              '  contents: read\n' +
              'jobs:\n' +
              '  test:\n' +
              '    ...\n' +
              '  publish:\n' +
              '    ...\n\n' +
              '# Use:\n' +
              'permissions:\n' +
              '  contents: read\n' +
              'jobs:\n' +
              '  test:\n' +
              '    runs-on: ubuntu-latest\n' +
              '    steps: [...]\n' +
              '  publish:\n' +
              '    runs-on: ubuntu-latest\n' +
              '    permissions:\n' +
              '      id-token: write   # <- scoped to publish job only\n' +
              '      contents: read\n' +
              '    environment: production\n' +
              '    steps: [...]\n' +
              '```' +
              ENV_VERIFY_NOTE,
            file: workflow.path,
            line: findLineNumber(workflow.content, 'permissions:'),
            evidence: `workflow-level permissions: ${JSON.stringify(workflowScopePermissions(workflow.parsed))}`,
          });
        }
      }

      // --- Rule 2 + Rule 3: per-job analysis ---
      const jobs = getJobs(workflow.parsed);
      const workflowHasIdToken = workflowScopeHasIdToken(workflow.parsed);
      for (const job of jobs) {
        const jobHasIdToken = job.hasIdTokenWrite || workflowHasIdToken;
        if (!jobHasIdToken) continue;

        // Object form of `environment:` must have a non-empty `name` to count.
        // `{}` or `{ url: ... }` without a name is treated as missing.
        const envIsValidString =
          typeof job.environment === 'string' && job.environment.trim().length > 0;
        const envIsValidObject =
          typeof job.environment === 'object' &&
          job.environment !== null &&
          !Array.isArray(job.environment) &&
          typeof (job.environment as Record<string, unknown>)['name'] === 'string' &&
          ((job.environment as Record<string, unknown>)['name'] as string).trim().length > 0;
        const hasEnvironment = envIsValidString || envIsValidObject;

        if (hasEnvironment) continue; // protected (presence-only check)

        const publish = detectPublishingPattern(job);

        if (publish.matched) {
          // Rule 3: trusted-publishing without environment → CRITICAL
          const dedupeKey = `r3:${workflow.path}:${job.name}`;
          if (reported.has(dedupeKey)) continue;
          reported.add(dedupeKey);
          findings.push({
            checkId: 'permissions/oidc-overscope',
            severity: 'critical',
            category: 'permissions',
            title: `Trusted-publishing job has id-token: write but no environment gate: ${job.name}`,
            description:
              `Job "${job.name}" in workflow "${workflow.name}" has \`id-token: write\` AND a trusted-publishing pattern (${publish.signal}), but no \`environment:\` key. ` +
              `This is exactly the May 2026 TanStack/Mini Shai-Hulud publish vector unprotected: any step earlier in the job — including a poisoned cached dependency or a compromised third-party action — runs as the same UID and can intercept the OIDC token.`,
            risk:
              'Without an environment gate, GitHub Actions provides no platform-level barrier between trusted publish steps and untrusted earlier steps in the same job. ' +
              'A compromised earlier step can mint OIDC tokens directly, read the trusted helper\'s token via filesystem or `/proc`, or replace the publish command before it runs. ' +
              'Environment protection adds: required reviewers (manual gate per deploy), branch protection (only main can deploy), wait timers (delay window to detect bad deploys), and a separate audit trail.',
            remediation:
              'Add an `environment:` to the publish job and configure required reviewers in the GitHub UI:\n\n' +
              '```yaml\n' +
              `  ${job.name}:\n` +
              '    runs-on: ubuntu-latest\n' +
              '    environment: production   # <- required\n' +
              '    permissions:\n' +
              '      id-token: write\n' +
              '      contents: read\n' +
              '    steps:\n' +
              '      # ... your publish steps\n' +
              '```\n\n' +
              'Then in GitHub: Settings > Environments > New environment > name it `production` > add Required reviewers (you + at least one teammate) > restrict to the `main` branch.' +
              ENV_VERIFY_NOTE,
            file: workflow.path,
            line: findLineNumber(workflow.content, `${job.name}:`),
            evidence: `job: ${job.name} | id-token: write | publishing signal: ${publish.signal} | environment: (none)`,
          });
        } else {
          // Rule 2: id-token: write without environment, no publish signal → HIGH
          const dedupeKey = `r2:${workflow.path}:${job.name}`;
          if (reported.has(dedupeKey)) continue;
          reported.add(dedupeKey);
          findings.push({
            checkId: 'permissions/oidc-overscope',
            severity: 'high',
            category: 'permissions',
            title: `Job with id-token: write has no environment gate: ${job.name}`,
            description:
              `Job "${job.name}" in workflow "${workflow.name}" has \`id-token: write\` but no \`environment:\` key. ` +
              `Any step in the job can mint OIDC tokens with no platform-level review or branch protection.`,
            risk:
              'OIDC tokens authenticate the job to external systems (cloud providers, package registries, internal services that trust GitHub\'s OIDC issuer). ' +
              'Without an environment gate, any compromised step — including third-party actions and `run:` blocks that execute lockfile-resolved dependencies — can mint tokens. ' +
              'For deploys, the `environment:` block is the platform\'s only built-in reviewer gate.',
            remediation:
              'If this job legitimately needs `id-token: write`, add an environment gate and configure required reviewers:\n\n' +
              '```yaml\n' +
              `  ${job.name}:\n` +
              '    runs-on: ubuntu-latest\n' +
              '    environment: production\n' +
              '    permissions:\n' +
              '      id-token: write\n' +
              '      contents: read\n' +
              '    steps: [...]\n' +
              '```\n\n' +
              'If this job does NOT need OIDC, remove `id-token: write` entirely.' +
              ENV_VERIFY_NOTE,
            file: workflow.path,
            line: findLineNumber(workflow.content, `${job.name}:`),
            evidence: `job: ${job.name} | id-token: write | environment: (none)`,
          });
        }
      }
    }

    return findings;
  },
};
