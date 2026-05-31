import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * injection/insecure-commands
 *
 * Detects `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` in any env block
 * (workflow, job, or step). This opt-in re-enables the deprecated
 * `::set-env::` and `::add-path::` workflow commands, which GitHub
 * disabled by default (CVE-2020-15228) precisely because any step that
 * echoes attacker-controlled text could inject environment variables and
 * PATH entries into the runner. Turning it back on reopens that hole.
 */

const TARGET_KEY = 'ACTIONS_ALLOW_UNSECURE_COMMANDS';

function isTruthy(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === 'string') {
    const v = value.trim().toLowerCase();
    return v === 'true' || v === '1' || v === 'yes';
  }
  return false;
}

interface EnvScope {
  env: Record<string, unknown>;
  where: string;
}

function collectEnvScopes(parsed: Record<string, unknown>): EnvScope[] {
  const scopes: EnvScope[] = [];

  const pushEnv = (env: unknown, where: string) => {
    if (env && typeof env === 'object' && !Array.isArray(env)) {
      scopes.push({ env: env as Record<string, unknown>, where });
    }
  };

  pushEnv(parsed['env'], 'workflow');

  const jobs = parsed['jobs'];
  if (jobs && typeof jobs === 'object') {
    for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
      if (!jobDef || typeof jobDef !== 'object') continue;
      const job = jobDef as Record<string, unknown>;
      pushEnv(job['env'], `job "${jobId}"`);
      const steps = job['steps'];
      if (Array.isArray(steps)) {
        for (let i = 0; i < steps.length; i++) {
          const step = steps[i];
          if (step && typeof step === 'object') {
            pushEnv((step as Record<string, unknown>)['env'], `job "${jobId}" step ${i + 1}`);
          }
        }
      }
    }
  }

  return scopes;
}

export const insecureCommandsCheck: CheckDefinition = {
  id: 'injection/insecure-commands',
  name: 'Deprecated insecure workflow commands enabled',
  description:
    'Detects ACTIONS_ALLOW_UNSECURE_COMMANDS, which re-enables the deprecated set-env/add-path commands disabled by GitHub for CVE-2020-15228.',
  category: 'injection',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const scope of collectEnvScopes(workflow.parsed)) {
        if (!(TARGET_KEY in scope.env)) continue;
        if (!isTruthy(scope.env[TARGET_KEY])) continue;

        findings.push({
          checkId: 'injection/insecure-commands',
          severity: 'high',
          category: 'injection',
          title: `Insecure workflow commands enabled (${scope.where})`,
          description:
            `Workflow "${workflow.name}" sets \`${TARGET_KEY}: true\` at the ${scope.where} level. ` +
            'This re-enables the deprecated `::set-env::` and `::add-path::` stdout workflow commands.',
          risk:
            'GitHub disabled these commands by default (CVE-2020-15228) because any step that prints attacker-controlled text to stdout could inject environment variables and PATH entries. ' +
            'With this flag on, a log line like `::set-env name=LD_PRELOAD::/tmp/evil.so` emitted from untrusted build output silently rewrites the environment for later steps, leading to code execution.',
          remediation:
            'Remove the flag and migrate any remaining `set-env`/`add-path` usage to the environment files:\n\n' +
            '```yaml\n' +
            '# Remove this:\n' +
            'env:\n' +
            `  ${TARGET_KEY}: true\n\n` +
            '# Replace set-env / add-path with the env files:\n' +
            '- run: |\n' +
            '    echo "MY_VAR=value" >> "$GITHUB_ENV"\n' +
            '    echo "/opt/tool/bin" >> "$GITHUB_PATH"\n' +
            '```\n\n' +
            'Treat any value derived from untrusted input as dangerous even with the env files (see the github-env check).',
          file: workflow.path,
          line: findLineNumber(workflow.content, TARGET_KEY),
          evidence: `${TARGET_KEY}: ${String(scope.env[TARGET_KEY])} (${scope.where})`,
        });
      }
    }

    return findings;
  },
};
