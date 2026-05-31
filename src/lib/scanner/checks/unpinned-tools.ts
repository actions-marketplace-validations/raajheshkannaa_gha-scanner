import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * supply-chain/unpinned-tools
 *
 * Detects setup actions that fetch an external tool at runtime via a
 * `version:` input that is unpinned (missing, `latest`, or a dynamic
 * expression). Even when the action itself is SHA-pinned, an unpinned
 * `version` lets the action pull a mutable, attacker-influenceable tool
 * build into the job. Mirrors zizmor's narrow `unpinned-tools` scope.
 */

const TOOL_ACTIONS = ['aquasecurity/setup-trivy', '1password/load-secrets-action'];
const EXPRESSION_RE = /\$\{\{[^}]*\}\}/;

function actionMatches(uses: string): string | null {
  const path = uses.split('@')[0].toLowerCase();
  return TOOL_ACTIONS.find((a) => path === a) ?? null;
}

export const unpinnedToolsCheck: CheckDefinition = {
  id: 'supply-chain/unpinned-tools',
  name: 'Unpinned external tool version',
  description:
    'Detects setup actions whose version input is missing, latest, or dynamic, pulling a mutable external tool build at runtime.',
  category: 'supply-chain',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;
      const jobs = workflow.parsed['jobs'];
      if (!jobs || typeof jobs !== 'object') continue;

      for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
        if (!jobDef || typeof jobDef !== 'object') continue;
        const steps = (jobDef as Record<string, unknown>)['steps'];
        if (!Array.isArray(steps)) continue;

        for (const step of steps) {
          if (!step || typeof step !== 'object') continue;
          const uses = (step as Record<string, unknown>)['uses'];
          if (typeof uses !== 'string') continue;
          const action = actionMatches(uses);
          if (!action) continue;

          const withBlock = (step as Record<string, unknown>)['with'];
          const version =
            withBlock && typeof withBlock === 'object'
              ? (withBlock as Record<string, unknown>)['version']
              : undefined;

          let reason: string | null = null;
          if (version === undefined) reason = 'no `version` input (defaults to the latest tool build)';
          else if (typeof version === 'string' && version.trim().toLowerCase() === 'latest') reason = '`version: latest`';
          else if (typeof version === 'string' && EXPRESSION_RE.test(version)) reason = 'a dynamic `version` expression';

          if (!reason) continue;

          findings.push({
            checkId: 'supply-chain/unpinned-tools',
            severity: 'medium',
            category: 'supply-chain',
            title: `Unpinned tool version for ${action} in job "${jobId}"`,
            description:
              `Workflow "${workflow.name}" uses \`${action}\` with ${reason}. The action fetches an external tool build that is not pinned to a fixed version.`,
            risk:
              'An unpinned tool version resolves at runtime to whatever the upstream currently serves. ' +
              'A compromised or rolled tool release runs inside your job even though the action reference itself is pinned, reintroducing the supply chain risk you closed by SHA-pinning the action.',
            remediation:
              `Pin the tool to a specific version:\n\n` +
              '```yaml\n' +
              `- uses: ${action}@<sha>\n` +
              '  with:\n' +
              '    version: v0.50.0   # pin to a fixed release\n' +
              '```',
            file: workflow.path,
            line: findLineNumber(workflow.content, uses),
            evidence: `${action}: ${reason}`,
          });
        }
      }
    }

    return findings;
  },
};
