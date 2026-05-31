import type { CheckDefinition, Finding, RepoContext } from '../types';

/**
 * secrets/overprovisioned-secrets
 *
 * Detects use of the entire `secrets` context at once, via
 * `${{ toJSON(secrets) }}` or the bare `${{ secrets }}` object. Both
 * serialize every secret in the repository/environment into one value,
 * which is almost always passed to a step, action, or env var that needs
 * only one of them. This maximizes exposure: a single sink (a log, a
 * compromised action, a crash dump) leaks the full secret set.
 */

const TOJSON_SECRETS = /\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}/gi;
const BARE_SECRETS = /\$\{\{\s*secrets\s*\}\}/g;

export const overprovisionedSecretsCheck: CheckDefinition = {
  id: 'secrets/overprovisioned-secrets',
  name: 'Whole secrets context exposed',
  description:
    'Detects ${{ toJSON(secrets) }} or the bare ${{ secrets }} context, which serializes every secret into one value.',
  category: 'secrets-exposure',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      const content = workflow.content;
      const seenIndexes = new Set<number>();

      const scan = (re: RegExp, label: string) => {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          if (seenIndexes.has(m.index)) continue;
          seenIndexes.add(m.index);

          // Map the match offset to a 1-based line directly, so two identical
          // expressions on different lines are reported separately.
          const line = content.slice(0, m.index).split('\n').length;

          findings.push({
            checkId: 'secrets/overprovisioned-secrets',
            severity: 'high',
            category: 'secrets-exposure',
            title: `Entire secrets context exposed via ${label}`,
            description:
              `Workflow "${workflow.name}" references \`${m[0]}\`, which expands every secret available to the workflow into a single value. ` +
              'Consumers of that value receive secrets they do not need.',
            risk:
              'Serializing the whole secrets context means one leak point exposes all credentials at once. ' +
              'If the value reaches a third-party action, a log line, an artifact, or a crash dump, every secret is compromised together rather than just the one a step required. ' +
              'It also defeats per-secret auditing of which workflow uses which credential.',
            remediation:
              'Reference only the specific secrets a step needs:\n\n' +
              '```yaml\n' +
              '# Instead of:\n' +
              '- env:\n' +
              '    ALL: ${{ toJSON(secrets) }}\n\n' +
              '# Use named secrets:\n' +
              '- env:\n' +
              '    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n' +
              '    AWS_ROLE: ${{ secrets.AWS_ROLE_ARN }}\n' +
              '```',
            file: workflow.path,
            line: line || undefined,
            evidence: m[0],
          });
        }
      };

      scan(TOJSON_SECRETS, 'toJSON(secrets)');
      scan(BARE_SECRETS, 'the bare secrets context');
    }

    return findings;
  },
};
