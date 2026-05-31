import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * secrets/unredacted-secrets
 *
 * Detects `fromJSON(secrets.X)` (and `fromJSON(secrets)`), which decodes a
 * secret inside an expression. GitHub's log redaction matches the literal
 * secret value; once a secret is JSON-parsed, the decoded fields are new
 * strings the runner never registered as secrets, so they print to logs
 * unredacted.
 */

const FROMJSON_SECRETS = /\$\{\{[^}]*\bfromJSON\(\s*secrets(?:\.[A-Za-z0-9_]+)?\s*\)[^}]*\}\}/g;

export const unredactedSecretsCheck: CheckDefinition = {
  id: 'secrets/unredacted-secrets',
  name: 'Secret decoded past log redaction',
  description:
    'Detects fromJSON(secrets.X), which decodes a secret into values GitHub no longer redacts in logs.',
  category: 'secrets-exposure',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      const content = workflow.content;
      const seen = new Set<string>();
      FROMJSON_SECRETS.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = FROMJSON_SECRETS.exec(content)) !== null) {
        const evidence = m[0];
        if (seen.has(evidence)) continue;
        seen.add(evidence);

        findings.push({
          checkId: 'secrets/unredacted-secrets',
          severity: 'medium',
          category: 'secrets-exposure',
          title: 'Secret JSON-decoded, bypassing log redaction',
          description:
            `Workflow "${workflow.name}" uses \`${evidence}\`. Decoding a secret with \`fromJSON\` produces values that GitHub\'s log masking does not recognize.`,
          risk:
            'GitHub redacts logs by matching the registered secret string. The fields produced by `fromJSON(secrets.X)` are freshly derived strings, so if any of them is echoed, passed to a verbose tool, or appears in an error, it prints in clear text. ' +
            'This is a common way structured secrets (JSON service-account keys, multi-field credentials) leak despite redaction.',
          remediation:
            'Avoid decoding secrets inside expressions. If you need structured secret data, store each field as its own secret, or decode it inside a step from an env var (where the value stays a registered secret):\n\n' +
            '```yaml\n' +
            '- env:\n' +
            '    SA_KEY: ${{ secrets.GCP_SA_KEY }}\n' +
            '  run: |\n' +
            '    # parse from the env var at runtime; do not interpolate fromJSON(secrets...)\n' +
            '    echo "$SA_KEY" | jq -r .client_email > /dev/null\n' +
            '```',
          file: workflow.path,
          line: findLineNumber(content, evidence),
          evidence,
        });
      }
    }

    return findings;
  },
};
