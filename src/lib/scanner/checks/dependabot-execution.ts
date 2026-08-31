import type { CheckDefinition, Finding, RepoContext } from '../types';

/**
 * supply-chain/dependabot-execution
 *
 * Detects `insecure-external-code-execution: allow` in a Dependabot
 * configuration. For ecosystems that run manifest code during dependency
 * resolution (e.g. bundler, mix, pip with setup.py), this opt-in lets a
 * malicious transitive dependency execute arbitrary code inside the
 * Dependabot update job, which has access to the repository and its
 * Dependabot secrets.
 */

export const dependabotExecutionCheck: CheckDefinition = {
  id: 'supply-chain/dependabot-execution',
  name: 'Dependabot insecure external code execution',
  description:
    'Detects `insecure-external-code-execution: allow` in dependabot.yml, which permits manifest code execution during dependency resolution.',
  category: 'supply-chain',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];
    const config = context.dependabotConfig;
    if (!config) return findings;

    const updates = config['updates'];
    if (!Array.isArray(updates)) return findings;

    for (let i = 0; i < updates.length; i++) {
      const entry = updates[i];
      if (!entry || typeof entry !== 'object') continue;
      const value = (entry as Record<string, unknown>)['insecure-external-code-execution'];
      if (value !== 'allow') continue;

      const ecosystem = String((entry as Record<string, unknown>)['package-ecosystem'] ?? 'unknown');
      findings.push({
        checkId: 'supply-chain/dependabot-execution',
        severity: 'high',
        category: 'supply-chain',
        title: `Dependabot allows insecure external code execution (${ecosystem})`,
        description:
          `The Dependabot update for the \`${ecosystem}\` ecosystem sets \`insecure-external-code-execution: allow\`. ` +
          'This lets dependency manifests execute code during Dependabot\'s resolution step.',
        risk:
          'With external code execution allowed, a malicious or compromised (transitive) dependency can run arbitrary code inside the Dependabot job. ' +
          'That job can read the repository contents and any Dependabot secrets, turning a dependency update into a code-execution and secret-exfiltration vector.',
        remediation:
          'Remove the override (the secure default is `deny`):\n\n' +
          '```yaml\n' +
          'updates:\n' +
          `  - package-ecosystem: "${ecosystem}"\n` +
          '    directory: "/"\n' +
          '    schedule:\n' +
          '      interval: "weekly"\n' +
          '    # do NOT set insecure-external-code-execution: allow\n' +
          '```',
        file: '.github/dependabot.yml',
        evidence: `updates[${i}].insecure-external-code-execution: allow (ecosystem: ${ecosystem})`,
      });
    }

    return findings;
  },
};
