import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * runner/hardcoded-container-credentials
 *
 * Detects literal (non-expression) registry credentials on job
 * `container.credentials` and `services.<id>.credentials`. A password or
 * token written directly into the workflow YAML is committed to the
 * repository in plaintext, visible to anyone with read access and to the
 * full git history forever. Credentials belong in `${{ secrets.* }}`.
 */

const EXPRESSION_RE = /\$\{\{[^}]*\}\}/;
const CREDENTIAL_KEYS = ['password', 'username'];

interface CredFinding {
  where: string;
  key: string;
  value: string;
}

function getCredentials(def: unknown): Record<string, unknown> | null {
  if (!def || typeof def !== 'object' || Array.isArray(def)) return null;
  const creds = (def as Record<string, unknown>)['credentials'];
  if (!creds || typeof creds !== 'object' || Array.isArray(creds)) return null;
  return creds as Record<string, unknown>;
}

function collectHardcoded(parsed: Record<string, unknown>): CredFinding[] {
  const out: CredFinding[] = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;

  const inspect = (creds: Record<string, unknown> | null, where: string) => {
    if (!creds) return;
    for (const key of CREDENTIAL_KEYS) {
      const value = creds[key];
      if (typeof value !== 'string') continue;
      if (value.trim() === '') continue;
      if (EXPRESSION_RE.test(value)) continue; // sourced from a secret/expression
      // username alone is low-risk; only report it if a literal password is also present.
      if (key === 'username' && !(typeof creds['password'] === 'string' && !EXPRESSION_RE.test(creds['password'] as string))) {
        continue;
      }
      out.push({ where, key, value });
    }
  };

  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const job = jobDef as Record<string, unknown>;

    inspect(getCredentials(job['container']), `job "${jobId}" container`);

    const services = job['services'];
    if (services && typeof services === 'object' && !Array.isArray(services)) {
      for (const [svcId, svcDef] of Object.entries(services as Record<string, unknown>)) {
        inspect(getCredentials(svcDef), `job "${jobId}" service "${svcId}"`);
      }
    }
  }
  return out;
}

export const hardcodedContainerCredentialsCheck: CheckDefinition = {
  id: 'runner/hardcoded-container-credentials',
  name: 'Hardcoded container registry credentials',
  description:
    'Detects literal username/password values on container or service credentials instead of ${{ secrets.* }} references.',
  category: 'runner-security',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      const seen = new Set<string>();
      for (const cred of collectHardcoded(workflow.parsed)) {
        const dedupeKey = `${cred.where}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        findings.push({
          checkId: 'runner/hardcoded-container-credentials',
          severity: 'high',
          category: 'runner-security',
          title: `Hardcoded registry credentials in ${cred.where}`,
          description:
            `Workflow "${workflow.name}" sets container registry credentials as a literal value in ${cred.where}. ` +
            'The credential is stored in plaintext in the workflow file and its entire git history.',
          risk:
            'A hardcoded registry password or token is readable by anyone with repository read access (everyone, for public repos) and is permanently recorded in git history even after removal. ' +
            'Leaked registry credentials let an attacker pull private images or push malicious ones that your CI then runs.',
          remediation:
            'Move the credential into an encrypted secret and reference it:\n\n' +
            '```yaml\n' +
            'jobs:\n' +
            '  build:\n' +
            '    container:\n' +
            '      image: ghcr.io/acme/ci:1.2.3\n' +
            '      credentials:\n' +
            '        username: ${{ secrets.REGISTRY_USER }}\n' +
            '        password: ${{ secrets.REGISTRY_TOKEN }}\n' +
            '```\n\n' +
            'Then rotate the exposed credential, since it must be considered compromised, and purge it from history if feasible.',
          file: workflow.path,
          line: findLineNumber(workflow.content, 'credentials'),
          evidence: `${cred.where}: ${cred.key} set to a literal value`,
        });
      }
    }

    return findings;
  },
};
