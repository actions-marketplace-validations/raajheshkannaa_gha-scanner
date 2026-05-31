import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * supply-chain/unverified-remote-exec
 *
 * Detects `run:` steps that download a script over the network and pipe it
 * straight into an interpreter (`curl ... | bash`, `wget ... | sh`,
 * `iwr ... | iex`, `python <(curl ...)`). There is no integrity check, so
 * whoever controls (or hijacks, or MITMs) the remote host gets code
 * execution in CI with the repository checkout and secrets. This is a
 * supply chain hole equivalent to running an unpinned action.
 */

const PATTERNS: { re: RegExp; label: string }[] = [
  { re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)\b/i, label: 'curl/wget | shell' },
  { re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b/i, label: 'curl/wget | interpreter' },
  { re: /\b(?:iwr|invoke-webrequest|curl)\b[^\n|]*\|\s*(?:iex|invoke-expression)\b/i, label: 'iwr | iex' },
  { re: /\b(?:bash|sh|python3?|perl)\b[^\n]*<\(\s*(?:curl|wget)\b/i, label: 'process substitution from curl/wget' },
  { re: /\bdeno\s+run\s+[^\n]*https?:\/\//i, label: 'deno run <url>' },
];

function getRunSteps(parsed: Record<string, unknown>): Array<{ run: string; jobId: string }> {
  const out: Array<{ run: string; jobId: string }> = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;
  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const steps = (jobDef as Record<string, unknown>)['steps'];
    if (!Array.isArray(steps)) continue;
    for (const step of steps) {
      if (step && typeof step === 'object' && typeof (step as Record<string, unknown>)['run'] === 'string') {
        out.push({ run: (step as Record<string, unknown>)['run'] as string, jobId });
      }
    }
  }
  return out;
}

export const unverifiedRemoteExecCheck: CheckDefinition = {
  id: 'supply-chain/unverified-remote-exec',
  name: 'Unverified remote script execution',
  description:
    'Detects piping a network download directly into an interpreter (curl | bash and similar) with no integrity verification.',
  category: 'supply-chain',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const { run, jobId } of getRunSteps(workflow.parsed)) {
        const hit = PATTERNS.find((p) => p.re.test(run));
        if (!hit) continue;

        const line = run.split('\n').find((l) => hit.re.test(l))?.trim() ?? hit.label;

        findings.push({
          checkId: 'supply-chain/unverified-remote-exec',
          severity: 'medium',
          category: 'supply-chain',
          title: `Remote script piped into an interpreter in job "${jobId}"`,
          description:
            `Workflow "${workflow.name}" job "${jobId}" downloads a script over the network and executes it directly (${hit.label}). ` +
            'The fetched content is run without any checksum or signature verification.',
          risk:
            'There is no integrity check between download and execution. If the remote host is compromised, hijacked (expired domain, account takeover), or MITM-able, it serves attacker code that runs in CI with the checkout and the GITHUB_TOKEN. ' +
            'Even reputable installer URLs are a standing single point of failure for your pipeline.',
          remediation:
            'Download, verify, then execute as separate steps:\n\n' +
            '```yaml\n' +
            '- run: |\n' +
            '    curl -fsSL -o install.sh https://example.com/install.sh\n' +
            '    echo "<known-sha256>  install.sh" | sha256sum -c -\n' +
            '    bash install.sh\n' +
            '```\n\n' +
            'Better, pin to a specific released artifact by digest, or use a SHA-pinned action that vendors the tool.',
          file: workflow.path,
          line: findLineNumber(workflow.content, line.slice(0, 40)),
          evidence: line.slice(0, 120),
        });
      }
    }

    return findings;
  },
};
