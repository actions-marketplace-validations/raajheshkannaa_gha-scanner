import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * triggers/confused-deputy-automerge
 *
 * Detects the confused-deputy auto-merge pattern: a privileged-trigger
 * workflow (`pull_request_target` / `workflow_run`) that gates on the
 * actor being a bot and then auto-merges or auto-approves the PR, without
 * verifying the update with `dependabot/fetch-metadata` or checking that
 * the PR head is not a fork. An attacker can arrange for the trusted bot
 * to be the triggering actor while their fork PR is what gets merged with
 * the base repo's elevated permissions.
 */

const PRIVILEGED_TRIGGERS = ['pull_request_target', 'workflow_run'];

const BOT_ACTOR_GATE =
  /(?:github\.(?:triggering_)?actor|github\.event\.pull_request\.sender\.login)\s*==\s*['"][^'"]*\[bot\]['"]/;

const MERGE_SIGNALS = [
  /\bgh\s+pr\s+merge\b/,
  /\bgh\s+pr\s+review\s+[^\n]*--approve\b/,
  /pascalgn\/automerge-action/,
  /peter-evans\/enable-pull-request-automerge/,
  /hmarr\/auto-approve-action/,
  /alexwilson\/enable-github-automerge-action/,
];

// A guard only counts as "safe" when it is an ACTUAL non-fork / metadata
// check, not merely a reference to a fork-related field (which could be
// logging). Bare substring presence is not enough.
const FORK = 'github\\.event\\.pull_request\\.head\\.repo\\.fork';
const FULL_NAME = 'github\\.event\\.pull_request\\.head\\.repo\\.full_name';
const SAFE_SIGNALS = [
  /dependabot\/fetch-metadata/,
  new RegExp(`${FORK}\\s*==\\s*false`),
  new RegExp(`false\\s*==\\s*${FORK}`),
  new RegExp(`${FORK}\\s*!=\\s*true`),
  new RegExp(`true\\s*!=\\s*${FORK}`),
  new RegExp(`!\\s*${FORK}\\b`),
  // head.repo.full_name == github.repository (either operand order) is the
  // canonical "same-repo, not a fork" guard. Only `==` proves same-repo; `!=`
  // would mean "is a fork", which is not a safety guard.
  new RegExp(`${FULL_NAME}\\s*==\\s*github\\.repository`),
  new RegExp(`github\\.repository\\s*==\\s*${FULL_NAME}`),
];

function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

export const confusedDeputyAutomergeCheck: CheckDefinition = {
  id: 'triggers/confused-deputy-automerge',
  name: 'Bot-gated auto-merge on a privileged trigger',
  description:
    'Detects auto-merge/approve gated only on a bot actor under pull_request_target/workflow_run, without fetch-metadata or a fork check.',
  category: 'dangerous-triggers',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      const triggers = getTriggers(workflow.parsed);
      const privileged = triggers.filter((t) => PRIVILEGED_TRIGGERS.includes(t));
      if (privileged.length === 0) continue;

      const jobs = workflow.parsed['jobs'];
      if (!jobs || typeof jobs !== 'object') continue;

      // Scope detection to a single job: the bot gate, the merge command, and
      // the safety signal (fetch-metadata / fork check) must co-occur in the
      // SAME job. A guard in an unrelated job must not suppress a real finding.
      for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
        if (!jobDef || typeof jobDef !== 'object') continue;
        const jobText = safeStringify(jobDef);

        if (!BOT_ACTOR_GATE.test(jobText)) continue;
        if (!MERGE_SIGNALS.some((re) => re.test(jobText))) continue;
        if (SAFE_SIGNALS.some((re) => re.test(jobText))) continue; // properly guarded in this job

        const mergeSignal = MERGE_SIGNALS.map((re) => jobText.match(re)?.[0]).find(Boolean) ?? 'auto-merge';

        findings.push({
          checkId: 'triggers/confused-deputy-automerge',
          severity: 'high',
          category: 'dangerous-triggers',
          title: `Bot-gated auto-merge on a privileged trigger in job "${jobId}"`,
          description:
            `Workflow "${workflow.name}" runs on a privileged trigger (${privileged.join(', ')}), and job "${jobId}" ` +
            `gates on the actor being a bot, and auto-merges/approves (${mergeSignal}) without verifying the update with \`dependabot/fetch-metadata\` or checking the PR head fork.`,
          risk:
            'This is the confused-deputy pattern. `github.actor` reflects who triggered the run, not who wrote the code. An attacker can get a trusted bot to re-trigger the workflow (or chain through `workflow_run`) so the actor check passes while their fork PR is the one merged, with the base repo\'s write permissions and secrets. Dependabot-targeted variants of this have been used to auto-merge malicious PRs.',
          remediation:
            'Verify the PR with Dependabot metadata and confirm it is not a fork before merging:\n\n' +
            '```yaml\n' +
            '    steps:\n' +
            '      - id: meta\n' +
            '        uses: dependabot/fetch-metadata@v2\n' +
            '      - if: >-\n' +
            "          github.event.pull_request.user.login == 'dependabot[bot]' &&\n" +
            "          steps.meta.outputs.update-type == 'version-update:semver-patch'\n" +
            '        run: gh pr merge --auto --squash "$PR_URL"\n' +
            '```\n\n' +
            'Gate on `github.event.pull_request.user.login` (the author), not `github.actor`, and prefer `pull_request` over `pull_request_target` where possible.',
          file: workflow.path,
          line: findLineNumber(workflow.content, mergeSignal) ?? 1,
          evidence: `job "${jobId}": privileged trigger + bot-actor gate + ${mergeSignal}; no fetch-metadata/fork check`,
        });
      }
    }

    return findings;
  },
};
