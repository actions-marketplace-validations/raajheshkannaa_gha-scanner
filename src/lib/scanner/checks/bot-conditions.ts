import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * triggers/bot-conditions
 *
 * Detects job/step `if:` gates that trust a bot purely by comparing
 * `github.actor` (or `github.triggering_actor`) to a bot login such as
 * `dependabot[bot]`. `github.actor` reflects who triggered the current
 * run, not who authored the code being run. On `pull_request_target` and
 * `workflow_run`, an attacker's fork code can execute while `actor`
 * resolves to the bot, so an actor-equals-bot gate is not a real trust
 * boundary. The correct signal is the PR author plus a fork check, or
 * `dependabot/fetch-metadata`.
 */

// Spoofable name contexts zizmor flags: github.actor, github.triggering_actor,
// and github.event.pull_request.sender.login.
//
// Only positive (`==`) comparisons are flagged: `actor == 'x[bot]'` GRANTS
// trust to the bot and is the confused-deputy risk. An `actor != 'x[bot]'`
// gate excludes the bot and is not this issue, so it is intentionally not
// matched.
const ACTOR_CTX =
  '(?:github\\.(?:triggering_)?actor|github\\.event\\.pull_request\\.sender\\.login)';
const BOT_ACTOR_RE = new RegExp(`${ACTOR_CTX}\\s*==\\s*['"][^'"]*\\[bot\\]['"]`);
// Also catch the reversed comparison: 'dependabot[bot]' == github.actor
const BOT_ACTOR_RE_REV = new RegExp(`['"][^'"]*\\[bot\\]['"]\\s*==\\s*${ACTOR_CTX}`);

function matchesBotActor(expr: string): boolean {
  return BOT_ACTOR_RE.test(expr) || BOT_ACTOR_RE_REV.test(expr);
}

// The spoofable-actor risk only matters on triggers where the triggering
// actor can differ from the code author (fork-reachable / privileged events).
// On push / pull_request, an actor-based bot gate is harmless special-casing.
const PRIVILEGED_TRIGGERS = [
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'discussion_comment',
];

function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

function ifToString(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  return null;
}

interface Conditioned {
  expr: string;
  where: string;
}

function collectConditions(parsed: Record<string, unknown>): Conditioned[] {
  const out: Conditioned[] = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;

  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const job = jobDef as Record<string, unknown>;

    const jobIf = ifToString(job['if']);
    if (jobIf) out.push({ expr: jobIf, where: `job "${jobId}"` });

    const steps = job['steps'];
    if (Array.isArray(steps)) {
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        if (!step || typeof step !== 'object') continue;
        const stepIf = ifToString((step as Record<string, unknown>)['if']);
        if (stepIf) out.push({ expr: stepIf, where: `job "${jobId}" step ${i + 1}` });
      }
    }
  }
  return out;
}

export const botConditionsCheck: CheckDefinition = {
  id: 'triggers/bot-conditions',
  name: 'Spoofable bot actor condition',
  description:
    'Detects if: conditions that trust a bot solely via github.actor / github.triggering_actor equality, which is not a reliable trust boundary on privileged triggers.',
  category: 'dangerous-triggers',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      // Only flag on triggers where github.actor can diverge from the author.
      const triggers = getTriggers(workflow.parsed);
      if (!triggers.some((t) => PRIVILEGED_TRIGGERS.includes(t))) continue;

      for (const cond of collectConditions(workflow.parsed)) {
        if (!matchesBotActor(cond.expr)) continue;

        const evidence = `if: ${cond.expr.trim().split('\n')[0]}`;
        findings.push({
          checkId: 'triggers/bot-conditions',
          severity: 'high',
          category: 'dangerous-triggers',
          title: `Bot trust gated on github.actor in ${cond.where}`,
          description:
            `Workflow "${workflow.name}" gates ${cond.where} on a \`github.actor\`/\`github.triggering_actor\` comparison to a bot login. ` +
            '`github.actor` identifies who triggered the run, not who wrote the code that runs. It can resolve to a trusted bot while attacker-controlled fork code executes.',
          risk:
            'On `pull_request_target` and `workflow_run`, an attacker can arrange for a trusted bot (e.g. dependabot) to be the triggering actor while their fork code is what actually runs. ' +
            'An actor-equals-bot gate then passes and grants the run the base repo\'s permissions and secrets. This is the confused-deputy pattern behind several auto-merge exploits.',
          remediation:
            'Do not treat `github.actor` as an authorization boundary. For Dependabot, verify the update with its official metadata action:\n\n' +
            '```yaml\n' +
            'jobs:\n' +
            '  automerge:\n' +
            '    runs-on: ubuntu-latest\n' +
            '    if: github.event.pull_request.user.login == \'dependabot[bot]\'\n' +
            '    steps:\n' +
            '      - id: meta\n' +
            '        uses: dependabot/fetch-metadata@v2\n' +
            '      # Then gate on steps.meta.outputs (update-type, dependency-names)\n' +
            '```\n\n' +
            'Also confirm `github.event.pull_request.head.repo.fork == false` before any privileged action.',
          file: workflow.path,
          line: findLineNumber(workflow.content, cond.expr.trim().split('\n')[0]),
          evidence,
        });
      }
    }

    return findings;
  },
};
