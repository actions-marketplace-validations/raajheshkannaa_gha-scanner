import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * supply-chain/cache-poisoning
 *
 * Detects the May 2026 TanStack / Mini Shai-Hulud pattern: a fork-reachable
 * workflow saves a cache entry that a later trusted workflow restores via
 * overlapping restore-keys, executing attacker-controlled code with the
 * trusted workflow's secrets and OIDC tokens.
 *
 * Four sub-rules:
 *   1. Cross-workflow cache sharing where fork-reachable and trusted sides
 *      share path + a colliding key/restore-key prefix (HIGH).
 *   2. Same workflow on both fork-reachable and trusted triggers, with cache
 *      keys NOT trust-namespaced (MEDIUM). Trust-namespaced configs are
 *      suppressed — see hasTrustNamespacing().
 *   3. Cache key in a fork-reachable workflow contains attacker-controlled
 *      expressions or PR-controlled hashFiles globs (MEDIUM standalone, HIGH
 *      auto-paired with rule 1 in the same workflow).
 *   4. actions/cache/save in a fork-reachable workflow without an explicit
 *      fork-bound namespace in the key (HIGH).
 *
 * Known limitations (surfaced in findings):
 *   - Composite actions wrapping actions/cache are not analyzed.
 *   - Runtime-resolved keys (variables, outputs from earlier steps) cannot
 *     be statically resolved beyond literal expressions and hashFiles().
 *   - Reusable workflows (workflow_call only) are skipped — their trust
 *     classification comes from the parent caller.
 */

export const FORK_REACHABLE_TRIGGERS: ReadonlyArray<string> = [
  'pull_request_target',
  'pull_request',
  'issue_comment',
];

export const TRUSTED_TRIGGERS: ReadonlyArray<string> = [
  'push',
  'release',
  'schedule',
  'workflow_dispatch',
];

export const CACHE_ACTIONS: ReadonlyArray<string> = [
  'actions/cache',
  'actions/cache/save',
  'actions/cache/restore',
];

const ATTACKER_CONTROLLED_EXPRS: ReadonlyArray<string> = [
  'github.event.pull_request.head.ref',
  'github.event.pull_request.head.sha',
  'github.event.pull_request.head.label',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.comment.body',
  'github.event.comment.id',
  'github.head_ref',
];

// Expressions that ONLY render in a fork-reachable trigger context. On a
// push/release run these resolve to empty/null, so a key containing them
// becomes structurally different from a key on the fork side. That makes
// them trigger-disjoint (not just per-run-unique).
const FORK_ONLY_EXPRS: ReadonlyArray<string> = [
  'github.event.pull_request.number',
  'github.event.issue.number',
  'github.event.comment.id',
  'github.event.pull_request.head.sha',
  'github.event.pull_request.head.ref',
];

// Expressions that distinguish runs but NOT triggers. github.run_id is
// unique per run but appears in BOTH push runs and PR runs, so a key built
// only from run_id can still collide across triggers.
const RUN_SCOPE_EXPRS: ReadonlyArray<string> = [
  'github.run_id',
  'github.event.workflow_run.id',
];

// Expressions that reliably distinguish the trigger event itself. Only
// these qualify a key as `trigger-aware` for cross-trigger isolation
// purposes. `github.event_name` is the canonical one; equivalents that
// always render the trigger name (e.g. `github.event.action` for issue
// events) could go here too, but only if they truly disambiguate the
// trigger and never collide across triggers.
//
// NOT included (and why):
//   - `github.ref_protected`, `github.ref_type`: describe the ref, not the
//     trigger. A push to a protected branch and a PR targeting the same
//     protected branch both render `github.ref_protected == true`.
//   - `github.ref`: branch/tag identifier, not trigger-discriminating.
const TRIGGER_AWARE_EXPRS: ReadonlyArray<string> = [
  'github.event_name',
];

const TRUST_NAMESPACE_LITERAL_PREFIXES: ReadonlyArray<string> = [
  'pr-',
  'pull-',
  'fork-',
  'trusted-',
  'release-',
  'push-',
  'main-',
  'production-',
];

const PR_CONTROLLED_HASHFILES_GLOBS = [
  '**/package.json',
  '**/package-lock.json',
  '**/pnpm-lock.yaml',
  '**/yarn.lock',
  '**/requirements*.txt',
  '**/pyproject.toml',
  '**/poetry.lock',
  '**/Gemfile.lock',
  '**/go.sum',
  '**/Cargo.lock',
  '**/composer.lock',
  '**/*.lock',
];

export type TrustClass = 'fork-reachable' | 'trusted' | 'mixed' | 'reusable-only' | 'none';

export interface CacheStep {
  workflowPath: string;
  workflowName: string;
  workflowContent: string;
  triggers: string[];
  trustClass: TrustClass;
  path: string;
  key: string;
  restoreKeys: string[];
  action: string;
  usesLine: string;
  keyLine?: number;
}

export function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

export function classifyTriggers(triggers: string[]): TrustClass {
  if (triggers.length === 1 && triggers[0] === 'workflow_call') return 'reusable-only';
  const hasFork = triggers.some(t => FORK_REACHABLE_TRIGGERS.includes(t));
  const hasTrusted = triggers.some(t => TRUSTED_TRIGGERS.includes(t));
  if (hasFork && hasTrusted) return 'mixed';
  if (hasFork) return 'fork-reachable';
  if (hasTrusted) return 'trusted';
  // workflow_run alone: classify as 'trusted' by default. classifyWorkflow()
  // promotes this to 'fork-reachable' when the parent workflow it watches
  // is itself fork-triggered. classifyTriggers() has no cross-workflow
  // context, so it returns the conservative default.
  if (triggers.includes('workflow_run')) return 'trusted';
  return 'none';
}

/**
 * The names of workflows that a `workflow_run` trigger watches.
 * Returns empty array if not a workflow_run trigger.
 */
export function getWorkflowRunParents(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on || typeof on !== 'object' || Array.isArray(on)) return [];
  const wr = (on as Record<string, unknown>)['workflow_run'];
  if (!wr || typeof wr !== 'object' || Array.isArray(wr)) return [];
  const workflows = (wr as Record<string, unknown>)['workflows'];
  if (typeof workflows === 'string') return [workflows];
  if (Array.isArray(workflows)) return workflows.map(String);
  return [];
}

/**
 * Cross-workflow trust classification. A `workflow_run`-triggered workflow
 * inherits fork-reachability from its source workflows transitively: if
 * any source workflow it watches is itself fork-triggered, OR if any
 * source workflow is a `workflow_run` handler whose parent (recursively)
 * is fork-triggered, the handler runs on artifacts derived from a fork PR
 * and is effectively fork-reachable.
 *
 * Cycles are guarded via a visited set.
 *
 * For non-workflow_run workflows, this is identical to classifyTriggers().
 */
export function classifyWorkflowTrust(
  parsed: Record<string, unknown>,
  allWorkflows: Array<{ parsed: Record<string, unknown> | null; name: string }>,
  visited: Set<Record<string, unknown>> = new Set(),
): TrustClass {
  if (visited.has(parsed)) return classifyTriggers(getTriggers(parsed));
  visited.add(parsed);

  const triggers = getTriggers(parsed);
  const base = classifyTriggers(triggers);
  if (!triggers.includes('workflow_run')) return base;

  const parents = getWorkflowRunParents(parsed);
  if (parents.length === 0) return base;

  for (const wf of allWorkflows) {
    if (!wf.parsed) continue;
    if (visited.has(wf.parsed)) continue;
    // workflow_run can reference parent by name or by filename (no .yml).
    const parsedName = (wf.parsed['name'] ?? '') as string;
    const fileNameNoExt = wf.name.replace(/\.ya?ml$/, '');
    const matches = parents.some(
      p => p === parsedName || p === wf.name || p === fileNameNoExt,
    );
    if (!matches) continue;
    // Recurse so two-hop chains (CI fork-triggered → CD via workflow_run →
    // deploy via workflow_run) propagate fork-reachability correctly.
    const parentClass = classifyWorkflowTrust(wf.parsed, allWorkflows, visited);
    if (parentClass === 'fork-reachable' || parentClass === 'mixed') {
      return 'fork-reachable';
    }
  }
  return base;
}

/**
 * Extract literal "namespace" segment of a cache key — the leading text
 * before the first ${{ ... }} interpolation. Used to detect explicit
 * trust namespacing like "pr-${{ ... }}" or "trusted-${{ ... }}".
 */
export function extractLiteralNamespace(key: string): string {
  if (!key) return '';
  const exprIdx = key.indexOf('${{');
  const literal = exprIdx === -1 ? key : key.substring(0, exprIdx);
  return literal.trim();
}

/**
 * Returns the set of namespace categories a key carries explicitly:
 *   - "fork" if the key contains a fork-scope expression (pr number, issue
 *     number) or a fork literal prefix (pr-, fork-, pull-)
 *   - "trusted" if the key contains a trusted literal prefix (trusted-,
 *     release-, push-, main-, production-)
 *   - "trigger-aware" if the key contains github.event_name or similar
 *
 * These are computed conservatively — a key like "pnpm-${{ runner.os }}-"
 * has no namespace; "pr-${{ github.event.pull_request.number }}" has fork.
 */
export function keyNamespaces(key: string): Set<'fork' | 'trusted' | 'trigger-aware'> {
  const out = new Set<'fork' | 'trusted' | 'trigger-aware'>();
  if (!key) return out;
  const lower = key.toLowerCase();
  const literal = extractLiteralNamespace(key).toLowerCase();

  for (const expr of FORK_ONLY_EXPRS) {
    if (lower.includes(expr.toLowerCase())) out.add('fork');
  }
  // RUN_SCOPE_EXPRS deliberately not mapped to 'fork' — github.run_id et al.
  // exist in both fork and trusted runs and do not disambiguate triggers.
  for (const expr of TRIGGER_AWARE_EXPRS) {
    if (lower.includes(expr.toLowerCase())) out.add('trigger-aware');
  }
  for (const prefix of TRUST_NAMESPACE_LITERAL_PREFIXES) {
    if (!literal.startsWith(prefix)) continue;
    if (prefix.startsWith('pr-') || prefix.startsWith('pull-') || prefix.startsWith('fork-')) {
      out.add('fork');
    } else {
      out.add('trusted');
    }
  }
  return out;
}

/**
 * For a MIXED-trigger workflow (single workflow on both fork-reachable and
 * trusted triggers): does EVERY key (primary key + every restore-key)
 * carry a namespace that PROVABLY isolates fork-run cache writes from
 * trusted-run cache reads within this workflow?
 *
 * Critical: in a mixed-trigger workflow, BOTH fork and trusted runs
 * evaluate the SAME `key:` and `restore-keys:` expressions. The only way
 * to make them structurally disjoint is to interpolate something that
 * resolves DIFFERENTLY per trigger. The only built-in expression that
 * does that reliably is `github.event_name` (and a few related ones).
 *
 * Why static literal prefixes are NOT sufficient in mixed workflows:
 *   A key like `pr-${{ github.event.pull_request.number }}-${{ runner.os }}`
 *   in an `on: [pull_request, push]` workflow:
 *     - PR run renders: `pr-42-Linux`
 *     - push run renders: `pr--Linux`   (pull_request.number is empty)
 *   Both runs use a key starting with `pr-`, so a restore-key `pr-` on
 *   either side will hit the other side's cache. The literal prefix does
 *   NOT structurally isolate triggers.
 *
 * What IS sufficient:
 *   - `${{ github.event_name }}-...` (interpolated): renders `pull_request-...`
 *     vs `push-...`, structurally disjoint per trigger.
 *   - A ternary like `${{ github.event_name == 'pull_request' && 'pr-' || 'trusted-' }}`:
 *     renders different literal prefixes per trigger. (Detected via
 *     `trigger-aware` because it contains `github.event_name`.)
 *
 * For a PURE fork-reachable or PURE trusted workflow, the rule 1
 * cross-workflow check handles isolation between workflows; this function
 * is only called for the mixed case (see rule 2 caller).
 */
export function hasTrustNamespacing(step: CacheStep): boolean {
  const allKeys = [step.key, ...step.restoreKeys].filter(k => k && k.trim().length > 0);
  if (allKeys.length === 0) return false;

  // Per-key categories.
  const perKey: Array<Set<'fork' | 'trusted' | 'trigger-aware'>> = allKeys.map(k => keyNamespaces(k));

  // Every key must carry at least one category.
  if (perKey.some(cats => cats.size === 0)) return false;

  // In a mixed-trigger workflow, ONLY trigger-aware scoping isolates
  // triggers structurally. Every key must contain `github.event_name` or
  // an equivalent.
  return perKey.every(cats => cats.has('trigger-aware'));
}

/**
 * Returns true if the key (or any restore-key) interpolates an expression
 * that an attacker can fully control from a fork PR. hashFiles() over
 * PR-controlled paths counts.
 */
export function isAttackerControlled(key: string): { controlled: boolean; reason: string } {
  if (!key) return { controlled: false, reason: '' };
  const lower = key.toLowerCase();
  for (const expr of ATTACKER_CONTROLLED_EXPRS) {
    if (lower.includes(expr.toLowerCase())) {
      return { controlled: true, reason: `attacker-controlled expression: \`${expr}\`` };
    }
  }
  // hashFiles() over PR-controllable lockfiles. The attacker controls the
  // lockfile contents in their fork, so hashFiles() resolves deterministically.
  const hashFilesMatch = key.match(/hashFiles\(([^)]+)\)/i);
  if (hashFilesMatch) {
    const args = hashFilesMatch[1].toLowerCase();
    for (const glob of PR_CONTROLLED_HASHFILES_GLOBS) {
      if (args.includes(glob.toLowerCase())) {
        return {
          controlled: true,
          reason: `hashFiles() over PR-controlled path: \`${glob}\` (attacker can change the lockfile in their fork to pick the cache key)`,
        };
      }
    }
  }
  return { controlled: false, reason: '' };
}

/**
 * Determine whether two cache steps have overlapping cache namespaces that
 * could let a fork-side save be picked up by a trusted-side restore.
 *
 * Semantics, faithful to actions/cache behavior:
 *
 *   - A restore step looks up the exact `key:` first, then falls back to
 *     each `restore-keys:` entry in order. A restore-key matches any
 *     existing cache entry whose key STARTS WITH the restore-key string —
 *     no separator boundary required, because actions/cache itself does
 *     literal substring-from-start matching.
 *
 *   - Concretely, restore-key `pnpm-` matches cache key `pnpm-linux-abc`
 *     AND `pnpm-docs-linux` AND `pnpm-anything`. Devs sometimes intend
 *     `npm-docs-` to be a separate namespace from `npm-`, but actions/cache
 *     does not enforce that — a restore-key `npm-` will still hit a key
 *     `npm-docs-...`. That collision is a real vulnerability if one side
 *     is fork-reachable.
 *
 *   - "Namespace" here means the literal text of the key/restore-key with
 *     all `${{ ... }}` interpolations stripped to the first `${{`.
 *
 * Returns:
 *   - The colliding namespace string (the restore-key prefix or exact key
 *     literal that triggers the collision), or null if no overlap.
 *
 * Collision rules checked, in order:
 *   1. Exact namespace match: any literal namespace from side A equals any
 *      literal namespace from side B.
 *   2. Restore-key-from-A → key-on-B: any restore-key namespace from A is
 *      a prefix (in actions/cache's literal-start sense) of any key
 *      namespace from B.
 *   3. Restore-key-from-B → key-on-A: symmetric counterpart of rule 2.
 */
export function findColludingNamespace(a: CacheStep, b: CacheStep): string | null {
  const aAllKeys = [a.key, ...a.restoreKeys].filter(Boolean);
  const bAllKeys = [b.key, ...b.restoreKeys].filter(Boolean);
  const aRestoreOnly = a.restoreKeys.filter(Boolean);
  const bRestoreOnly = b.restoreKeys.filter(Boolean);

  const aNamespaces = new Set<string>();
  for (const k of aAllKeys) {
    const ns = extractLiteralNamespace(k);
    if (ns.length >= 2) aNamespaces.add(ns);
  }
  const bNamespaces = new Set<string>();
  for (const k of bAllKeys) {
    const ns = extractLiteralNamespace(k);
    if (ns.length >= 2) bNamespaces.add(ns);
  }

  // Rule 1: exact match.
  for (const ans of aNamespaces) {
    if (bNamespaces.has(ans)) return ans;
  }

  // Rule 2 + 3: restore-key fallback. A restore-key on one side hits a key
  // on the other side iff the key literal namespace starts with the
  // restore-key literal namespace. No separator boundary required —
  // actions/cache does pure literal prefix matching.
  const checkFallback = (
    restoreSide: string[],
    keySide: Set<string>,
  ): string | null => {
    for (const rk of restoreSide) {
      const rkNs = extractLiteralNamespace(rk);
      if (rkNs.length < 2) continue;
      for (const kNs of keySide) {
        if (kNs.startsWith(rkNs)) return rkNs;
      }
    }
    return null;
  };

  const fromAtoB = checkFallback(aRestoreOnly, bNamespaces);
  if (fromAtoB) return fromAtoB;
  const fromBtoA = checkFallback(bRestoreOnly, aNamespaces);
  if (fromBtoA) return fromBtoA;

  return null;
}

/**
 * Pull every cache step out of every workflow. Returns one CacheStep per
 * `uses: actions/cache*` step found.
 */
export function extractCacheSteps(context: RepoContext): CacheStep[] {
  const out: CacheStep[] = [];

  for (const workflow of context.workflows) {
    if (!workflow.parsed) continue;
    const triggers = getTriggers(workflow.parsed);
    const trustClass = classifyWorkflowTrust(workflow.parsed, context.workflows);
    if (trustClass === 'none' || trustClass === 'reusable-only') continue;

    const jobs = workflow.parsed['jobs'] as Record<string, unknown> | undefined;
    if (!jobs || typeof jobs !== 'object') continue;

    for (const jobDef of Object.values(jobs)) {
      const job = jobDef as Record<string, unknown>;
      const steps = job?.['steps'] as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(steps)) continue;

      for (const step of steps) {
        if (!step || typeof step['uses'] !== 'string') continue;
        const uses = step['uses'].trim();
        const atIdx = uses.indexOf('@');
        const actionName = atIdx === -1 ? uses : uses.substring(0, atIdx);
        if (!CACHE_ACTIONS.includes(actionName)) continue;

        const withBlock = step['with'] as Record<string, unknown> | undefined;
        if (!withBlock) continue;

        const path = String(withBlock['path'] ?? '');
        const key = String(withBlock['key'] ?? '');
        const restoreKeysRaw = withBlock['restore-keys'];
        const restoreKeys: string[] = [];
        if (typeof restoreKeysRaw === 'string') {
          restoreKeysRaw.split('\n').forEach(k => {
            const trimmed = k.trim();
            if (trimmed) restoreKeys.push(trimmed);
          });
        } else if (Array.isArray(restoreKeysRaw)) {
          restoreKeysRaw.forEach(k => restoreKeys.push(String(k)));
        }

        const keyLine = key ? findLineNumber(workflow.content, `key: ${key}`) : undefined;

        out.push({
          workflowPath: workflow.path,
          workflowName: workflow.name,
          workflowContent: workflow.content,
          triggers,
          trustClass,
          path,
          key,
          restoreKeys,
          action: actionName,
          usesLine: uses,
          keyLine,
        });
      }
    }
  }

  return out;
}

const KNOWN_LIMITATIONS_NOTE =
  '\n\n**Known limitations of this check:**\n' +
  '- Composite actions that wrap `actions/cache` are not analyzed. If your workflow uses a wrapper action, audit it manually.\n' +
  '- Runtime-resolved keys (variables set by earlier steps, outputs, env vars from previous jobs) are not statically tracked.\n' +
  '- Reusable workflows (`workflow_call` only) are skipped; their trust class depends on the caller.';

export const cachePoisoningCheck: CheckDefinition = {
  id: 'supply-chain/cache-poisoning',
  name: 'Cache Poisoning via Cross-Trigger Sharing',
  description:
    'Detects actions/cache usage where a fork-reachable workflow can poison a cache that a trusted workflow later restores. This is the May 2026 TanStack/Mini Shai-Hulud attack vector.',
  category: 'supply-chain',
  severity: 'high',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];
    const cacheSteps = extractCacheSteps(context);
    const reported = new Set<string>();

    // Track which workflows the cross-workflow rule already fired on, so
    // rule 3 can promote to HIGH when paired.
    const rule1WorkflowPaths = new Set<string>();

    // --- Rule 1: cross-workflow fork ↔ trusted cache sharing ---
    for (let i = 0; i < cacheSteps.length; i++) {
      for (let j = i + 1; j < cacheSteps.length; j++) {
        const a = cacheSteps[i];
        const b = cacheSteps[j];
        if (a.workflowPath === b.workflowPath) continue;
        if (a.path !== b.path) continue;

        const aHasFork = a.trustClass === 'fork-reachable' || a.trustClass === 'mixed';
        const bHasFork = b.trustClass === 'fork-reachable' || b.trustClass === 'mixed';
        const aHasTrusted = a.trustClass === 'trusted' || a.trustClass === 'mixed';
        const bHasTrusted = b.trustClass === 'trusted' || b.trustClass === 'mixed';

        const forkSide = aHasFork ? a : b;
        const trustedSide = aHasFork ? b : a;
        if (!((aHasFork && bHasTrusted) || (bHasFork && aHasTrusted))) continue;

        const overlap = findColludingNamespace(a, b);
        if (!overlap) continue;

        // Dedupe includes both actions so distinct cache actions on the
        // same path/namespace pair don't collapse into one finding.
        const dedupeKey = `r1:${forkSide.workflowPath}#${forkSide.action}<->${trustedSide.workflowPath}#${trustedSide.action}:${a.path}:${overlap}`;
        if (reported.has(dedupeKey)) continue;
        reported.add(dedupeKey);

        rule1WorkflowPaths.add(forkSide.workflowPath);

        findings.push({
          checkId: 'supply-chain/cache-poisoning',
          severity: 'high',
          category: 'supply-chain',
          title: `Cache shared between fork-reachable and trusted workflows: ${a.path}`,
          description:
            `Workflow \`${forkSide.workflowName}\` (triggers: ${forkSide.triggers.join(', ')}) and workflow \`${trustedSide.workflowName}\` ` +
            `(triggers: ${trustedSide.triggers.join(', ')}) both read/write the cache path \`${a.path}\` ` +
            `with colliding namespace \`${overlap}\`. A fork PR can save a poisoned entry that the trusted workflow later restores via \`restore-keys\` fallback.`,
          risk:
            'This is the May 2026 TanStack / Mini Shai-Hulud attack vector. An attacker opens a PR that runs the fork-reachable workflow, ' +
            'poisons the shared cache, then waits for any merge to main to trigger the trusted workflow. The trusted workflow restores ' +
            'the poisoned cache via overlapping restore-keys and executes attacker-controlled code with publish credentials and OIDC tokens.',
          remediation:
            'Rename the cache namespace on EVERY cache step involved, including split `actions/cache/save` and `actions/cache/restore` steps. ' +
            'Use disjoint prefixes for fork-reachable vs trusted runs, then purge existing cache entries under the old shared prefixes so previously poisoned entries cannot still be restored:\n\n' +
            '```yaml\n' +
            `# Fork-reachable workflow — PR-scoped namespace:\n` +
            `key: pr-\${{ github.event.pull_request.number }}-\${{ hashFiles('**/pnpm-lock.yaml') }}\n` +
            `restore-keys: |\n` +
            `  pr-\${{ github.event.pull_request.number }}-\n\n` +
            `# Trusted release workflow — disjoint namespace, never overlaps with PR:\n` +
            `key: trusted-\${{ github.sha }}-\${{ hashFiles('**/pnpm-lock.yaml') }}\n` +
            `restore-keys: |\n` +
            `  trusted-\n` +
            '```\n\n' +
            'After deploying, purge old cache entries via the GitHub UI (Actions → Caches) or `gh cache delete`. ' +
            'If cache logic is hidden inside a composite action, audit that wrapper manually.' +
            KNOWN_LIMITATIONS_NOTE,
          file: trustedSide.workflowPath,
          line: trustedSide.keyLine ?? findLineNumber(trustedSide.workflowContent, trustedSide.usesLine),
          evidence: `${forkSide.workflowName}: key=${forkSide.key || '(none)'} restore-keys=[${forkSide.restoreKeys.join(', ')}] | ${trustedSide.workflowName}: key=${trustedSide.key || '(none)'} restore-keys=[${trustedSide.restoreKeys.join(', ')}]`,
        });
      }
    }

    // --- Rule 2: same-workflow mixed triggers, UNLESS keys are trust-namespaced ---
    for (const step of cacheSteps) {
      if (step.trustClass !== 'mixed') continue;
      if (hasTrustNamespacing(step)) continue; // hardened — suppress

      const dedupeKey = `r2:${step.workflowPath}:${step.path}:${step.action}:${step.key}`;
      if (reported.has(dedupeKey)) continue;
      reported.add(dedupeKey);

      findings.push({
        checkId: 'supply-chain/cache-poisoning',
        severity: 'medium',
        category: 'supply-chain',
        title: `Cache in workflow with both fork-reachable and trusted triggers: ${step.workflowName}`,
        description:
          `Workflow \`${step.workflowName}\` is triggered by both fork-reachable events ` +
          `(${step.triggers.filter(t => FORK_REACHABLE_TRIGGERS.includes(t)).join(', ')}) ` +
          `and trusted events (${step.triggers.filter(t => TRUSTED_TRIGGERS.includes(t)).join(', ')}), ` +
          `and uses \`${step.action}\` on path \`${step.path}\` with key \`${step.key}\`. ` +
          `At least one of the cache key or its restore-keys does not interpolate \`github.event_name\` — the only expression that structurally disambiguates triggers in a mixed-trigger workflow. ` +
          `Every entry (primary \`key:\` AND every \`restore-keys:\` line) must include \`github.event_name\` for cross-trigger isolation to hold. ` +
          `Static literal prefixes like \`pr-\` are not sufficient inside a mixed-trigger workflow because both triggers evaluate the same expression — on a push run \`github.event.pull_request.number\` is empty, so a key like \`pr-\${{ github.event.pull_request.number }}-...\` still renders with a \`pr-\` prefix that any \`pr-\` restore-key will hit. ` +
          `Similarly, if only the primary key is trigger-aware but a restore-key falls back to a non-trigger-aware prefix, a PR-run save can be picked up by a push-run restore via that fallback.`,
        risk:
          'Cache entries persist across triggers of the same workflow. A poisoned entry from a PR run can be restored by a subsequent push or release run with secrets and write permissions.',
        remediation:
          'If one workflow file must handle both PR and trusted triggers, make both `key:` and EVERY `restore-keys:` entry include a disjoint trust namespace such as `pr-` vs `trusted-`. ' +
          'This finding is suppressed only when those namespaces cannot overlap across triggers.\n\n' +
          '```yaml\n' +
          `key: \${{ github.event_name == 'pull_request' && format('pr-{0}-', github.event.pull_request.number) || 'trusted-' }}\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}\n` +
          `restore-keys: |\n` +
          `  \${{ github.event_name == 'pull_request' && format('pr-{0}-', github.event.pull_request.number) || 'trusted-' }}\${{ runner.os }}-\n` +
          '```\n\n' +
          'Or split into two workflow files (cleaner): one on `pull_request[_target]`, one on `push`/`release`.' +
          KNOWN_LIMITATIONS_NOTE,
        file: step.workflowPath,
        line: step.keyLine ?? findLineNumber(step.workflowContent, step.usesLine),
        evidence: `triggers: [${step.triggers.join(', ')}] | key: ${step.key} | restore-keys: [${step.restoreKeys.join(', ')}]`,
      });
    }

    // --- Rule 3: attacker-controlled key in fork-reachable workflow ---
    // MEDIUM standalone; HIGH when paired with rule 1 in the same workflow.
    for (const step of cacheSteps) {
      if (step.trustClass !== 'fork-reachable' && step.trustClass !== 'mixed') continue;
      const keyCheck = isAttackerControlled(step.key);
      const restoreCheck = step.restoreKeys
        .map(r => isAttackerControlled(r))
        .find(c => c.controlled);
      const controlled = keyCheck.controlled ? keyCheck : restoreCheck;
      if (!controlled || !controlled.controlled) continue;

      const dedupeKey = `r3:${step.workflowPath}:${step.path}:${step.action}:${step.key}`;
      if (reported.has(dedupeKey)) continue;
      reported.add(dedupeKey);

      const promoted = rule1WorkflowPaths.has(step.workflowPath);
      const severity: 'high' | 'medium' = promoted ? 'high' : 'medium';
      const pairingNote = promoted
        ? ' This finding is promoted to HIGH because the same workflow already has a cross-workflow cache collision (rule 1) — the attacker can pick the exact key under which the poisoned cache lands on the trusted side.'
        : '';

      findings.push({
        checkId: 'supply-chain/cache-poisoning',
        severity,
        category: 'supply-chain',
        title: `Cache key contains attacker-controlled expression: ${step.workflowName}`,
        description:
          `Workflow \`${step.workflowName}\` uses \`${step.action}\` with a cache key derived from an attacker-controlled input: ${controlled.reason}. ` +
          `An attacker opening a PR can pick the exact cache key the save lands under.${pairingNote}`,
        risk:
          'Attacker-controlled key components let a fork PR force a deterministic save location for the poisoned cache entry. ' +
          'Without rule 1\'s cross-workflow restore, this is exposure to same-workflow rerun reuse only (medium); paired with rule 1, it is the full exploit primitive.',
        remediation:
          'Remove attacker-controlled inputs from cache keys. Prefer server-side values like `github.sha` or PR-scoped namespaces with explicit fork prefixes that cannot collide with main caches:\n\n' +
          '```yaml\n' +
          `# Avoid: cache key derived from PR-controlled lockfile or head ref\nkey: \${{ runner.os }}-\${{ github.head_ref }}\n` +
          `key: \${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}  # PR controls the lockfile content\n\n` +
          `# Prefer: PR-namespaced key that cannot collide with trusted caches\nkey: pr-\${{ github.event.pull_request.number }}-\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}\n` +
          '```' +
          KNOWN_LIMITATIONS_NOTE,
        file: step.workflowPath,
        line: step.keyLine ?? findLineNumber(step.workflowContent, step.usesLine),
        evidence: `key: ${step.key}${step.restoreKeys.length ? ' | restore-keys: [' + step.restoreKeys.join(', ') + ']' : ''}`,
      });
    }

    // --- Rule 4: actions/cache/save in fork-reachable workflow without fork-scope ---
    for (const step of cacheSteps) {
      if (step.trustClass !== 'fork-reachable' && step.trustClass !== 'mixed') continue;
      if (step.action !== 'actions/cache/save') continue;

      const ns = keyNamespaces(step.key);
      if (ns.has('fork')) continue; // explicitly fork-scoped — safe

      const dedupeKey = `r4:${step.workflowPath}:${step.path}:${step.key}`;
      if (reported.has(dedupeKey)) continue;
      reported.add(dedupeKey);

      findings.push({
        checkId: 'supply-chain/cache-poisoning',
        severity: 'high',
        category: 'supply-chain',
        title: `actions/cache/save in fork-reachable workflow without fork-scoped key: ${step.workflowName}`,
        description:
          `Workflow \`${step.workflowName}\` uses \`actions/cache/save\` in a fork-reachable context with key \`${step.key}\`. ` +
          `The key has no fork-scope namespace (such as \`pr-\`, \`pull-\`, \`fork-\`, or an interpolation of \`github.event.pull_request.number\` / \`github.event.issue.number\`). ` +
          `The save-only action writes to the cache regardless of whether any restore step hit, so a fork PR can directly seed any key it constructs.`,
        risk:
          'Unlike the combined `actions/cache` action, `actions/cache/save` always writes. A fork PR can directly seed any cache key it constructs. ' +
          'If the key is not in a fork-only namespace, it can collide with or shadow trusted-workflow caches.',
        remediation:
          'Prefer removing `actions/cache/save` from fork-reachable workflows entirely. If you must keep it, use a PR- or issue-scoped namespace that cannot overlap with trusted caches, and ensure the trusted restore side uses a different prefix:\n\n' +
          '```yaml\n' +
          `key: pr-\${{ github.event.pull_request.number }}-\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}\n` +
          '```\n\n' +
          'After deploying, purge any existing shared cache keys via `gh cache delete` so previously poisoned entries cannot still be restored.' +
          KNOWN_LIMITATIONS_NOTE,
        file: step.workflowPath,
        line: step.keyLine ?? findLineNumber(step.workflowContent, step.usesLine),
        evidence: `${step.action} | key: ${step.key}`,
      });
    }

    return findings;
  },
};
