import { describe, it, expect } from 'vitest';
import { cachePoisoningCheck, extractLiteralNamespace, keyNamespaces, hasTrustNamespacing, isAttackerControlled, findColludingNamespace, classifyTriggers } from '../../lib/scanner/checks/cache-poisoning';
import type { CacheStep } from '../../lib/scanner/checks/cache-poisoning';
import { makeContext, makeWorkflow } from '../helpers';

const check = cachePoisoningCheck;

// --- Reusable fixture YAML ---

const prBuildYaml = `
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@v4
        with:
          path: ~/.local/share/pnpm/store/v3
          key: pnpm-\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}
          restore-keys: |
            pnpm-\${{ runner.os }}-
      - run: pnpm install
`;

const releaseYaml = `
name: Release
on:
  push:
    branches: [main]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.local/share/pnpm/store/v3
          key: pnpm-\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}
          restore-keys: |
            pnpm-\${{ runner.os }}-
      - run: pnpm install
      - run: pnpm publish
`;

// --- Unit tests on extracted helpers ---

describe('cache-poisoning helpers', () => {
  describe('extractLiteralNamespace', () => {
    it('returns text before the first interpolation', () => {
      expect(extractLiteralNamespace('pnpm-${{ runner.os }}-')).toBe('pnpm-');
      expect(extractLiteralNamespace('pr-${{ github.event.pull_request.number }}-')).toBe('pr-');
      expect(extractLiteralNamespace('trusted-')).toBe('trusted-');
    });
    it('returns empty string for empty input', () => {
      expect(extractLiteralNamespace('')).toBe('');
    });
  });

  describe('keyNamespaces', () => {
    it('detects fork-scope expressions', () => {
      const ns = keyNamespaces('pr-${{ github.event.pull_request.number }}-');
      expect(ns.has('fork')).toBe(true);
    });
    it('detects trigger-aware expressions', () => {
      const ns = keyNamespaces('${{ github.event_name }}-${{ runner.os }}-');
      expect(ns.has('trigger-aware')).toBe(true);
    });
    it('detects trusted literal prefix', () => {
      const ns = keyNamespaces('trusted-${{ github.sha }}-');
      expect(ns.has('trusted')).toBe(true);
    });
    it('returns empty for unscoped keys', () => {
      const ns = keyNamespaces('pnpm-${{ runner.os }}-${{ hashFiles(\'**/pnpm-lock.yaml\') }}');
      expect(ns.size).toBe(0);
    });
  });

  describe('hasTrustNamespacing', () => {
    const baseStep = {
      workflowPath: '.github/workflows/x.yml',
      workflowName: 'x.yml',
      workflowContent: '',
      triggers: ['pull_request', 'push'],
      trustClass: 'mixed' as const,
      path: '~/.cache',
      action: 'actions/cache',
      usesLine: 'actions/cache@v4',
    };
    it('returns true when every key carries a namespace', () => {
      const step: CacheStep = {
        ...baseStep,
        key: '${{ github.event_name }}-${{ runner.os }}',
        restoreKeys: ['${{ github.event_name }}-'],
      };
      expect(hasTrustNamespacing(step)).toBe(true);
    });
    it('returns false when restore-keys omit the namespace', () => {
      const step: CacheStep = {
        ...baseStep,
        key: '${{ github.event_name }}-${{ runner.os }}',
        restoreKeys: ['${{ runner.os }}-'],
      };
      expect(hasTrustNamespacing(step)).toBe(false);
    });
    it('returns false when both key and restore-keys are unscoped', () => {
      const step: CacheStep = {
        ...baseStep,
        key: 'pnpm-${{ runner.os }}-${{ hashFiles(\'**/pnpm-lock.yaml\') }}',
        restoreKeys: ['pnpm-${{ runner.os }}-'],
      };
      expect(hasTrustNamespacing(step)).toBe(false);
    });
    it('returns false for run-scoped expressions that do NOT disambiguate triggers', () => {
      const step: CacheStep = {
        ...baseStep,
        key: 'run-${{ github.run_id }}-${{ runner.os }}',
        restoreKeys: ['run-'],
      };
      expect(hasTrustNamespacing(step)).toBe(false);
    });
    it('returns false even when every key has a static fork prefix (does not structurally isolate triggers in mixed workflow)', () => {
      // In an on:[pull_request, push] workflow, BOTH runs evaluate the same
      // expression. On push, github.event.pull_request.number is empty, so
      // both runs use a key starting with "pr-". The restore-key "pr-" hits
      // both. Static prefixes are NOT enough — only github.event_name is.
      const step: CacheStep = {
        ...baseStep,
        key: 'pr-${{ github.event.pull_request.number }}-${{ runner.os }}',
        restoreKeys: ['pr-${{ github.event.pull_request.number }}-', 'pr-'],
      };
      expect(hasTrustNamespacing(step)).toBe(false);
    });
    it('returns true only when every key interpolates github.event_name', () => {
      const step: CacheStep = {
        ...baseStep,
        key: '${{ github.event_name }}-${{ runner.os }}',
        restoreKeys: ['${{ github.event_name }}-'],
      };
      expect(hasTrustNamespacing(step)).toBe(true);
    });
    it('returns false when only the primary key is trigger-aware but restore-keys are not', () => {
      const step: CacheStep = {
        ...baseStep,
        key: '${{ github.event_name }}-${{ runner.os }}',
        restoreKeys: ['${{ runner.os }}-'],
      };
      expect(hasTrustNamespacing(step)).toBe(false);
    });
  });

  describe('isAttackerControlled', () => {
    it('flags github.head_ref in key', () => {
      const r = isAttackerControlled('${{ runner.os }}-${{ github.head_ref }}');
      expect(r.controlled).toBe(true);
      expect(r.reason).toContain('github.head_ref');
    });
    it('flags hashFiles over PR-controlled lockfile', () => {
      const r = isAttackerControlled("${{ runner.os }}-${{ hashFiles('**/pnpm-lock.yaml') }}");
      expect(r.controlled).toBe(true);
      expect(r.reason).toContain('hashFiles');
    });
    it('does not flag hashFiles over non-lockfile path', () => {
      const r = isAttackerControlled("${{ hashFiles('.github/workflows/*.yml') }}");
      expect(r.controlled).toBe(false);
    });
    it('does not flag github.sha', () => {
      const r = isAttackerControlled('trusted-${{ github.sha }}');
      expect(r.controlled).toBe(false);
    });
  });

  describe('findColludingNamespace', () => {
    const stepWith = (key: string, restoreKeys: string[]): CacheStep => ({
      workflowPath: 'x',
      workflowName: 'x',
      workflowContent: '',
      triggers: [],
      trustClass: 'mixed',
      path: '~/cache',
      key,
      restoreKeys,
      action: 'actions/cache',
      usesLine: '',
    });
    it('returns the colliding namespace when key prefixes match exactly', () => {
      const a = stepWith('pnpm-${{ runner.os }}-${{ hashFiles(\'l\') }}', ['pnpm-${{ runner.os }}-']);
      const b = stepWith('pnpm-${{ runner.os }}-${{ hashFiles(\'l\') }}', ['pnpm-${{ runner.os }}-']);
      expect(findColludingNamespace(a, b)).toBe('pnpm-');
    });
    it('flags npm- vs npm-docs- as a collision (actions/cache literal prefix matching)', () => {
      // This IS a real collision: a restore-key `npm-` matches any cache key
      // starting with `npm-`, including `npm-docs-...`. actions/cache does
      // literal start-match — there is no separator boundary.
      const a = stepWith('npm-${{ runner.os }}-${{ hashFiles(\'l\') }}', ['npm-${{ runner.os }}-', 'npm-']);
      const b = stepWith('npm-docs-${{ runner.os }}-${{ hashFiles(\'l\') }}', ['npm-docs-${{ runner.os }}-']);
      expect(findColludingNamespace(a, b)).toBe('npm-');
    });
    it('returns null when restore-keys are disjoint and don\'t cross-match', () => {
      // A's only namespace is "pnpm-linux-", B's only namespace is "pnpm-mac-".
      // Neither side has a shorter restore-key that could fall through.
      const a = stepWith('pnpm-linux-${{ hashFiles(\'l\') }}', ['pnpm-linux-']);
      const b = stepWith('pnpm-mac-${{ hashFiles(\'l\') }}', ['pnpm-mac-']);
      expect(findColludingNamespace(a, b)).toBeNull();
    });
    it('returns the prefix when one side\'s restore-key falls through to the other side\'s key', () => {
      // A has restore-key "pnpm-" — it will hit B's key namespace "pnpm-linux-".
      const a = stepWith('pnpm-linux-${{ hashFiles(\'l\') }}', ['pnpm-']);
      const b = stepWith('pnpm-mac-${{ hashFiles(\'l\') }}', ['pnpm-mac-']);
      expect(findColludingNamespace(a, b)).toBe('pnpm-');
    });
    it('handles asymmetric restore-keys (only B has the broad prefix)', () => {
      // Only B has the broad restore-key — A has narrowly scoped keys.
      // B's restore-key "pnpm-" will hit A's "pnpm-linux-" key.
      const a = stepWith('pnpm-linux-${{ hashFiles(\'l\') }}', ['pnpm-linux-']);
      const b = stepWith('pnpm-mac-${{ hashFiles(\'l\') }}', ['pnpm-']);
      expect(findColludingNamespace(a, b)).toBe('pnpm-');
    });
    it('returns null when one side is pr- and the other is trusted- (no fallback overlap)', () => {
      const a = stepWith('pr-${{ github.event.pull_request.number }}-${{ hashFiles(\'l\') }}', ['pr-${{ github.event.pull_request.number }}-', 'pr-']);
      const b = stepWith('trusted-${{ github.sha }}-${{ hashFiles(\'l\') }}', ['trusted-']);
      expect(findColludingNamespace(a, b)).toBeNull();
    });
  });

  describe('classifyTriggers', () => {
    it('classifies workflow_call only as reusable-only', () => {
      expect(classifyTriggers(['workflow_call'])).toBe('reusable-only');
    });
    it('does not classify standalone workflow_run as fork-reachable', () => {
      expect(classifyTriggers(['workflow_run'])).toBe('trusted');
    });
    it('classifies mixed correctly', () => {
      expect(classifyTriggers(['pull_request', 'push'])).toBe('mixed');
    });
  });
});

// --- Integration tests on the check itself ---

describe('supply-chain/cache-poisoning', () => {
  it('rule 1: flags cross-workflow restore-key overlap (May 11 TanStack pattern)', () => {
    const ctx = makeContext([
      { ...makeWorkflow(prBuildYaml), path: '.github/workflows/pr-build.yml', name: 'pr-build.yml' },
      { ...makeWorkflow(releaseYaml), path: '.github/workflows/release.yml', name: 'release.yml' },
    ]);
    const findings = check.run(ctx);
    const xworkflow = findings.filter(f => f.title.startsWith('Cache shared between'));
    expect(xworkflow.length).toBeGreaterThanOrEqual(1);
    expect(xworkflow[0].severity).toBe('high');
    expect(xworkflow[0].description).toContain('pnpm-');
    expect(xworkflow[0].description.toLowerCase()).toContain('colliding namespace');
  });

  it('rule 1: does not flag cache scoped per trigger (hardened pattern)', () => {
    const hardenedPr = prBuildYaml.replace(
      "key: pnpm-${{ runner.os }}-${{ hashFiles('**/pnpm-lock.yaml') }}",
      "key: pr-${{ github.event.pull_request.number }}-${{ runner.os }}-${{ hashFiles('**/pnpm-lock.yaml') }}"
    ).replace(
      'restore-keys: |\n            pnpm-${{ runner.os }}-',
      'restore-keys: |\n            pr-${{ github.event.pull_request.number }}-'
    );
    const hardenedRelease = releaseYaml.replace(
      "key: pnpm-${{ runner.os }}-${{ hashFiles('**/pnpm-lock.yaml') }}",
      "key: trusted-${{ github.sha }}-${{ hashFiles('**/pnpm-lock.yaml') }}"
    ).replace('restore-keys: |\n            pnpm-${{ runner.os }}-', 'restore-keys: |\n            trusted-');
    const ctx = makeContext([
      { ...makeWorkflow(hardenedPr), path: '.github/workflows/pr-build.yml', name: 'pr-build.yml' },
      { ...makeWorkflow(hardenedRelease), path: '.github/workflows/release.yml', name: 'release.yml' },
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBe(0);
  });

  it('rule 1: DOES flag npm- restore-key vs npm-docs- key (actions/cache literal-prefix collision)', () => {
    // This is the correct security call: a restore-key `npm-${{ runner.os }}-`
    // matches any cache key starting with `npm-`, including `npm-docs-...`.
    // actions/cache does literal start-match. If devs want separate namespaces
    // they must use restore-keys with no overlap. Many real codebases get this
    // wrong, which is why the May 11 attack worked.
    const npmPr = `
name: PR
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-\${{ runner.os }}-\${{ github.event.pull_request.number }}
          restore-keys: |
            npm-\${{ runner.os }}-
`;
    const npmDocsRelease = `
name: Docs Release
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-docs-\${{ runner.os }}-\${{ github.sha }}
          restore-keys: |
            npm-docs-\${{ runner.os }}-
`;
    const ctx = makeContext([
      { ...makeWorkflow(npmPr), path: '.github/workflows/pr.yml', name: 'pr.yml' },
      { ...makeWorkflow(npmDocsRelease), path: '.github/workflows/docs.yml', name: 'docs.yml' },
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBeGreaterThanOrEqual(1);
  });

  it('rule 1: does NOT misfire on genuinely disjoint namespaces (pr-X vs trusted-X)', () => {
    // The hardened pattern: PR side uses "pr-..." namespace, trusted side uses
    // "trusted-..." namespace. No restore-key on either side falls through.
    // This is the correct shape devs should land on after fixing the bug.
    const prSide = `
name: PR
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: pr-\${{ github.event.pull_request.number }}-\${{ runner.os }}
          restore-keys: |
            pr-\${{ github.event.pull_request.number }}-
`;
    const trustedSide = `
name: Release
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: trusted-\${{ github.sha }}-\${{ runner.os }}
          restore-keys: |
            trusted-
`;
    const ctx = makeContext([
      { ...makeWorkflow(prSide), path: '.github/workflows/pr.yml', name: 'pr.yml' },
      { ...makeWorkflow(trustedSide), path: '.github/workflows/release.yml', name: 'release.yml' },
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBe(0);
  });

  it('does not flag workflows without cache', () => {
    const ctx = makeContext([
      makeWorkflow(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('does not flag cache only in fork-reachable triggers (no trusted counterpart)', () => {
    const ctx = makeContext([
      { ...makeWorkflow(prBuildYaml), path: '.github/workflows/pr-build.yml', name: 'pr-build.yml' },
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBe(0);
  });

  it('rule 4: detects actions/cache/save in fork-reachable workflow without fork scope', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save@v4
        with:
          path: ~/.local/share/pnpm/store/v3
          key: pnpm-\${{ runner.os }}-build
`),
    ]);
    const findings = check.run(ctx);
    const saveFinding = findings.find(f => f.title.includes('actions/cache/save'));
    expect(saveFinding).toBeDefined();
    expect(saveFinding!.severity).toBe('high');
  });

  it('rule 4: does NOT flag actions/cache/save with explicit non-`pr-` fork-scoped key', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Issue Triage
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: issue-\${{ github.event.issue.number }}-\${{ runner.os }}
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.includes('actions/cache/save')).length).toBe(0);
  });

  it('detects actions/cache/restore in cross-workflow overlap', () => {
    const ctx = makeContext([
      {
        ...makeWorkflow(`
name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save@v4
        with:
          path: /tmp/build
          key: build-\${{ runner.os }}-pr
          restore-keys: |
            build-\${{ runner.os }}-
`),
        path: '.github/workflows/pr.yml',
        name: 'pr.yml',
      },
      {
        ...makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: /tmp/build
          key: build-\${{ runner.os }}-release
          restore-keys: |
            build-\${{ runner.os }}-
`),
        path: '.github/workflows/release.yml',
        name: 'release.yml',
      },
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBeGreaterThanOrEqual(1);
  });

  it('rule 2: flags same-workflow mixed-trigger cache at medium severity (unscoped)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: [pull_request, push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-\${{ hashFiles('**/package-lock.json') }}
`),
    ]);
    const findings = check.run(ctx);
    const mixedFinding = findings.find(f => f.title.includes('both fork-reachable and trusted triggers'));
    expect(mixedFinding).toBeDefined();
    expect(mixedFinding!.severity).toBe('medium');
  });

  it('rule 2: does NOT flag hardened mixed-trigger with github.event_name scoping in BOTH key and restore-keys', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: [pull_request, push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: \${{ github.event_name }}-\${{ runner.os }}-\${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            \${{ github.event_name }}-\${{ runner.os }}-
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.filter(f => f.title.includes('both fork-reachable and trusted triggers')).length).toBe(0);
  });

  it('rule 3: flags attacker-controlled github.head_ref at medium standalone', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: /tmp/cache
          key: \${{ runner.os }}-\${{ github.head_ref }}
`),
    ]);
    const findings = check.run(ctx);
    const attackerKey = findings.find(f => f.title.includes('attacker-controlled'));
    expect(attackerKey).toBeDefined();
    expect(attackerKey!.severity).toBe('medium');
    expect(attackerKey!.evidence).toContain('github.head_ref');
  });

  it('rule 3: flags hashFiles() over PR-controlled lockfile in fork-reachable workflow', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: \${{ runner.os }}-\${{ hashFiles('**/package-lock.json') }}
`),
    ]);
    const findings = check.run(ctx);
    const attackerKey = findings.find(f => f.title.includes('attacker-controlled'));
    expect(attackerKey).toBeDefined();
    expect(attackerKey!.description.toLowerCase()).toContain('hashfiles');
  });

  it('rule 3: promotes to HIGH when paired with rule 1 in same workflow', () => {
    // PR has attacker-controlled key AND shares cache with release workflow.
    const ctx = makeContext([
      {
        ...makeWorkflow(`
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: \${{ runner.os }}-\${{ github.head_ref }}
          restore-keys: |
            npm-shared-\${{ runner.os }}-
`),
        path: '.github/workflows/pr.yml',
        name: 'pr.yml',
      },
      {
        ...makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-shared-\${{ runner.os }}-\${{ github.sha }}
          restore-keys: |
            npm-shared-\${{ runner.os }}-
`),
        path: '.github/workflows/release.yml',
        name: 'release.yml',
      },
    ]);
    const findings = check.run(ctx);
    const attackerKey = findings.find(f => f.title.includes('attacker-controlled'));
    expect(attackerKey).toBeDefined();
    expect(attackerKey!.severity).toBe('high');
    expect(attackerKey!.description.toLowerCase()).toContain('promoted');
  });

  it('skips reusable workflows (workflow_call only)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Reusable
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: \${{ runner.os }}-\${{ hashFiles('**/package-lock.json') }}
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('propagates fork-reachability through TWO-HOP workflow_run chain', () => {
    // CI on pull_request → CD via workflow_run("CI") → Deploy via workflow_run("CD")
    // Deploy must be classified as fork-reachable.
    const ctx = makeContext([
      {
        ...makeWorkflow(`
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ci
`),
        path: '.github/workflows/ci.yml',
        name: 'ci.yml',
      },
      {
        ...makeWorkflow(`
name: CD
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - run: echo cd
`),
        path: '.github/workflows/cd.yml',
        name: 'cd.yml',
      },
      {
        ...makeWorkflow(`
name: Deploy
on:
  workflow_run:
    workflows: ["CD"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: deploy-\${{ runner.os }}
          restore-keys: |
            deploy-
`),
        path: '.github/workflows/deploy.yml',
        name: 'deploy.yml',
      },
      {
        ...makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: deploy-\${{ runner.os }}-\${{ github.sha }}
          restore-keys: |
            deploy-
`),
        path: '.github/workflows/release.yml',
        name: 'release.yml',
      },
    ]);
    const findings = check.run(ctx);
    // deploy.yml (fork-reachable via CD via CI) and release.yml (trusted)
    // share the "deploy-" namespace → rule 1 must fire.
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBeGreaterThanOrEqual(1);
  });

  it('treats workflow_run with FORK-TRIGGERED parent as fork-reachable (cross-workflow trust)', () => {
    // Parent CI workflow is on pull_request (fork-reachable).
    // The workflow_run handler watches it — it inherits fork-reachability.
    const ctx = makeContext([
      {
        ...makeWorkflow(`
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "this is the fork-triggered parent"
`),
        path: '.github/workflows/ci.yml',
        name: 'ci.yml',
      },
      {
        ...makeWorkflow(`
name: Process PR Artifacts
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: shared-\${{ runner.os }}-\${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            shared-\${{ runner.os }}-
`),
        path: '.github/workflows/process.yml',
        name: 'process.yml',
      },
      {
        ...makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: shared-\${{ runner.os }}-\${{ github.sha }}
          restore-keys: |
            shared-\${{ runner.os }}-
`),
        path: '.github/workflows/release.yml',
        name: 'release.yml',
      },
    ]);
    const findings = check.run(ctx);
    // process.yml (workflow_run → CI which is pull_request → fork-reachable)
    // and release.yml (push → trusted) both touch the "shared-..." cache.
    // Rule 1 SHOULD fire.
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBeGreaterThanOrEqual(1);
  });

  it('treats standalone workflow_run as trusted (does not auto-classify as fork-reachable)', () => {
    // Two workflows: a workflow_run handler (trusted by default) and a release workflow.
    // These should NOT trigger rule 1 unless the workflow_run handler is actually fork-fed.
    const ctx = makeContext([
      {
        ...makeWorkflow(`
name: WorkflowRun Handler
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: shared-\${{ runner.os }}
`),
        path: '.github/workflows/wr.yml',
        name: 'wr.yml',
      },
      {
        ...makeWorkflow(`
name: Release
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: shared-\${{ runner.os }}
`),
        path: '.github/workflows/release.yml',
        name: 'release.yml',
      },
    ]);
    const findings = check.run(ctx);
    // Both are trusted → no cross-workflow rule 1 finding.
    expect(findings.filter(f => f.title.startsWith('Cache shared between')).length).toBe(0);
  });

  it('documents composite-action limitation explicitly in findings', () => {
    const ctx = makeContext([
      { ...makeWorkflow(prBuildYaml), path: '.github/workflows/pr-build.yml', name: 'pr-build.yml' },
      { ...makeWorkflow(releaseYaml), path: '.github/workflows/release.yml', name: 'release.yml' },
    ]);
    const findings = check.run(ctx);
    const xworkflow = findings.find(f => f.title.startsWith('Cache shared between'));
    expect(xworkflow).toBeDefined();
    expect(xworkflow!.remediation.toLowerCase()).toContain('composite');
    expect(xworkflow!.remediation.toLowerCase()).toContain('known limitations');
    expect(xworkflow!.remediation.toLowerCase()).toContain('runtime-resolved keys');
    expect(xworkflow!.remediation.toLowerCase()).toContain('reusable workflows');
  });

  it('composite-action negative: cache hidden inside a wrapper action is not detected (documented blind spot)', () => {
    // The scanner only sees workflow YAML. When a composite/wrapper action
    // wraps `actions/cache` internally, the workflow file shows only the
    // wrapper's `uses:` line — there is no `actions/cache@*` step at the
    // workflow level for extractCacheSteps() to find. This is a documented
    // limitation; the check correctly produces no finding (rather than a
    // false positive based on guessing what the wrapper does internally).
    //
    // This test pins the blind-spot behavior so a future change that tries
    // to "peek into" composite actions doesn't silently introduce false
    // positives without an explicit decision.
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: [pull_request_target, push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/setup-and-cache-wrapper@v3
        with:
          # The wrapper internally calls actions/cache with the user's path/key.
          # The scanner cannot see that.
          path: ~/.local/share/pnpm/store/v3
          key: pnpm-\${{ runner.os }}-\${{ hashFiles('**/pnpm-lock.yaml') }}
          restore-keys: |
            pnpm-\${{ runner.os }}-
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('composite-action negative: limitation IS surfaced in remediation when a real cache step is present elsewhere', () => {
    // If the same repo also has a real (non-wrapped) cache step that fires
    // a finding, the remediation explicitly tells the user to audit wrappers
    // manually. This is how the user learns about the blind spot.
    const ctx = makeContext([
      { ...makeWorkflow(prBuildYaml), path: '.github/workflows/pr-build.yml', name: 'pr-build.yml' },
      { ...makeWorkflow(releaseYaml), path: '.github/workflows/release.yml', name: 'release.yml' },
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].remediation.toLowerCase()).toContain('composite');
    expect(findings[0].remediation.toLowerCase()).toContain('audit');
  });

  it('finding points to the key: line, not the uses: line, when key is extractable', () => {
    const yaml = `name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: \${{ runner.os }}-\${{ github.head_ref }}
`;
    const ctx = makeContext([
      { ...makeWorkflow(yaml), path: '.github/workflows/pr.yml', name: 'pr.yml', content: yaml },
    ]);
    const findings = check.run(ctx);
    const attackerKey = findings.find(f => f.title.includes('attacker-controlled'));
    expect(attackerKey).toBeDefined();
    // The yaml puts `key:` on a different line than `uses:` — line should be the key line.
    const lines = yaml.split('\n');
    const keyLine = lines.findIndex(l => l.trim().startsWith('key:')) + 1; // 1-indexed
    expect(attackerKey!.line).toBe(keyLine);
  });
});
