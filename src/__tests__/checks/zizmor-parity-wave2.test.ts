import { describe, it, expect } from 'vitest';
import { makeContext, makeWorkflow } from '../helpers';
import type { RepoContext } from '../../lib/scanner/types';

import { dependabotExecutionCheck } from '../../lib/scanner/checks/dependabot-execution';
import { githubAppTokenCheck } from '../../lib/scanner/checks/github-app';
import { unredactedSecretsCheck } from '../../lib/scanner/checks/unredacted-secrets';
import { unsoundConditionCheck } from '../../lib/scanner/checks/unsound-condition';
import { unsoundContainsCheck } from '../../lib/scanner/checks/unsound-contains';
import { useTrustedPublishingCheck } from '../../lib/scanner/checks/use-trusted-publishing';
import { githubScriptInjectionCheck } from '../../lib/scanner/checks/github-script-injection';
import { unverifiedRemoteExecCheck } from '../../lib/scanner/checks/unverified-remote-exec';
import { confusedDeputyAutomergeCheck } from '../../lib/scanner/checks/confused-deputy-automerge';
import { debugExposureCheck } from '../../lib/scanner/checks/debug-exposure';
import { typosquatUsesCheck } from '../../lib/scanner/checks/typosquat-uses';
import { unpinnedToolsCheck } from '../../lib/scanner/checks/unpinned-tools';

function withDependabot(config: Record<string, unknown>): RepoContext {
  return { ...makeContext([]), dependabotConfig: config, hasDependabot: true };
}

describe('supply-chain/dependabot-execution', () => {
  it('flags insecure-external-code-execution: allow', () => {
    const ctx = withDependabot({
      version: 2,
      updates: [{ 'package-ecosystem': 'bundler', 'insecure-external-code-execution': 'allow' }],
    });
    const f = dependabotExecutionCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('high');
  });
  it('does not flag a normal dependabot config', () => {
    const ctx = withDependabot({ version: 2, updates: [{ 'package-ecosystem': 'npm' }] });
    expect(dependabotExecutionCheck.run(ctx).length).toBe(0);
  });
});

describe('permissions/github-app-token', () => {
  it('flags skip-token-revoke: true', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v2
        with:
          app-id: 1
          private-key: x
          repositories: this
          permission-contents: write
          skip-token-revoke: true
`),
    ]);
    expect(githubAppTokenCheck.run(ctx).length).toBe(1);
  });
  it('does not flag a tightly-scoped token', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v2
        with:
          app-id: 1
          private-key: x
          repositories: this
          permission-contents: read
`),
    ]);
    expect(githubAppTokenCheck.run(ctx).length).toBe(0);
  });
});

describe('secrets/unredacted-secrets', () => {
  it('flags fromJSON(secrets.X)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ fromJSON(secrets.CONFIG).token }}"
`),
    ]);
    expect(unredactedSecretsCheck.run(ctx).length).toBe(1);
  });
  it('does not flag a plain secret reference', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: \${{ secrets.TOKEN }}
        run: echo hi
`),
    ]);
    expect(unredactedSecretsCheck.run(ctx).length).toBe(0);
  });
});

describe('dangerous-triggers/unsound-condition', () => {
  it('flags a block-scalar if: that is always true', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    if: >
      \${{ github.actor == 'dependabot[bot]' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    const f = unsoundConditionCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('high');
  });
  it('does not flag a sound inline condition', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request
jobs:
  b:
    if: \${{ github.actor == 'dependabot[bot]' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundConditionCheck.run(ctx).length).toBe(0);
  });
  it('does not flag an unfenced condition', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundConditionCheck.run(ctx).length).toBe(0);
  });
});

describe('dangerous-triggers/unsound-contains', () => {
  it('flags contains(string literal, github.ref)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    if: contains('refs/heads/main refs/heads/dev', github.ref)
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundContainsCheck.run(ctx).length).toBe(1);
  });
  it('does not flag a fromJSON array membership check', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    if: contains(fromJSON('["refs/heads/main"]'), github.ref)
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundContainsCheck.run(ctx).length).toBe(0);
  });

  it('does not flag a contains() string outside an if: gate (step name)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - name: "example: contains('a b c', github.ref)"
        run: echo hi
`),
    ]);
    expect(unsoundContainsCheck.run(ctx).length).toBe(0);
  });

  it('does not flag contains() over github.sha (not attacker-controlled)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    if: contains('abc def', github.sha)
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundContainsCheck.run(ctx).length).toBe(0);
  });

  it('does not flag contains() over a safe scalar event field', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    if: contains('1 2 3', github.event.number)
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(unsoundContainsCheck.run(ctx).length).toBe(0);
  });
});

describe('permissions/use-trusted-publishing', () => {
  it('flags pypi publish with a password and no id-token', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: \${{ secrets.PYPI_TOKEN }}
`),
    ]);
    const f = useTrustedPublishingCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('info');
  });
  it('does not flag a job already using OIDC (id-token: write)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
`),
    ]);
    expect(useTrustedPublishingCheck.run(ctx).length).toBe(0);
  });

  it('does not flag setup-node with a registry-url when nothing is published', () => {
    // Regression: registry-url is also used for authenticated private installs.
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
      - run: npm ci
`),
    ]);
    expect(useTrustedPublishingCheck.run(ctx).length).toBe(0);
  });
});

describe('injection/github-script', () => {
  it('flags untrusted event input in a github-script body', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            core.info("\${{ github.event.pull_request.title }}")
`),
    ]);
    const f = githubScriptInjectionCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('critical');
  });
  it('flags a mixed format() expression combining a safe field with an attacker-controlled one', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            core.info("\${{ format('{0}-{1}', github.event.number, github.event.pull_request.title) }}")
`),
    ]);
    const f = githubScriptInjectionCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags github.head_ref in a github-script body (no github.event member)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            core.info("\${{ github.head_ref }}")
`),
    ]);
    const f = githubScriptInjectionCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('critical');
  });

  it('does not flag a github-script reading process.env', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        env:
          TITLE: \${{ github.event.pull_request.title }}
        with:
          script: |
            core.info(process.env.TITLE)
`),
    ]);
    expect(githubScriptInjectionCheck.run(ctx).length).toBe(0);
  });
});

describe('supply-chain/unverified-remote-exec', () => {
  it('flags curl | bash', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/i.sh | bash
`),
    ]);
    expect(unverifiedRemoteExecCheck.run(ctx).length).toBe(1);
  });
  it('does not flag download-then-verify-then-run', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsSL -o i.sh https://example.com/i.sh
          sha256sum -c i.sh.sha256
          bash i.sh
`),
    ]);
    expect(unverifiedRemoteExecCheck.run(ctx).length).toBe(0);
  });
});

describe('dangerous-triggers/confused-deputy-automerge', () => {
  it('flags bot-gated auto-merge on pull_request_target', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Automerge
on: pull_request_target
jobs:
  m:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
`),
    ]);
    expect(confusedDeputyAutomergeCheck.run(ctx).length).toBe(1);
  });
  it('does not flag when fetch-metadata guards the merge', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Automerge
on: pull_request_target
jobs:
  m:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: dependabot/fetch-metadata@v2
      - run: gh pr merge --auto --squash "$PR_URL"
`),
    ]);
    expect(confusedDeputyAutomergeCheck.run(ctx).length).toBe(0);
  });

  it('still flags the risky job when a guard lives in a DIFFERENT job', () => {
    // Regression: a fetch-metadata step in an unrelated job must not suppress
    // the finding for the job that actually does the unguarded merge.
    const ctx = makeContext([
      makeWorkflow(`
name: Automerge
on: pull_request_target
jobs:
  meta-only:
    runs-on: ubuntu-latest
    steps:
      - uses: dependabot/fetch-metadata@v2
  risky:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
`),
    ]);
    expect(confusedDeputyAutomergeCheck.run(ctx).length).toBe(1);
  });
});

describe('secrets/debug-exposure', () => {
  it('flags action-tmate', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: mxschmitt/action-tmate@v3
`),
    ]);
    expect(debugExposureCheck.run(ctx).length).toBe(1);
  });
  it('does not flag a normal workflow', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
`),
    ]);
    expect(debugExposureCheck.run(ctx).length).toBe(0);
  });

  it('does not flag ACTIONS_STEP_DEBUG in a workflow env (not the real switch)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(debugExposureCheck.run(ctx).length).toBe(0);
  });

  it('does not flag a job that runs printenv (GitHub masks registered secrets)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: \${{ secrets.TOKEN }}
        run: printenv
`),
    ]);
    expect(debugExposureCheck.run(ctx).length).toBe(0);
  });
});

describe('supply-chain/typosquat-uses', () => {
  it('flags a near-miss of a popular action', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actons/checkout@v4
`),
    ]);
    const f = typosquatUsesCheck.run(ctx);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('high');
  });
  it('does not flag the exact popular action', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`),
    ]);
    expect(typosquatUsesCheck.run(ctx).length).toBe(0);
  });
});

describe('supply-chain/unpinned-tools', () => {
  it('flags setup-trivy with version: latest', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/setup-trivy@v0.2.0
        with:
          version: latest
`),
    ]);
    expect(unpinnedToolsCheck.run(ctx).length).toBe(1);
  });
  it('does not flag a pinned tool version', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/setup-trivy@v0.2.0
        with:
          version: v0.50.0
`),
    ]);
    expect(unpinnedToolsCheck.run(ctx).length).toBe(0);
  });
});
