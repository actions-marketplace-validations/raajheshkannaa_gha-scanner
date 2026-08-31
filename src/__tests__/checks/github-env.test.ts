import { describe, it, expect } from 'vitest';
import { githubEnvCheck } from '../../lib/scanner/checks/github-env';
import { makeContext, makeWorkflow } from '../helpers';

const check = githubEnvCheck;

describe('injection/github-env', () => {
  it('flags writing an attacker-controlled context to $GITHUB_ENV (critical)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE=\${{ github.event.issue.title }}" >> "$GITHUB_ENV"
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].checkId).toBe('injection/github-env');
  });

  it('flags writing an attacker-controlled context to $GITHUB_PATH', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.pull_request.head.ref }}/bin" >> $GITHUB_PATH
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('does not flag writing trusted event metadata (base.sha) to $GITHUB_ENV', () => {
    // Regression: constrained/trusted fields must not be treated as injection.
    const ctx = makeContext([
      makeWorkflow(`
name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "BASE=\${{ github.event.pull_request.base.sha }}" >> "$GITHUB_ENV"
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('flags an untrusted write split across a shell line-continuation', () => {
    const ctx = makeContext([
      makeWorkflow(
        'name: PR\n' +
        'on: pull_request_target\n' +
        'jobs:\n' +
        '  build:\n' +
        '    runs-on: ubuntu-latest\n' +
        '    steps:\n' +
        '      - run: |\n' +
        '          echo "DATA=${{ github.event.issue.title }}" \\\n' +
        '            >> $GITHUB_ENV\n'
      ),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('does not flag a static write to $GITHUB_ENV', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "NODE_ENV=production" >> "$GITHUB_ENV"
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag a run block that has no GITHUB_ENV/GITHUB_PATH write', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.issue.title }}"
`),
    ]);
    // This is caught by other injection checks, not github-env.
    expect(check.run(ctx).length).toBe(0);
  });

  it('flags a mixed format() expression combining a safe symbol with a dangerous context', () => {
    // The safe github.sha must not whitelist the dangerous issue.title; the
    // brace-aware extraction must see past the {0}/{1} placeholders.
    const ctx = makeContext([
      makeWorkflow(`
name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "X=\${{ format('{0}-{1}', github.sha, github.event.issue.title) }}" >> "$GITHUB_ENV"
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('does not flag when the untrusted expression is on a different line than the env write', () => {
    // Regression: an unrelated echo of an expression plus a separate static
    // env write must not be reported as env injection.
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "log: \${{ github.event.issue.title }}"
          echo "NODE_ENV=production" >> "$GITHUB_ENV"
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
