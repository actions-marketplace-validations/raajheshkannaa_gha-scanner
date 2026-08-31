import { describe, it, expect } from 'vitest';
import { secretsInheritCheck } from '../../lib/scanner/checks/secrets-inherit';
import { makeContext, makeWorkflow } from '../helpers';

const check = secretsInheritCheck;

describe('secrets/secrets-inherit', () => {
  it('flags a reusable workflow call with secrets: inherit', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Caller
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].checkId).toBe('secrets/secrets-inherit');
  });

  it('flags secrets: inherit on a remote reusable workflow', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Caller
on: push
jobs:
  call:
    uses: some-org/shared/.github/workflows/deploy.yml@main
    secrets: inherit
`),
    ]);
    expect(check.run(ctx).length).toBe(1);
  });

  it('does not flag explicitly enumerated secrets', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Caller
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      TOKEN: \${{ secrets.TOKEN }}
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag normal jobs without reusable calls', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
