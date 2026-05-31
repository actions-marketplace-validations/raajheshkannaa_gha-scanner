import { describe, it, expect } from 'vitest';
import { overprovisionedSecretsCheck } from '../../lib/scanner/checks/overprovisioned-secrets';
import { makeContext, makeWorkflow } from '../helpers';

const check = overprovisionedSecretsCheck;

describe('secrets/overprovisioned-secrets', () => {
  it('flags toJSON(secrets) whole-context serialization', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          ALL_SECRETS: \${{ toJSON(secrets) }}
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].checkId).toBe('secrets/overprovisioned-secrets');
  });

  it('flags the bare secrets context', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ secrets }}"
`),
    ]);
    expect(check.run(ctx).length).toBe(1);
  });

  it('does not flag a single named secret', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: \${{ secrets.DEPLOY_TOKEN }}
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
