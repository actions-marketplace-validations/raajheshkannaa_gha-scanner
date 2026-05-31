import { describe, it, expect } from 'vitest';
import { hardcodedContainerCredentialsCheck } from '../../lib/scanner/checks/hardcoded-container-credentials';
import { makeContext, makeWorkflow } from '../helpers';

const check = hardcodedContainerCredentialsCheck;

describe('runner/hardcoded-container-credentials', () => {
  it('flags a hardcoded container registry password', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/acme/ci:1.2.3
      credentials:
        username: ci-bot
        password: hunter2supersecret
    steps:
      - run: echo hi
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].checkId).toBe('runner/hardcoded-container-credentials');
  });

  it('flags hardcoded credentials on a service container', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    services:
      registry:
        image: private/registry:2
        credentials:
          username: svc
          password: literalpassword123
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(1);
  });

  it('does not flag credentials sourced from secrets', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/acme/ci:1.2.3
      credentials:
        username: \${{ secrets.REGISTRY_USER }}
        password: \${{ secrets.REGISTRY_TOKEN }}
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
