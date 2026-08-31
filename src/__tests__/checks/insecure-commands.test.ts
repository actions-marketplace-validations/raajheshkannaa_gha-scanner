import { describe, it, expect } from 'vitest';
import { insecureCommandsCheck } from '../../lib/scanner/checks/insecure-commands';
import { makeContext, makeWorkflow } from '../helpers';

const check = insecureCommandsCheck;

describe('injection/insecure-commands', () => {
  it('flags ACTIONS_ALLOW_UNSECURE_COMMANDS at step level', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-env name=FOO::bar"
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].checkId).toBe('injection/insecure-commands');
  });

  it('flags ACTIONS_ALLOW_UNSECURE_COMMANDS at workflow level', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(1);
  });

  it('does not flag when the variable is absent', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          NODE_ENV: production
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag when explicitly set to false', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: false
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
