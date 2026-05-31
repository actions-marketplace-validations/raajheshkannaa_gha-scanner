import { describe, it, expect } from 'vitest';
import { botConditionsCheck } from '../../lib/scanner/checks/bot-conditions';
import { makeContext, makeWorkflow } from '../helpers';

const check = botConditionsCheck;

describe('triggers/bot-conditions', () => {
  it('flags a job gated on github.actor == a bot login', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Auto-merge
on: pull_request_target
jobs:
  merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].checkId).toBe('triggers/bot-conditions');
  });

  it('flags a step gated on github.triggering_actor bot login', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: github.triggering_actor == 'renovate[bot]'
        run: ./privileged.sh
`),
    ]);
    expect(check.run(ctx).length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag non-actor conditions', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request
jobs:
  build:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag actor comparisons against non-bot logins', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    if: github.actor == 'octocat'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag a bot gate on a non-privileged trigger (push)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag an exclusion gate (actor != bot)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: pull_request_target
jobs:
  build:
    if: github.actor != 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
