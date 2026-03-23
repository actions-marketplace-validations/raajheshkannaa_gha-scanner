import { describe, it, expect } from 'vitest';
import { runScan } from '../lib/scanner/engine';
import { makeContext, makeWorkflow } from './helpers';

describe('runScan', () => {
  it('warns when no workflow files found', () => {
    const ctx = makeContext([]);
    const result = runScan(ctx);
    expect(result.warnings).toContain(
      'No workflow files found in this repository. Score reflects the absence of workflows, not their security.'
    );
    expect(result.workflowCount).toBe(0);
  });

  it('marks partial true and includes warnings when workflow fails to parse', () => {
    const ctx = makeContext([
      {
        content: '{{invalid yaml',
        parsed: null,  // simulates parse failure
      },
    ]);
    ctx.parseWarnings.push('test-0.yml: YAML parse error');
    const result = runScan(ctx);
    expect(result.partial).toBe(true);
    expect(result.warnings.some(w => w.includes('parse error'))).toBe(true);
  });

  it('produces a complete scan result for a normal workflow', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
      - run: echo "hello"
`)]);
    const result = runScan(ctx);
    expect(result.partial).toBe(false);
    expect(result.schemaVersion).toBe(1);
    expect(result.repo).toBe('test-owner/test-repo');
    expect(result.totalChecks).toBeGreaterThan(0);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.categories.length).toBeGreaterThan(0);
    expect(typeof result.grade).toBe('string');
  });

  it('counts findings correctly across checks', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "\${{ github.event.issue.title }}"
`)]);
    const result = runScan(ctx);
    // Should have at least the unpinned-actions + dangerous-contexts findings
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });
});

describe('inline suppression', () => {
  it('suppresses a finding when explicit check ID matches', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # gha-scanner-ignore: supply-chain/unpinned-actions
`)]);
    const result = runScan(ctx);
    const unpinned = result.findings.filter(f => f.checkId === 'supply-chain/unpinned-actions');
    expect(unpinned.length).toBe(0);
    expect(result.warnings.some(w => w.includes('suppressed'))).toBe(true);
  });

  it('does NOT suppress when check ID does not match', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # gha-scanner-ignore: injection/dangerous-contexts
`)]);
    const result = runScan(ctx);
    const unpinned = result.findings.filter(f => f.checkId === 'supply-chain/unpinned-actions');
    expect(unpinned.length).toBeGreaterThan(0);
  });

  it('does NOT allow blanket suppression without check ID', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # gha-scanner-ignore
`)]);
    const result = runScan(ctx);
    // Blanket ignore should NOT work, findings should remain
    const unpinned = result.findings.filter(f => f.checkId === 'supply-chain/unpinned-actions');
    expect(unpinned.length).toBeGreaterThan(0);
  });

  it('suppresses when comment is on the line above', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # gha-scanner-ignore: supply-chain/unpinned-actions
      - uses: actions/checkout@v4
`)]);
    const result = runScan(ctx);
    const unpinned = result.findings.filter(f => f.checkId === 'supply-chain/unpinned-actions');
    expect(unpinned.length).toBe(0);
  });

  it('does NOT suppress when comment is two lines above', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # gha-scanner-ignore: supply-chain/unpinned-actions

      - uses: actions/checkout@v4
`)]);
    const result = runScan(ctx);
    const unpinned = result.findings.filter(f => f.checkId === 'supply-chain/unpinned-actions');
    expect(unpinned.length).toBeGreaterThan(0);
  });
});
