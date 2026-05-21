import { describe, it, expect } from 'vitest';
import { oidcOverscopeCheck, detectPublishingPattern } from '../../lib/scanner/checks/oidc-overscope';
import { permissionsChecks } from '../../lib/scanner/checks/permissions';
import { allChecks } from '../../lib/scanner/checks';
import { makeContext, makeWorkflow } from '../helpers';

describe('oidc-overscope wiring', () => {
  it('is registered in permissionsChecks', () => {
    expect(permissionsChecks.some(c => c.id === 'permissions/oidc-overscope')).toBe(true);
  });
  it('is reachable via allChecks (top-level registry)', () => {
    expect(allChecks.some(c => c.id === 'permissions/oidc-overscope')).toBe(true);
  });
});

const check = oidcOverscopeCheck;

describe('detectPublishingPattern (helper)', () => {
  const jobWithStep = (step: Record<string, unknown>) => ({
    name: 'publish',
    raw: {},
    permissions: { 'id-token': 'write' },
    hasIdTokenWrite: true,
    environment: undefined,
    steps: [step],
  });

  it('matches actions/setup-node with registry-url ONLY when an npm/pnpm/yarn command appears in same job', () => {
    // setup-node alone is NOT a publish signal — used legitimately for scoped installs.
    const justSetupNode = detectPublishingPattern(jobWithStep({
      uses: 'actions/setup-node@v4',
      with: { 'registry-url': 'https://registry.npmjs.org' },
    }));
    expect(justSetupNode.matched).toBe(false);
  });

  it('matches setup-node + registry-url WITH `npm run publish` script in same job (fallback signal)', () => {
    const r = detectPublishingPattern({
      name: 'publish',
      raw: {},
      permissions: { 'id-token': 'write' },
      hasIdTokenWrite: true,
      environment: undefined,
      steps: [
        { uses: 'actions/setup-node@v4', with: { 'registry-url': 'https://registry.npmjs.org' } },
        { run: 'npm ci && npm run publish' },
      ],
    });
    expect(r.matched).toBe(true);
    expect(r.signal).toContain('setup-node');
  });

  it('does NOT match hyphenated lookalikes like `npm publish-package` (word-boundary edge case)', () => {
    // `publish-package` is not a real npm command, but the regex must not
    // false-match on it. Confirms `(?=\s|$)` boundary is honored, not `\b`.
    const r = detectPublishingPattern({
      name: 'build',
      raw: {},
      permissions: { 'id-token': 'write' },
      hasIdTokenWrite: true,
      environment: undefined,
      steps: [
        { run: 'npm publish-package some-script' },
      ],
    });
    expect(r.matched).toBe(false);
  });

  it('does NOT match setup-node + registry-url + only `npm ci` / `npm test` (install/test only)', () => {
    const r = detectPublishingPattern({
      name: 'build',
      raw: {},
      permissions: { 'id-token': 'write' },
      hasIdTokenWrite: true,
      environment: undefined,
      steps: [
        { uses: 'actions/setup-node@v4', with: { 'registry-url': 'https://npm.pkg.github.com' } },
        { run: 'npm ci' },
        { run: 'npm test' },
      ],
    });
    expect(r.matched).toBe(false);
  });

  it('matches pypa/gh-action-pypi-publish', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'pypa/gh-action-pypi-publish@release/v1' }));
    expect(r.matched).toBe(true);
  });

  it('matches aws-actions/configure-aws-credentials', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'aws-actions/configure-aws-credentials@v4' }));
    expect(r.matched).toBe(true);
    expect(r.signal).toContain('AWS');
  });

  it('matches google-github-actions/auth', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'google-github-actions/auth@v2' }));
    expect(r.matched).toBe(true);
    expect(r.signal).toContain('GCP');
  });

  it('matches azure/login', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'azure/login@v2' }));
    expect(r.matched).toBe(true);
    expect(r.signal).toContain('Azure');
  });

  it('matches npm publish in run block', () => {
    const r = detectPublishingPattern(jobWithStep({ run: 'pnpm install && npm publish --provenance' }));
    expect(r.matched).toBe(true);
    expect(r.signal).toContain('npm publish');
  });

  it('matches pnpm publish in run block', () => {
    const r = detectPublishingPattern(jobWithStep({ run: 'pnpm publish' }));
    expect(r.matched).toBe(true);
  });

  it('matches twine upload', () => {
    const r = detectPublishingPattern(jobWithStep({ run: 'python -m twine upload dist/*' }));
    expect(r.matched).toBe(true);
  });

  it('matches cargo publish', () => {
    const r = detectPublishingPattern(jobWithStep({ run: 'cargo publish' }));
    expect(r.matched).toBe(true);
  });

  it('does not match unrelated steps', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'actions/checkout@v4' }));
    expect(r.matched).toBe(false);
  });

  it('does not match setup-node without registry-url', () => {
    const r = detectPublishingPattern(jobWithStep({ uses: 'actions/setup-node@v4', with: { 'node-version': '20' } }));
    expect(r.matched).toBe(false);
  });
});

describe('permissions/oidc-overscope', () => {
  // --- Rule 1: workflow-scope id-token: write ---

  it('rule 1: flags workflow-scope id-token: write as HIGH', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Build
on: push
permissions:
  id-token: write
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{ run: echo test }]
  publish:
    runs-on: ubuntu-latest
    environment: production
    steps: [{ run: npm publish }]
`),
    ]);
    const findings = check.run(ctx);
    const r1 = findings.find(f => f.title.includes('workflow scope'));
    expect(r1).toBeDefined();
    expect(r1!.severity).toBe('high');
  });

  it('rule 1: does NOT flag workflow scope without id-token: write', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Build
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{ run: echo test }]
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('rule 1: flags workflow scope write-all', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Build
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{ run: echo test }]
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.some(f => f.title.includes('workflow scope'))).toBe(true);
  });

  // --- Rule 2: job-scope id-token: write without environment ---

  it('rule 2: flags job-scope id-token: write with no environment as HIGH', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC Job
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: curl example.com
`),
    ]);
    const findings = check.run(ctx);
    const r2 = findings.find(f => f.title.includes('no environment gate'));
    expect(r2).toBeDefined();
    expect(r2!.severity).toBe('high');
  });

  it('rule 2: does NOT flag job with id-token: write AND environment set', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC Job
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    environment: production
    steps:
      - run: curl example.com
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('rule 2: accepts environment as object form (with url)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC Job
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    environment:
      name: production
      url: https://example.com
    steps:
      - run: echo deploying
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('rule 2: finding text explicitly states env-presence is checked, reviewers must be verified out-of-band', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC Job
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo
`),
    ]);
    const findings = check.run(ctx);
    const r2 = findings.find(f => f.title.includes('no environment gate'));
    expect(r2).toBeDefined();
    expect(r2!.remediation.toLowerCase()).toContain('out-of-band');
    expect(r2!.remediation.toLowerCase()).toContain('required reviewers');
  });

  // --- Rule 3: trusted-publishing without environment → CRITICAL ---

  it('rule 3: flags npm publish + id-token: write without environment as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on:
  push:
    branches: [main]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
      - run: npm publish --provenance
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.title.toLowerCase().includes('trusted-publishing'));
    expect(r3).toBeDefined();
    expect(r3!.severity).toBe('critical');
    expect(r3!.description).toContain('May 2026');
  });

  it('rule 3: does NOT flag trusted-publishing job WITH environment', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on:
  push:
    branches: [main]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    environment: production
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
      - run: npm publish
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('rule 3: flags PyPI trusted publishing without environment as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.title.toLowerCase().includes('trusted-publishing'));
    expect(r3).toBeDefined();
    expect(r3!.severity).toBe('critical');
  });

  it('rule 3: flags AWS OIDC exchange without environment as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: us-east-1
      - run: aws s3 sync . s3://bucket/
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.title.toLowerCase().includes('trusted-publishing'));
    expect(r3).toBeDefined();
    expect(r3!.severity).toBe('critical');
  });

  // --- Negative cases ---

  it('does NOT flag jobs without id-token: write', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps: [{ run: npm test }]
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('skips reusable workflows (workflow_call only)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Reusable Publish
on: workflow_call
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: npm publish
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('DOES flag workflow with workflow_call + push triggers (mixed reusable+non-reusable analyzed normally)', () => {
    // Not pure workflow_call — should be analyzed normally.
    const ctx = makeContext([
      makeWorkflow(`
name: Maybe Reusable
on: [workflow_call, push]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: npm publish
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // --- Severity calibration / dedup ---

  it('dedups: workflow-scope id-token + job-scope environment-missing produces both findings (different rules)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Both
on: push
permissions:
  id-token: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
`),
    ]);
    const findings = check.run(ctx);
    // Rule 1 fires (workflow scope).
    expect(findings.some(f => f.title.includes('workflow scope'))).toBe(true);
    // Rule 3 also fires because the job inherits id-token: write and has a publish pattern + no environment.
    expect(findings.some(f => f.severity === 'critical')).toBe(true);
  });

  // --- Environment object-form validation ---

  it('environment as empty object {} does NOT count as protection', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    environment: {}
    steps:
      - run: echo
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('environment object with only `url` (no name) does NOT count as protection', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    environment:
      url: https://example.com
    steps:
      - run: echo
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('environment with empty-string name does NOT count as protection', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: OIDC
on: push
jobs:
  auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    environment:
      name: ""
      url: https://example.com
    steps:
      - run: echo
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // --- setup-node + registry-url false-positive guard ---

  it('rule 3: setup-node + registry-url alone (scoped install, no publish) does NOT trigger R3', () => {
    // A job that uses setup-node with registry-url to install from a private
    // registry but never publishes. Should NOT be flagged as trusted-publishing.
    // Should still get R2 (id-token: write without environment).
    const ctx = makeContext([
      makeWorkflow(`
name: Install
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          registry-url: https://npm.pkg.github.com
          node-version: '20'
      - run: echo "just running tests"
`),
    ]);
    const findings = check.run(ctx);
    // Should only have R2, NOT R3.
    expect(findings.find(f => f.severity === 'critical')).toBeUndefined();
    expect(findings.find(f => f.severity === 'high')).toBeDefined();
  });

  it('rule 3: setup-node + registry-url + `npm ci` (install only, no publish) does NOT trigger R3', () => {
    // Scoped install pattern. Job uses setup-node to authenticate to a private
    // registry, then `npm ci` to install. No publish verb anywhere. Should
    // only get R2 (id-token: write without environment), not R3 CRITICAL.
    const ctx = makeContext([
      makeWorkflow(`
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          registry-url: https://npm.pkg.github.com
          node-version: '20'
      - run: npm ci
      - run: npm test
`),
    ]);
    const findings = check.run(ctx);
    // R2 expected (high), R3 should NOT fire.
    expect(findings.find(f => f.severity === 'critical')).toBeUndefined();
    expect(findings.find(f => f.severity === 'high')).toBeDefined();
  });

  it('rule 3: setup-node + registry-url WITH `npm run publish` script DOES trigger R3', () => {
    // Common pattern: workflow doesn't call `npm publish` directly, instead
    // runs a release script via `npm run release` or `npm run publish`.
    // This is the May 11 attack shape when publish is hidden behind a script.
    const ctx = makeContext([
      makeWorkflow(`
name: Publish via Script
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
          node-version: '20'
      - run: npm ci
      - run: npm run publish
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.find(f => f.severity === 'critical')).toBeDefined();
  });

  it('rule 3: setup-node + registry-url WITH `pnpm release` script DOES trigger R3', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/setup-node@v4
        with:
          registry-url: https://registry.npmjs.org
      - run: pnpm release
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.find(f => f.severity === 'critical')).toBeDefined();
  });

  // --- yarn npm publish (Berry) ---

  it('rule 3: yarn npm publish (Berry) triggers R3 as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: yarn npm publish --access public
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.severity === 'critical');
    expect(r3).toBeDefined();
    expect(r3!.evidence).toContain('yarn npm publish');
  });

  // --- Positive-path R3 tests for cargo/gem/gcp/azure (full check output) ---

  it('rule 3: cargo publish triggers R3 as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release Crate
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: cargo publish --token \${{ secrets.CARGO_TOKEN }}
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.find(f => f.severity === 'critical')).toBeDefined();
  });

  it('rule 3: gem push triggers R3 as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release Gem
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: gem push my-gem-1.0.0.gem
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.find(f => f.severity === 'critical')).toBeDefined();
  });

  it('rule 3: google-github-actions/auth triggers R3 as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Deploy to GCP
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/pool/providers/provider'
          service_account: deploy@example.iam.gserviceaccount.com
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.severity === 'critical');
    expect(r3).toBeDefined();
    expect(r3!.evidence).toContain('GCP');
  });

  it('rule 3: azure/login triggers R3 as CRITICAL', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Deploy to Azure
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: azure/login@v2
        with:
          client-id: \${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: \${{ secrets.AZURE_TENANT_ID }}
          subscription-id: \${{ secrets.AZURE_SUBSCRIPTION_ID }}
`),
    ]);
    const findings = check.run(ctx);
    const r3 = findings.find(f => f.severity === 'critical');
    expect(r3).toBeDefined();
    expect(r3!.evidence).toContain('Azure');
  });

  it('per-job dedup: same job does not produce two findings', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: npm publish
`),
    ]);
    const findings = check.run(ctx);
    // Only one finding per job (rule 3 in this case, not rule 2 as well).
    const jobFindings = findings.filter(f => f.evidence.includes('job: publish'));
    expect(jobFindings.length).toBe(1);
  });
});
