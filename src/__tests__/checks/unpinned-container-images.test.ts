import { describe, it, expect } from 'vitest';
import { unpinnedContainerImagesCheck } from '../../lib/scanner/checks/unpinned-container-images';
import { makeContext, makeWorkflow } from '../helpers';

const check = unpinnedContainerImagesCheck;

describe('supply-chain/unpinned-container-images', () => {
  it('flags a job container image pinned by tag (string form)', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:18
    steps:
      - run: node --version
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].checkId).toBe('supply-chain/unpinned-container-images');
  });

  it('flags an implicit-latest service image at high severity', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    services:
      db:
        image: postgres
    steps:
      - run: echo hi
`),
    ]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not flag an image pinned by digest', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:18@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    steps:
      - run: node --version
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });

  it('does not flag an image provided via expression', () => {
    const ctx = makeContext([
      makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: \${{ matrix.image }}
    steps:
      - run: echo hi
`),
    ]);
    expect(check.run(ctx).length).toBe(0);
  });
});
