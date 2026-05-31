/**
 * A curated list of widely-used GitHub Actions (owner/repo, lowercased).
 * Used by supply-chain/typosquat-uses to flag references that are a tiny
 * edit-distance away from a popular action (likely a typosquat) without
 * being an exact match. This is a static, offline corpus — it is not
 * exhaustive, and a YAML-only scanner cannot confirm whether the
 * look-alike repo actually exists, so findings are framed as "verify".
 */
export const POPULAR_ACTIONS: string[] = [
  'actions/checkout',
  'actions/setup-node',
  'actions/setup-python',
  'actions/setup-java',
  'actions/setup-go',
  'actions/setup-dotnet',
  'actions/cache',
  'actions/upload-artifact',
  'actions/download-artifact',
  'actions/github-script',
  'actions/configure-pages',
  'actions/deploy-pages',
  'actions/upload-pages-artifact',
  'actions/create-github-app-token',
  'actions/stale',
  'actions/labeler',
  'actions/dependency-review-action',
  'actions/attest-build-provenance',
  'docker/setup-buildx-action',
  'docker/setup-qemu-action',
  'docker/build-push-action',
  'docker/login-action',
  'docker/metadata-action',
  'aws-actions/configure-aws-credentials',
  'azure/login',
  'google-github-actions/auth',
  'hashicorp/setup-terraform',
  'pnpm/action-setup',
  'ruby/setup-ruby',
  'astral-sh/setup-uv',
  'dtolnay/rust-toolchain',
  'swatinem/rust-cache',
  'softprops/action-gh-release',
  'ncipollo/release-action',
  'peter-evans/create-pull-request',
  'pypa/gh-action-pypi-publish',
  'codecov/codecov-action',
  'github/codeql-action',
  'step-security/harden-runner',
  'goreleaser/goreleaser-action',
  'gradle/actions',
  'golangci/golangci-lint-action',
  'treosh/lighthouse-ci-action',
  'jamesives/github-pages-deploy-action',
];
