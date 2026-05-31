# Security Checks

46 checks across 8 categories.

## Supply Chain and Action Pinning

| Check | Severity | Description |
|-------|----------|-------------|
| Unpinned GitHub Actions | Medium | Actions pinned by semver tag instead of commit SHA |
| Actions Pinned to Mutable Branch Refs | High | Actions pinned to `main`, `master`, or other branch names |
| Known Vulnerable Actions | Critical | Actions with known CVEs or confirmed supply chain compromises |
| Docker Actions with Mutable Tags | High | Docker actions using `:latest` or no tag |
| Cache Poisoning | High | Cache key/restore-key overlap between fork-reachable and trusted workflows |
| Unpinned Container Images | Medium | Job `container`/`services` images by mutable tag instead of `@sha256` digest |
| Dependabot Insecure External Code Execution | High | `insecure-external-code-execution: allow` in dependabot.yml |
| Unverified Remote Script Execution | Medium | `curl ... \| bash` and similar piping a download straight into an interpreter |
| Possible Typosquatted Action | High | `uses:` a tiny edit-distance from a popular action but not an exact match |
| Unpinned External Tool Version | Medium | Setup actions (setup-trivy, load-secrets) with missing/`latest`/dynamic `version` |

## Workflow Injection

| Check | Severity | Description |
|-------|----------|-------------|
| Event Expression in Run Block | Low | `${{ github.event.* }}` expressions used directly in shell scripts |
| Dangerous Context Variable in Run Block | Critical | Attacker-controlled context variables (`head.ref`, `title`, `body`) in run blocks |
| Workflow Dispatch Input in Run Block | Medium | `workflow_dispatch` inputs interpolated into shell commands |
| Environment Injection via GITHUB_ENV/GITHUB_PATH | High/Critical | Untrusted expressions written into `$GITHUB_ENV` or `$GITHUB_PATH` |
| Deprecated Insecure Workflow Commands | High | `ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables `set-env`/`add-path` (CVE-2020-15228) |
| Untrusted Input in actions/github-script | High/Critical | Attacker-controllable `github.event.*` interpolated into a github-script JS body |

## Dangerous Triggers

| Check | Severity | Description |
|-------|----------|-------------|
| pull_request_target with Head Checkout | Critical | Checks out PR head code with base branch permissions and secrets |
| pull_request_target with Secrets Access | High | Secrets accessible in workflows triggered by fork PRs |
| workflow_run with Artifact Download | Medium | Artifact poisoning vector via workflow_run trigger |
| Spoofable Bot Actor Condition | High | `if:` trusting a bot via spoofable `github.actor`/`triggering_actor` |
| Always-True if: Condition | High | Block-scalar/trailing-newline `if:` that GitHub evaluates as a truthy string |
| Unsound contains() Allowlist | High | `contains('a b c', userInput)` substring match used as a bypassable allowlist |
| Bot-Gated Auto-Merge on Privileged Trigger | High | Auto-merge gated only on a bot actor, no fetch-metadata/fork check |

## Permissions

| Check | Severity | Description |
|-------|----------|-------------|
| Missing Top-Level Permissions | Medium | No explicit `permissions:` block, inherits potentially broad repo defaults |
| Overly Broad Permissions | High | `write-all` or 3+ write scopes granted to GITHUB_TOKEN |
| Missing Job-Level Permission Overrides | Medium | Broad top-level permissions not narrowed at job level |
| OIDC Token Issuance Overscope | High/Critical | `id-token: write` without job scoping or environment protection |
| Over-Scoped GitHub App Token | High | `create-github-app-token` skipping revoke, omitting repo scope, or all permissions |
| Token-Based Publishing Instead of Trusted Publishing | Info | Package publish via stored token where OIDC trusted publishing is available |

## Secrets and Data Exposure

| Check | Severity | Description |
|-------|----------|-------------|
| Secrets Echoed to Logs | Critical | Secrets printed via `echo` or `printf` in run blocks |
| Secrets as Inline CLI Arguments | Medium | Secrets interpolated directly into shell commands instead of env vars |
| Git Credential Persistence in Checkout | Medium | `actions/checkout` without `persist-credentials: false` |
| Sensitive Files in Uploaded Artifacts | Medium | Artifact uploads matching sensitive file patterns (.env, .pem, .key) |
| Reusable Workflow Called with secrets: inherit | Medium | Forwards all caller secrets to the callee instead of only what it needs |
| Whole Secrets Context Exposed | High | `toJSON(secrets)` or the bare `secrets` context serializes every secret |
| Secret Decoded Past Log Redaction | Medium | `fromJSON(secrets.X)` produces values GitHub no longer redacts |
| Interactive Debug or Env Dump Exposure | Medium | action-tmate, committed debug-logging flags, or env/printenv with secrets |

## Runner Security

| Check | Severity | Description |
|-------|----------|-------------|
| Self-Hosted Runner on pull_request | Critical | Fork PRs can execute arbitrary code on self-hosted infrastructure |
| Self-Hosted Runner with Untrusted Triggers | High | Self-hosted runners used with external input triggers |
| Privileged Docker Execution | High | `--privileged` flag or Docker socket mounting in run blocks |
| Hardcoded Container Registry Credentials | High | Literal `container`/`services` credentials instead of `${{ secrets.* }}` |

## CI/CD Hygiene

| Check | Severity | Description |
|-------|----------|-------------|
| No Concurrency Controls | Info | Missing `concurrency:` group allows duplicate workflow runs |
| No Job Timeout Defined | Info | Missing `timeout-minutes` defaults to 6-hour timeout |
| Steps with continue-on-error | Medium | `continue-on-error: true` can silently mask security check failures |

## Best Practices

| Check | Severity | Description |
|-------|----------|-------------|
| No Dependabot for GitHub Actions | Medium | Missing or incomplete Dependabot configuration for actions ecosystem |
| No CODEOWNERS for Workflow Files | Low | No mandatory code review for workflow file changes |

## Coverage relative to zizmor

GHA Scanner aims to match [zizmor](https://github.com/zizmorcore/zizmor)'s default
(non-pedantic) audit set within a pure-YAML engine, and adds web-UI grading plus
several checks drawn from poutine, octoscan, and 2024-2026 incident research
(unsound conditions, bot-gated auto-merge, unverified remote execution, github-script
injection, debug exposure).

A few zizmor audits require resolving action refs against the GitHub API (impostor
commits, ref confusion, stale action refs). Those are not yet implemented here because
the engine is offline/static; `known-vulnerable` is covered by a local CVE database
instead of the live GitHub advisory API. zizmor's pedantic/auditor-only audits
(anonymous-definition, undocumented-permissions, secrets-outside-env, and similar) are
intentionally omitted since they do not fire in zizmor's default output either.

## Scoring

Each finding contributes its severity weight, capped at 3 findings per check:

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 2 |
| Info | 0 |

Score = `100 * (1 - failedWeight / maxPossibleWeight)`

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |
