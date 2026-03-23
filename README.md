# GHA Scanner

Static analysis for GitHub Actions workflows. Finds security misconfigurations, injection vulnerabilities, supply chain risks, and CI/CD hygiene issues.

25 checks. 8 categories. Results in seconds.

## Get Started

**Scan now (no install):** [scan.defensive.works](https://scan.defensive.works)

**From your terminal:**
```bash
git clone https://github.com/raajheshkannaa/gha-scanner.git
cd gha-scanner && npm install && npm run build:cli
GITHUB_TOKEN=ghp_your_token node dist/cli.js your-org/your-repo
```

**Via API:**
```bash
curl -X POST https://scan.defensive.works/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo":"your-org/your-repo"}'
```

## What It Does

Reads your `.github/workflows/` YAML files and checks them against 25 security rules derived from real attacks: tj-actions (CVE-2025-30066), Trivy supply chain compromise (2026), Shai Hulud worm, GhostAction campaign.

No code is executed. No agents are installed. It reads YAML and tells you what is wrong.

## Security Checks

25 checks across 8 categories:

### Supply Chain and Action Pinning

| Check | Severity | Description |
|-------|----------|-------------|
| Unpinned GitHub Actions | Medium | Actions pinned by semver tag instead of commit SHA |
| Actions Pinned to Mutable Branch Refs | High | Actions pinned to `main`, `master`, or other branch names |
| Known Vulnerable Actions | Critical | Actions with known CVEs or confirmed supply chain compromises |
| Docker Actions with Mutable Tags | High | Docker actions using `:latest` or no tag |

### Workflow Injection

| Check | Severity | Description |
|-------|----------|-------------|
| Event Expression in Run Block | Low | `${{ github.event.* }}` expressions used directly in shell scripts |
| Dangerous Context Variable in Run Block | Critical | Attacker-controlled context variables (`head.ref`, `title`, `body`) in run blocks |
| Workflow Dispatch Input in Run Block | Medium | `workflow_dispatch` inputs interpolated into shell commands |

### Dangerous Triggers

| Check | Severity | Description |
|-------|----------|-------------|
| pull_request_target with Head Checkout | Critical | Checks out PR head code with base branch permissions and secrets |
| pull_request_target with Secrets Access | High | Secrets accessible in workflows triggered by fork PRs |
| workflow_run with Artifact Download | Medium | Artifact poisoning vector via workflow_run trigger |

### Permissions

| Check | Severity | Description |
|-------|----------|-------------|
| Missing Top-Level Permissions | Medium | No explicit `permissions:` block, inherits potentially broad repo defaults |
| Overly Broad Permissions | High | `write-all` or 3+ write scopes granted to GITHUB_TOKEN |
| Missing Job-Level Permission Overrides | Medium | Broad top-level permissions not narrowed at job level |

### Secrets and Data Exposure

| Check | Severity | Description |
|-------|----------|-------------|
| Secrets Echoed to Logs | Critical | Secrets printed via `echo` or `printf` in run blocks |
| Secrets as Inline CLI Arguments | Medium | Secrets interpolated directly into shell commands instead of env vars |
| Git Credential Persistence in Checkout | Medium | `actions/checkout` without `persist-credentials: false` |
| Sensitive Files in Uploaded Artifacts | Medium | Artifact uploads matching sensitive file patterns (.env, .pem, .key) |

### Runner Security

| Check | Severity | Description |
|-------|----------|-------------|
| Self-Hosted Runner on pull_request | Critical | Fork PRs can execute arbitrary code on self-hosted infrastructure |
| Self-Hosted Runner with Untrusted Triggers | High | Self-hosted runners used with external input triggers |
| Privileged Docker Execution | High | `--privileged` flag or Docker socket mounting in run blocks |

### CI/CD Hygiene

| Check | Severity | Description |
|-------|----------|-------------|
| No Concurrency Controls | Info | Missing `concurrency:` group allows duplicate workflow runs |
| No Job Timeout Defined | Info | Missing `timeout-minutes` defaults to 6-hour timeout |
| Steps with continue-on-error | Medium | `continue-on-error: true` can silently mask security check failures |

### Best Practices

| Check | Severity | Description |
|-------|----------|-------------|
| No Dependabot for GitHub Actions | Medium | Missing or incomplete Dependabot configuration for actions ecosystem |
| No CODEOWNERS for Workflow Files | Low | No mandatory code review for workflow file changes |

## Usage

### Web

Go to [scan.defensive.works](https://scan.defensive.works), enter any public repo, get results.

### CLI

```bash
GITHUB_TOKEN=ghp_xxx node dist/cli.js facebook/react           # Colored terminal output
GITHUB_TOKEN=ghp_xxx node dist/cli.js owner/repo --json        # JSON (for CI pipelines)
GITHUB_TOKEN=ghp_xxx node dist/cli.js owner/repo --markdown    # Markdown (for PRs/docs)
```

Exit codes: `0` clean, `1` critical/high findings found, `2` error.

### API

```bash
curl -X POST https://scan.defensive.works/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo":"owner/repo"}'
```

Returns a `ScanResult` JSON object with score, grade, findings, and category breakdowns.

## How It Works

- **YAML parsing, not code execution.** The scanner reads workflow files and parses them as structured data. No workflows are triggered or executed.
- **Pattern matching against known-bad configurations.** Each check implements a `run` function that inspects the parsed workflow AST for specific anti-patterns, dangerous triggers, and risky permission configurations.
- **CVE database of compromised actions.** A curated list of GitHub Actions with confirmed supply chain compromises is cross-referenced against every `uses:` declaration in your workflows.
- **Weighted scoring model.** Each finding contributes its severity weight (critical: 10, high: 7, medium: 4, low: 2, info: 0), capped at 3 findings per check. The score is calculated as a ratio of failed weight to maximum possible weight, producing a 0-100 score.
- **GitHub API integration.** Fetches workflow files, Dependabot config, and CODEOWNERS via the GitHub API. Works with both authenticated and unauthenticated requests.

## Real-World Validation

Scan results for well-known open-source repositories (as of March 2026):

| Repository | Grade | Score | Findings | Notable |
|------------|-------|-------|----------|---------|
| facebook/react | B | 80/100 | 79 | Solid baseline, mostly unpinned actions |
| vercel/next.js | D | 68/100 | 103 | 4 critical findings |
| grafana/grafana | C | 79/100 | 84 | Catches tj-actions CVE-2025-30066 |
| prometheus/prometheus | A | 93/100 | 29 | Well-maintained workflow security |
| messypoutine/gravy-overflow | C | 70/100 | 24 | Deliberately vulnerable test repo, 6 critical |

## Self-Hosting

GHA Scanner is a Next.js application. Deploy it to Vercel, any Node.js host, or run it locally.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Recommended | GitHub personal access token for higher API rate limits (60/hr without, 5000/hr with) |
| `UPSTASH_REDIS_REST_URL` | Optional | Upstash Redis URL for rate limiting |
| `UPSTASH_REDIS_REST_TOKEN` | Optional | Upstash Redis token for rate limiting |

### Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/raajheshkannaa/gha-scanner)

### Run Locally

```bash
git clone https://github.com/raajheshkannaa/gha-scanner.git
cd gha-scanner
npm install
npm run dev
```

Open `http://localhost:3000` in your browser.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new security checks, update the vulnerable actions database, and submit pull requests.

## License

[MIT](LICENSE)
