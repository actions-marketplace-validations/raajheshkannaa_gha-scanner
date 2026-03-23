# Contributing

## Adding a New Check

The scanner is designed so that adding a new check requires minimal boilerplate. All checks live in category files under `src/lib/scanner/checks/`.

### Step by step

1. Open the appropriate category file in `src/lib/scanner/checks/` (e.g., `supply-chain.ts`, `injection.ts`, `permissions.ts`).
2. Add a new `CheckDefinition` object to the category's exported array.
3. Implement the `run()` function that takes a `RepoContext` and returns `Finding[]`.
4. The check is automatically registered. No changes needed in `index.ts` or anywhere else.
5. Test against real public repositories.

### Check Definition Structure

```typescript
interface CheckDefinition {
  id: string;            // Semantic ID: "category/check-name"
  name: string;          // Human-readable name
  description: string;   // What the check detects
  category: Category;    // Must match the file's category
  severity: Severity;    // critical | high | medium | low | info
  run: (context: RepoContext) => Finding[];
}
```

Each finding returned by `run()` must include:

```typescript
interface Finding {
  checkId: string;       // Same as the check's id
  severity: Severity;    // Can differ from check default (e.g., lower for same-org actions)
  category: Category;
  title: string;         // One-line summary of the specific finding
  description: string;   // What was found and where
  risk: string;          // Why this matters, with real-world context
  remediation: string;   // How to fix it, with code examples
  file: string;          // Workflow file path
  line?: number;         // Line number in the file (use findLineNumber)
  evidence: string;      // The specific code/config that triggered the finding
}
```

### Writing Detection Logic

The `RepoContext` provides:

- `context.workflows[]` - Array of workflow files, each with `path`, `name`, `content` (raw YAML string), and `parsed` (parsed YAML as object, or `null` if parsing failed).
- `context.owner` / `context.repo` - Repository identifiers.
- `context.hasDependabot` / `context.dependabotConfig` - Dependabot status and parsed config.
- `context.hasCodeowners` / `context.codeownersContent` - CODEOWNERS status and raw content.

Common patterns:

```typescript
// Access parsed YAML structure
const jobs = workflow.parsed?.jobs as Record<string, unknown>;

// Search raw content for patterns
const matches = workflow.content.match(/pattern/g);

// Get line numbers for findings
import { findLineNumber } from '../parser';
const line = findLineNumber(workflow.content, 'search-string');

// Always handle null parsed gracefully
if (!workflow.parsed) continue;
```

### Severity Guidelines

| Severity | Criteria | Score Weight |
|----------|----------|--------------|
| critical | Directly exploitable by an external attacker with no preconditions. Enables secret theft, code execution, or full pipeline compromise. | 10 |
| high | Exploitable with some preconditions (e.g., requires write access, specific trigger combination). Significant blast radius. | 7 |
| medium | Best practice violation with concrete security implications. Not directly exploitable but increases attack surface or blast radius. | 4 |
| low | Hardening recommendation. Improves security posture but absence is not directly exploitable. | 2 |
| info | Informational observation. Does not affect the score. Useful context for security-conscious teams. | 0 |

When in doubt, err toward the higher severity. It is better to flag something the user can dismiss than to miss a real issue.

### Updating the CVE Database

Known vulnerable actions are tracked in `src/lib/scanner/data/known-vulnerable-actions.ts`. To add a new entry:

```typescript
{
  action: 'owner/action-name',           // Full action path
  affectedVersions: '< 2.0.0',           // Human-readable version range
  cveId: 'CVE-YYYY-NNNNN',              // Optional, if assigned
  disclosedDate: 'YYYY-MM-DD',           // Public disclosure date
  fixedVersion: '2.0.0',                 // Optional, if a fix exists
  description: 'Brief description of the vulnerability and its impact',
}
```

Include entries for actions with confirmed CVEs or verified supply chain compromises. Do not add entries based on unconfirmed reports.

### Testing

There is no automated test suite yet. To validate a new check:

1. Run the dev server: `npm run dev`
2. Scan repositories known to have the pattern you are detecting. Good test targets:
   - Your own repos (you know what patterns exist)
   - Popular open source repos with many workflows
   - Repos referenced in security advisories
3. Verify findings are accurate: correct file, correct line, useful evidence.
4. Check for false positives by scanning repos that should NOT trigger the check.
5. Run `npm run build` to verify TypeScript compilation.

## Reporting Security Issues

If you find a security vulnerability in the scanner itself (not a check for workflows), please email security findings privately rather than opening a public issue. The scanner handles GitHub tokens and processes untrusted YAML, so vulnerabilities in the tool itself could have real impact.

## Code Style

- TypeScript, strict mode.
- Run `npm run build` before submitting a PR to catch type errors.
- Keep checks self-contained within their category file. Shared utilities go in `src/lib/scanner/parser.ts` or `src/lib/scanner/data/`.
- Write remediation examples that are copy-pasteable. Include YAML code blocks showing the before/after.
- Reference real-world incidents in risk descriptions when applicable.
