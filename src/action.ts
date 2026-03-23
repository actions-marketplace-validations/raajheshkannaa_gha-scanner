import { parseRepoInput } from './lib/utils/parse-repo';
import { fetchRepoContext } from './lib/github/fetch-workflows';
import { runScan } from './lib/scanner/engine';
import type { ScanResult } from './lib/scanner/types';
import * as fs from 'fs';
import * as crypto from 'crypto';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

const VALID_FAIL_ON = ['critical', 'high', 'medium', 'low', 'info', 'none'];

function getInput(name: string): string {
  return process.env[`INPUT_${name.toUpperCase().replace(/-/g, '_')}`] || '';
}

function setOutput(name: string, value: string) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
    fs.appendFileSync(outputFile, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
  }
}

function writeSummary(md: string) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    fs.appendFileSync(summaryFile, md);
  }
}

function sanitizeMd(s: string): string {
  return s.replace(/[|<>&\n]/g, c => `&#${c.charCodeAt(0)};`);
}

async function run() {
  const repo = process.env.GITHUB_REPOSITORY;
  if (!repo) {
    console.error('Error: GITHUB_REPOSITORY not set');
    process.exit(1);
  }

  const token = getInput('token') || process.env.GITHUB_TOKEN;
  if (token) process.env.GITHUB_TOKEN = token;

  const failOn = getInput('fail-on') || 'high';
  if (!VALID_FAIL_ON.includes(failOn)) {
    console.error(`Error: Invalid fail-on value: "${failOn}". Valid: ${VALID_FAIL_ON.join(', ')}`);
    process.exit(1);
  }

  const parsed = parseRepoInput(repo);
  if (!parsed) {
    console.error(`Error: Invalid repository format`);
    process.exit(1);
  }

  console.log(`Scanning ${parsed.owner}/${parsed.repo}...`);

  try {
    const context = await fetchRepoContext(parsed.owner, parsed.repo);
    const result = runScan(context);

    // Set outputs using heredoc delimiter (safe for multiline values)
    setOutput('score', String(result.score));
    setOutput('grade', result.grade);
    setOutput('findings', String(result.findings.length));
    setOutput('result', JSON.stringify(result));

    // Write step summary
    writeSummary(formatSummary(result));

    // Check fail threshold (none = never fail)
    if (failOn !== 'none') {
      const failSeverity = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
      const maxFindingSeverity = Math.max(
        ...result.findings.map(f => SEVERITY_ORDER[f.severity] ?? 0),
        -1
      );

      if (maxFindingSeverity >= failSeverity) {
        const count = result.findings.filter(
          f => (SEVERITY_ORDER[f.severity] ?? 0) >= failSeverity
        ).length;
        console.error(
          `\nFailed: ${count} finding(s) at ${failOn} severity or above.`
        );
        process.exit(1);
      }
    }

    console.log(`\nPassed: Grade ${result.grade} (${result.score}/100)`);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    process.exit(1);
  }
}

function formatSummary(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`## GHA Scanner: ${sanitizeMd(result.repo)}`);
  lines.push('');
  lines.push(`**Grade: ${result.grade} (${result.score}/100)** | ${result.workflowCount} workflows | ${result.findings.length} findings`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No security findings.');
  } else {
    lines.push('| Severity | Finding | File |');
    lines.push('|----------|---------|------|');
    for (const f of result.findings.slice(0, 30)) {
      lines.push(`| ${sanitizeMd(f.severity)} | ${sanitizeMd(f.title)} | \`${sanitizeMd(f.file)}\` |`);
    }
    if (result.findings.length > 30) {
      lines.push(`| | ... and ${result.findings.length - 30} more | |`);
    }
  }
  lines.push('');
  lines.push(`*Scanned with [GHA Scanner](https://github.com/raajheshkannaa/gha-scanner)*`);
  return lines.join('\n');
}

run();
