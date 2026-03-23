---
name: New Check Proposal
about: Propose a new security check for the scanner
title: "[Check] "
labels: enhancement, new-check
assignees: ''
---

## Check Summary

**Proposed ID**: `category/check-name`

**Category**: (supply-chain | injection | dangerous-triggers | permissions | secrets-exposure | runner-security | ci-cd-hygiene | best-practices)

**Severity**: (critical | high | medium | low | info)

## What It Detects

Describe the pattern or misconfiguration this check would flag.

## Why It Matters

Explain the security risk. Link to real-world incidents, CVEs, or research if applicable.

## Detection Logic

How would the check work? What would it look for in workflow YAML?

```yaml
# Example workflow pattern that should trigger this check
```

## Example Repositories

List public repositories where this pattern exists (for testing):

-

## Remediation

What should users do to fix the finding?

```yaml
# Example of the fixed pattern
```
