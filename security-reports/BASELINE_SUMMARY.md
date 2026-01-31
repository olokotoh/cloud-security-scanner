# Security Baseline Report

**Date:** 2026-01-27
**Project:** Cloud Security Scanner (Intentionally Vulnerable)

## Summary

This baseline scan captures all known vulnerabilities BEFORE remediation.

## Scan Results

### Bandit (Python SAST)
- **Command:** `bandit -r app/`
- **Findings:** [Check bandit-baseline.json]

### Hadolint (Dockerfile Linter)
- **Command:** `hadolint Dockerfile`
- **Findings:** [Check hadolint-baseline.txt]

### tfsec (Terraform Security Scanner)
- **Command:** `tfsec terraform/`
- **Findings:** [Check tfsec-baseline.json]

### Checkov (IaC Security Scanner)
- **Command:** `checkov -d terraform/`
- **Findings:** [Check checkov-baseline.json]

## Next Steps
These vulnerabilities will be systematically fixed in Phase 6 (Application Security).
