# Security Policy

## Supported versions

NNTune v2 is pre-release. Security fixes land on `main` and are released
forward; there are no maintained backport branches yet.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's
[private vulnerability reporting](../../security/advisories/new) on this repo.

Include: what is affected, steps to reproduce or exploit, and impact. We will
acknowledge within 5 business days and keep you updated until resolution.

## Protections on this repo

- Secret scanning + push protection enabled.
- `gitleaks` full-history scan is a required check on every PR.
- Dependabot alerts enabled.
