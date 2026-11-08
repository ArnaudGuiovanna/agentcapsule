# Security policy

Agent Capsule is pre-1.0 and has not reached its MVP. No version is supported for
production use yet, and security fixes land on `main` only.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub private vulnerability
reporting (the repository's *Security* tab, then *Report a vulnerability*). If it is
not available, contact the maintainer through the address on their GitHub profile.

Include the commit, the affected component and a way to reproduce the problem. Never
include real credentials, tokens or private tenant content.

## Scope

In scope: tenant isolation, authentication and delegated identity, the host/guest
control and platform channels, volume encryption and key handling, transit
encryption of invocation content and attachments, the LLM gateway's handling of
provider credentials, and the worker's use of Firecracker and the jailer.

Known limitations and unvalidated properties are listed per area in
[ROADMAP.md](ROADMAP.md) and in the documents under [docs/](docs/).

## Secrets in this repository

CI scans every change and the full history with [gitleaks](https://github.com/gitleaks/gitleaks).
Test fixtures that look like credentials are fake and marked `gitleaks:allow` on
their line. Never commit operator configuration, keys or tokens; the `.gitignore`
excludes the usual local paths (`.env`, `secrets/`, `*.pem`, `*.key`).
