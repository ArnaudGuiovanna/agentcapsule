# Security policy

Agent Capsule is pre-1.0 and has not reached its MVP. No version is supported for
production use yet. Security fixes land on `main`, and in the next release once
releases exist: only the latest release is maintained.

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

## Dependency and image scanning

Every pull request and every release run the release audit
([docs/release.md](docs/release.md)):

- govulncheck on every Go module: a vulnerability whose vulnerable function the
  code calls fails the check;
- the licenses of every shipped dependency, against an allowed list;
- an SBOM of each release binary, of the guest image and of the reference
  harness packages, scanned with grype together with the container images of
  `deploy/` and the Python and npm lock files: a High or Critical finding fails
  the check.

A finding that cannot be fixed at once (no fixed version yet, an upstream image)
is accepted only by an entry of `scripts/vulnerability-allowlist.json` that gives
the reason and expires within 90 days. A release refuses a vulnerability that the
code calls, even when an entry covers it. Every tool of the audit is pinned by
digest.

## Patch policy

Defaults pending the product owner ([ADR 013](docs/adr/013-release-supply-chain.md)):

- a Critical vulnerability in code we ship, or that our code calls: fixed in a
  release within 7 days of its disclosure or report; a High one within 30 days;
  others in the next release;
- a Go security release: adopted within 14 days (toolchain pin, guest image,
  campaigns);
- Firecracker and the guest kernel: each upstream security release adopted within
  30 days, with `scripts/build-firecracker.py`, `scripts/build-guest-kernel.py` and
  the KVM campaigns. Operators rebuild and roll out their workers.

Advisories are published through GitHub's security advisories once fixed.

## Verifying a release

Each release's checksums are signed with cosign (keyless, the release workflow's
GitHub identity, in the protected `release` environment), every file has a SLSA
provenance attestation and every binary an SPDX SBOM. The installer, the CLI and
the host helper refuse a signature from another workflow, tag, trigger,
repository or environment. [docs/release.md](docs/release.md#verify-a-release) says how to verify them.

## Secrets in this repository

GitHub Actions runs Gitleaks on pushes to every branch and tag, and on pull requests. It scans the full checked-out history, redacts findings and fails the check when it detects a secret. [Push workflow](.github/workflows/secret-push.yml) · [Main and pull request workflow](.github/workflows/ci.yml)
Test fixtures that look like credentials are fake and marked `gitleaks:allow` on
their line. Never commit operator configuration, keys or tokens; the `.gitignore`
excludes the usual local paths (`.env`, `secrets/`, `*.pem`, `*.key`).
