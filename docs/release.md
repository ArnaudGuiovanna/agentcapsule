# Releases: audit, build, signing and verification

This page says what a release of Agent Capsule contains, what is checked
before one is published, how a maintainer cuts one and how a user verifies
one. The decisions behind it are in
[ADR 013](adr/013-release-supply-chain.md). No release has been cut yet.

## What a release contains

A release is a draft GitHub release created by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) from a
version tag. A maintainer reviews it, then publishes it.

| File | What it is |
|---|---|
| `agentcapsule-api`, `agentcapsule-worker`, `agentcapsule-admin`, `agentcapsule-authority`, `agentcapsule-slim-bridge` | The host programs, linux/amd64, linked dynamically against glibc 2.39 or newer (Ubuntu 24.04). The worker also needs `libcryptsetup.so.12`. |
| `agentcapsule-harness` | The harness package tool (pack, push, sign, verify), static. |
| `<binary>.spdx.json` | The SPDX 2.3 SBOM of each binary. |
| `third-party-licenses.txt`, `licenses.json` | The license and notice files of every linked module, and the license inventory. |
| `build.json` | How the binaries were built: commit, Go, C compiler, host packages, flags, both builds' digests. |
| `dependency-audit.json`, `vulnerability-scan.json` | The dependency audit and the vulnerability scan of this release, with every allowlisted finding and its reason. |
| `SHA256SUMS` | The SHA-256 of every file above. |
| `SHA256SUMS.sigstore.json` | The cosign signature of `SHA256SUMS` (keyless: a certificate for the release workflow's GitHub identity, logged in Rekor). |
| `provenance.sigstore.json` | The SLSA build provenance of every file in `SHA256SUMS`, signed by GitHub (artifact attestation). |

The guest image (`product.initrd`) and `capsule-adapter` are built, described
and scanned by the workflow but not published: they hold GPL and LGPL code
(cryptsetup, e2fsprogs, util-linux, and glibc linked statically) whose source
a release would have to offer. Until the product owner decides (ADR 013,
question 4), operators build them with `scripts/build-product-guest.py` and
the Dagger module, as today. The guest kernel and Firecracker are not
released either: `scripts/build-guest-kernel.py` and
`scripts/build-firecracker.py` build them.

## What is checked

Every pull request runs the same checks as a release, in the CI job
*Release audit*, plus the SBOMs and scan of the reference harness packages in
the job *Harness packages*. A release runs them again on the tagged commit.

1. **Dependencies** (`scripts/audit-dependencies.py`). govulncheck checks
   every Go module of the repository. A vulnerability whose vulnerable
   function the code calls fails, unless allowlisted; in a release it fails
   even when allowlisted. A vulnerability in a module the code requires but
   does not call is reported. The licenses of every Go module linked into a
   shipped program, and of the Python packages of the adapted-agent example,
   must be on the list of `scripts/license-policy.json`.
2. **Reproducible build** (`scripts/build-release.py --twice`). The commit is
   cloned twice, at two paths, and built with two homes, build caches,
   umasks, time zones and locales; every binary and the guest image must
   have the same digest in both.
3. **SBOMs** (`scripts/release-sbom.py`). One SPDX SBOM per binary, for the
   guest image and for each reference harness package.
4. **Vulnerability scan** (`scripts/scan-artifacts.py`). grype scans the
   SBOMs, the container images that `deploy/` names (by digest; an image
   without a digest fails), and the Python and npm lock files (those of
   tools that do not ship are reported only). A High or Critical finding
   fails, unless allowlisted.
5. **Workflows** are linted with actionlint and ShellCheck.

### Pinned tools

Every tool fetched from the network is pinned by digest, in
[`scripts/release-tools.json`](../scripts/release-tools.json) (SHA-256 of the
release file) or by `go.sum` (govulncheck,
[`scripts/tools/go.mod`](../scripts/tools/go.mod)). `scripts/release_tools.py`
downloads each once into `~/.cache/agentcapsule-release-tools`, checks it
before use and refuses any other file.

| Tool | Version | Use |
|---|---|---|
| govulncheck | v1.9.0 | Go vulnerabilities, with reachability |
| syft | 1.55.0 | SBOMs and license detection |
| grype | 0.121.0 | Vulnerability scan of SBOMs, images and lock files |
| cosign | 3.1.4 | Signing and verifying `SHA256SUMS` |
| actionlint | 1.7.12 | Workflow lint |
| ShellCheck | v0.11.0 | The workflows' scripts, through actionlint (CI only; a Docker image pinned by digest in `ci.yml`) |

To change a pin: take a release at least two weeks old, check its
publisher's signed checksums file (cosign `verify-blob` with the publisher's
identity) and GitHub's digest of the asset, write the new SHA-256, and run
the audit. govulncheck: `go get -tool golang.org/x/vuln/cmd/govulncheck@vX`
in `scripts/tools`. The GitHub actions are pinned by commit SHA.

The vulnerability databases (the Go vulnerability database, grype's
database) are data, fetched at each run and checked by the tools
themselves; their dates are recorded in the reports.

## Run the audit locally

Linux amd64 with Go 1.27.3, a C compiler, the libcryptsetup headers, e2fsprogs
(`debugfs`) and network access. The outputs are new directories; the reports
are `summary.json` in each.

```bash
# Dependencies: govulncheck and licenses (about 2 minutes).
python3 scripts/audit-dependencies.py --go <go> [--native-tools <tools-dir>] \
  --output <out>/audit

# Build twice and compare; with the guest image (about 6 minutes).
python3 scripts/build-release.py --go <go> [--native-tools <tools-dir>] --twice \
  --guest-cryptsetup /usr/sbin/cryptsetup --output <out>/build

# SBOMs of the binaries, the guest image and harness packages.
python3 scripts/release-sbom.py --go <go> --output <out>/sbom \
  --binary <out>/build/dist/agentcapsule-api [--binary ...] \
  --guest-build <out>/build/dist [--extracted-debs <tools-dir>] \
  [--harness-package <package-dir> ...]

# Scan them, and the deploy images (the first run fetches grype's database,
# about 3 GB unpacked, a few minutes).
python3 scripts/scan-artifacts.py --output <out>/scan --deploy-images \
  --sbom <out>/sbom/agentcapsule-api.spdx.json [--sbom ...] \
  --manifest examples/adapted-agent/requirements.txt
```

`--native-tools` and `--extracted-debs` name a directory into which the
libcryptsetup and cryptsetup packages were extracted without root (see
[scripts/README.md](../scripts/README.md)): the guest SBOM attributes the
files that come from there to those `.deb` files, and the other native files
to the packages dpkg installed.

## Allowlist

[`scripts/vulnerability-allowlist.json`](../scripts/vulnerability-allowlist.json)
holds the reviewed exceptions to both gates. An entry names:

- `ids`: the vulnerabilities (an ID or an alias, such as `GO-2026-6859` or
  `CVE-2026-4738`);
- `package`: the one package they are found in;
- `targets`: the scans it covers, as patterns (`sbom:agentcapsule-worker`,
  `image:ghcr.io/agntcy/slim:3.4.6`, `.` for the platform's Go module; all when
  omitted);
- `reason`: why the finding is accepted, and what will remove it;
- `expires`: a date at most 90 days ahead.

An expired or malformed entry fails the audit. An entry no scan used is
listed in the reports, so that it can be removed. Add an entry only after
reading the advisory: a finding with a fixed version is fixed, not
allowlisted, unless the fix needs its own change (a new guest, a new upstream
image). A release refuses a vulnerability the code calls even when an entry
covers it.

## Licenses

[`scripts/license-policy.json`](../scripts/license-policy.json) lists the
licenses a Go module or a Python package may carry: permissive licenses and
MPL-2.0. A module whose archive has no license file needs a `declared` entry
naming its repository's license and where it is stated. A license outside
the list needs an `accepted` entry for that package with its reason. GPL,
LGPL and AGPL are not on the list. `third-party-licenses.txt` gathers the
license and notice files that the binaries must carry.

## Reproducibility

Reproducible today, with the same Go and the same Ubuntu packages: every
release binary and the guest image. Two builds of one commit, in two clean
clones on one host, give the same digests (checked by every pull request).
Go embeds the commit's version, revision and time, which `go version -m`
shows, and no build time; `-trimpath` removes the paths and the build ID is
empty. The SBOMs are reproducible too: their time is `SOURCE_DATE_EPOCH`
(the commit's time) and their namespace derives from the artifact's digest.

Not reproducible yet, and why:

- **Across hosts.** The cgo binaries link the host's C library and compiler
  output, and the SLIM bridge the pinned SLIM native library: another Ubuntu
  release or package version gives other digests. `build.json` lists the
  packages to install to rebuild one.
- **The guest image across hosts.** It holds the build host's cryptsetup,
  e2fsprogs, glibc and their libraries. Fetching them from a fixed snapshot
  of the Ubuntu archive, as `scripts/fetch-backup-tools.py` does for the
  backup tools, would make it reproducible anywhere; it is not done.
- **The harness packages.** The Dagger module installs Alpine packages
  (`gcc`, `musl-dev`, `e2fsprogs`) without pinning their versions; their
  reproducibility is not checked.
- **The guest kernel and Firecracker.** Not studied.

## Cut a release

The maintainer:

1. Checks that `main` is green, including the *Release audit* job, and that
   no allowlist entry covers a vulnerability the code calls: a release would
   refuse it.
2. Tags the commit of `main`, signed, and pushes the tag:

   ```bash
   git tag -s v0.1.0 -m "Agent Capsule v0.1.0"
   git push origin v0.1.0
   ```

   Only `vMAJOR.MINOR.PATCH` and `vMAJOR.MINOR.PATCH-PRE` tags start the
   workflow, and only for a commit of `main`. A tag with a suffix makes a
   prerelease.
3. Follows the workflow. Its jobs:
   - **build** (read-only token): checks the tag, audits the dependencies
     (`--release`), builds everything twice with fresh module caches and
     compares, writes the SBOMs, scans them and the deploy images, and
     assembles the files and `SHA256SUMS`;
   - **sign** (an OIDC token, no write access to the repository): checks the
     files against `SHA256SUMS`, signs it with cosign keyless and verifies
     the signature, and attests the SLSA provenance of every file;
   - **publish** (write access to the repository's contents only): creates
     the draft release with every file.
4. Reviews the draft: the files, `dependency-audit.json` and
   `vulnerability-scan.json` (every allowlisted finding is listed with its
   reason), and verifies the release as a user would (below). Then publishes
   it.

A failed run publishes nothing. Fix the cause on `main`, then tag a new
version; never move a published tag.

Repository settings that the workflow assumes but does not create: a tag
ruleset that lets only maintainers create `v*` tags and forbids moving or
deleting them, and Actions allowed to create releases.

## Verify a release

Download the files you need, with `SHA256SUMS` and `SHA256SUMS.sigstore.json`.
`<repository>` below is the release page's repository, as
`<owner>/<name>`; `v0.1.0` is the version.

1. **The signature of the checksums** ([cosign](https://github.com/sigstore/cosign) 2.4 or newer):

   ```bash
   cosign verify-blob --bundle SHA256SUMS.sigstore.json \
     --certificate-identity "https://github.com/<repository>/.github/workflows/release.yml@refs/tags/v0.1.0" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     SHA256SUMS
   ```

   It proves that `SHA256SUMS` was signed by the release workflow of that
   repository for that tag.

2. **The files**:

   ```bash
   sha256sum --ignore-missing -c SHA256SUMS
   ```

3. **The provenance** ([GitHub CLI](https://cli.github.com/) 2.49 or newer):

   ```bash
   gh attestation verify agentcapsule-api --repo <repository> \
     --signer-workflow <repository>/.github/workflows/release.yml
   ```

   Offline, add `--bundle provenance.sigstore.json`. The provenance names the
   workflow, the commit and the run that built the file.

4. **The SBOM.** `agentcapsule-api.spdx.json` describes the binary whose
   SHA-256 its root element carries. To scan it yourself:
   `grype sbom:agentcapsule-api.spdx.json`. `go version -m agentcapsule-api`
   shows the same modules, the commit and its version.

5. **Rebuild it** (optional). On Ubuntu 24.04 with the packages and the Go
   version that `build.json` names:

   ```bash
   git clone https://github.com/<repository> && cd <name> && git checkout v0.1.0
   python3 scripts/build-release.py --go <go-1.27.3> --version v0.1.0 --output /tmp/rebuild
   sha256sum /tmp/rebuild/dist/agentcapsule-api
   ```

   The digest matches when the packages match exactly; see
   [Reproducibility](#reproducibility).

## What this does not cover

- The CI job proves reproducibility on one runner, not between two
  independent builders.
- The release workflow has not run yet: it needs a tag on GitHub. Its steps
  that need no GitHub identity were run locally (see ADR 013, Validation).
- The provenance is SLSA Build Level 2: GitHub signs it, but the build runs
  in the repository's own workflow, not in an isolated reusable one.
- The guest image's native packages are scanned with the build host's
  distribution data; the guest kernel and Firecracker are not scanned.
- Vulnerabilities of the SLIM native library's Rust dependencies are not
  scanned: its published archive carries no SBOM.
