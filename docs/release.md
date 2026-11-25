# Releases: audit, build, signing and verification

This page says what a release of Agent Capsule contains, what is checked
before one is published, how a maintainer cuts one and how a user verifies
one. The decisions behind it are in
[ADR 013](adr/013-release-supply-chain.md). The first release is `v0.0.1`.

## What a release contains

A release is a GitHub release that
[`.github/workflows/release.yml`](../.github/workflows/release.yml) builds,
signs and publishes from a version tag, without a manual step.

| File | What it is |
|---|---|
| `agentcapsule-api`, `agentcapsule-worker`, `agentcapsule-admin`, `agentcapsule-authority`, `agentcapsule-slim-bridge` | The host programs, linux/amd64, linked dynamically against glibc 2.39 or newer (Ubuntu 24.04). The worker also needs `libcryptsetup.so.12`. |
| `agentcapsule-harness` | The harness package tool (pack, push, sign, verify), static. |
| `install.sh` | The `curl \| sh` installer of the workstation CLI ([Verify a release](#verify-a-release)). |
| `agentcapsule-userspace-linux-amd64.tar.gz` | Private Linux filesystem for a new portable installation, when listed in the signed server manifest. Its SPDX inventory covers the installed packages. The matching package sources are in the source archives and their notices are under `/usr/share/doc` inside the filesystem. |
| `cli-cheatsheet.pdf` | English quick reference for installing the PaaS and operating the CLI. The v0.1.1 tag contains the original French manual in its signed file set. [Read the cheat sheet](cli-cheatsheet.md) |
| `formal-summary.json`, `p1-*.json`, `p2-certificate.json` | Formal model results and evidence prepared for the tag. The signed checksum index covers the evidence and documentation shipped with that version. |
| `oci-<service>.spdx.json` | Inventory of the exact container image distributed for the service. |
| `component-sources.json`, `component-notices.tar.gz` | Component versions, package source locations, SHA-256 identities and notices copied from application sources, container layers, Java archives and native Rust dependencies. |
| `agentcapsule-oci-sources-*.tar` | Application sources, BusyBox, distribution source packages and recipes, plus the source of the SLIM native binding and the crate archives matching its Cargo.lock. |
| `<binary>.spdx.json` | The SPDX 2.3 SBOM of each binary. |
| `third-party-licenses.txt`, `licenses.json` | The license and notice files of every linked module, and the license inventory. |
| `agentcapsule-sources-*.tar` | Server and guest sources, including the Firecracker build’s Cargo.lock, checksum-verified crate archives, and the micro-http Git source at the commit recorded in the lock. |
| `build.json` | How the binaries were built: commit, Go, C compiler, host packages, flags, both builds' digests. |
| `dependency-audit.json`, `vulnerability-scan.json` | The dependency audit and the vulnerability scan of this release, with every allowlisted finding and its reason. |
| `SHA256SUMS` | The SHA-256 of every file above. |
| `SHA256SUMS.sigstore.json` | The cosign signature of `SHA256SUMS` (keyless: a certificate for the release workflow's GitHub identity, logged in Rekor). |
| `provenance.sigstore.json` | The SLSA build provenance of every file in `SHA256SUMS`, signed by GitHub (artifact attestation). |

The release also includes six static CLI builds (Linux, macOS and Windows,
amd64 and arm64), the Ubuntu 24.04 server bundle, its signed package and OCI
archives, and the source archives of the exact host and guest packages. The
server bundle contains the patched Firecracker/jailer, kernel, guest initrd
with the reference echo harness, adapter, deploy configuration, units, public
HTTP contract and host guide. `agentcapsule-bundle.json` records the server
release, migration format, commit and artifact digests. The release workflow signs checksums and attests the provenance of these files. GitHub allows up to 1,000 files per release and requires each to be smaller than 2 GiB. The builder splits source archives at 1,500 MiB before checking every final file. [GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

Before signing a tag, the release workflow runs the six packaged CLIs on
native amd64 and arm64 runners for Linux, macOS and Windows. Each runner
verifies its executable against the build job’s checksum index, checks the
embedded target, commit and release version, and exercises an HTTPS session
across separate CLI processes. The test rejects an incompatible API before
sending credentials, then logs in with a trusted test CA and reads the current
organization from the saved private context. The signing job verifies the
same index digest. Pull requests run this scenario with native builds.
[Native runner platforms](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

Each image inventory is tied to its offline archive and the pinned reference in the deployment configuration. The scanner applies the same image policy to the local SPDX and the registry scan. The source index records exact Red Hat SRPMs, Debian source packages, and Alpine recipes with their upstream files and packaging patches. Maven source-classifier URLs and Go module URLs identify further upstream components. [Candidate image qualification](release-image-qualification.md)

### Signed Linux development build `v0.1.0-dev.6`

For local development on Ubuntu 24.04 amd64, including an Ubuntu instance in WSL2, use the Linux build mode below with the release build dependencies installed. It builds the host programs, the Linux/amd64 CLI and the guest image from the current Git commit. The version appears in `build.json` and in `agentcapsule version`. Choose a fresh output directory for each run.

```sh
python3 scripts/build-release.py --go "$(command -v go)" \
  --linux-dev-version v0.1.0-dev.8 --twice \
  --guest-cryptsetup /usr/sbin/cryptsetup --output /var/tmp/agentcapsule-dev8
```

Two clean builds of `f1d216d` on Ubuntu 24.04 amd64 in WSL2 produced the same eight executables and guest initrd. The development key signed an index of 41 files. Its SHA-256 is `fa277755417542dfd6ee6ac82ffd6d32cc98af8222ec7e5a201ec1d0ff5a98d2`. An independent offline verification checked the signed files, the 63 files inside the server bundle and the six pinned container references. The candidate admin binary applied 54 migrations to a fresh PostgreSQL schema and the resulting ledger matched the one shipped with the build.

The release scanner checked the 19 SPDX inventories on this medium. The Ubuntu package archive and the Keycloak image account for all 12 findings that block publication, one Critical and 11 High. [Image qualification](release-image-qualification.md) · [Ubuntu package findings](#ubuntu-package-archive-19-november-2026)

### Signed Linux development build `v0.1.0-dev.11`

On 20 November 2026, two clean Ubuntu 24.04 amd64 builds of commit `b14a85f` in WSL2 produced identical bytes for all eight Linux executables and `product.initrd`. The development signing key used for `dev.6` signed an index of 44 files totaling 2,548,341,450 bytes. The SHA-256 of `SHA256SUMS` is `34cfec44601cbc3b4f21c38c4970bc6fd1d10eec0f39e45c9cd14dd419a3a38a`. The offline reader verified the signature, extracted the server bundle and checked all 63 files. Its manifest declares the binary rollback contract `agentcapsule-state/v1` and 54 PostgreSQL migration records. The installation and restored-agent exercise used the earlier `dev.6` media. [WSL installation and recovery](cli-host.md#development-qualification-on-wsl2)

The Linux/arm64 CLI from the same commit ran under QEMU 10.2.1 in WSL2 against a native Linux HTTPS API and PostgreSQL. The test observed 49 TLS 1.3 requests across enrollment, context isolation, key rotation and logout. It also checked that the client rejected an untrusted certificate authority and an overly permissive context file. The arm64 executable's SHA-256 was `f51294db614ecadba7c631b31523b0957c7e06a85cd1242aebc9161a96f47777`.

The scan of the 19 SPDX inventories found one Critical and eleven High matches that block publication. The six Ubuntu package matches and six Keycloak matches are detailed below and in the image qualification. [Image findings](release-image-qualification.md)

### Signed Linux development build `v0.1.0-dev.12`

The `dev.12` media were built from commit `c9d1e38` on 20 November 2026 and include the single-agent CPU and memory resize command. Two clean Noble amd64 builds in WSL2 produced identical digests for all eight executables and the guest initrd. The signed index covers 45 files totaling 2,548,385,505 bytes. Its SHA-256 is `fa2c3251ff15891de35e2ce1a27f160f9c5c36a13e6563dfd3981668e1cc8d41`. The offline reader checked all 63 server files. PostgreSQL applied all 55 migrations and its ledger matched the signed record, including the new `agent-resize` migration. [CLI progress](plan-cli.md#suivi-du-chantier)

All seven checks passed on the Ubuntu 24.04 WSL2/KVM installation upgraded from `dev.6`. The test verified the media signature, and the guest verified a second signature on the identical index using its existing trusted public key. The scan of the 19 inventories still reports twelve release-blocking findings, six in Ubuntu packages and six in Keycloak. [Installation qualification](cli-host.md#development-qualification-on-wsl2) · [Image findings](release-image-qualification.md)

### Signed Linux workstation CLI `v0.1.0-dev.13`

The Linux amd64 and arm64 CLI binaries from commit `f0aa5c0` include the fix for following an invocation that the server requeues after a restore. Both run against CLI protocol 1. The server qualified in WSL2/KVM is `v0.1.0-dev.12`.

Two clean builds with Go 1.27.4 produced identical executables for each architecture. An offline rebuild from the delivered source and Go module archives reproduced both digests with an empty module cache and the Git metadata of the release commit. The signed checksum index covers ten files, including the two executables, their SPDX inventories, sources, notices, build record and CLI scan. The scan found no matches in either CLI inventory. The server is assessed separately.

The Linux amd64 executable passed the native HTTPS test on WSL2. Under QEMU, the signed arm64 executable completed 49 TLS 1.3 requests in the enrollment test and submitted a single-agent resize to the API backed by PostgreSQL. The CLI returned the rollout member for the requested agent.

The signed amd64 CLI also ran against the HTTPS API and PostgreSQL 18.6 with a test worker. After a volume restore requeued an invocation, `operation wait --type invocation` observed `lost` twice and then `completed` under the same ID. The command exited with code 0 and the member read the replacement result. The restore skipped a second invocation because its requester had lost access. The auditor’s CLI reported `requester_revoked` and exited with code 5.

| SHA-256 | Digest |
|---|---|
| Signed checksum index | `e026a64d468ea44346ddc8f918e2cf7960bd370875c25cb8e90277edfe9ef2a4` |
| Linux amd64 CLI | `ca34e21d7f721ca172f67fc9c58fffb443ccc842e7432911634856be73789a7f` |
| Linux arm64 CLI | `9e1fd92feb4441e5a36938c8e74ec1f88a0185e4f42585515e2341d430f021c6` |

Use the previously trusted development public key with SHA-256 `1305029f0b5e0aeca207bedf8cdf90470bea39826a44c06afeb75194ee70cb22`. After extracting the workstation archive, run these commands from its top-level directory.

```sh
printf '%s  %s\n' 1305029f0b5e0aeca207bedf8cdf90470bea39826a44c06afeb75194ee70cb22 dev-trust/dev.pub | sha256sum --check --strict &&
  openssl pkeyutl -verify -pubin -inkey dev-trust/dev.pub -rawin \
    -in assets/SHA256SUMS -sigfile assets/SHA256SUMS.dev.sig &&
  (cd assets && sha256sum --check --strict SHA256SUMS)
```

### Ubuntu package archive, 19 November 2026

The offline Noble snapshot used in the installation test contained 171 binary packages. The release inventory checks every archived `.deb` against the server's package index and records its SHA-256, Ubuntu release, binary version and source package. Grype 0.121.0 with the 19 November database reported six High matches, 452 Medium, 37 Low and five Negligible. The six High matches block this archive under the release policy. The six separate Keycloak matches also block the offline images. [Image qualification](release-image-qualification.md)

The development media's `agentcapsule-ubuntu-sources-01.tar` contains the 108 exact Ubuntu source versions for those 171 packages. Its `ubuntu-source-index.json` maps each binary to its source name and version. The qualification checked all 349 source files against the signed Noble indexes and the corresponding `.dsc` files, then read the finished tar back. The tar SHA-256 is `8f621aceab2ce35552afc9a8f63014624352ab3b1a8dbadbf7761b776c8ff5e4`.

| Binary and exact Ubuntu source | Shipped Noble version | High advisories | Ubuntu evidence |
|---|---|---|---|
| `docker.io` from `docker.io-app` | `29.1.3-0ubuntu3~24.04.2` | CVE-2024-41110 | Canonical fixed the application source in `27.5.1-0ubuntu3~24.04.2`. [Ubuntu advisory](https://ubuntu.com/security/CVE-2024-41110) |
| `runc` from `runc-app` | `1.3.4-0ubuntu1~24.04.1` | CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 | Canonical fixed all three in `1.3.3-0ubuntu1~24.04.2`. [USN-7851-1](https://ubuntu.com/security/notices/USN-7851-1) |
| `containerd` from `containerd-app` | `2.2.1-0ubuntu1~24.04.4` | CVE-2026-53488 | Canonical fixed the application source in `2.2.1-0ubuntu1~24.04.3`. The shipped package changelog records the backport. [Ubuntu advisory](https://ubuntu.com/security/CVE-2026-53488) |
| `containerd` from `containerd-app` | `2.2.1-0ubuntu1~24.04.4` | CVE-2026-39821 | Canonical lists `containerd` as needing evaluation and gives no Noble fix for `containerd-app`. The shipped ELF build information identifies `go1.24.13` and `golang.org/x/net v0.47.0`. [Ubuntu advisory](https://ubuntu.com/security/CVE-2026-39821), [Go advisory](https://pkg.go.dev/vuln/GO-2026-5026) |

For `v0.0.1`, these six matches and the six Keycloak matches are accepted by reviewed entries in [the allowlist](../scripts/vulnerability-allowlist.json), which expire on 20 January 2027. On 20 November the 13 November snapshot was still current for these packages: Ubuntu had published no newer `docker.io`, `runc` or `containerd` for Noble. Five matches concern versions that already include Canonical's fix. The containerd finding in Go's `idna` is not reached: the installer loads every image from the signed offline archive and starts it by digest with `--pull never`, so containerd resolves no registry host name.

On 20 November, the shipped SPDX inventory was compared with independent Syft JSON and SPDX inventories built from the dpkg metadata of all 171 verified packages. The three scans produced the same 500 matches, including the same six High findings. Grype had the Ubuntu source package names and matched these six findings on binary package names. Five reported matches concern versions that include Canonical's fixes. The remaining containerd finding requires upstream or distribution assessment.
[Single-host installation and updates](cli-host.md)

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

### Model checks (before a release, not in CI)

The bounded and exhaustive checks of the formal models
(`scripts/check-models.py`, Apalache and TLC) take hours, far more than a CI
job's budget; CI only typechecks the models and runs the script's unit tests,
which fail when a witness schedule or a depth wrapper has no check. Before a
release, a maintainer runs every check on the tagged commit, with the
toolchain [spec/README.md](../spec/README.md#bounded-and-exhaustive-checks)
names, and keeps its `summary.json` with the release notes:

```bash
(cd spec && npm ci)
python3 scripts/check-models.py --output <out>/models
```

A check that ends otherwise than expected blocks the release until it is
explained: a counterexample in a correct configuration is a finding
(projected into a failing Go test, or the model is fixed). A timeout is a
check not run, never a pass: the release notes list the checks that did not
finish. The two bounded P1 checks, `concurrentProtocolDepth8` and
`concurrentProtocolLoadedDepth12`, have exceeded the budget on a 12-core,
15 GB machine. The P2 instance `restoreAuthorityTiny` admits arbitrarily
many promotions. Record the TLC verdict, depth, distinct states and remaining
queue when its time budget expires. Record the separate `certificate.json`
from `python3 scripts/check-restore-authority-induction.py` for unbounded
safety of this instance. On 2026-11-22 the 7,200-second TLC attempt timed
out at reported depth 19, with 144,950,532 distinct states and 67,067,889
queued. The induction certificate established all 21 safety conjuncts over
all 45 action alternatives. [P2 certificate and scope](../spec/proofs/restore-authority-induction.md)

Releasing with these outstanding checks listed is the default
pending the product owner. [Formal check scopes](../spec/README.md#bounded-and-exhaustive-checks)

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

Linux amd64 with Go 1.27.4, a C compiler, the libcryptsetup headers, e2fsprogs
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

An expired or malformed entry fails the audit. From 21 days before an entry
expires (`ALLOWLIST_WARNING_DAYS` in `scripts/release_tools.py`), the CI
checks job (`release_tools.py --check-allowlist`), the scans and the
dependency audit each print a warning annotation for it, without failing:
review it again, or fix the finding, before the expiry fails them. Never move
an expiry beyond 90 days. An entry no scan used is listed in the reports, so
that it can be removed. Add an entry only after
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
- **The guest kernel and Firecracker.** The release builds them from the recorded sources and configuration. Their separate builds have no two-builder reproducibility result.

## Cut a release

The maintainer:

1. Checks that `main` is green, including the *Release audit* job, and that
   no allowlist entry covers a vulnerability the code calls: a release would
   refuse it.
2. Tags the commit of `main` and pushes the tag:

   ```bash
   git tag -a v0.1.3 -m "Agent Capsule v0.1.3"
   git push origin v0.1.3
   ```

   Only `vMAJOR.MINOR.PATCH` and `vMAJOR.MINOR.PATCH-PRE` tags start the
   workflow, and only for a commit of `main`. A tag with a suffix makes a
   prerelease.
3. Follows the workflow. Its jobs:
   - **build** (read-only token): checks the tag, audits the dependencies
     (`--release`), builds everything twice with fresh module caches and
     compares, writes the SBOMs, scans them and the deploy images, and
     assembles the files and `SHA256SUMS`;
   - **sign** (an OIDC token, no write access to the repository), in the
     `release` environment: checks the files against `SHA256SUMS`, signs it
     with cosign keyless and verifies the signature, installs the CLI with
     `install.sh` from those files as a user would (which checks the signer),
     and attests the SLSA provenance of every file;
   - **publish** (write access to the repository's contents only), in the
     `release` environment: publishes the release with every file.
4. Reads `dependency-audit.json` and `vulnerability-scan.json` of the
   published release (every allowlisted finding is listed with its reason).

A failed run publishes nothing. Fix the cause on `main`, then tag a new
version; never move a published tag.

Repository settings that the workflow assumes but does not create: a tag
ruleset that lets only maintainers create `v*` tags and forbids moving or
deleting them, the `release` environment below, and Actions allowed to create
releases.

### The release environment

The ancestry check (only a commit of `main` is released) runs in the tagged
commit's own workflow, so a tag on another commit could carry a workflow
without it (S-16). The `sign` and `publish` jobs therefore run in the
protected environment `release`, and Fulcio writes the environment of the
signing job in the certificate (extension `1.3.6.1.4.1.57264.1.23`).
`install.sh`, `agentcapsule self update` and the host helper refuse a
`SHA256SUMS` whose certificate does not name `release`, as well as a
signature from another trigger than the tag's `push`, another repository or
another ref. A workflow that leaves the environment out signs with a
certificate that every verifier refuses. The two releases signed before the
environment existed, `v0.0.1` and `v0.1.0`, are accepted by the SHA-256 of
their `SHA256SUMS` only, pinned in the three verifiers.

The owner creates, in the repository's settings:

1. **Environments → New environment `release`**:
   - *Required reviewers*: off while the project has a single maintainer
     (since 26 November 2026). With two or more maintainers, name them here:
     each run then waits for an approval before `sign`, then before
     `publish`. Turn on *Prevent self-review* as well.
   - *Deployment branches and tags*: *Selected branches and tags*, with the
     tag rules `v[0-9]*.[0-9]*.[0-9]*` and `v[0-9]*.[0-9]*.[0-9]*-*`, and no
     branch: no other ref can run a job in this environment.
   - *Allow administrators to bypass configured protection rules*: off.
2. **Rules → Rulesets → New tag ruleset**, active, targeting `v*`:
   *Restrict creations*, *Restrict updates* and *Restrict deletions*, with
   only the maintainers (or a release team) in the bypass list.
3. **Branch protection of `main`** stays as it is: changes to
   `.github/workflows/release.yml` reach `main` only through review.

When reviewers are configured, a reviewer approves `sign` only for a tag of a
commit of `main` that they expect to release: the approval page names the tag
and the commit.

## Verify a release

### With the installer

`install.sh`, published with each release, performs the checks of steps 1 to 3
below for the workstation CLI. It runs under any POSIX shell:

```sh
curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh
curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/download/v0.0.1/install.sh | sh -s -- --version v0.0.1
```

The script selects the executable from `uname` (Linux or macOS, amd64 or
arm64; Windows under Git Bash or MSYS2). It takes the latest release unless
`--version` names one, and downloads the executable with `SHA256SUMS`. It
needs `curl` and `openssl`, and verifies the signature with `cosign` 2.4 or
newer (S-17). Without a cosign on PATH it downloads the cosign release file
for the system (cosign 3.1.4, the version of `scripts/release-tools.json`),
runs it only when its SHA-256 is the one written in the script, and removes
it afterwards; Windows on arm64 has no such file and needs its own cosign. It verifies
`SHA256SUMS.sigstore.json` against the release workflow's identity for that
exact tag, the `push` trigger, the repository and the tag's ref, then reads
the certificate with openssl and requires the `release` environment
([above](#the-release-environment)). It stops on any failure, and without
a verified cosign. The executable is installed only when `SHA256SUMS` lists its name
exactly once with its digest. The default directory is `~/.local/bin`, or
`/usr/local/bin` as root; `--dir` selects another. An existing CLI is
replaced only after every check passes. `--require-signature`, the default,
is still accepted.

`--insecure-skip-signature` (or `AGENTCAPSULE_INSECURE_SKIP_SIGNATURE=1`)
skips the signature and prints a warning: the digest check then protects
against a damaged download but not against a compromised release, since
whoever can replace the executable can replace `SHA256SUMS`. Verify the
signature as in step 2 before trusting such a CLI with a production host.
`scripts/test_install_cli.py` tests these refusals. Later updates use
`agentcapsule self update`, which always verifies the signature, the same
claims and the environment, and refuses a release older than the highest the
CLI has been (`--allow-older` overrides, L-13).

### By hand

Choose the published tag you intend to install and the asset for the workstation
that will run the CLI. On Linux and macOS, `uname -m` reports `x86_64` or
`aarch64`/`arm64`. On Windows, use the system type in Settings → System → About.
[AgentCapsule releases](https://github.com/ArnaudGuiovanna/agentcapsule/releases)

| Workstation | Intel/AMD 64-bit | Arm 64-bit |
|---|---|---|
| Linux | `agentcapsule-linux-amd64` | `agentcapsule-linux-arm64` |
| macOS | `agentcapsule-darwin-amd64` | `agentcapsule-darwin-arm64` |
| Windows | `agentcapsule-windows-amd64.exe` | `agentcapsule-windows-arm64.exe` |

1. In an empty directory, download the selected asset, `SHA256SUMS` and
   `SHA256SUMS.sigstore.json` from that release. With an independently installed
   GitHub CLI, the following are POSIX shell commands. On Windows PowerShell
   assign `$tag` and `$asset` instead. Replace the two example values.

   ```sh
   tag='RELEASE_TAG'
   asset='agentcapsule-linux-amd64'
   gh release download "$tag" --repo ArnaudGuiovanna/agentcapsule -p "$asset" -p SHA256SUMS -p SHA256SUMS.sigstore.json
   ```

2. Verify the checksum index with an independently trusted cosign 2.4 or newer.
   The signer must match the project workflow, the selected tag, the `push`
   trigger and the repository. Continue only when this command exits
   successfully. [Cosign](https://github.com/sigstore/cosign)

   ```sh
   cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "https://github.com/ArnaudGuiovanna/agentcapsule/.github/workflows/release.yml@refs/tags/$tag" --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-trigger push --certificate-github-workflow-repository ArnaudGuiovanna/agentcapsule --certificate-github-workflow-ref "refs/tags/$tag" SHA256SUMS
   ```

   Then check that the signing job ran in the `release` environment: this
   prints `..release` (the extension's two DER header bytes, then the name)
   for every release after `v0.1.0`.

   ```sh
   python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verificationMaterial"]["certificate"]["rawBytes"])' SHA256SUMS.sigstore.json |
     openssl base64 -d -A | openssl x509 -inform DER -noout -text | grep -A1 '1.3.6.1.4.1.57264.1.23:'
   ```

3. Verify the **selected executable** under its original release filename.
   Save the following as `verify-cli.py` in the download directory. It requires
   exactly one matching entry in the authenticated index and checks the bytes
   you will execute.

   ```python
   import hashlib, pathlib, sys
   path = pathlib.Path(sys.argv[1])
   lines = pathlib.Path("SHA256SUMS").read_text(encoding="ascii").splitlines()
   entries = [line for line in lines if line.partition("  ")[2] == path.name]
   digest = hashlib.sha256(path.read_bytes()).hexdigest()
   if entries != [digest + "  " + path.name]:
       sys.exit("Checksum verification failed for " + path.name)
   print("Verified", path.name)
   ```

   Run `python3 verify-cli.py "$asset"` (Windows: `py -3 verify-cli.py "$asset"`)
   and continue only on `Verified <filename>`.

   To verify the build provenance as well, download `provenance.sigstore.json`
   from the same release and run the following with GitHub CLI 2.49 or newer.
   The provenance names the workflow, commit and run that built the selected file.

   ```sh
   gh attestation verify "$asset" --repo ArnaudGuiovanna/agentcapsule --signer-workflow ArnaudGuiovanna/agentcapsule/.github/workflows/release.yml --bundle provenance.sigstore.json
   ```

   On Linux or macOS, install the verified file as `agentcapsule` in a directory
   on your PATH with mode 0755. On Windows, rename the verified file to
   `agentcapsule.exe` and place it on PATH. Run `agentcapsule version` to see
   the release tag, then `agentcapsule install --help` on the workstation.
   [Install the matching server bundle](cli-host.md)

4. **The SBOM.** `agentcapsule-api.spdx.json` describes the binary whose
   SHA-256 its root element carries. To scan it yourself:
   `grype sbom:agentcapsule-api.spdx.json`. `go version -m agentcapsule-api`
   shows the same modules, the commit and its version.

5. **Rebuild it** (optional). On Ubuntu 24.04 with the packages and the Go
   version that `build.json` names:

   ```bash
   git clone https://github.com/ArnaudGuiovanna/agentcapsule && cd agentcapsule && git checkout "$tag"
   python3 scripts/build-release.py --go /path/to/go --version "$tag" --output /tmp/rebuild
   sha256sum /tmp/rebuild/dist/agentcapsule-api
   ```

   The digest matches when the packages match exactly; see
   [Reproducibility](#reproducibility).

## What this does not cover

- The CI job proves reproducibility on one runner, not between two
  independent builders.
- The release workflow's first run is the one for `v0.0.1`. Its steps that
  need no GitHub identity were first run locally (see ADR 013, Validation).
- The provenance is SLSA Build Level 2: GitHub signs it, but the build runs
  in the repository's own workflow, not in an isolated reusable one.
- The guest image's native packages are scanned with the build host's
  distribution data. The release scans the Firecracker workspace dependency lock. The kernel build has no configuration-specific vulnerability inventory.
- The SLIM native library has an inventory of the source revision and the Rust dependency lock. The lock also contains optional and build dependencies. It describes the upstream source tree and cannot identify every crate linked into the prebuilt native library.

### Binary rollback compatibility

The signed server manifest contains a `binary_rollback_epoch`. Bump the value
in `scripts/build-server-bundle.py` whenever an older server could misinterpret
persistent state, guest or authority protocols, revocations, destroyed keys,
exclusive volume ownership or security policy after the new server has run.
Use a fresh epoch even when the database schema and HTTP API are unchanged.
Within an epoch the host helper separately checks the full SQL ledger,
external dependencies, guest runtime and host configuration before it accepts
a binary rollback. The build and its own signed version remain independently
identifiable. [Host rollback procedure](cli-host.md#update-and-recovery)

## Runtime images

Three images carry the OpenSSL backports of
[deploy/images/openssl](../deploy/images/openssl/README.md):
`runtime:python-3.13-<date>` (the base of both example harnesses),
`runtime:haproxy-3.2-<date>` (the Directory's edge) and
`runtime:oasf-2.0.0-<date>` (the OASF schema server), all in
`ghcr.io/arnaudguiovanna/agentcapsule/runtime`.

**Build.** The
[runtime-images workflow](../.github/workflows/runtime-images.yml) builds them
for linux/amd64 from the Dockerfile and its build plan,
[images.json](../deploy/images/openssl/images.json), with the upstream bases
pinned by digest. It pushes each one under a new tag, attests its SLSA build
provenance (`actions/attest-build-provenance`, the attestation stored by
GitHub and in the registry), then verifies the pushed images as the release
does. A maintainer runs it by hand, from `main` only:

1. Actions, Runtime images, Run workflow, on `main`, with the build date
   (`YYYYMMDD`) as tag suffix. A tag that exists already is refused.
2. The job summary, and the `runtime-images` artifact, give each image's
   reference `<tag>@sha256:<digest>`, the SHA-256 of its OpenSSL files and of
   the APKs of the build stage.
3. Pin the three references in `deploy/images/openssl/qualification.json`
   (`registry_images`), `deploy/interop/compose.yml`,
   `runtime/interop/profile.json`, `.dagger/main.go` and the Dockerfiles of
   `examples/python-echo` and `examples/adapted-agent`. Update the file and
   APK digests of the qualification's profiles from the summary, and the
   allowlist entries that name the old tags. `scripts/test_runtime_images.py`
   fails while one of these files names a reference that the qualification
   does not pin.
4. Rebuild the harnesses and run the interoperability and release checks.

The workflow's token pushes to the package only if the package grants this
repository write access (package settings, Manage Actions access).

**Verification.** The release runs
`scan-artifacts.py --verify-runtime-images`
(`scripts/runtime_images.py verify`, which needs skopeo and gh). For each
pinned image:

- its configuration is its pinned upstream base plus exactly one layer, the
  runtime stage's, with the base's entry point and command and the plan's
  user (`skopeo inspect --config`);
- it carries a SLSA provenance attestation signed for
  `.github/workflows/runtime-images.yml` of this repository, on
  `refs/heads/main`, by a GitHub-hosted runner (`gh attestation verify`).

Any failure, or a missing tool, fails the release. The images pinned on
21 November 2026 were built by hand on a workstation: they pass the first
check and fail the second, so the next release needs the workflow's images.
`python3 scripts/runtime_images.py verify` runs the same check locally, with
a GitHub login for `gh`.
