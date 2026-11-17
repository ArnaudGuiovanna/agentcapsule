# VAL-03 — The release supply chain

Date: November 16, 2026. **Status: proposed; the defaults marked "pending the
product owner" apply until the [questions](#questions-for-the-product-owner)
are answered.** References: [docs/product.md](../product.md) §6 (supply chain,
vulnerabilities), REG-009 (trust policy for harness signatures), VAL-03 of the
[roadmap](../../ROADMAP.md), the guide [docs/release.md](../release.md).

## Context

The repository is public, under MIT, and aims to become an open standard.
Product §6 asks for digest-pinned releases with provenance, signatures, SBOMs
and scans, dependency and image scanning, and signed releases. Before this
record: CI pinned its actions by SHA and a few tools by checksum (gitleaks,
Dagger, promtool by image digest); harness packages had publisher signatures
in cosign's format (REG-009); there was no release, no SBOM, no scan, no
dependency audit, and no check that a build is reproducible. Operators built
every binary with `go build`.

## Decisions

### 1. Every network-fetched tool is pinned by digest

Release files by their SHA-256 in `scripts/release-tools.json` (syft, grype,
cosign, actionlint), govulncheck by `go.sum` in a separate tool module
(`scripts/tools`). A pin is a release at least two weeks old, whose digest
was checked against the publisher's signed checksums file and against
GitHub's own digest of the asset. Tags of tools and actions can be moved by
whoever controls them, as happened to widely used GitHub actions; a digest
cannot.

### 2. SBOMs: SPDX 2.3 JSON, written by syft

One SBOM per artifact: each binary, the guest image, each harness package.
SPDX is an ISO standard (ISO/IEC 5962), read by GitHub, cosign, grype and
most scanners; CycloneDX would have served as well, and syft writes both.

Go's build information alone (`go version -m`) lists the modules of a Go
binary, with their hashes, and syft reads exactly that; but it says nothing
of the guest image's native files, the Alpine and Python packages of a
harness, or licenses. syft covers all of them with one tool, and it is the
cataloger of grype, the scanner: the scan reads the SBOM that is published.

Two additions where syft cannot see: the guest image's native files are
attributed to the Debian packages that installed them (dpkg's database, or
the `.deb` files they were extracted from), after checking that each file in
the image is the packaged one; and a binary linked statically with cgo
records the build host's C library, and the SLIM bridge the pinned SLIM
native library. SBOMs are deterministic (time from `SOURCE_DATE_EPOCH`,
namespace from the artifact's digest).

### 3. Vulnerability gates

- **Go code: reachability.** govulncheck on every module. A vulnerability
  whose vulnerable function the code calls fails CI unless allowlisted, and
  fails a release even when allowlisted. One in a required module that the
  code does not call is reported. The Go vulnerability database rates no
  severity, so severity cannot be the gate for Go.
- **Everything else: severity.** grype on the SBOMs, the deploy images (an
  image without a digest fails) and the lock files. High or Critical fails
  unless allowlisted. Lock files of tools that do not ship (the Quint
  typecheck's npm packages, the OpenAPI validator, the adapter's SDK test
  set) are reported only.
- **Allowlist.** One file for both gates. An entry names its
  vulnerabilities, one package, the targets it covers, a reason that says
  what will remove it, and an expiry at most 90 days ahead. An expired entry
  fails the audit, so every exception is reviewed again.

grype rather than Trivy: syft and grype share their catalog, so the scan sees
exactly what the SBOM says. Both are Apache-2.0 static binaries with signed
checksums.

### 4. Reproducible builds, checked on every pull request

Release binaries are built with `-trimpath`, an empty build ID, no symbol
table and no DWARF, and with Go's stamp of the commit (version, revision,
time; no build time). `scripts/build-release.py --twice` clones the commit
twice and builds with different paths, homes, caches, umasks, time zones and
locales, and compares every digest, the guest image's included. What is not
reproducible yet is listed in [docs/release.md](../release.md#reproducibility):
across hosts (the C library and compiler are the host's), the guest image
across hosts (its native files are the host's packages), the harness packages
(unpinned Alpine packages in the Dagger builder), the kernel and Firecracker.

### 5. Signing and provenance: keyless, from the release workflow only

- `SHA256SUMS` lists every release file and is signed with cosign keyless:
  the certificate binds the signature to the release workflow of this
  repository at that tag (GitHub's OIDC identity), and the signature is in
  Rekor's public log. There is no key to keep, rotate or leak. Signing the
  checksums once, rather than each file, gives one statement to verify and
  one log entry.
- The SLSA build provenance of every file comes from GitHub's artifact
  attestations (`actions/attest-build-provenance`, pinned by SHA): SLSA v1
  provenance signed through Sigstore, verifiable with `gh attestation verify`
  online or with the bundle published in the release. This is SLSA Build
  Level 2.
- The workflow runs on a version tag only, for a commit of `main`. Three jobs
  hold the least they need: the build job (third-party tools run there) has a
  read-only token and no OIDC token; the sign job has the OIDC token and no
  write access; the publish job may write the repository's contents and
  creates a draft release, which a maintainer publishes.

Rejected: `slsa-github-generator` (Build Level 3, but it must be referenced
by tag, not SHA, and its last release is from February 2025); a long-lived
signing key (a secret to protect and rotate, for no gain over keyless on a
public repository). Harness publishers keep their own keys (REG-009): this
record changes nothing for them.

### 6. What a release publishes

The host programs and `agentcapsule-harness`, each with its SBOM, the
third-party licenses, the build record, the audit and scan reports, the
checksums, the signature and the provenance. The guest image and
`capsule-adapter` are built, described and scanned, but not published:
default pending the product owner (question 4).

### 7. Licenses

Default pending the product owner: a Go module or Python package that ships
may carry permissive licenses and MPL-2.0 only (`scripts/license-policy.json`).
GPL, LGPL and AGPL are refused in the dependency graphs. A module without a
license file is declared with its repository's license and the URL that
states it. A release carries `third-party-licenses.txt`.

## First audit run (November 16, 2026)

On the commit this branch starts from, with the tools above and grype's
database of November 16:

- **Called Go vulnerability.** GO-2026-6859 (net/http, an HTTP/1 server can
  crash on a MaxBytesReader header race), in Go 1.27.3's standard library,
  called by the guest volume server (`internal/capsuleprotocol`) and the SLIM
  bridge, and by the interop probes. Fixed in Go 1.27.4. Allowlisted until
  November 30: the bump touches CI, the scripts, the Dagger image, the
  interop profile and the guest. A release refuses it until then.
- **Required, not called.** golang.org/x/net v0.60.0: GO-2026-6860 and
  GO-2026-6866 (html; grype rates the first High in the worker and SLIM
  bridge SBOMs; allowlisted, fixed in v0.62.0); golang.org/x/crypto v0.57.0:
  GO-2026-5932 (openpgp unmaintained).
- **Licenses.** 56 packages (42 Go modules, 14 Python packages), all allowed:
  four modules declared (no license file in their archives), go-digest's
  documentation license (CC-BY-SA-4.0) accepted.
- **Release binaries and guest image.** No High or Critical finding besides
  x/net above. The guest image: 33 Medium and 1 Low in Ubuntu 26.04's
  packages, none fixed yet.
- **Reference harness packages** (python:3.13-alpine base): zlib
  CVE-2026-4738 (Critical, fixed in 1.4-r0) and four High in sqlite-libs (no
  fix). Allowlisted until December 16.
- **Deploy images** (deploy/interop): the OASF server (Erlang/OTP 28.5.0.2:
  1 Critical and 22 High, fixed upstream; zlib Critical), Directory (go-jose
  v4.1.5, High, fixed in v4.1.6), the Directory edge (haproxy:3.2-alpine,
  zlib Critical), the SLIM node (Debian 12 glibc: 1 Critical, 4 High, no
  fix). Allowlisted until December 16; each needs a new upstream image or
  pin, then `verify-interop.py --services`.
- **Lock files.** None in the adapted-agent example's Python packages, the
  Quint npm packages or the scripts' Python requirements.
- **Reproducibility.** The seven binaries and the guest image: identical
  digests in two clean builds.

## Go 1.27.4 (amended on November 17, 2026)

- **The pins.** Go moved from 1.27.3 to 1.27.4 everywhere at once: the `go`
  line of every module (the root module's was 1.27.2), both workflows, the
  versions `check-go.py`, `build-release.py`, `verify-interop.py` and
  `build-slim-bridge.py` require, the Dagger builder image and the interop
  profile. The Dagger module's own `go` line stays 1.27.3, the highest the Go
  SDK of Dagger v0.21.11 accepts; its code does not ship.
- **The allowlist.** GO-2026-6859 left it. golang.org/x/net moved to v0.62.0
  (with x/crypto v0.58.0, x/sync v0.24.0, x/sys v0.49.0 and x/text v0.43.0),
  which fixes GO-2026-6860 and GO-2026-6866, so their entry left too.
- **The audit.** `audit-dependencies.py --release` with Go 1.27.4 passes: no
  called vulnerability in any module. One is required and not called:
  GO-2026-5932 (x/crypto's openpgp, unmaintained, never linked; the platform
  links blake2b, blake2s and sha3 only). 56 packages, all licenses allowed.
- **The release binaries.** `build-release.py --twice`: the seven binaries
  have identical digests in both builds. grype on their SBOMs (database of
  November 15): no finding in the standard library or x/net; GO-2026-5932
  (no severity) in the worker; two Medium in the host's static glibc in
  capsule-adapter.
- **A link flag.** Go 1.27.4 refuses `-l:<file>` in a `#cgo LDFLAGS`
  directive, a fix against linker inputs a dependency chooses. The worker's
  `-l:libcryptsetup.so.12` links the shared library without the development
  symlink, which a host that extracts the headers without root lacks. It
  stays, and `CGO_LDFLAGS_ALLOW='-l:libcryptsetup\.so\.12'` allows that one
  flag: the workflows and the scripts that compile it set it, developers run
  `go env -w` once. The other way, `-lcryptsetup`, needs the development
  package on every build host.
- **The guest and the harness packages** embed Go binaries built with 1.27.3
  until they are rebuilt with 1.27.4 and the KVM campaigns rerun on them.

## Validation

Run locally, on Ubuntu 26.04: the four scripts end to end (the dependency
audit, in release mode too; the build twice with the guest image; the SBOMs
of the binaries, the guest image, the a2a-agent package and two Dagger-built
packages from an earlier build; the scans), the SBOMs twice
(byte-identical), actionlint and ShellCheck on both workflows, the
publishers' signatures of the pinned checksums, the release workflow's
assembly and checksum steps as written, a cosign signature and verification
of `SHA256SUMS` with a local key (nothing sent to a transparency log), and
unit tests of the rules, on Python 3.14 and 3.10 (each test fails when its
rule is removed). Only GitHub can run: the workflows themselves on Ubuntu
24.04, the Dagger export of the packages in CI, keyless signing, the
provenance attestation and the draft release.

## Questions for the product owner

1. **A new Critical in an upstream image with no fix.** The SLIM node's
   image gets a Critical glibc advisory on a Tuesday; Debian has no fix.
   Every pull request fails the next morning, whatever it changes.
   (a) Block until a maintainer adds a reviewed, expiring allowlist entry
   (today's behavior); (b) scan third-party images on a schedule and at
   release only, never blocking pull requests; (c) block only on findings
   that have a fix. Recommendation: (a): one entry is quick, and the failure
   makes sure someone reads the advisory.
2. **Patch times.** Defaults written in SECURITY.md: a Critical
   vulnerability in code we ship, or that the code calls, fixed in a release
   within 7 days, a High within 30; a Go security release adopted within 14
   days; Firecracker and guest kernel security releases within 30. Shorter
   times need someone on call. Recommendation: keep them until 1.0.
3. **A release with a called vulnerability.** On November 16, Go 1.27.3 had
   one (GO-2026-6859), which Go 1.27.4 fixes. (a) A release waits for the
   fix even when the finding is allowlisted (today's behavior); (b) the
   allowlist applies to releases too. Recommendation: (a).
4. **Publishing the guest image and capsule-adapter.** The guest image holds
   GPL (cryptsetup, e2fsprogs, util-linux) and LGPL (glibc) programs, and
   capsule-adapter links glibc statically. Publishing them obliges us to
   offer their exact source. (a) Do not publish them; operators build them
   (today's behavior); (b) publish them with the source packages of the
   exact versions attached to the release, fetched from a fixed Ubuntu
   snapshot (which also makes the guest reproducible on any host);
   (c) build capsule-adapter against musl (MIT), as the Dagger module
   already does, and publish it; keep the guest image out. Recommendation:
   (c) now, (b) when the guest's native packages come from a snapshot.
5. **Who may cut a release.** The workflow assumes that only maintainers can
   create `v*` tags (a tag ruleset, not created by this change).
   Recommendation: one maintainer tags, a second reviews the draft before it
   is published, once there are two.
