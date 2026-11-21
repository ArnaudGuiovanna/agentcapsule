# OpenSSL backports for the Alpine images

The Dockerfile builds the Alpine OpenSSL 3.5.9 package with Agent Capsule revision `r20261121`. It retains Alpine's previous security patches and runs the package's OpenSSL test suite before installing the rebuilt packages. The runtime stage upgrades `libcrypto3`, `libssl3` and, where already installed, the `openssl` command. Package signing keys are generated in the build stage. Only the public key is used to verify the local APKs during installation. [Alpine packaging source](https://github.com/alpinelinux/aports/tree/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl)

| Advisory | Source of the production code change |
|---|---|
| CVE-2026-107493 | [OpenSSL 3.5 maintenance commit](https://github.com/openssl/openssl/commit/c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d) |
| CVE-2026-124709 | [OpenSSL 3.5 maintenance commit](https://github.com/openssl/openssl/commit/f3acb0a3328046741479482c51cec815839e1b05) |
| CVE-2026-121482 | [OpenSSL 3.5 maintenance commit](https://github.com/openssl/openssl/commit/468c287cf451a834b370b69ab321b8ffdfac23aa) |
| CVE-2026-107494 | Downstream backport from proposed change [33544](https://github.com/openssl/openssl/pull/33544), pinned to [cc6ddac](https://github.com/openssl/openssl/commit/cc6ddac0e961798d351f86919d488d53be16960e). |
| CVE-2026-84786 | Downstream backport from proposed change [33634](https://github.com/openssl/openssl/pull/33634), pinned to [d54155a](https://github.com/openssl/openssl/commit/d54155a80a4fa8d2ebc2a5a850e7ea8270818217). |

## Build the candidates

Run the commands from the root of the Agent Capsule repository on a machine with Docker BuildKit. The Python runtime supplies the base filesystem for both example harnesses. HAProxy and OASF keep the users and entry points of their upstream images. OASF needs the build for Alpine 3.23.

```sh
docker build --platform linux/amd64 -t agentcapsule-local/python:openssl-backport deploy/images/openssl

docker build --platform linux/amd64 \
  --build-arg RUNTIME_BASE=docker.io/library/haproxy:3.2-alpine@sha256:96ec3c75a9264ba94e733eeacb44051ed6e7b79bb77a73c2c36f236b6423f1f0 \
  --build-arg RUNTIME_USER=haproxy \
  -t agentcapsule-local/haproxy:openssl-backport deploy/images/openssl

docker build --platform linux/amd64 \
  --build-arg BUILD_BASE=alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2 \
  --build-arg RUNTIME_BASE=ghcr.io/agntcy/oasf-server@sha256:4ef8f82f1c2a5b9dc703e208ef8764a558ec0301f7459a7073d2d8758d3d5f9f \
  --build-arg RUNTIME_USER=app \
  -t agentcapsule-local/oasf:openssl-backport deploy/images/openssl
```

After an upstream update, compare its fixes to all five source revisions, rebuild the two harnesses and run the interoperability and release checks before updating deployment digests. [Release qualification](../../../docs/release.md)

## Release verification

The release includes `openssl-qualification.json`, the original Grype reports in `vulnerability-reports.tar.gz`, and the decisions in `vulnerability-scan.json`. Their checksums are signed with the release. The qualification records the Git revision of each fix, the digest of each runtime image, and the SHA-256 of the installed binaries and their Alpine packages.

Grype can report the five advisories against the upstream version number after these changes. The release scanner records a match under `verified_backports` only when the target, advisory, Alpine package identity, file ownership and file checksum match the qualification. Both reference harnesses also undergo a direct checksum comparison on files extracted from their guest filesystem. The scanner preserves the original severity and every other finding. [Qualification manifest](qualification.json)
