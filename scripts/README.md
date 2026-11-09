# Scripts: builds, checks and campaigns

Current Go code lives in `cmd/` and `internal/`. Runners work on a frozen copy
of the sources and write their evidence (logs, `summary.json`, digests) to a
fresh `--output` directory, never overwritten. When `--output` is omitted, the
default is `./_evidence/<timestamp>` (git-ignored; Go tooling skips `_` directories, so the frozen source copies never reach `go test ./...`). Replace the `<...>`
placeholders below with paths from your environment.

## Prerequisites

- Linux amd64.
- **Go 1.27.3**, Python 3.10+ (3.11+ for `verify-interop.py`) and a C compiler
  (CGO and the race detector are on).
- libcryptsetup headers (`libcryptsetup-dev`) and the shared library
  `libcryptsetup.so.12`. If the headers are not installed system-wide, extract
  them into a private tools directory and pass it with `--native-tools`
  (`<tools-dir>` below).
- PostgreSQL (server binaries), for `verify-postgres.py` and the PostgreSQL
  phases of the KVM runners.
- For KVM campaigns: access to `/dev/kvm`, Firecracker 1.17.0 (the downstream
  build produced by `build-firecracker.py` plus the upstream binary used as a
  negative control), a guest kernel (`build-guest-kernel.py`) and a guest image
  (`build-product-guest.py` or `build-control-guest.py`). The jailer and cgroups
  require **root**.

Do not run `go test ./...` at the repository root with sources outside
`cmd/` and `internal/`; use the runners below.

## Scripts

| Script | Purpose |
|---|---|
| `check-go.py` | Go tests with race detector, no PostgreSQL or KVM |
| `test_check_go.py` | Unit tests of `check-go.py` |
| `check-repo-hygiene.py` | Rejects new tracked files with a personal absolute path or Go sources committed under `_evidence/` (baseline: `hygiene-baseline.json`) |
| `verify-postgres.py` | Go/race tests against a private, owned PostgreSQL cluster, with crash/WAL recovery; optional live LLM phase |
| `verify-runtime.py` | Real Go host-driver/KVM tests (root orchestration; optional PostgreSQL placement checks) |
| `verify-product-guest.py` | Reusable encrypted guest under jailed Firecracker (root, KVM) |
| `verify-vm-isolation.py` | Disposable jailer isolation tests (root) |
| `verify-vm-storage.py` | Disposable Firecracker/KVM storage lab |
| `verify-interop.py` | Partial A2A/OASF/Directory/SLIM qualification probe; see [docs/interop.md](../docs/interop.md) |
| `build-firecracker.py` | Builds the pinned Firecracker variant with VMM-owned file locks |
| `build-guest-kernel.py` | Builds the pinned guest kernel with device-mapper/dm-crypt, without root |
| `build-product-guest.py` | Builds capsule-init and the echo harness into a pinned initramfs |
| `build-control-guest.py` | Builds the disposable authenticated SQL harness fixture |
| `build-python-harness.py` | Builds the python-echo harness package (Docker, pinned base image, then `pack`); its `package/` directory is required by `verify-product-guest.py --python-harness` |
| `openapi-requirements.txt` | Python requirements for validating the OpenAPI specification |

## Local Go check (no PostgreSQL)

```bash
python3 scripts/check-go.py --go <path-to-go> --native-tools <tools-dir>/guest-build
```

Omit `--native-tools` to use the system headers. The script freezes `go.mod`,
`go.sum`, `cmd/` and `internal/`, then runs
`go test -race -json -count=1 -timeout=180s ./cmd/... ./internal/...`. It
enforces the Go version, disables implicit toolchain selection and inherited Go
flags. Child tests use the same Go executable through `PATH`. PostgreSQL
connection variables and crash-helper subprocess variables are removed so that
no existing database or helper is touched.

`summary.json` holds digests, command, version, passed cases and tests not run.
A result of `passed_local_only` only means the local check passes. Known skips
that need `verify-postgres.py` are listed in
`required_postgres_tests_not_run`; PostgreSQL and KVM validation stays
`required_not_run`. An unexpected skip, a non-terminal output, zero tests run, a
change to the frozen sources or a failure fails the check. `--fail-on-skip`
also rejects the PostgreSQL skips; it does not provide a database and does not
replace the integration runner. Case counts include subtests and helpers run by
Go; they are not a coverage measure.

Tests of the script itself, with no Go or database needed:

```bash
python3 -m unittest discover -s scripts -p test_check_go.py -v
```

## Repository hygiene

```bash
python3 scripts/check-repo-hygiene.py
```

Files that predate the rules are listed in `scripts/hygiene-baseline.json`;
fixing one never fails the check. Use `--update` only to record a reviewed
decision, never to hide a new offending file. CI runs this check before the
PostgreSQL campaign.

## PostgreSQL integration (required)

```bash
python3 scripts/verify-postgres.py \
  --pg-bin /usr/lib/postgresql/16/bin \
  --native-tools / \
  --output <output-dir>/postgres
```

This example uses Ubuntu 24.04 packages and the system headers. The runner
creates its own cluster on a private Unix socket and uses no existing database.
It freezes the sources before the Go/race tests, enforces
`AGENTCAPSULE_REQUIRE_POSTGRES=1`, refuses any skipped test and checks WAL
recovery after an immediate shutdown (not a physical power cut). All phases
(nine, ten with `llm-live`) must succeed; a test run without PostgreSQL is not a
substitute. For a PostgreSQL install that is not system-wide, use
`--pg-bin` and `--library-path`.

`--llm-base-url URL --llm-model MODEL` adds a `llm-live` phase after the
integration: `TestLive*` tests compiled with `-tags=llmlive` against a real
OpenAI-compatible endpoint, for example a local Ollama
(`http://127.0.0.1:11434/v1`, `tinyllama:latest`). Without these options the
phase does not exist and `environment.json` reports `llm_live: not_run`.
Inherited `AGENTCAPSULE_TEST_LLM_*` variables are removed, except the optional
secret, which is never written to the evidence.

## KVM campaigns (root)

These runners need root for the jailer, namespaces and cgroups, and access to
`/dev/kvm`. They create only their own temporary directories, cgroups, volumes,
keys and VMMs, and touch no existing volume, host network setting or unrelated
process. Run each with `--help` for the full option list.

```bash
# Runtime: Go host-driver tests under KVM. --native-headers is required with
# the PostgreSQL checks (--pg-bin), because the worker links libcryptsetup.
sudo python3 scripts/verify-runtime.py --go <path-to-go> \
  --firecracker-build <firecracker-build-dir> \
  --upstream-firecracker <upstream-firecracker> \
  --kernel <guest-kernel> --guest <guest-image> \
  --pg-bin <postgres-bin-dir> --pg-user <non-root-user> \
  --native-headers <tools-dir>/guest-build/usr/include \
  --output <output-dir>/runtime

# Encrypted product guest, two owners and two VMs
sudo python3 scripts/verify-product-guest.py --go <path-to-go> \
  --firecracker-build <firecracker-build-dir> \
  --upstream-firecracker <upstream-firecracker> \
  --kernel <guest-kernel> --guest-build <product-guest-build-dir> \
  --native-headers <tools-dir>/guest-build/usr/include \
  --python-harness <python-harness-build-dir>/package \
  --pg-bin <postgres-bin-dir> --pg-user <non-root-user> \
  --output <output-dir>/product-guest

# Jailer isolation and storage labs
sudo python3 scripts/verify-vm-isolation.py --firecracker <firecracker> \
  --jailer <jailer> --kernel <guest-kernel> --guest <guest> \
  --output <output-dir>/isolation
python3 scripts/verify-vm-storage.py --firecracker <firecracker> \
  --kernel <guest-kernel> --guest <guest> --output <output-dir>/storage
```

`verify-vm-storage.py` runs the VMM as a non-root user (`--vmm-user` is
required when orchestrating as root); `--inject-io-errors` uses an owned
loop/dm-error device and requires root. None of these runners claims production
isolation beyond what each documents in its `--help`.

## GitHub Actions

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the local-check
tests, then the real PostgreSQL runner, on pull requests, pushes to `main` and
manual triggers. The job does not replace the runner with a suite that could
skip every database test. Native dependencies are installed, the PostgreSQL path
is taken from the installed package, and reports are kept seven days, including
on failure. Only top-level reports are uploaded, not the database or the test
volumes/keys.

Go is pinned to **1.27.3**; the `go 1.25.0` line of `go.mod` remains the
module's language/minimum version, not a promise of validation on all Go
versions. CI uses PostgreSQL **16** from Ubuntu 24.04; the patch number and the
native versions are recorded on each run. The Ubuntu image and its patches
evolve, so this is not a hermetic system build.

Actions are pinned by full SHA
([checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1),
[setup-go v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0),
[upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2));
Go availability can be checked in the [official catalog](https://go.dev/dl/?mode=json).
The job explicitly uses [Ubuntu 24.04](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).
An action or toolchain update must change the pins and re-run the tests; do not
replace the SHAs with a floating branch.

GitHub permissions are limited to reading the repository, with no credentials
persisted by checkout. No deployment, LLM provider or KVM secret is needed. The
workflow does not use `pull_request_target` and deploys nothing.

CI does **not** validate Firecracker/jailer on the target host, physical
storage cuts, complete product isolation, AGNTCY interoperability or an
external restore. The KVM/production campaigns of the [roadmap](../ROADMAP.md)
remain mandatory for the relevant work packages. The workflow configuration
alone is not proof of a green run on GitHub.
