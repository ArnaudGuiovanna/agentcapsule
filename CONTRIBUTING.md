# Contributing

Thanks for your interest in Agent Capsule. The project is pre-MVP; the
[roadmap](ROADMAP.md) lists what is missing and is the best place to find work.

## Before you start

- For anything larger than a small fix, open an issue first to agree on the approach.
- Security problems go through private reporting, never public issues: see
  [SECURITY.md](SECURITY.md).

## Development setup

You need Linux amd64, Go 1.27.4, a C compiler, the `libcryptsetup` development
headers and PostgreSQL 16 or newer. KVM, Firecracker and root access are only needed
for the VM campaigns. The worker links `libcryptsetup.so.12` by its file name,
a flag Go refuses unless `CGO_LDFLAGS_ALLOW` allows it: allow it once with the
first command below.

```bash
go env -w CGO_LDFLAGS_ALLOW='-l:libcryptsetup\.so\.12'
go build ./cmd/...
go test -race ./...
python3 scripts/verify-postgres.py --pg-bin /usr/lib/postgresql/16/bin --native-tools /
```

Tests that need PostgreSQL skip without `AGENTCAPSULE_TEST_POSTGRES`; the
`verify-postgres.py` runner provides a private cluster and refuses skipped tests.
See [scripts/README.md](scripts/README.md) for every runner.

## What a change needs

- **Tests at the right level.** A transactional rule needs a PostgreSQL test; a VM,
  volume or jailer behavior needs a KVM test; concurrency needs a race test. Unit
  tests alone do not validate those.
- **Database changes as new migrations.** Add `internal/controlplane/migrations/NNNN_*.sql`
  and register it in `migrations.go`; never edit an installed migration.
- **API changes in the contract.** Update [openapi/openapi.yaml](openapi/openapi.yaml)
  and the relevant page in [docs/api/](docs/api/).
- **Protocol changes in the models.** If you change delivery, revocation, lifecycle or
  completion rules, update the matching model in [spec/](spec/) and keep its
  invariants passing. `python3 scripts/check-model-runs.py` runs every run of
  the models and replays the traces kept under `internal/**/testdata` on them;
  a copy of a model kept there must match it or be declared frozen
  ([spec/pinned-models.json](spec/pinned-models.json)).
- **Honest documentation.** State limits and what is not validated.
- `gofmt`, `go vet`, English everywhere (code, comments, docs, messages).

## Pull requests

- Keep each pull request focused, with a description of the behavior change and how
  it was tested.
- CI must pass: formatting and vet, unit and race tests, the PostgreSQL integration
  runner, the OpenAPI validation, the Quint typecheck, repository hygiene, the
  secret scan and the release audit (vulnerabilities, licenses, reproducible build,
  SBOMs, scans; see [docs/release.md](docs/release.md)).
- **New dependencies and images.** A new Go module, Python package or container
  image must carry an allowed license (`scripts/license-policy.json`) and an image
  must be pinned by digest. Accept a vulnerability only with a reviewed entry of
  `scripts/vulnerability-allowlist.json`.
- Never commit credentials, keys, tokens, personal paths or generated evidence
  (`_evidence/` is ignored). Fake secrets in tests must be obviously fake and marked
  `gitleaks:allow`.

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
