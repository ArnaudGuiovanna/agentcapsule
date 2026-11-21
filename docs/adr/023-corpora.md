# Corpora: knowledge built from Git, published immutable, mounted read-only

Date: November 20, 2026. **Status: accepted, not built.** The product owner
asked to follow the recommendations of the plan: D-C1 to D-C9 below are its
recommendations. Lots 1 to 10 of the plan build it; each lot implements the
sections this record names for it (see [Lots](#what-each-lot-builds)).
References: [plan-corpus.md](../plan-corpus.md) (the plan, in French),
[plan-streaming.md](../plan-streaming.md) (its SSE hub will carry live build
progress), REG-005, REG-006, REG-007, RUN-010 and the COR requirements of the
[product spec](../product.md#corpora), [ADR 010](010-transport-security-and-preflight.md)
(addresses and transport), [ADR 011](011-llm-access-and-cost-budgets.md)
(aliases, prices, budgets), [ADR 012](012-limits-restart-budgets-egress.md)
(drive limits), [ADR 016](016-content-links-capabilities.md) (JSON content,
capabilities), [ADR 021](021-organization-quotas.md) (organization quotas),
the model [corpus_lifecycle.qnt](../../spec/corpus_lifecycle.qnt), and the
Served contract in [openapi/openapi.yaml](../../openapi/openapi.yaml).

## Context

An organization wants its agents to know its documents: PDF, office files,
spreadsheets, audio and video. The documents live in a Git repository. The
platform converts them to Markdown and data, builds an index and a summary
(`INDEX.md`), and publishes the result as an immutable version. Every VM that
needs it mounts the same image read-only, with no copy, and reads it with no
network. A **corpus** is that knowledge; a **build** turns a commit of its
repository into an image; a **release** is a published build, `name:version`.

Constraints of the plan: platform processing runs on CPU; every inference
(OCR, transcription, image description, summaries, embeddings) goes to the
providers through the LLM gateway, never to a local model; large corpora build
asynchronously; the core holds no business logic (a harness-specific step goes
through an external enricher, lot 9).

What exists at `321143b`, and what this record reuses:

| Subject | State | Where |
|---|---|---|
| Image format | `BuildRootfs`: reproducible ext4 (UUID and hash seed from `sha256(name\0version)`, no journal, fixed times), `CheckRootfs` (superblock), `InspectRootfs` (confined debugfs, `stat` only) | `internal/harnesspkg/build.go:24`, `package.go:187`, `inspect.go:32` |
| Package | `harness.yaml`, `checksums.json`, `harness.ext4`; schema `agentcapsule.harness/v1`; base `agentcapsule-guest/1` | `internal/harnesspkg/package.go:38-47` |
| Outbound client | `addrpolicy` dialer, rule per host and repository prefix, `blob_hosts`, at most 2 redirects, `Authorization` dropped when the host changes | `internal/ociregistry/client.go:59-93`, `policy.go:42-183` |
| Import loop | `HarnessImporter`: lease, 5 attempts, backoff `30 s << (n-1)` up to 30 min, storage pressure | `internal/worker/registry.go:99-246`, `internal/controlplane/operations.go:47` |
| Secrets | provider secret sealed with AES-GCM, key `HMAC-SHA256(receipt key, "agentcapsule.llm-provider-secret.v1")`, AAD organization, provider and generation | `internal/controlplane/users.go:50-56`, `llm_providers.go:117-135` |
| Distribution | hard link into the jail (copy on `EXDEV`), read-only drive, `LOCK_SH` for read-only drives (Firecracker patch), cache `<registry.cache>/sha256/<hex>/` (default `<root>/releases`), `Refill`, `Evict`, `-collect-garbage` | `internal/runtime/firecracker_provisioning_linux.go:21`, `runtime/firecracker/volume-lock.patch:17`, `internal/worker/registry.go:126-341` |
| Binding | templates `name@N`, `validateTemplate` with `FOR SHARE`, rollouts with a canary, `Enrollment`, `ChangeAgentRelease` at the next boot | `internal/controlplane/templates.go:130-211`, `rollouts.go:98-176`, `provisioning.go:19`, `agent_release.go:32-99` |
| Guest | `/dev/vdb` hard-coded for the harness, `MountHarnessRoot` (`ro,nosuid,nodev,noatime`), strict boot files `etc/capsule/{boot,harness,runtime}.json`, boot record on FD 3 (4,096 bytes, unknown fields refused in Go and Python) | `internal/capsuleprotocol/initrd.go:21-45`, `internal/guestinit/harness_root_linux.go:21`, `cmd/capsule-init/main.go:31-51`, `sdk/python/agentcapsule_harness.py:55` |
| Asynchronous resource | `harness_imports` (`IMPORTING`, `READY`, `REJECTED`, `error_code`), `agentcapsule operation wait --type` | `internal/controlplane/migrations/0019_harness_registry.sql:20`, `cmd/agentcapsule/routes.go:300-316` |

## Decisions D-C1 to D-C9

| ID | Decision | Why |
|---|---|---|
| D-C1 | The resource is **`corpus`** (plural `corpora`) in the API, the CLI and the guest ABI: `/v1/corpora`, `agentcapsule corpus …`, `/corpus/<mount>` in the VM. | Short and accurate; the CLI's `context` already names connection contexts, and renaming them would break `v0.0.1`. |
| D-C2 | The image is **ext4**, built with the options of `BuildRootfs`; its UUID is set by the worker before the build. | Reuses `CheckRootfs`, the confined debugfs and reproducible builds. The host cannot inspect squashfs, and `unsquashfs` would run content on the host (REG-007). EROFS needs a new guest kernel (`# CONFIG_EROFS_FS is not set`, `runtime/guest/microvm-linux-6.1.config:2952`). Compression is left for later. |
| D-C3 | Builds run in a **hidden builder agent per organization**, harness `agentcapsule-corpus-builder`. | Reuses the whole agent path: platform channel, gateway, the organization's budgets, capabilities, sleep. Its encrypted volume is the conversion cache, so rebuilds are incremental. A new "job" VM kind would rewrite `capsule-init` (which always opens LUKS) and placement; a host sandbox would break REG-007. |
| D-C4 | Sources are fetched as **forge archives** by commit (GitHub `tarball/{sha}`, GitLab `repository/archive.tar.gz?sha=`), by the worker, as opaque bytes. | A clone on the host would parse untrusted packfiles; the VM has no network. |
| D-C5 | Large files come through **Git LFS, in two phases**: the builder lists the pointers (`oid`, size) from the archive; the worker downloads each object through the LFS batch API, checks `sha256 == oid`, and hands them over as a raw drive. | The host never parses an object. An OCI source (`corpus source --oci`, reusing `Fetcher`) comes later for local files. |
| D-C6 | Integrity in the guest: the **digest is checked when the image enters the cache**, then the check is remembered by inode, size and mtime. | Hashing several GB at each resolution, as `harnessImage` does for a harness, costs too much. dm-verity (absent from the guest kernel) is P2. |
| D-C7 | Human corrections live **in the repository** (`corrections:` of the manifest), then a rebuild. | Git keeps the history; the platform holds no hidden state. |
| D-C8 | A corpus belongs to **one organization**. | Isolation by default. A platform corpus shared between organizations is a P2 question. |
| D-C9 | Distribution uses the **local cache only**. | The product is single-host first. P2: push the signed package as an OCI artifact and reuse `Fetcher` and `Refill`. |

## 1. Vocabulary

| Term | Meaning |
|---|---|
| corpus | An organization's knowledge from one repository path: `name`, source, credential |
| source credential | An organization's read-only forge token, sealed; never shown again |
| build | One conversion of one commit of a corpus into an image, through states |
| image | `corpus.ext4`, the published layout `agentcapsule.corpus/v1`, keyed by its sha256 (its digest) |
| release | `name:version`, immutable, pointing to one digest |
| binding | An agent's list of corpora (`{name, version, mount}`, or a build in `REVIEW` for a try), applied at its next boot |
| mount | The directory name under `/corpus/` in the VM |
| builder | The hidden agent of kind `corpus_builder` that runs the builds of its organization |
| review bundle | `INDEX.md`, `report.json` and each document's `README.md`, read out of the image by the worker, sealed, readable through the API |
| pin | A reason the host's cache must keep an image (§9) |

Names: a corpus `name` is 1 to 100 of `[a-z0-9._-]`, starting with a letter or
a digit, unique in its organization. A `mount` matches
`^[a-z0-9][a-z0-9_-]{0,62}$`; it defaults to the corpus name when that name
is a valid mount, and is required otherwise (`400 invalid_request`). A
`version` is an integer from 1 to 2,147,483,647.
Identifiers are opaque, kind and 128 random bits (`newID`): `scr_` source
credential, `cor_` corpus, `cbd_` build, `crel_` release.

## 2. Formats

The full specification of the two formats is lot 1's new page `docs/corpus.md`.
This section fixes what other lots rely on.

### 2.1 Source manifest: `agentcapsule.corpus-source/v1`

File `agentcapsule-corpus.yaml` at the corpus's `path` in the repository,
versioned with the sources. Strict YAML: unknown fields, duplicate keys and
extra documents are refused; at most 64 KiB. Only the builder reads it, in its
VM; the host never does.

```yaml
schema: agentcapsule.corpus-source/v1
title: "Corporate finance, year 3"     # 1-200 characters
language: fr                           # BCP 47
include: ["courses/**", "videos/**", "data/**"]   # globs relative to path; default ["**"]
exclude: ["**/drafts/**"]
processing:
  ocr: auto                            # auto | always | never: pages without native text
  transcription: {alias: transcribe-fr}
  vision: {alias: vision, describe_figures: true}
  summaries: {alias: summary}
  embeddings: {alias: embed}           # optional
documents:                             # optional metadata per file
  - path: courses/chap1.pdf
    title: "Chapter 1: time value of money"
    tags: [discounting, NPV]
corrections:                           # replaces the generated Markdown view of a document
  - path: videos/session2.mp4
    markdown: corrections/session2.md
```

Each `alias` is an LLM alias of the organization: its grants, budgets and
prices apply as for any agent ([api/llm.md](../api/llm.md)). A missing
`processing` entry turns that step off: without `transcription`, audio and
video are listed as skipped. Paths are clean, relative, inside `path`; a path
with `..`, a leading `/` or a NUL is invalid.

### 2.2 Published layout: `agentcapsule.corpus/v1`

```
/corpus/<mount>/
  corpus.json          name, version, source commit, builder version, languages,
                       document count, tokens in total and per document, modalities,
                       embedding model when search/vectors.* exists
  INDEX.md             global summary: collections, documents, 2-3 line summaries,
                       paths; target at most 8,000 tokens, at most 64 KiB
  topics/*.md          topic indexes (notion -> sections)
  glossary.md          extracted terms with a sourced definition
  docs/<id>/
    doc.json           canonical form: typed elements, reading order, page and
                       coordinates or timecode, extraction confidence, stable IDs
    README.md          summary, outline, metadata, source path
    part-001.md ...    Markdown view in parts, anchors to element IDs
    pages/*.webp       pages, slides, video key frames
    data/*.csv         data kept as data, each with its .md description
  search/fts.sqlite    contextualized passages (FTS5); open with mode=ro&immutable=1
  search/vectors.*     optional
  report.json          build report (agentcapsule.corpus-report/v1, §2.4)
  ext/                 reserved for enrichers (lot 9); empty in this version
```

The originals are not copied into the image. A citation names the source path
and commit; a client can build the forge link. `corpus.json`, `INDEX.md` and
`search/fts.sqlite` are required; the worker refuses an image without them
(§6.4). The image holds only directories, regular files and symbolic links
that stay inside it: no device, FIFO, socket, hard link to outside, setuid or
setgid file.

### 2.3 Host package

The mirror of a harness package, in `<corpus.cache>/sha256/<hex>/` where
`<hex>` is the sha256 of `corpus.ext4`. Default `corpus.cache` is
`<root>/corpora`. The worker writes it; it never comes from outside.

| File | Content |
|---|---|
| `corpus.yaml` | `schema: agentcapsule.corpus/v1`, `name` (the corpus's), `build_id`, `commit`, `builder` (the builder release's `name@version` and digest), `base: agentcapsule-guest/2`, `uuid`, `bytes`; no version (C13) |
| `checksums.json` | sha256 of `corpus.yaml` and `corpus.ext4` |
| `corpus.ext4` | the image, read-only (mode 0444) |

The UUID of the image is set by the worker before the build:
`uuid = sha256("agentcapsule.corpus-uuid.v1\0" + corpus_id + "\0" + commit + "\0" + builder digest)`,
first 16 bytes, formatted as a UUID; it is also the ext4 hash seed. The same
commit built by the same builder gets the same UUID, so the same image and the
same digest. The builder runs `mkfs.ext4` with the options of `BuildRootfs`
(`-O ^has_journal -E root_owner=0:0,hash_seed=<uuid> -U <uuid>`,
`E2FSPROGS_FAKE_TIME=1`, every inode's times set to 1); lot 1 shares that
code between `harnesspkg` and `internal/corpuspkg`.

### 2.4 Report: `agentcapsule.corpus-report/v1`

The image contains a reproducible `report.json` with the content build
identifier and converted statuses. The API review preserves the execution's
actual build ID and per-file cache hits. The builder writes the latter JSON
immediately before a 48-byte footer at the end of the output drive, beyond
the ext4 filesystem. The footer contains the eight ASCII bytes `ACRPT001`,
the JSON length as an unsigned 64-bit big-endian value, and the raw SHA-256
of the JSON. The worker checks the bounds (1 MiB maximum), digest, schema,
commit and build ID before copying only the ext4 region into the image cache.

The execution report in the review bundle:

```json
{"schema": "agentcapsule.corpus-report/v1",
 "build_id": "cbd_...", "commit": "<40 hex>",
 "files": [{"path": "courses/chap1.pdf", "kind": "pdf", "status": "converted",
            "doc_id": "d0001", "bytes": 182340, "tokens": 5120,
            "warnings": ["ocr_low_confidence"], "error": ""}],
 "totals": {"files": 0, "converted": 0, "cached": 0, "skipped": 0, "failed": 0, "tokens": 0}}
```

`status` is `converted`, `cached` (from the conversion cache), `skipped`
(excluded type or step turned off) or `failed`; `error` is a closed code
(`unsupported_type`, `too_large`, `malformed`, `inference_failed`,
`timeout`); `kind` is `markdown`, `text`, `pdf`, `docx`, `pptx`, `odt`,
`xlsx`, `csv`, `image`, `audio`, `video` or `other`. The worker checks it
strictly when it reads the review bundle (unknown fields refused); costs come
from the platform's ledger, not from the report (§7.6).

## 3. Source credentials and host rules (lot 3)

### 3.1 Credentials

| Route | Scope | Effect |
|---|---|---|
| `GET /v1/source-credentials` | `corpus:manage` | metadata only: `id`, `name`, `kind`, `host`, `generation`, `status`, `created_at`, `rotated_at`, `disabled_at` |
| `POST /v1/source-credentials` | `corpus:manage` | `{name, kind: github\|gitlab, host, secret}`; 201 with the metadata |
| `POST /v1/source-credentials/{id}/rotate` | `corpus:manage` | `{secret}`; a new generation; 200 |
| `POST /v1/source-credentials/{id}/disable` | `corpus:manage` | erases the ciphertext; 200; builds that need it then fail `access_denied` |

- `name` 1 to 100 of `[a-z0-9._-]`, unique in the organization; `secret` 1 to
  4,096 bytes of printable ASCII; it is never returned, logged, traced or put
  in an audit event.
- **Sealing**, as a provider secret: AES-GCM with the key
  `HMAC-SHA256(receipt key, "agentcapsule.source-credential-secret.v1")`, AAD
  `"agentcapsule.source-credential/" + tenant + "/" + credential + "/"`
  followed by the generation as a big-endian uint64. Only the worker opens
  it, when it fetches.
- `host` must be a host of a `corpus.sources.rules` entry of the same `kind`
  on at least one worker; the API cannot see worker configurations, so it
  checks the syntax only (a DNS name, optional port) and the worker refuses a
  build whose credential host matches no rule (`policy`).
- **Expected token**: read-only. GitHub: a fine-grained personal access token
  with `contents:read` on the repository. GitLab: a project or group access
  token with `read_repository` (LFS through the same token). The docs (lot 7)
  say so; the platform cannot verify a token's scopes.
- A credential is sent only to its own `host` and to the rule's
  `archive_hosts` and `lfs_hosts` when the forge redirects there with a
  signed URL; `Authorization` is dropped at every change of host, as the
  registry client does.

### 3.2 Host rules (worker configuration)

The worker's JSON configuration (unknown fields refused) gains a `corpus`
section. Its `sources.rules` follow the registry rules:

```json
"corpus": {
  "cache": "/var/lib/agentcapsule/corpora",
  "staging": "/var/lib/agentcapsule/corpus-staging",
  "max_archive_mib": 2048,
  "max_lfs_mib": 20480,
  "max_lfs_objects": 10000,
  "max_image_mib": 16384,
  "builder": {"harness": {"name": "agentcapsule-corpus-builder", "version": "1.0.0"},
              "vcpus": 2, "memory_mib": 4096, "volume_mib": 2048},
  "sources": {
    "rules": [
      {"host": "github.com", "kind": "github", "api_host": "api.github.com",
       "repositories": ["acme/"], "archive_hosts": ["codeload.github.com"],
       "lfs_hosts": ["github-cloud.githubusercontent.com"]},
      {"host": "gitlab.example.org", "kind": "gitlab", "repositories": ["school/"]}
    ],
    "allowed_internal_hosts": ["gitlab.example.org:443"]
  }
}
```

| Key | Meaning | Default |
|---|---|---|
| `corpus.cache` | absolute directory of the verified images; must be on the file system of `<root>/jails` (§5.1) | `<root>/corpora` |
| `corpus.staging` | absolute directory of the builds' downloads and output drives | `<root>/corpus-staging` |
| `corpus.max_archive_mib` | one archive | 2,048 |
| `corpus.max_lfs_mib`, `corpus.max_lfs_objects` | all LFS objects of one build | 20,480; 10,000 |
| `corpus.max_image_mib` | the output drive, so one image | 16,384 |
| `corpus.builder.harness` | the builder's harness release, imported by the operator | required to build |
| `corpus.builder.vcpus`, `memory_mib`, `volume_mib` | the builder agent's resources | 2, 4,096, 2,048 |
| `corpus.sources.rules[]` | `host`, `kind` (`github` or `gitlab`), `api_host` (default: `api.github.com` for `github.com`, the `host` otherwise), `repositories` (prefixes, as registry rules), `archive_hosts`, `lfs_hosts`, `local` | none: no rule, no build |
| `corpus.sources.allowed_internal_hosts` | internal forge addresses the operator allows, in the syntax of `llm.allowed_internal_providers` (`host:port` or an internal CIDR) | none |
| `drive_limits.corpus` | the rate of a corpus drive (§5.1) | 128 MiB/s, 4,000 IOPS |

- Addresses are checked after DNS resolution by `addrpolicy`, with the
  gateway's classes ([ADR 010](010-transport-security-and-preflight.md) §4):
  public only, unless the address is in `allowed_internal_hosts`. Link-local,
  unspecified, multicast and metadata addresses are never allowed.
- **HTTPS only.** `local: true` fetches over plain HTTP and allows internal
  addresses, for development; production refuses the worker's start with
  such a rule, as it refuses a local registry rule
  (`internal/worker/preflight_linux.go:29-44`). An internal GitLab in
  production uses `allowed_internal_hosts`, over HTTPS.
- **Redirects**: at most 2 per request, as the registry client, each to the
  rule's `host`, `api_host`, `archive_hosts` or `lfs_hosts`; another host is
  refused (`policy`).

## 4. Fetching (lot 3)

The `CorpusFetcher` loop of the worker follows `HarnessImporter`: it claims a
`QUEUED` build of an organization with no build in progress, with a lease;
5 attempts; backoff `30 s << (n-1)` up to 30 min; a network failure retries,
a refusal ends the build `FAILED`. The API refuses a new build under image
storage pressure (`503 storage_pressure`, as `refuseUnderImagePressure`), and
the worker's `Pressure` hook stops a fetch, retried later.

1. **Ref to commit** (`FETCHING`). GitHub `GET /repos/{repository}/commits/{ref}`,
   GitLab `GET /api/v4/projects/{url-encoded repository}/repository/commits/{ref}`.
   The build records `commit` (40 hex) and is pinned to it. A build
   requested with `commit` skips this step.
2. **Archive** (`FETCHING`). GitHub `GET /repos/{repository}/tarball/{commit}`
   (redirect to `codeload.github.com`), GitLab
   `GET /api/v4/projects/{…}/repository/archive.tar.gz?sha={commit}`.
   Streamed to `<corpus.staging>/<build>/source.bin`, at most
   `max_archive_mib`, hashed as it arrives, then padded with zeros to a
   multiple of 4 KiB. The build records `archive_bytes` (exact, before
   padding) and `archive_sha256`.
3. **Scan** (`SCANNING`): the builder's `scan` (§6.3) returns the LFS pointers.
4. **LFS** (`FETCHING_LFS`). The worker calls the batch API
   (`POST {repository}.git/info/lfs/objects/batch`, `operation: download`,
   `transfers: ["basic"]`) for the pointers, at most 100 per call, downloads
   each object from the `href` it answers (an `lfs_hosts` host, or the
   forge), checks its size and `sha256 == oid`, and appends it to
   `<corpus.staging>/<build>/lfs.bin` at a 4 KiB-aligned offset. An object
   whose hash differs fails the build `integrity`. Objects already verified
   are kept for the build's life: a retry downloads only what is missing.
   `lfs.bin` starts with its index (§6.2). No LFS pointer, no `lfs.bin`.
5. The output drive `<corpus.staging>/<build>/output.ext4` is a sparse file of
   `max_image_mib`, created when `PACKAGING` starts.

The host only downloads, hashes, pads and concatenates. It runs no program on
these bytes, never decompresses them, never reads a file inside them: that is
REG-007 and RUN-010 extended to corpus sources. Lot 3 adds traps named `tar`,
`gzip`, `git`, `git-lfs`, `ffmpeg`, `pdftotext`, `soffice` and `unzip` to
`TestTheHostNeverRunsWhatAPackageHolds` (`internal/worker/package_content_test.go:41`)
and lists in `workerStarts` (`cmd/agentcapsule-api/imports_test.go:181`) every
program the corpus code starts (none on content; debugfs, confined, on the
output image, §6.4).

## 5. Drives and the guest mount (lot 4)

### 5.1 Runtime

- `prepare` (`internal/runtime/firecracker_linux.go:1010`) takes an ordered
  list of extra drives instead of the harness special case. Drive order:
  0 the data volume, then the registry harness when there is one, then the
  corpora in binding position order, then, for the builder only, the build
  drives `source`, `lfs` (when present), `output`.
- **Corpus drive**: `is_read_only: true`, `cache_type: "Unsafe"`,
  `io_engine: "Sync"`, the image hard-linked into the jail as the harness
  image is, under `LOCK_SH`.
- **Build drives**: `source` and `lfs` read-only; `output` read-write, a
  preallocated sparse file.
- **At most 4 corpora per VM.** The builder has none.
- **No silent copy.** `linkOrCopy` copies on `EXDEV`
  (`internal/runtime/firecracker_provisioning_linux.go:21`); for a corpus
  image it is a refusal. The worker's preflight refuses to start with a
  `corpus` section when `corpus.cache` and `<root>/jails` are on different
  file systems (`corpus_cache_filesystem`), and a link that still fails with
  `EXDEV` fails the boot, never copies.
- **Rate.** `DriveLimits` gains `corpus` (`drive_limits.corpus`,
  `bandwidth_mib_per_second` and `iops`, default 128 and 4,000, valid as the
  others), applied to each corpus drive, with a one-time burst of at most
  256 MiB (not the image's size, unlike the harness drive). Build drives use
  the `volume` rate. Lot 4 adds the row to ADR 012's table.

### 5.2 Boot file `etc/capsule/corpora.json`

Appended to the initrd by `AppendBootConfig`, read by `capsule-init` with
`readPrivateJSON` (root, mode 0400, at most 64 KiB, unknown fields refused):

An agent with a registry harness and two corpora, then the builder:

```json
{"schema": "agentcapsule.guest-corpora/v1",
 "corpora": [{"index": 2, "mount": "finance", "uuid": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"},
             {"index": 3, "mount": "handbook", "uuid": "6fa459ea-ee8a-4ca4-894e-db77e160355e"}]}
```

```json
{"schema": "agentcapsule.guest-corpora/v1",
 "corpora": [],
 "build": {"source": {"index": 2, "bytes": 52428800},
           "lfs": {"index": 3, "bytes": 1073741824},
           "output": {"index": 4, "bytes": 17179869184}}}
```

`index` is the drive's position: device `/dev/vd` plus the letter of that
index (`0` is `vda`). `corpora` has at most 4 entries with distinct indexes,
mounts and UUIDs; `build` is present only for the builder, and then
`corpora` is empty. The file is absent when the VM has neither.

The harness boot record (FD 3, 4,096 bytes, unknown fields refused by Go and
by Python) **does not change**: a harness discovers its corpora by listing
`/corpus/`, and the builder finds its drives at fixed paths (below).

### 5.3 `capsule-init`

- For each corpus entry it reads the ext4 superblock of `/dev/vd<letter>`
  and **checks its UUID** against `uuid`. Any mismatch, a missing device or
  an unreadable superblock refuses the boot: the guest exits before starting
  the harness, a failed boot (ADR 012). This guards against any shift in
  drive order. The registry harness stays drive 1, `HarnessDevice="/dev/vdb"`
  (`internal/capsuleprotocol/initrd.go:21`); corpora and build drives come
  after it, at the indexes the boot file gives, and start at 1 when the
  harness is built in.
- It mounts each corpus `ro,nosuid,nodev,noexec,noatime` at
  `/corpus/<mount>` in the harness root, or in the initramfs root for a
  built-in harness. `/corpus` itself is a read-only empty directory when the
  VM has no corpus.
- For the builder, it checks each build drive's size against `bytes`, then
  makes it available to the harness user only, as `/dev/corpus/source` and
  `/dev/corpus/lfs` (mode 0400) and `/dev/corpus/output` (mode 0600). A raw
  drive has no UUID: the builder checks the source's and the LFS drive's
  sha256 against its invocation (§6.3).

### 5.4 ABI `agentcapsule-guest/2`

- Base 2 adds the mount point `/corpus` to `harnesspkg.MountPoints`
  (`internal/harnesspkg/package.go:57`), `HarnessMountPoints`
  (`internal/capsuleprotocol/initrd.go:26`), `addMountPoints`
  (`internal/harnesspkg/build.go:143`) and the check of `InspectRootfs`.
- `harnesspkg` `Validate` accepts the bases `agentcapsule-guest/1` and
  `agentcapsule-guest/2`; a base-1 harness boots as before.
- An agent may bind corpora only if its harness is a release of base 2 or a
  built-in harness, **and** its recorded system image declares the feature
  `corpus.mount` (§5.5). Otherwise `422 corpus_incompatible`.

### 5.5 System image features

- A migration adds `system_images.features text[] NOT NULL DEFAULT '{}'`,
  from a closed list: `corpus.mount` (its `capsule-init` reads `corpora.json`,
  checks UUIDs and mounts corpora; it also exposes build drives).
- `POST /v1/system-images` accepts `features` (default empty); a system image
  is an immutable approval, so its features are fixed at approval.
  `GET /v1/system-images` shows them.
- An older `capsule-init` would ignore `corpora.json` and boot without the
  corpus, silently: hence the feature, checked by `validateTemplate` and by
  the binding routes against `agent_specs.system_image`. An agent created
  without a template has no recorded system image and cannot bind corpora in
  this version.

## 6. The builder agent (lot 5)

### 6.1 The agent

- One per organization, `agents.kind = 'corpus_builder'` (a new column,
  default `'agent'`). The worker creates it when it claims the
  organization's first build, from `corpus.builder` (harness release,
  resources), with a system image declaring `corpus.mount`.
- Hidden: never listed by `GET /v1/agents`, never in the Directory, never
  assignable, never a recipient of requests from other agents. Its routes
  under `/v1/agents/{id}` answer 404 to every caller.
- It does not count in the organization's agent, storage or VM quotas
  (ADR 021); it counts in the host's capacity (`max_active`, the capacity
  queue). Its idle policy sleeps it after 10 minutes without a build.
- Its volume (`corpus.builder.volume_mib`) is the **conversion cache**, keyed
  by `sha256(file) + builder version + options`, so a rebuild converts only
  the files that changed. It is archived and restored as any agent's volume.
- The builder requests `llm.invoke` for conversions that use a model and
  `stream.output` for per-file progress. The organization's capability
  policy applies to both. Its invocations come from an internal
  technical account of the organization, `corpus-builder`, created with it,
  never listed, with no token, assigned `invoke` and `read_content` on the
  builder only.
- Builds of one organization run one at a time on its builder, in the order
  they were requested; the others wait `QUEUED`.

### 6.2 The LFS drive

`lfs.bin` begins with an index written by the worker, so that the index never
travels in an invocation (32 KiB, ADR 016):

| Offset | Bytes | Content |
|---|---|---|
| 0 | 8 | magic `ACPLFS01` |
| 8 | 8 | big-endian length `L` of the index |
| 16 | `L` | JSON `{"schema":"agentcapsule.corpus-lfs/v1","objects":[{"oid":"<64 hex>","offset":N,"length":N}]}`, `offset` from the start of the drive, a multiple of 4,096, sorted |
| padded to 4 KiB | … | the objects |

### 6.3 Protocol: `scan`, `convert`, `package`

Each phase is one invocation of the builder by its technical account: one
JSON part (ADR 016), schema `agentcapsule.corpus-builder/v1`. The builder
answers `working`, then completes with one JSON part, at most 32 KiB. The
worker decodes both strictly. The invocation's deadline is the build's
(`deadline_at`). A failed completion, a timeout or a reply that does not
decode ends the build `FAILED builder_failed`.

| Phase | Input (`json`) | Result (`json`) |
|---|---|---|
| `scan` | `{"schema", "phase": "scan", "build_id", "commit", "path", "source": {"bytes", "sha256"}, "cursor"?}` | `{"schema", "phase": "scan", "manifest": "valid" \| "invalid", "errors": [..]?, "files": {"total", "included", "skipped"}, "bytes", "kinds": {"pdf": N, ...}, "estimate": {"llm_calls", "input_tokens", "audio_seconds", "pages"}, "aliases": [..], "lfs": [{"oid", "size"}], "next_cursor"?}` |
| `convert` | `{"schema", "phase": "convert", "build_id", "source": {...}, "lfs": {"bytes", "sha256"}?}` | `{"schema", "phase": "convert", "files": {"converted", "cached", "skipped", "failed"}, "tokens"}` |
| `package` | `{"schema", "phase": "package", "build_id", "uuid", "output": {"bytes"}}` | `{"schema", "phase": "package", "image_bytes", "documents", "tokens", "index_tokens"}` |

- `scan` pages its LFS pointers: at most 256 per answer; the worker repeats
  `scan` with `cursor` set to the `next_cursor` it got until there is none.
  `manifest: "invalid"` (with at most 16 closed `errors` codes) ends the
  build `FAILED invalid_manifest`. `lfs.size` totals past `max_lfs_mib`, or
  more than `max_lfs_objects`, end it `FAILED too_large`.
- `convert` reads the source and LFS drives, converts file by file, reuses
  the conversion cache, and calls the gateway for OCR, transcription, vision,
  summaries and embeddings (§12). It writes nothing to the drives.
- `package` assembles the layout, the indexes, `INDEX.md` and `report.json`,
  then runs `mkfs.ext4 -d` on `/dev/corpus/output` with the given UUID and
  reports the image's size.
- Progress reaches the API at the end of each phase (the build's counters).
  Once the streaming plan's lot 3 is built, the builder also emits `step`
  events per file, relayed by its SSE hub (lot 4 there).

The packaged ext4 image keeps a canonical report for reproducibility. The per-build report records the actual build ID and the cached or converted status of each file. The guest puts this report in the output drive after the filesystem. At the very end of the allocated drive it writes a 48-byte footer with eight ASCII bytes `ACRPT001`, an unsigned 64-bit big-endian JSON length, and the raw 32-byte SHA-256 of that JSON. The JSON immediately precedes the footer and occupies at most 1 MiB. The guest must leave room for both when choosing the filesystem size.

The worker verifies the length, non-overlap with the filesystem, digest, report schema, build ID and commit. It retains the exact report bytes in the encrypted review bundle. Only the first `image_bytes` bytes enter the package and its digest. The worker preserves the raw output until the review transaction commits, so an interrupted publication can be retried.

### 6.4 The worker's checks after `package`

1. Truncates `output.ext4` to `image_bytes` (at most `max_image_mib`; a larger
   or zero value is `invalid_image`).
2. `CheckRootfs` on the superblock (the UUID must be the build's).
3. Confined debugfs, as for a harness image: `corpus.json`, `INDEX.md` (at most
   64 KiB) and `search/fts.sqlite` are regular files; no special file, no
   setuid or setgid bit, no symbolic link that leaves the image. Otherwise
   `FAILED invalid_image`.
4. sha256 of the image; the package (§2.3) is written and moved into
   `<corpus.cache>/sha256/<hex>/`, read-only, in one rename.
5. The **review bundle** is read out of the image by the same confined
   debugfs with `cat` (one call per file, to its standard output, which the
   sandbox already caps at 1 MiB): `INDEX.md`, `report.json` (checked against
   §2.4) and each `docs/<id>/README.md`, at most 8 MiB in total; past it, the
   bundle stops and says so. It is sealed with the organization's transit
   key and stored in segments as attachments are (`corpus_review_files`).
   Lot 5 measures the seccomp allow-list of debugfs for `cat`.
6. The build turns `REVIEW`; `review_expires_at` is 30 days later.

The staging directory is removed when the build leaves the states before
`REVIEW`, whatever the outcome.

## 7. Builds, publication and try (lots 5 and 6)

### 7.1 States

`QUEUED → FETCHING → SCANNING → FETCHING_LFS → CONVERTING → PACKAGING → REVIEW → PUBLISHED`.
`FETCHING_LFS` is skipped without LFS pointers. Other ends: `FAILED` (from
any state before `REVIEW`, with an `error_code`), `CANCELED` (from any state
before `PUBLISHED`), `EXPIRED` (from `REVIEW` after 30 days). `PUBLISHED`,
`FAILED`, `CANCELED` and `EXPIRED` are final.

| `error_code` | Meaning |
|---|---|
| `policy` | no source rule for the host or repository, a redirect to an undeclared host, an address not allowed |
| `not_found` | the ref, commit or repository does not exist (or the forge does not say) |
| `access_denied` | the forge refused the credential, or the credential is disabled |
| `integrity` | an LFS object or a download does not match its digest or size |
| `too_large` | archive, LFS objects or image past their limits |
| `invalid_manifest` | the builder found the manifest missing or invalid |
| `builder_failed` | a phase failed, timed out or answered what does not decode |
| `invalid_image` | the output failed §6.4 |
| `timeout` | 24 hours after the request |
| `unavailable` | still failing after the last attempt, or the builder release missing on the host |
| `storage_pressure` | the image file system stayed past its threshold for every attempt |
| `quota_exceeded` | the image would put the organization past `max_corpus_storage_mib` |

### 7.2 Routes

| Route | Scope | Answer |
|---|---|---|
| `GET /v1/corpora` | `corpus:read` | the organization's corpora; `?name=` |
| `POST /v1/corpora` | `corpus:manage` | `{name, title?, source: {kind, url, ref, path?, credential_id?}}`; 201 |
| `GET /v1/corpora/{id}` | `corpus:read` | one corpus, with `latest_build_id` and `latest_release` |
| `POST /v1/corpora/{id}/builds` | `corpus:manage` | `{ref?, commit?}` (at most one; default the corpus's `ref`); **202** with the build |
| `GET /v1/corpus-builds` | `corpus:read` | `?corpus_id=&state=&after=&limit=` |
| `GET /v1/corpus-builds/{id}` | `corpus:read` | state, commit, counters, costs, `error_code`, timestamps |
| `POST /v1/corpus-builds/{id}/cancel` | `corpus:manage` | 200; `409 invalid_transition` once final |
| `GET /v1/corpus-builds/{id}/review` | `corpus:manage` | the bundle's files: `path`, `bytes`, `sha256`, `truncated` |
| `GET /v1/corpus-builds/{id}/review-file?path=` | `corpus:manage` | one file of the bundle (`text/markdown` or `application/json`) |
| `POST /v1/corpus-builds/{id}/try` | `corpus:manage` and `agent:manage` | `{agent_id, mount?}`; 200, applies at the agent's next boot |
| `POST /v1/corpus-builds/{id}/publish` | `corpus:manage` | `{version}`; 201 with the release, or 200 with the existing one |
| `GET /v1/corpus-releases` | `corpus:read` | `?corpus_id=&include_deprecated=` |
| `GET /v1/corpus-releases/{id}` | `corpus:read` | one release |
| `POST /v1/corpus-releases/{id}/deprecate` | `corpus:manage` | 200; idempotent |
| `GET /v1/agents/{id}/corpora` | `agent:read` and `corpus:read` | the agent's binding (releases and tries) |
| `POST /v1/agents/{id}/corpora` | `agent:manage` and `corpus:read` | `{corpora: [{name, version, mount?}]}` replaces the binding; 200, `applies: next_boot` |

Every mutation takes an `Idempotency-Key`. `POST /v1/corpora/{id}/builds` is
an asynchronous route (202, listed by `TestAsynchronousRoutesAreListed`),
followed by `GET /v1/corpus-builds/{id}` and by
`agentcapsule operation wait --type corpus-build` (exit 0 for `REVIEW` or
`PUBLISHED`, 5 for `FAILED`, `CANCELED` or `EXPIRED`, 130 on interruption).
The endpoints are specified in [openapi/openapi.yaml](../../openapi/openapi.yaml).

`source.url` is `https://<host>/<repository>` (no user, query or fragment;
GitLab subgroups allowed); `kind` is `github` or `gitlab`; `path` is a clean
relative path, default the repository root; `credential_id` is a source
credential of the organization with the same `kind` and `host`, or absent for
a public repository. A corpus's source does not change in this version: a
new corpus is created instead.

### 7.3 Publication

`POST /v1/corpus-builds/{id}/publish {version}`, in one transaction under the
corpus row (`FOR UPDATE`):

- The build must be `REVIEW`, else `409 invalid_transition`. A build
  publishes at most once (`buildPublishesAtMostOnce`).
- If `name:version` does not exist, it is created with the build's digest:
  **201**. If it exists with the same digest, the build turns `PUBLISHED`
  and the answer is the existing release: **200**. If it exists with another
  digest: **`409 version_conflict`**, nothing changes (`publishedIsImmutable`).
  `version_conflict` is a new problem code of the API.
- The release records `digest`, `image_bytes`, `build_id`, `commit`, the
  builder release, the host whose cache holds the image (`host_id`) and
  `created_by`. A trigger refuses any `UPDATE` of a release's `corpus_id`,
  `version`, `digest`, `image_bytes` or `build_id`, and any `DELETE`.
- `deprecate` stops every new binding, try and template naming the release;
  agents already bound keep it, and so do their VMs.

### 7.4 Try before publishing

`POST /v1/corpus-builds/{id}/try {agent_id, mount?}` puts the build, which
must be `REVIEW`, into the agent's binding (replacing a binding of the same
corpus), at its next boot. The agent must be of the organization (else 404),
live, and able to mount corpora (§5.4). An administrator can then question an
ordinary harness (Pi, for example) before publishing. A try binding of a
build that turns `CANCELED` or `EXPIRED` is removed from the binding (next
boot); a running VM keeps its mount until it stops. Publishing leaves try
bindings as they are: the image is the release's.

### 7.5 Cancellation and limits

`POST /v1/corpus-builds/{id}/cancel` ends a build before `PUBLISHED`: its
invocation in progress is canceled (the builder learns it at its next
platform call), its staging files and output drive are purged, and a build in
`REVIEW` loses its review bundle. A build still before `REVIEW` 24 hours after
its request ends `FAILED timeout`. A `REVIEW` build not published within 30
days turns `EXPIRED`, and its bundle is purged.

### 7.6 Costs

The builder's model calls are metered by the gateway as any agent's, against
the organization's budgets, through the aliases the manifest names. Builds of
one organization run one at a time, so a build's costs are the builder's
ledger rows (`llm_usage`) between its `FETCHING` and its end. The build
records them at the end of each phase: `llm_calls`, `input_tokens`,
`output_tokens`, `audio_seconds`, `pages`, `cost_micros` (null when an alias
used is unpriced).

## 8. Bindings, templates and rollouts (lot 6)

- `TemplateSpec` gains `corpora: [{name, version, mount?}]`, at most 4, each
  corpus once, mounts distinct. Publishing a template with corpora also
  requires `corpus:read`.
- `validateTemplate` checks each release under `FOR SHARE`: it exists **in
  the template's organization** (unlike harness releases, which have no
  organization), is not deprecated, and the template's harness and system
  image can mount corpora (§5.4). Unknown, deprecated or another
  organization's: `422 corpus_unavailable`, the same answer for all three.
  Incompatible harness or system image: `422 corpus_incompatible`.
- `Enrollment`, `RolloutStep`, `SetRolloutProfile` and the host's record of
  an agent (`HostAgent`, `<root>/registry.json`) carry each corpus's
  `{release_id, digest, uuid, mount}`. `RegisterProvisioned` keeps its
  immutability with corpora; a binding change replaces the record only while
  no VM runs, as `ReplaceHarness` does.
- `POST /v1/agents/{id}/corpora` replaces the agent's binding, checked as a
  template's, at the next boot, as `POST /v1/agents/{id}/release`
  (`bindingChangesAtBootOnly`). `{corpora: []}` removes every corpus. It
  answers `{agent_id, corpora, previous, applies: "next_boot"}`.
- **One host in this version** (D-C9): a release's image is only in the
  cache of the host that built it (`corpus_releases.host_id`). A binding of
  an agent of another host is refused, `422 corpus_unavailable`.
- Before a boot, the worker resolves the binding to digests, finds each image
  in its cache, and refuses to boot (the agent stays stopped, as for a
  missing harness image) when one is missing. It checks each image's digest
  when the image enters the cache and remembers the check by inode, size and
  mtime (D-C6); a mismatch removes the image from the cache.
- No `policy_version` bump: binding a corpus is not an authorization rule,
  as `agent release` is not (`internal/controlplane/agent_release.go:99`).

## 9. Cache and eviction (lot 6)

The worker keeps an image while a **pin** needs it:

1. a binding of an agent not deleted (a release or a try);
2. the mount of a running VM (its boot's record);
3. a release named by a template of an open rollout;
4. a build in `REVIEW`;
5. **a release that is not deprecated** (this version, see
   [Changes](#changes-during-implementation), C4).

Eviction runs in the corpus loop, under the cache's lock, at most once an
hour when idle, and with `-collect-garbage`. It reads the pins from
PostgreSQL (`CorpusImagesInUse`, and `CorpusImagesInUseAt` from a runtime
root under the host lock, the corpus counterparts of `HarnessImagesInUse`
and `HarnessImagesInUseAt`), moves an unpinned image out of the
content-addressed path in one rename, then deletes it. It also deletes the
staging of builds in final states. Every unpinned image is unpinned for good:
a deprecated release, a final build and a closed rollout never pin again, so
a pin read before the rename cannot appear after it (`gcNeverRemovesPinned`).

## 10. Quotas (lot 6)

Two organization quotas, set by the platform operator with the others
(`PUT /v1/organizations/{id}/quotas`, [ADR 021](021-organization-quotas.md)),
`null` for no limit:

| Quota | Counts | Checked |
|---|---|---|
| `max_corpus_storage_mib` | the `image_bytes` of the organization's releases not deprecated and builds in `REVIEW` (an image both counts once) | at `POST /v1/corpora/{id}/builds` (already at or past it: `409 organization_quota_exceeded`, `quota: max_corpus_storage_mib`), and when a build would turn `REVIEW` (past it: `FAILED quota_exceeded`) |
| `max_corpus_builds` | the organization's builds not final and not `REVIEW` (queued or running) | at `POST /v1/corpora/{id}/builds`: `409 organization_quota_exceeded`, `quota: max_corpus_builds` |

Builds run one at a time per organization whatever the quota (§6.1); the
quota bounds how many wait. Inference costs go to the organization's budgets
(§7.6). The builder's VM and volume count in neither the organization's VM
nor its storage quotas.

## 11. Authorization and audit (lot 6)

- Two actions and scopes, added to `internal/authorization/policy.go` and to
  `DelegableScopes`:

  | Action | Scope | Roles |
  |---|---|---|
  | `corpus.manage` | `corpus:manage` | `org_owner`, `org_admin` |
  | `corpus.read` | `corpus:read` | `org_owner`, `org_admin`, `agent_operator`, `auditor` |

- A corpus, build, release or credential of another organization answers
  404, as if it did not exist (`bootsOnlyBoundCorporaOfItsOrganization`).
  A name in a body that is not the caller organization's answers
  `422 corpus_unavailable`, the same as an unknown name.
- The review bundle is the organization's documents, imported by its
  administrators: reading it needs `corpus:manage`. It is not a member's
  private content; no member's conversation reaches it.
- `docs/api/rbac.md` and `TestRBACMatrix` gain a row per route;
  `auditedRoutes` (`internal/api/refusals.go:26`) gains each mutation.
- Audit, in a new table `corpus_audit` whose actions are a CHECK constraint:
  `source_credential.created`, `source_credential.rotated`,
  `source_credential.disabled`, `corpus.created`, `corpus_build.requested`,
  `corpus_build.canceled`, `corpus_build.tried`, `corpus_build.published`,
  `corpus_release.deprecated`. `POST /v1/agents/{id}/corpora` writes
  `agent.corpora_changed` in `tenant_agent_audit` (its CHECK gains it), as
  `agent.release_changed`. Both reach `GET /v1/audit` and its export. An
  event names identifiers, never a secret, a path inside a repository or
  content.

## 12. Multimodal gateway (lot 2)

New platform channel routes, beside `/v1/llm/complete` and `/v1/llm/forward`,
for the builder and for any harness (query embeddings, for example). They need
the capability `llm.invoke` (lot 2 adds them to `capability.ForRoute`,
`internal/capability/capability.go:66`, and to the platform handler's
switch). Draft contract: [docs/guest/llm-multimodal.md](../guest/llm-multimodal.md).

| Channel route | Upstream | Unit |
|---|---|---|
| `POST /v1/llm/embed` | OpenAI `POST /v1/embeddings`, `encoding_format: base64` | input tokens |
| `POST /v1/llm/transcribe` | OpenAI `POST /v1/audio/transcriptions`, `response_format: verbose_json`, segment timestamps; the gateway builds the multipart body from the JSON request | seconds of audio |
| `POST /v1/llm/ocr` | Mistral `POST /v1/ocr` (an `openai_compatible` provider whose alias declares `ocr`) | pages |

- **Alias operations.** An alias declares the operations its model serves:
  `operations`, a subset of `chat`, `vision`, `embed`, `transcribe`, `ocr`,
  default `["chat"]` (existing aliases get `["chat"]`). `POST /v1/llm/aliases`
  accepts it; `POST /v1/llm/aliases/{alias}/operations` replaces it
  (`provider:manage`, audited `alias.operations_set` in `llm_audit`). A
  channel route the alias does not declare is refused before any
  reservation, with the channel code **`unsupported`** (HTTP 400). `vision`
  is informative: `/v1/llm/forward` does not inspect bodies (ADR 016's "the
  body is the agent's"); the builder uses it to check its manifest's aliases.
- **Prices.** `POST /v1/llm/aliases/{alias}/prices` gains two optional
  prices: `audio_micro_per_minute` and `ocr_micro_per_page`; embeddings use
  `input_micro_per_mtok`. A call of a unit its alias does not price is
  unpriced, as in ADR 011: a hard cost budget refuses it (`quota_exceeded`).
  Token budgets count embedding input tokens; seconds and pages count only in
  cost budgets.
- **Reservation and settlement** follow `/v1/llm/complete`: reserve before the
  call (embed: body size / 3 tokens; transcribe: the declared
  `duration_seconds`; OCR: the declared `pages`), call outside the host lock,
  settle on the provider's reported usage (`usage.prompt_tokens`, `duration`,
  `usage_info.pages_processed`), or on the reservation when the provider
  reports none. A cut after sending is `outcome_unknown`, reconciled as
  today; replaying a settled key never calls the provider again.
- **The host never decodes media.** The gateway checks the base64 syntax and
  the decoded size, never the audio or image itself: the duration and the
  page count of the reservation are the caller's declarations, bounded.
- **Bounds.** Requests at most 960 KiB, as `forward`, inside the channel's
  1 MiB message limit (`internal/capsuleprotocol/control.go:21`): decoded
  audio, image or PDF at most 700 KiB, `duration_seconds` 1 to 600, `pages`
  1 to 8, `input` 1 to 64 strings of at most 32 KiB each. An answer past
  960 KiB was still produced: `outcome_unknown`. The builder splits audio and
  pages to fit.
- `llm_usage` gains `audio_seconds` and `pages`; `GET /v1/llm/usage` shows
  them; metrics count them by provider kind and unit, never by organization.
- Live qualification: Ollama for embeddings (a small local embedding model);
  a hosted provider for transcription and OCR, chosen with the operator.

## 13. Limits

| Limit | Value | Where set |
|---|---|---|
| Archive | 2 GiB | `corpus.max_archive_mib` |
| LFS objects of one build | 20 GiB, 10,000 objects | `corpus.max_lfs_mib`, `corpus.max_lfs_objects` |
| Image | 16 GiB | `corpus.max_image_mib` |
| Corpora per VM | 4 | fixed |
| Build | 24 h from the request | fixed |
| Review | 30 days, then `EXPIRED` | fixed |
| Builds running per organization | 1 | fixed (one builder) |
| Manifest | 64 KiB | fixed |
| `INDEX.md` | 64 KiB (target 8,000 tokens) | fixed, checked by the worker |
| Review bundle | 8 MiB in total, 1 MiB per file | fixed |
| Phase invocation and result | 32 KiB of JSON | ADR 016 |
| LFS pointers per `scan` answer | 256 | fixed |
| Redirects per request | 2 | fixed |
| Source credential secret | 4,096 bytes | fixed |
| Channel request (embed, transcribe, OCR) | 960 KiB; media 700 KiB; 600 s of audio; 8 pages; 64 inputs of 32 KiB | fixed |
| Corpus drive rate | 128 MiB/s, 4,000 IOPS, burst 256 MiB | `drive_limits.corpus` |

## 14. Error codes

New API problem codes (added to `problemCodes`, `internal/api/telemetry.go:15`):

| Code | Status | When |
|---|---|---|
| `version_conflict` | 409 | publish: `name:version` holds another digest |
| `corpus_unavailable` | 422 | a binding, try or template names an unknown, deprecated or other organization's release or build, or a release on another host |
| `corpus_incompatible` | 422 | the agent's or template's harness base or system image cannot mount corpora |
| `corpus_name_taken` | 409 | `POST /v1/corpora` with a name the organization uses |
| `source_credential_name_taken` | 409 | `POST /v1/source-credentials` with a name the organization uses |
| `source_credential_unavailable` | 422 | `POST /v1/corpora` names a credential that is unknown, disabled or of another kind or host |

Reused: `invalid_transition` (409), `organization_quota_exceeded` (409, with
`quota`), `storage_pressure` (503), `not_found` (404), `invalid_request`
(400), `forbidden` (403). New platform channel code: `unsupported` (400,
added to `safePlatformCode`, `internal/capsuleprotocol/platform.go:61`).
Build error codes: §7.1. Report error codes: §2.4.

## 15. Database (migrations 0056 and following)

Each lot that needs a migration takes the next number in the `corpus` branch,
from 0056; the orchestrator renumbers against the streaming branch at
integration. New error codes, states and audit actions are CHECK constraints,
so they change only through migrations.

| Table or change | Lot | Columns (main) |
|---|---|---|
| `llm_model_aliases` | 2 | `operations text[] NOT NULL DEFAULT '{chat}'`, `audio_micro_per_minute bigint`, `ocr_micro_per_page bigint` |
| `llm_usage` | 2 | `operation text NOT NULL DEFAULT 'chat'`, `audio_seconds bigint`, `pages integer`; `llm_audit` CHECK gains `alias.operations_set` |
| `source_credentials` | 3 | `id`, `tenant_id`, `name`, `kind` (`github`, `gitlab`), `host`, `generation`, `sealed` (null once disabled), `status` (`active`, `disabled`), `created_by`, `created_at`, `rotated_at`, `disabled_at`; `UNIQUE (tenant_id, name)`, `UNIQUE (tenant_id, id)` |
| `system_images` | 4 | `features text[] NOT NULL DEFAULT '{}'`, CHECK `features <@ '{corpus.mount}'` |
| `agents` | 5 | `kind text NOT NULL DEFAULT 'agent'`, CHECK `kind IN ('agent','corpus_builder')`; one builder per organization (partial unique index) |
| `corpora` | 6 | `id`, `tenant_id`, `name`, `title`, `source_kind`, `source_host`, `repository`, `ref`, `path`, `credential_id` (composite FK `(tenant_id, credential_id)`), `created_by`, `created_at`; `UNIQUE (tenant_id, name)`, `UNIQUE (tenant_id, id)` |
| `corpus_builds` | 6 | `id`, `tenant_id`, `corpus_id`, `state` (§7.1), `requested_ref`, `commit`, `builder_release_id`, `builder_agent_id`, `archive_bytes`, `archive_sha256`, `lfs_objects`, `lfs_bytes`, file counters, `image_bytes`, `image_digest`, `image_uuid`, cost columns (§7.6), `error_code` (§7.1), `attempts`, `next_attempt_at`, `lease_owner`, `lease_until`, `deadline_at`, `review_expires_at`, `release_id`, `created_by`, `created_at`, `review_at`, `completed_at`; a partial unique index allows one build per organization in `FETCHING` to `PACKAGING` |
| `corpus_releases` | 6 | `id`, `tenant_id`, `corpus_id`, `version`, `digest`, `image_bytes`, `build_id`, `commit`, `builder_release_id`, `host_id`, `created_by`, `created_at`, `deprecated_at`; `UNIQUE (tenant_id, corpus_id, version)`; the immutability trigger (§7.3) |
| `corpus_review_files`, `corpus_review_segments` | 5 | the sealed review bundle, by build and path, as attachments |
| `agent_corpora` | 6 | `tenant_id`, `agent_id`, `position` (0 to 3), `mount`, `release_id` or `build_id` (exactly one), composite FKs on `(tenant_id, …)` so a binding cannot cross organizations; `PRIMARY KEY (agent_id, position)`, `UNIQUE (agent_id, mount)` |
| `corpus_audit` | 6 | `id`, `tenant_id`, `actor_principal_id`, `credential_id`, `action` (§11, CHECK), `corpus_id`, `build_id`, `release_id`, `source_credential_id`, `agent_id`, `created_at` |
| `tenant_agent_audit` | 6 | CHECK gains `agent.corpora_changed` |
| `organization_quotas` | 6 | `max_corpus_storage_mib bigint`, `max_corpus_builds integer` |

`schema.sql` follows, as for every migration.

## 16. Observability

Metrics carry closed labels only: never an organization, a corpus, a path or
a host name of a forge. The worker adds
`agentcapsule_worker_corpus_builds_total{outcome}` (`review`, the build error
codes, `canceled`, `expired`), `agentcapsule_worker_corpus_phase_seconds{phase}`
(`fetching`, `scanning`, `fetching_lfs`, `converting`, `packaging`),
`agentcapsule_worker_corpus_fetched_bytes_total{kind}` (`archive`, `lfs`),
`agentcapsule_worker_corpus_cache_bytes` and
`agentcapsule_worker_corpus_evictions_total`. Logs name build and release
identifiers and error codes, never a secret, a URL with credentials, a file
name or content. Lot 7 documents them in [observability.md](../observability.md).

## 17. The model

[spec/corpus_lifecycle.qnt](../../spec/corpus_lifecycle.qnt) models two
organizations, three builds, three releases, two agents and one host cache:
builds that end in `REVIEW` or fail, publication, deprecation, bindings and
tries, boots and stops, rollouts, eviction. Its invariants:

| Invariant | Says | Broken instance (counterexample) |
|---|---|---|
| `publishedIsImmutable` | `name:version` keeps the digest of its first publication | `corpusLifecycleNoVersionCheck`: another digest overwrites the version |
| `bootsOnlyBoundCorporaOfItsOrganization` | a VM mounts only corpora of its agent's organization | `corpusLifecycleNoOrganizationCheck`: a binding of another organization's release |
| `bindingChangesAtBootOnly` | a running VM sees what its boot resolved | `corpusLifecycleHotSwap`: a binding swaps the drive of a running VM |
| `buildPublishesAtMostOnce` | a build is the source of at most one publication | `corpusLifecycleNoReviewCheck`: a published build publishes again |
| `gcNeverRemovesPinned` | every image a pin needs is in the cache | `corpusLifecycleNoPinCheck`: eviction ignores pins; `corpusLifecycleEvictsActive`: the plan's first eviction rule (C4) |

Its eight runs are in [projections.md](../../spec/projections.md), `pending`
until lots 4 and 6 project them. `scripts/check-models.py` checks every
reachable state of `corpusLifecycleOk` (TLC) and a counterexample from each
broken instance (Apalache). On November 20, 2026: `safety` holds in all
1,011,740 reachable states (depth 19, 57 s), and each broken instance fails
its invariant within 2 to 4 steps; `quint run` finds the same
counterexamples, and none in 200,000 traces of 40 steps of the correct
instance (evidence kept locally under `quint/results/chantiers/corpus-lot0/`).
Not modelled: several hosts, quotas, fetching, the builder, agent deletion,
mount names.

## Plan facts checked

The plan cites the code at `321143b`. These turned out different; the
sections above use the code's facts.

| Plan | Code |
|---|---|
| `BuildRootfs`, `CheckRootfs`, `InspectRootfs` in `package.go` | `BuildRootfs` is `internal/harnesspkg/build.go:24`, `InspectRootfs` `inspect.go:32`; `CheckRootfs` is `package.go:187` and reads only the superblock |
| Review bundle extracted by debugfs `dump`, "an extension of the allow-list" | The confined debugfs runs only `stat` (`inspect.go:41`); its seccomp allow-list was measured on `-V` and `stat` (`internal/sandbox/seccomp_linux_amd64.go:23-58`); `dump` cannot work: file size limit 0 (`internal/sandbox/helper_linux.go:121`), read-only mounts (`:101`), no `mkdir`. Output is capped at 1 MiB (`internal/sandbox/sandbox.go:46`) |
| "At most 3 redirects" | The registry client follows at most 2 (`len(via) >= 3` refused, `internal/ociregistry/client.go:82`) |
| Credential label `agentcapsule.source-credential.v1`, "as an LLM provider key" | The provider's label is `agentcapsule.llm-provider-secret.v1` (`internal/controlplane/users.go:50-56`); the source label follows it: `agentcapsule.source-credential-secret.v1` |
| `refuseUnderImagePressure` in the worker loop | It is the API's (`internal/controlplane/operations.go:47`, called from `harness_registry.go:129`); the worker has its `Pressure` hook (`internal/worker/registry.go:114`, `:302`) |
| Internal GitLab "like `llm.allowed_internal_providers`, refused in production (`preflight_linux.go:29`)" | Line 29 is `ErrClearTextRegistry`; `CheckProductionTransport` (`:34-44`) refuses any `local` registry rule. Registries have no internal-address allowlist: internal means `local`, which is plain HTTP. The LLM allowlist is `llm.allowed_internal_providers` (`internal/worker/llm_linux.go:22`, parsed by `llmgateway.ParseAllowlist`, `internal/llmgateway/egress.go:75`) |
| `harnessImage` re-hashes at each resolution of an agent | It re-hashes in `resolveHarness` (`internal/worker/harness_image_linux.go:104-108`: provisioning, restore, rollout), but `syncHarness` skips it before a boot when the recorded path and digest match (`:63-66`) |
| `validateTemplate` checks that each release is of the same organization | It checks no organization for harness releases: `harness_releases` has no tenant column (`internal/controlplane/templates.go:170-185`). Corpora add the check |
| Worker configuration section `corpus.sources.rules` | The configuration is JSON with unknown fields refused (`internal/worker/service_config_linux.go:294`), not YAML; the keys of §3.2 are JSON |
| Alias refusal `capability_denied` | `capability_denied` is the channel's code for a capability outside the harness's effective set (`internal/capsuleprotocol/platform.go:66`, ADR 016); it is not an API problem code |
| `version_conflict` "as for imports" | For imports it is a build-like `error_code` (`internal/controlplane/harness_registry.go:326`), not an API problem code (`problemCodes`, `internal/api/telemetry.go:15`) |
| "New error codes and audit actions go through CHECK constraints" | True of most audit tables; `deployment_audit` (templates, deployments, rollouts) has none (`internal/controlplane/migrations/0053_volume_growth.sql:1-3`) |
| `MountHarnessRoot` options for corpora | `MountHarnessRoot` mounts `ro,nosuid,nodev,noatime`, without `noexec` (`internal/guestinit/harness_root_linux.go:21`); corpora add `noexec` |
| A template or an agent binds a corpus only to a base-2 release | `agent_specs.system_image` is null for an agent created without a template (`internal/controlplane/migrations/0049_deployments.sql`), so the feature check needs it (§5.5) |

Confirmed as the plan says: `linkOrCopy` copies on `EXDEV`; the harness drive
is read-only with cache `Unsafe`; `HarnessDevice="/dev/vdb"`;
`max_harness_mib` 1,024; the channel's 1 MiB message limit; `/v1/llm/forward`
passes images; `LOCK_SH` for read-only drives; no `features` column on
`system_images`; `# CONFIG_EROFS_FS is not set`, `CONFIG_SQUASHFS=y`, no
dm-verity in the guest kernel; `ChangeAgentRelease` applies at the next boot
and bumps no policy version; `TestAPILinksNoRuntimeWorkerOrGuestCode`,
`TestTheHostNeverRunsWhatAPackageHolds` and `workerStarts` exist.

## Changes during implementation

Lot 0 changed the plan where the code showed it could not work as written;
each change keeps the plan's guarantees.

- **C1. Alias operations, code `unsupported`.** The plan's alias
  "capabilities" and refusal `capability_denied` would reuse ADR 016's
  vocabulary for another concept: a harness getting `capability_denied` could
  not tell a missing `llm.invoke` (its organization's policy) from an alias
  that serves no OCR (the alias's configuration). The alias declares
  `operations`; the refusal is `unsupported`.
- **C2. Review bundle by `cat`, not `dump`.** `dump` writes files, which the
  sandbox forbids by design (no writable mount, file size limit 0). `cat`
  writes to the standard output the sandbox already reads, so the sandbox's
  mounts and limits stay; only the allow-list is measured again for `cat`.
- **C3. LFS index on the LFS drive.** The plan sends the index
  `{oid, offset, length}` with the next invocation; 10,000 objects make about
  1 MB, past the 32 KiB of an invocation. The worker writes the index at the
  head of `lfs.bin` (§6.2).
- **C4. An active release pins its image in this version.** The plan keeps
  only images pinned by an agent, an open rollout, a build in review or a
  try. With the local cache as the only copy (D-C9), an active release no one
  binds would be evicted, and a later binding or rollout would name an image
  that no longer exists anywhere. The model shows it:
  `corpusLifecycleEvictsActive` fails `gcNeverRemovesPinned` (publish,
  evict, bind). The space is freed by deprecating, as the plan's journey
  does ("deprecates version 3 … it leaves the cache once no one uses it").
  When D-C9's P2 brings `Refill` from a registry, an active unbound release
  may leave a host's cache as the plan says.
- **C5. Internal forges over HTTPS.** Registries have no internal-address
  option except `local`, which is plain HTTP and refused in production. The
  sources get `corpus.sources.allowed_internal_hosts`, with the syntax and
  checks of `llm.allowed_internal_providers`, and stay on HTTPS.
- **C6. Two redirects**, as the registry client, not three.
- **C7. The feature check needs a recorded system image.** An agent created
  without a template has none, so it cannot bind corpora in this version.
- **C8. One host.** A release's image is only on the host that built it;
  a binding of an agent on another host is refused (`corpus_unavailable`).
  Recovery of a lost host's corpora is a rebuild of the same commit on the
  new host: the builder's conversion cache comes back with its volume's
  archive, so the rebuild calls no model again and, being reproducible,
  gives the same digest, which publishes under the same version.
- **C9. Build concurrency is the builder's, the quota bounds the queue.**
  One builder runs one build at a time; the plan's
  `corpus_builds_concurrent (1)` becomes that rule plus `max_corpus_builds`,
  which bounds queued and running builds with ADR 021's semantics (`null`, no
  limit). The plan's `corpus_bytes` is `max_corpus_storage_mib`, in ADR 021's
  naming.
- **C10. Raw build drives are checked by size, then by digest in the VM**,
  since they have no UUID (§5.3).
- **C11. `corpus-build files` reads `report.json`.** The CLI filters the
  report it reads from the review bundle; no per-file table and no route of
  its own. `corpus-build index` reads `INDEX.md` the same way.
- **C12. `corpus_releases` has `deprecated_at` and no `enabled`.** A release
  is never disabled otherwise.
- **C13. The host package carries no version.** The worker writes it when
  the build turns `REVIEW`, before any publication, and one digest may be
  published under several versions (§7.3); a version in `corpus.yaml` would
  make the cached package change after the fact. PostgreSQL maps
  `name:version` to the digest.

Lot 4 changed these, each keeping the guarantees above:

- **C14. A release records its guest base.** §5.4 binds corpora only to a
  release of base 2, but `harness_releases` did not record the base.
  Migration `0058_corpus_mounts` on the corpus branch adds `harness_releases.base` (base 1 for existing and
  locally approved releases); the importer records `harness.yaml`'s base,
  and `GET /v1/harness-releases` shows it. The check lot 6 calls is
  `corporaMountable` (`internal/controlplane/corpus_images.go`): a base-2
  release, or the image's built-in harness, on an image declaring
  `corpus.mount`; otherwise `ErrCorpusIncompatible`.
- **C15. The guest refuses corpora for a base-1 harness.** A harness of
  base 1 has no `/corpus` in its image. If a record still gives it corpora,
  `capsule-init` refuses the boot rather than start the harness without
  them.
- **C16. The host checks an image's UUID when it records it.**
  `ReplaceCorpora` and `RegisterProvisioned` read each image's superblock
  and refuse a UUID other than the record's: a wrong record fails at once,
  not at each boot against the agent's restart budget. The guest's check
  stays: it guards the drive order inside the VM.
- **C17. The file system check is a hard-link probe, and covers staging.**
  `link(2)` refuses another mount of the same file system too, which a
  comparison of device numbers misses. `runtime.CheckLinkable` links a probe
  file into `<root>/jails` and removes it. The preflight check
  `corpus_cache_filesystem` is `worker.CorpusFilesystemCheck(root, cache,
  staging)`. Build drives are hard linked as corpus images are, so
  `corpus.staging` obeys the same rule as `corpus.cache`. The `corpus`
  section of the worker's configuration is lot 3's: the check runs from
  `MandatoryPreflight` once that section exists.
- **C18. A zero drive rate takes its default.** A `DriveLimits` without
  `Corpus`, from code or a test that predates corpora, would fail
  validation; each zero rate now takes its default, as each number of the
  worker's configuration already did.
- **C19. `/corpus` is a read-only tmpfs.** The `/corpus` of a registry
  harness is in its read-only image, where no mount point can be created.
  `capsule-init` mounts a small tmpfs at `/corpus` in its own root, creates
  one directory per corpus, mounts the corpora, remounts the tmpfs
  read-only, and binds it at the harness's `/corpus`. A base-2 harness then
  never sees files of its own image under `/corpus`.
- **C20. `schema.sql` does not follow the migrations.** §15 says it does;
  it is migration 1, the baseline, embedded and checksummed
  (`internal/controlplane/migrations.go`): editing it would change an
  installed migration. Migrations alone change the schema.

## Questions for the product owner

1. **Who reads the review bundle.** It holds the organization's documents
   in converted form. Options: (a) `corpus:manage`, owners and administrators,
   who import the documents (chosen); (b) a separate right
   `corpus:content:read`. Recommendation: (a); the documents are the
   organization's, not a member's private content.
2. **Eviction of an active release** (C4). Acme publishes `handbook:1`, binds
   nothing for a month. Options: (a) the image stays until `handbook:1` is
   deprecated (chosen); (b) it is evicted, and a later binding fails until a
   rebuild. Recommendation: (a) until releases can be refilled (D-C9, P2).
3. **Corpus quotas for a new organization.** Options: (a) no limit until the
   operator sets one, as ADR 021 (chosen); (b) installation-wide defaults,
   for example 10 GiB and 3 builds. Recommendation: (a) for this version.
4. **The builder outside the organization's VM quota.** Acme is at its
   `max_active_vms` and starts a build. Options: (a) the builder boots anyway,
   counted only in the host's capacity, as the plan says (chosen); (b) it
   waits for the organization's quota. Recommendation: (a): one VM per
   organization, and its work is the platform's.

## What each lot builds

| Lot | Sections |
|---|---|
| 1. Formats and package | §2 (the page `docs/corpus.md`), `internal/corpuspkg`, `corpus init` and `corpus lint` |
| 2. Multimodal gateway | §12, the channel draft [llm-multimodal.md](../guest/llm-multimodal.md) |
| 3. Git sources | §3, §4 |
| 4. Drives and guest mount | §5 |
| 5. Builder agent | §6, §7.1, §7.5, §7.6 |
| 6. Publication, binding and cache | §7.2 to §7.4, §8 to §11, §14, §15; endpoints in [openapi/openapi.yaml](../../openapi/openapi.yaml) |
| 7. CLI and docs | the plan's §7, §16, the CLI's `--type corpus-build` |
| 8. SDK and adapter | reading `/corpus/` |
| 9. Enrichers | `ext/` (§2.2) |
| 10. Acceptance | the COR rows of [acceptance.md](../acceptance.md) |
