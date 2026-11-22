# Harness registry

Harnesses are built off-host, published to an OCI registry and imported by the
platform **by digest**. The host never builds tenant code: it pulls, verifies and
caches packages, and boots them.

> **Status.** Import from public and private registries, verification, caching,
> release states, deprecation, booting agents from imported releases, manual upgrade and
> rollback, and cache eviction work and are validated on real KVM (two tenant agents on
> one imported release share the cached image; an agent is upgraded, rolled back across
> sleep/wake and still answers after the unused package is evicted). Publisher
> signatures (cosign format, trusted keys, strict mode) are verified at import. The
> reference Dagger module builds, publishes, signs and verifies packages in CI. Keyless
> signatures come next. See [ROADMAP.md](../ROADMAP.md)
> (REG-01 to REG-04).

## Package format

A package is an OCI artifact (image manifest, `artifactType`
`application/vnd.agentcapsule.harness.v1`) with an empty config and exactly three
layers, in this order:

| File | Media type | Limit |
|---|---|---|
| `harness.yaml` | `application/vnd.agentcapsule.harness.manifest.v1+yaml` | 64 KiB |
| `checksums.json` | `application/vnd.agentcapsule.harness.checksums.v1+json` | 16 KiB |
| `harness.ext4` | `application/vnd.agentcapsule.harness.rootfs.v1+ext4` | worker setting, 1 GiB by default |

`harness.yaml` is parsed strictly (unknown fields, duplicate keys and extra documents
are refused):

```yaml
schema: agentcapsule.harness/v1
name: echo                      # 1-100 of [A-Za-z0-9._-]
version: 1.0.0                  # same rule
protocol: capsule.v1            # the guest contract the harness speaks
architecture: x86_64
base: agentcapsule-guest/1      # guest ABI: kernel, capsule-init, mount layout
entrypoint: [/bin/harness, --serve]   # clean absolute path inside harness.ext4
description: Reference echo harness   # optional
capabilities: [llm.invoke]            # optional; see below
```

`capabilities` lists what the harness asks the platform for over its
platform channel: `llm.invoke`, `agents.delegate`, `agents.discover`
([ADR 016](adr/016-content-links-capabilities.md)), `stream.output`
([ADR 022](adr/022-native-streaming.md)). The importer records the
list on the release; an unknown name rejects the package: a platform older
than ADR 022 rejects a manifest that requests `stream.output`. An empty list asks
for nothing. A manifest without the field predates it and is treated as
asking for every capability. The agent gets the intersection of this list and
its organization's and its own policies
([agents-assignments.md](api/agents-assignments.md#capabilities-cap-01-ext-003)).

`checksums.json` lists the sha256 of `harness.yaml` and `harness.ext4`, so a package
copied out of a registry can still be checked. `harness.ext4` is the read-only root
filesystem of the harness; the platform never mounts it on the host.

The base `agentcapsule-guest/1` requires these directories in `harness.ext4`, where the
guest mounts its runtime: `/dev`, `/proc`, `/run`, `/tmp` and `/var/lib/agent` (the
agent's private data). `pack` creates them when they are missing. The base
`agentcapsule-guest/2` adds `/corpus`, where the guest mounts the agent's corpora
([ADR 023](adr/023-corpora.md), [guest/README.md](guest/README.md#corpora)); only
a release of base 2 can be bound to corpora. The release records its base, and
`GET /v1/harness-releases` shows it. The entrypoint must be
an executable file (or a symlink) inside the image. The harness runs chrooted in its
image, as an unprivileged user, so it must carry everything it needs (a static binary,
or an interpreter and its libraries).

## Building and publishing

A harness can be written in any language whose runtime fits in the image: Go (see
`cmd/capsule-echo`) or Python with the [Python SDK](../sdk/python/README.md). An
existing agent can also run unchanged, packed with
[capsule-adapter](adapter.md) (`dagger call adapt`). All three run in the product
KVM campaign. The Python harness answers from its encrypted SQLite state across
sleep and wake, and posts a deferred model answer over the platform channel. The
adapted example reads an attached file with its own tool call, through its
model, and answers again after sleep and wake.

### Reference build (Dagger)

The [Dagger](https://dagger.io) module at the repository root (`dagger.json`,
`.dagger/main.go`) is the reference build. Every image it uses is pinned by digest,
and it runs the same way on a laptop and in CI (Docker and the `dagger` CLI are the
only requirements):

```bash
dagger call python-echo export --path=./build/python-echo   # Python SDK + examples/python-echo
dagger call go-echo export --path=./build/go-echo           # capsule-echo, one static binary
dagger call pack --rootfs=./my-rootfs --manifest=./harness.yaml export --path=./build/mine
dagger call publish --pkg=./build/python-echo --registry=ghcr.io --repository=acme/python-echo \
  --tag=1.0.0 --username=acme-bot --password=env:GHCR_TOKEN
dagger call sign --ref=ghcr.io/acme/python-echo:1.0.0@sha256:... --key=file:./acme-release.key \
  --username=acme-bot --password=env:GHCR_TOKEN
dagger call verify --ref=ghcr.io/acme/python-echo:1.0.0@sha256:... --key=./acme-release.pub
dagger call check   # the whole chain against a throwaway registry (run by CI)
```

`check` builds both reference harnesses, pushes them to a `registry:2` service (a
registry without the referrers API, like GHCR), checks that an unsigned package is
refused when a signature is required, then signs both and verifies them as the
platform importer would, but for the inspection's sandbox: Dagger's containers cannot
create it, so `verify` and `check` inspect each image unconfined (`--unconfined`, as
`nobody`). Set `DO_NOT_TRACK=1` to disable Dagger's anonymous telemetry.

Without Dagger, `scripts/build-python-harness.py` builds the same harness with plain
Docker. Each path is reproducible on its own; their digests differ because they pack
with different e2fsprogs versions.

```bash
go build ./cmd/agentcapsule-harness
agentcapsule-harness pack --manifest harness.yaml --rootfs ./rootfs --size-mib 64 --out ./package
AGENTCAPSULE_REGISTRY_PASSWORD=<token> agentcapsule-harness push --dir ./package \
  --registry ghcr.io --repository acme/echo --tag 1.0.0 --username <user>
# prints: ghcr.io/acme/echo:1.0.0@sha256:...
```

With the tool alone (`go build ./cmd/agentcapsule-harness`), `pack` uses
`mkfs.ext4 -d` and `debugfs` (e2fsprogs) without root and without mounting. Timestamps, UUID and ownership are fixed, so the same inputs give the same
digest. `push` prints the reference pinned by digest; the tag is informational.

### Signing

A publisher signs each package it pushes; the platform can then refuse anything its
trusted publishers did not sign. The format is cosign v3's, so either tool works:

```bash
agentcapsule-harness keygen --out ./acme-release      # acme-release.key (private), acme-release.pub
AGENTCAPSULE_REGISTRY_PASSWORD=<token> agentcapsule-harness sign \
  --key ./acme-release.key --ref ghcr.io/acme/echo:1.0.0@sha256:... --username <user>
# or: cosign sign --key cosign.key ghcr.io/acme/echo@sha256:...
agentcapsule-harness verify --ref ghcr.io/acme/echo:1.0.0@sha256:... --key ./acme-release.pub
```

`verify` downloads the package and runs the importer's checks (digests, layout,
`harness.yaml`, image inspection, and the signature when keys are given), so a
publisher or an operator can check a package before it is imported. It runs
`debugfs` in the importer's sandbox ([below](#image-inspection-sandbox)), as the
`nobody` account (65534) when run as root. Where the machine cannot create the
sandbox (a container without user namespaces, as in CI), `verify` fails. With
`--unconfined`, it inspects the image without the sandbox and prints a warning;
it refuses that flag as root. The Dagger check runs it so, as `nobody`. The
platform host never inspects unconfined: the sandbox refuses it to root.

The signature is an in-toto statement naming the package manifest digest, in a DSSE
envelope signed with the key (ECDSA P-256/P-384/P-521, Ed25519 or RSA of at least
2048 bits), packaged as a Sigstore bundle (v0.3). It is attached to the package as an
OCI referrer, or through the referrers tag (`sha256-<hex>`) on registries without the
referrers API, such as GHCR. `agentcapsule-harness sign` reads an unencrypted PKCS#8
or EC key; use cosign for cosign's encrypted key files. Give the operator the `.pub`
file.

## Importing

The platform operator requests an import with the `platform:admin` credential:

```bash
curl -X POST https://api.example/v1/harness-imports \
  -H "Authorization: Bearer $PLATFORM_TOKEN" -H "Idempotency-Key: echo-1.0.0" \
  -H "Content-Type: application/json" \
  -d '{"reference":"ghcr.io/acme/echo:1.0.0@sha256:..."}'
```

The import is `IMPORTING` until a worker processes it:

1. The reference is checked against the worker's trust policy **before any
   connection**: approved registry, approved repository prefix.
2. The manifest is fetched and must hash to the pinned digest; its layout must match
   the format above exactly.
3. If the rule trusts publisher keys, a signature by one of them must cover that
   digest (see [Publisher signatures](#publisher-signatures)), before anything large is
   downloaded.
4. Each blob is streamed to a private staging directory with a size limit and checked
   against its digest.
5. `harness.yaml`, `checksums.json` and the ext4 superblock are validated, and the
   image is inspected read-only with `debugfs`, confined
   ([Image inspection sandbox](#image-inspection-sandbox)): the mount points must be
   directories and the entrypoint an executable file.
6. The package moves to `<cache>/sha256/<digest>/`, read-only, and the release is
   published, with the ID of the key that signed it (`signer`) if any.

Outcomes: `READY` with a release, or `REJECTED` with `policy`, `not_found`,
`access_denied`, `signature`, `integrity`, `version_conflict`, `unavailable` or
`storage_pressure`. `storage_pressure` means the file system of the worker's cache
stayed past its threshold for every attempt ([worker.md](worker.md#storage-pressure));
while one is, new import requests are refused with `503 storage_pressure`. `access_denied`
means the registry refused access: the repository is private and the worker has no
valid credentials for it, or it does not exist (registries often do not say which).
Network failures are retried with backoff up to 5 attempts. A rejected package can be
requested again, for example after fixing the credentials.

Releases are immutable: `name:version` maps to one package digest forever; another
package claiming it is rejected (`version_conflict`). Requesting a package that is
already released answers with that release and downloads nothing.
`POST /v1/harness-releases/{id}/deprecate` stops new agents from using a release;
agents already pinned to it keep running. Organization members with `agent:read` and
a role that reads every agent's metadata (owner, administrator, operator, auditor) can
list releases (`GET /v1/harness-releases`).

### Live test on GHCR

REG-002 asks that the import test pass on GHCR as on a local registry. The
tests of the worker run on a local registry; `-tags ghcrlive` adds two tests
that reach GHCR, never run by CI or the PostgreSQL campaign:

```bash
AGENTCAPSULE_TEST_POSTGRES='host=/path/to/socket user=... dbname=postgres' \
AGENTCAPSULE_TEST_GHCR_REFERENCE=ghcr.io/<owner>/<name>:<version>@sha256:<digest> \
go test -tags ghcrlive -run TestLiveGHCR ./internal/worker
```

`TestLiveGHCRImport` imports the harness package that the variable
names, with the assertions of the local-registry test: `READY` with a
release, read-only files in the cache, nothing left to do.
For a private package, set `AGENTCAPSULE_TEST_GHCR_USERNAME` and supply its
token through `AGENTCAPSULE_REGISTRY_PASSWORD`, never a command-line argument.
Set `AGENTCAPSULE_TEST_GHCR_PUBLISHER_KEY` to a publisher's PEM public key
to require that publisher's signature before downloading the image.
`AGENTCAPSULE_TEST_GHCR_EXPORT` can name a new directory into which the test
copies the verified package. It can then feed `--pi-harness` in the KVM
campaign: compare its checksums with the published package before running it.
The KVM scenario imports those same bytes through its own local registry;
the preceding live test is the proof of the GHCR import.
`TestLiveGHCRRejectsAnImageThatIsNotAHarness` needs no variable: it gets an
anonymous token from GHCR, fetches the manifest of a public image that is not a
harness package, and checks that it is rejected as `integrity` before any
layer. The rule for GHCR names its blob CDN,
`pkg-containers.githubusercontent.com`. Both tests passed on 2026-11-19
with a signed private Pi qualification
package in `ghcr.io/arnaudguiovanna/agentcapsule/pi-agent`. This is a test
package, not a published platform release. The qualified package is pinned to:

```text
ghcr.io/arnaudguiovanna/agentcapsule/pi-agent:qualification-20261119T150746Z@sha256:d6853fcce563d413c35961e2e9e0377df517214d1aea8319b42411a63a9b5d85
```

The exported package then passed the Pi KVM scenario with local Ollama on
2026-11-19. Its adapter uses the static cgo/SQLite build from
`scripts/build-adapted-harness.py`; a build with `CGO_ENABLED=0` can compile
but cannot open the SQLite store at startup.

## Running an imported release

An agent created on an imported release (`"harness": {"name": ..., "version": ...}`)
boots from the package cached on its host:

1. At provisioning, the worker finds the package by its digest in the cache, hashes
   `harness.ext4` again and refuses it if it no longer matches the release, then
   records the image with the agent on the host.
2. At each boot, the image is hard-linked into the VM's jail (one inode shared by every
   agent of the release; copied only if the cache is on another filesystem) and
   attached as a second, read-only drive. A boot-specific file tells `capsule-init` the
   entrypoint.
3. In the guest, `capsule-init` mounts the drive read-only (`nosuid`, `nodev`) on
   `/harness`, binds `/dev`, `/run` and `/tmp`, mounts `/proc`, binds the decrypted data
   directory at `/var/lib/agent` for the life of the harness process, and runs the
   entrypoint chrooted in `/harness` as the unprivileged harness user. The platform
   socket and data paths are the same as for the built-in harness.

An agent stays pinned to its release; deprecating the release does not stop it.
Without a configured registry, or if the host does not hold the package, provisioning
fails and the agent is not created.

## Upgrading and rolling back an agent

Upgrades are manual: an owner, administrator or agent operator pins the agent to another
approved release, then restarts it.

```bash
curl -X POST https://api.example/v1/agents/$AGENT_ID/release \
  -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: upgrade-echo-2.0.0" \
  -H "Content-Type: application/json" \
  -d '{"harness":{"name":"echo","version":"2.0.0"}}'
# {"agent_id":"agt_...","harness":{"name":"echo","version":"2.0.0"},
#  "previous":{"name":"echo","version":"1.0.0"},"applies":"next_boot"}
```

- The target must be approved and not deprecated, and the agent live. The change is
  audited with the new release, and `GET /v1/agents/{id}` shows the pinned release.
- It applies at the next boot. A running VM keeps its harness until it stops; nothing
  is restarted for you. Before booting, the worker compares the agent's release with the
  image it recorded for the agent; if they differ it verifies the new cached image
  (hash) and records it, which is only possible while the VM is stopped.
- The agent keeps its encrypted data volume. Migrating data between harness versions is
  the harness's job.

Recommended procedure:

1. **Prepare.** Import the new release on the agent's host and wait for `READY`. Do not
   deprecate the current release yet: it is your rollback target.
2. **Back up.** Capture an encrypted archive of the agent on demand
   ([worker.md](worker.md#archive-on-demand)). Restoring an archive is not
   automated yet (REC-01), so keep in mind that a rollback after the new version has
   migrated the data may not be possible.
3. **Upgrade.** Pin the new release, then `POST /v1/agents/{id}/sleep` and `.../wake`.
4. **Check.** The wake operation succeeds once the VM has booted the new image and its
   guest has established the platform contract. Then send the agent a real invocation
   and check the answer: that is what proves the new harness works.
5. **Roll back if needed.** Pin the previous release and sleep/wake again. If the new
   release cannot boot (for example, it is missing from the host's cache), the wake keeps
   retrying and the agent stays stopped: pinning the previous release is enough for the
   pending wake to succeed.
6. **Clean up.** Once every agent has moved, deprecate the old release; its package
   then leaves the cache (below).

## Cache eviction

The worker removes cached packages that no agent of its host can boot any more. In the
import loop (so never during a download), at most once an hour when idle, it keeps:

- every approved (not deprecated) release, used or not;
- deprecated releases still pinned by an agent of this host that is not deleted;
- packages being imported;
- any image the host still records for an agent, such as the release it ran before a
  change that has not been booted yet.

Everything else in `<cache>/sha256/` is moved out of the content-addressed path in one
step and deleted, with leftovers of interrupted downloads. VMs already running keep their
own hard link to their image. To free the space of a release, deprecate it. A deprecated
package cannot be imported again (the release already exists), so evict only what you
will not roll back to.

## Refilling the cache

A host rebuilt from its backups has its releases in PostgreSQL, each with the reference
and digest of its package, but not its cache (OPR-10). In the same loop, at most once a
minute when idle, the worker fetches again each package that an agent of its host, not
deleted, pins and that the cache lacks. It fetches the release's reference by digest,
under the same registry rules, verifies the package as at its import, and keeps it only
if it holds the release's root file system. Until then the agent does not boot. A
package that its registry no longer serves leaves its agents stopped: copy it into the
cache ([recovery.md](recovery.md#prepare)). A one-shot `-restore-agent` or
`-restore-host` does not refill: run the worker service first, or copy the cache.

## Worker trust policy

In the worker configuration ([example](../runtime/worker/config.example.json)):

```json
"registry": {
  "max_harness_mib": 1024,
  "inspection_uid": 61999,
  "rules": [
    {"host": "ghcr.io", "repositories": ["acme/"],
     "blob_hosts": ["pkg-containers.githubusercontent.com"],
     "allow_unsigned": true}
  ]
}
```

- `allow_unsigned`: this rule imports packages that no trusted publisher signed; in
  production, a rule without `publisher_keys` must say so
  ([below](#publisher-signatures)).
- `inspection_uid`: the UID, and the GID of the same number, that `debugfs` runs as
  when it inspects a downloaded image ([below](#image-inspection-sandbox)). Reserve it
  for this use, as the provisioning range is reserved: no account or group uses it, it
  owns no file, it lies outside the provisioning range and is not the SLIM bridge's
  user. It needs no entry in `/etc/passwd`. It must lie between 1 and 2147483646, and
  not be 65535: the kernel takes -1 (4294967295) as "unchanged", and some interfaces
  take 65535 the same way. Required when the worker runs as root. The worker refuses a
  value outside that range, in the provisioning range, the SLIM bridge's, or one that
  an account or a group of the host has (as a GID, 6 would be `disk` on Debian); it
  then does not start (`registry_configuration_invalid`).
- `repositories`: `"org/"` allows every repository under `org`; `"org/name"` exactly one.
- The worker connects only to the rule's host, its `token_hosts` (bearer token realm)
  and `blob_hosts` (redirected blob downloads, such as a CDN). It follows a redirect to
  one of these, at most three times; redirects elsewhere are refused.
- The worker checks each address when it connects, after DNS resolution, so a public
  name cannot be pointed at an internal address. This holds for the registry, its token
  service and its blob hosts, redirects included. The address classes are the model
  gateway's ([ADR 010](adr/010-transport-security-and-preflight.md) §4):
  - public addresses are allowed;
  - internal addresses are refused: loopback, private (RFC 1918, RFC 4193),
    carrier-grade NAT (`100.64.0.0/10`) and the other reserved ranges;
  - always refused, whatever the rule: unspecified, multicast and link-local addresses,
    `0.0.0.0/8`, and the cloud metadata addresses (`169.254.169.254` and the rest of
    `169.254.0.0/16`, `100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`,
    `fd00:ec2::23`, `fd20:ce::254`);
  - IPv4-mapped and NAT64 (`64:ff9b::/96`) addresses count as the IPv4 address they
    carry.
- `"local": true` allows internal addresses and plain HTTP, for a registry on the
  operator's own network; never use it for a public registry. It does not open the
  always-refused addresses: write `127.0.0.1` or `localhost`, not `0.0.0.0`. In
  production the worker refuses to start with such a rule
  ([ADR 010](adr/010-transport-security-and-preflight.md)); it is for development.
- A refused address fails the import with the code `policy`.
- Environment proxy settings are ignored.

### Publisher signatures

A rule may list the publisher keys it trusts (PEM public keys, such as `cosign.pub`).
Every package imported through that rule must then carry a signature by one of them;
otherwise the import is rejected as `signature`.

```json
"registry": {
  "require_signatures": true,
  "rules": [
    {"host": "ghcr.io", "repositories": ["acme/"],
     "blob_hosts": ["pkg-containers.githubusercontent.com"],
     "publisher_keys": ["/etc/agentcapsule/publishers/acme-release.pub"]}
  ]
}
```

- In production (the default mode, [ADR 010](adr/010-transport-security-and-preflight.md)),
  signatures are required by default: a rule that lists no publisher key must say
  `"allow_unsigned": true`, an explicit opt-out for that rule, or the worker refuses to
  start (`registry_signatures_required_in_production`). A rule that says
  `allow_unsigned` beside publisher keys is refused. In development
  (`AGENTCAPSULE_MODE=development`), a rule without keys imports unsigned packages, as
  before.
- Every rule that imports unsigned packages is reported: the worker logs
  `registry_unsigned_rules` with their number at each start, the preflight's
  `registry_signatures` check warns and names them, and each release imported through
  one records no `signer`.
- The shipped example (`runtime/worker/config.example.json`), which the installer
  writes for a new host, says `allow_unsigned` for its GHCR rule: the project's
  packages are not signed yet. An update of a host installed before writes
  `"allow_unsigned": true` in each rule that lists no key and says nothing, so that its
  imports keep working, and names those rules in the operation's status
  (`registry_rules_allowing_unsigned`). To require signatures, list the publishers'
  keys and drop `allow_unsigned`.
- `require_signatures` is strict mode: the worker refuses to start if a rule lists no
  publisher key, or says `allow_unsigned`, so no unsigned package can be imported.
  Recommended in production.
- Key files must be regular files (not symlinks) owned by root or the worker's user and
  writable only by their owner. The worker reads them at startup.
- The release records the key that signed it: `signer` is `sha256:` and the SHA-256 of
  the DER public key (`openssl pkey -pubin -in key.pub -outform DER | sha256sum`).
- Only the configured keys are trusted. Certificates and transparency-log entries that
  a bundle may carry (cosign keyless signing with Fulcio and Rekor) are not checked:
  keyless identities are not supported yet.
- Enabling signatures does not revoke releases imported before; deprecate those you no
  longer trust. A release is immutable: re-signing a package does not change its
  `signer`.

### Private registries

A rule may name a credentials file; the configuration never holds the secret itself:

```json
{"host": "ghcr.io", "repositories": ["acme/"],
 "blob_hosts": ["pkg-containers.githubusercontent.com"],
 "credentials_file": "/etc/agentcapsule/registry-ghcr.json"}
```

```json
{"username": "acme-bot", "password": "<token>"}
```

- The file must be a regular file (not a symlink) owned by root or the worker's user,
  with no group or other access (`chmod 600`), at most 4 KiB, with exactly these two
  fields. The worker reads it once at startup: restart the worker after rotating it
  (running agents are not affected).
- For GHCR, use a token with only the `read:packages` scope. Docker Hub uses an access
  token, and its token service must be approved: `"token_hosts": ["auth.docker.io"]`.
- Every request goes out anonymously first. The credentials are sent only in answer to
  a challenge: to the approved token service in exchange for a short-lived token (the
  usual case), or to the registry itself if it asks for Basic authentication. They are
  removed from any redirect to another host, such as a blob CDN.
- Only static credentials are supported. Registries that need a cloud SDK to mint
  short-lived passwords (Amazon ECR, Google Artifact Registry with workload identity)
  are not supported yet.

Imports run in their own loop beside maintenance, so a large download never delays
deliveries or VM lifecycle work.

### Image inspection sandbox

`debugfs` (e2fsprogs) parses each downloaded image before the import accepts it. The
worker runs as root, and the image comes from outside: a flaw of e2fsprogs must not
reach the host. So every `debugfs` run on a downloaded image is confined
(`internal/sandbox`, REG-01):

- The worker starts itself again as a helper, in new mount, network, PID, IPC and UTS
  namespaces, and the helper executes `debugfs`. Its network namespace has only an
  unconfigured loopback interface.
- Every mount is read-only, `nosuid` and `nodev`: no device node opens. `/proc` is the
  namespace's own and shows its process only (`subset=pid`); `/sys` is empty. The
  image is opened read-only, then reopened through those read-only mounts, and
  `debugfs` reads it as its descriptor 3 (`/proc/self/fd/3`). It inherits no other
  descriptor than 0 to 3: every other one is closed when it starts, whatever the
  worker's C code left open. Its standard input is empty, or, when it lists a
  corpus image's directories (since the v0.1.0 audit, P-12), a pipe that holds
  its commands (`debugfs -f -`, at most 32 KiB) before it starts.
- `debugfs` runs as `inspection_uid` and its GID, without supplementary groups or
  capabilities, with `no_new_privs`; the helper checks its UIDs, GIDs and groups
  before it starts `debugfs`. It runs on one processor, with every signal blocked.
- A seccomp filter allows the system calls `debugfs` makes and nothing else
  ([below](#the-allow-list)). Any other call kills it; it cannot start a process or a
  thread, open a socket, mount, change namespaces or credentials, or trace.
- Limits: 30 seconds of processor time, one minute in all, 256 MiB of address space,
  no byte written to any file, no core dump, 64 open files, and the first victim under
  memory pressure. The worker kills it at its limits, and with itself; the helper
  checks that the worker still lives before it starts `debugfs`.

A worker that is not root (a test, a laboratory) runs the helper in a user namespace of
its own instead: `debugfs` keeps the worker's account, without capabilities, and
`inspection_uid` is not used. Such an account cannot drop its supplementary groups;
`nodev` keeps the devices they open closed. A worker that is root of a user namespace
other than the host's, as in a container, is refused: it can take no reserved UID. At
start, the worker runs `debugfs -V` in the sandbox, and does not start if that fails
(`registry_inspection_unavailable`): it needs a kernel with `mount_setattr` (5.12,
below the 5.14 the worker requires), a service manager that lets it create namespaces
(no `RestrictNamespaces=` in its unit) and, when not root, user namespaces. The
preflight reports it as `registry_inspection` ([install.md](install.md#preflight)).

What remains: `debugfs` can read the host's files that any account may read, through
the read-only mounts. It can send them nowhere but its standard output, which the
inspection reduces to a type and a mode. A filesystem allow-list (Landlock) or a
minimal root would remove that; neither is done.

#### The allow-list

The filter's list is what `debugfs -V` and `debugfs -R 'stat "PATH"' /proc/self/fd/3`,
run as the inspection runs them, call on 72 images: the reference harnesses, ext2,
ext3 and ext4 with unusual features (1 KiB and 64 KiB blocks, inline data, bigalloc,
casefold, MMP, quota, encryption and verity, 32-bit, meta_bg, large directories,
special files where the entrypoint is expected, a journal to recover), damaged images
(no superblock, truncated, garbage, empty, a damaged group descriptor or inode table)
and fuzzed ones. Each call was traced with ptrace, with e2fsprogs 1.47.0 to 1.47.4,
glibc 2.36, 2.39 and 2.43, and musl:

- reading and writing: `read`, `pread64`, `lseek`, `write`, `writev`, `open`, `openat`,
  `close`, `fsync`, `fadvise64`, `fstat`, `newfstatat`, `stat`, `lstat`, `access`,
  `readlink`;
- memory: `brk`, `mmap`, `munmap`, `mprotect`, and, not measured, `mremap` (glibc's
  `realloc` of a large block) and `madvise` (musl's allocator);
- the program's start and end: `execve`, `arch_prctl`, `set_tid_address`,
  `set_robust_list`, `rseq`, `prlimit64`, `getrandom`, `sched_getaffinity`,
  `rt_sigaction`, `exit_group`, `getuid`, `geteuid`, `getgid`, `getegid`;
- clocks, which the vDSO answers unless the clock source does not allow it (not
  measured): `clock_gettime`, `gettimeofday`, `time`;
- with some arguments only: `prctl(PR_GET_DUMPABLE)`, `fcntl` to read or set a
  descriptor's flags, `futex` to wait and wake. The filter answers `ioctl` itself with
  `ENOTTY`, as the kernel does on the image, a pipe and `/dev/null`, another `prctl` or
  `fcntl` with `EINVAL`.

Any other call kills `debugfs` (`SECCOMP_RET_KILL_PROCESS`): `debugfs` never makes one,
so a call outside the list means an image led it astray, or a C library that calls one
the list lacks. Killing ends the first at once and makes the second visible: the
import fails with "a system call outside its allow-list". A call numbered above the
newest of Linux 6.18 gets `ENOSYS`, as an older kernel answers, so that the C library
falls back to an older call. Another architecture and the x32 calls kill. e2fsprogs
1.47.4 reads an image's bitmaps with one thread per processor; on its one processor,
it reads them in its own thread, which the filter requires.

`internal/sandbox`'s tests run a static program of a few instructions per call, under
exactly that filter, and evaluate the filter for every call number; `internal/harnesspkg`'s
tests compare `debugfs`'s output confined and direct on images of each kind above.

`pack` runs `mkfs.ext4` and `debugfs -w` unconfined: it builds the publisher's own
package, on the publisher's machine.

### The key check of a restore test

A restore test ([worker.md](worker.md#testing-a-restore)) checks that the agent's key
opens a copy of an archive. The copy's LUKS2 header comes from the guest: the guest
holds its volume open and may rewrite its header, and the archive keeps it. So
libcryptsetup never reads it in the worker (S-21). The worker starts its own executable
again in the sandbox above, as the program `agentcapsule-luks-check`
(`internal/volumestore`), with the same namespaces, mounts, `inspection_uid`, dropped
capabilities, `no_new_privs`, processor, limits and closed descriptors. The key reaches
it on its standard input, through a pipe, never in its arguments or environment. It
answers one word: the key opens the key slot, it does not, or the header is not of the
platform's shape. The worker reads nothing else from it.

Before any key derivation, the program refuses a header that is not the platform's: one
key slot with Argon2id over at most 64 MiB and one thread, at most 16 passes (the
platform asks for 100 ms, at least 4 passes), one segment in `aes-xts-plain64` with
512-byte sectors, one PBKDF2-SHA256 digest of at most 2 000 000 iterations, no token
and no requirement. The test then fails as `key`. The sandbox bounds the rest: 10
seconds of processor time, 30 seconds in all, 256 MiB of writable memory.

A Go program needs more than `debugfs`, so this program runs under the self filter:
`debugfs`'s list, and what the program called when it was traced (a filter that logs
or traps any other call, on a key that opens, another key, another volume and a damaged
header, from the worker's executable, with Go 1.27, glibc 2.43, libcryptsetup 2.8.4 and
OpenSSL 3.5; the same checks pass under the filter with Ubuntu 24.04's glibc 2.39,
libcryptsetup 2.7.0 and OpenSSL 3.0):

- the Go runtime: `rt_sigprocmask`, `sigaltstack`, `rt_sigreturn`, `getpid`, `gettid`,
  `tgkill` (preemption of its own threads), `nanosleep`, `sched_yield`, and `clone` for
  a thread only (`CLONE_THREAD`, without any new namespace); `clone3` gets `ENOSYS`, so
  that the C library falls back to `clone`;
- the start of the worker's packages: protobuf reads the executable to seed its
  output, through the runtime's poller: `readlinkat`, `epoll_create1`, `epoll_ctl`,
  `epoll_pwait`, `eventfd2`;
- libcryptsetup and its libraries: `statfs`, `fstatfs`, `uname`, `sysinfo`, `mlock`,
  `munlock` (its key buffers), `umask`; `mkdir` and `mkdirat` get `EROFS` (its lock
  directory), `request_key` gets `ENOSYS` (no kernel keyring);
- `seccomp`: once started, the program adds a filter of its own that kills it at
  `execve` or `execveat`, so it starts no other program.

Any other call kills it. A program of the worker's executable runs only confined:
started under its name otherwise, it exits. `/dev` holds only two empty regular files,
`random` and `urandom`, which libcryptsetup opens when it starts (the check creates no
key or salt). The address space is 4 GiB: the Go runtime reserves about 1.1 GiB it
never uses, which the writable-memory limit (`RLIMIT_DATA`) does not count.
`TestTheWorkerExecutableChecksAContainerConfined` (`cmd/agentcapsule-worker`) runs the
check from a binary that links every package of the worker, so a package whose start
calls outside the list fails there.

## Limits

- Signatures are verified against configured publisher keys only; keyless signatures
  (CI identities through Fulcio and Rekor) and other attestations (SLSA provenance) are
  not supported yet.
- The cache is per host; a multi-host installation must import on every host that will
  run the release.
- Import has been tested against an in-process OCI registry (token flow, private
  access with Basic and token credentials, CDN redirect, tampering); a live GHCR import
  has not been run yet.
