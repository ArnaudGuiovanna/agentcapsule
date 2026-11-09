# Harness registry

Harnesses are built off-host, published to an OCI registry and imported by the
platform **by digest**. The host never builds tenant code: it pulls, verifies and
caches packages, and boots them.

> **Status.** Import from public and private registries, verification, caching,
> release states, deprecation, booting agents from imported releases, manual upgrade and
> rollback, and cache eviction work and are validated on real KVM (two tenant agents on
> one imported release share the cached image; an agent is upgraded, rolled back across
> sleep/wake and still answers after the unused package is evicted). Signature policy
> and the reference Dagger module come next. See [ROADMAP.md](../ROADMAP.md)
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
```

`checksums.json` lists the sha256 of `harness.yaml` and `harness.ext4`, so a package
copied out of a registry can still be checked. `harness.ext4` is the read-only root
filesystem of the harness; the platform never mounts it on the host.

The base `agentcapsule-guest/1` requires these directories in `harness.ext4`, where the
guest mounts its runtime: `/dev`, `/proc`, `/run`, `/tmp` and `/var/lib/agent` (the
agent's private data). `pack` creates them when they are missing. The entrypoint must be
an executable file (or a symlink) inside the image. The harness runs chrooted in its
image, as an unprivileged user, so it must carry everything it needs (a static binary,
or an interpreter and its libraries).

## Building and publishing

```bash
go build ./cmd/agentcapsule-harness
agentcapsule-harness pack --manifest harness.yaml --rootfs ./rootfs --size-mib 64 --out ./package
AGENTCAPSULE_REGISTRY_PASSWORD=<token> agentcapsule-harness push --dir ./package \
  --registry ghcr.io --repository acme/echo --tag 1.0.0 --username <user>
# prints: ghcr.io/acme/echo:1.0.0@sha256:...
```

`pack` uses `mkfs.ext4 -d` and `debugfs` (e2fsprogs) without root and without
mounting. Timestamps, UUID and ownership are fixed, so the same inputs give the same
digest. `push` prints the reference pinned by digest; the tag is informational.

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
3. Each blob is streamed to a private staging directory with a size limit and checked
   against its digest.
4. `harness.yaml`, `checksums.json` and the ext4 superblock are validated, and the
   image is inspected read-only with `debugfs`: the mount points must be directories
   and the entrypoint an executable file.
5. The package moves to `<cache>/sha256/<digest>/`, read-only, and the release is
   published.

Outcomes: `READY` with a release, or `REJECTED` with `policy`, `not_found`,
`access_denied`, `integrity`, `version_conflict` or `unavailable`. `access_denied`
means the registry refused access: the repository is private and the worker has no
valid credentials for it, or it does not exist (registries often do not say which).
Network failures are retried with backoff up to 5 attempts. A rejected package can be
requested again, for example after fixing the credentials.

Releases are immutable: `name:version` maps to one package digest forever; another
package claiming it is rejected (`version_conflict`). Requesting a package that is
already released answers with that release and downloads nothing.
`POST /v1/harness-releases/{id}/deprecate` stops new agents from using a release;
agents already pinned to it keep running. Organization members with `agent:read` can
list releases (`GET /v1/harness-releases`).

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
2. **Back up.** Capture a cold encrypted archive of the agent
   ([worker.md](worker.md#cold-encrypted-archive-capture)). Restoring an archive is not
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

## Worker trust policy

In the worker configuration ([example](../runtime/worker/config.example.json)):

```json
"registry": {
  "max_harness_mib": 1024,
  "rules": [
    {"host": "ghcr.io", "repositories": ["acme/"],
     "blob_hosts": ["pkg-containers.githubusercontent.com"]}
  ]
}
```

- `repositories`: `"org/"` allows every repository under `org`; `"org/name"` exactly one.
- The worker connects only to the rule's host, its `token_hosts` (bearer token realm)
  and `blob_hosts` (redirected blob downloads, such as a CDN). Redirects elsewhere are
  refused.
- Connections to loopback, private, link-local, carrier-grade NAT and other
  non-public addresses are refused at dial time, after DNS resolution, so a public
  name cannot be pointed at an internal address. `"local": true` lifts this and
  allows plain HTTP for a registry on the operator's own network; never use it for a
  public registry.
- Environment proxy settings are ignored.

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

## Limits

- No signature or attestation policy yet (REG-009): trust rests on the approved
  registry/repository and the pinned digest.
- The cache is per host; a multi-host installation must import on every host that will
  run the release.
- Import has been tested against an in-process OCI registry (token flow, private
  access with Basic and token credentials, CDN redirect, tampering); a live GHCR import
  has not been run yet.
