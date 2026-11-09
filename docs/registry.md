# Harness registry

Harnesses are built off-host, published to an OCI registry and imported by the
platform **by digest**. The host never builds tenant code: it pulls, verifies and
caches packages, and boots them.

> **Status.** Import, verification, caching, release states and deprecation work.
> Booting an agent from an imported release (attaching `harness.ext4` read-only to
> the VM) is the next step; until then, agent creation accepts only
> operator-approved local releases. Signature policy and the reference Dagger module
> come after. See [ROADMAP.md](../ROADMAP.md) (REG-01 to REG-04).

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
filesystem of the harness; the platform only reads its superblock on the host and
never mounts it there.

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
4. `harness.yaml`, `checksums.json` and the ext4 superblock are validated.
5. The package moves to `<cache>/sha256/<digest>/`, read-only, and the release is
   published.

Outcomes: `READY` with a release, or `REJECTED` with `policy`, `not_found`,
`integrity`, `version_conflict` or `unavailable`. Network failures are retried with
backoff up to 5 attempts. A rejected package can be requested again.

Releases are immutable: `name:version` maps to one package digest forever; another
package claiming it is rejected (`version_conflict`). Requesting a package that is
already released answers with that release and downloads nothing.
`POST /v1/harness-releases/{id}/deprecate` stops new agents from using a release;
agents already pinned to it keep running. Organization members with `agent:read` can
list releases (`GET /v1/harness-releases`).

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

Imports run in their own loop beside maintenance, so a large download never delays
deliveries or VM lifecycle work.

## Limits

- Only anonymous pulls are configured today (public packages, e.g. public GHCR
  packages). Credentials for private registries are next.
- No signature or attestation policy yet (REG-009): trust rests on the approved
  registry/repository and the pinned digest.
- The cache is per host and is not evicted yet (REG-03).
- Import has been tested against an in-process OCI registry (token flow, CDN
  redirect, tampering); a live GHCR import has not been run yet.
