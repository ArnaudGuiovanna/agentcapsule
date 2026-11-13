# Maintenance and delivery worker

`cmd/agentcapsule-worker` reconciles placements, renews boot certificates and
resumes interrupted replacements, without any incoming request. It also
discovers the deliveries, closures, expirations and deletions to process in
PostgreSQL. With `key_authority` and `provisioning` configured, it also resumes
creation reservations. The API path with two owners and two VMs, including
provisioning and encrypted wake, is exercised by
`scripts/verify-product-guest.py`. The restore scenarios remain open.

Build with the repository's Go version, CGO and the libcryptsetup headers:

```sh
go build -trimpath -o bin/agentcapsule-worker ./cmd/agentcapsule-worker
```

Adapt [config.example.json](../runtime/worker/config.example.json) with the
verified paths and digests. `firecracker` must be the variant that keeps the
volume lock. The initrd must provide the trusted harness and the authenticated
protocol; the disposable SQL harness of the test campaigns remains a test tool.
The configuration file must be owned by root, be a regular file and not be
writable by group or others. Boot keys are not parameters of this file.

The process requires root for the jailer, namespaces and cgroups; the VMMs use
their dedicated UIDs. Provide `AGENTCAPSULE_DATABASE_URL` through the service
manager's protected environment, then run:

```sh
/opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json
```

The schema must be migrated. `-migrate` explicitly applies the migration before
starting; a normal launch does not modify the schema. The `host_id`, the
registry, the images and the capacity must be consistent across all workers of
the same host. Stop older versions before migrating.

For encrypted guests, explicitly initialize the key authority with
`agentcapsule-admin init-key-authority`, then the independent catalog with
`agentcapsule-admin init-restore-authority --root <catalog> --data-root <runtime>
--key-authority-root <keys> --key-authority-id <keys-identity>`.
For local provisioning, also add a UID/GID range reserved exclusively for this
host registry:

```json
{
  "key_authority": {
    "root": "/var/lib/agentcapsule-key-authority",
    "identity": "<PUBLIC_IDENTITY_RETURNED_BY_INITIALIZATION>"
  },
  "restore_authority": {
    "root": "/var/lib/agentcapsule-restore-authority",
    "identity": "<PUBLIC_IDENTITY_OF_THE_INDEPENDENT_CATALOG>"
  },
  "provisioning": { "first_uid": 62000, "last_uid": 62999 }
}
```

Both authorities must be separate from the runtime and its backups. The service
refuses an absent authority or one with a different identity; it does not
initialize it at startup. The UIDs of removed agents stay reserved. This first
harness source accepts the approved local image whose digest is exactly
`sha256:<initrd.sha256>`; OCI import and assembly remain to be built.

New installations register each volume with an initial incarnation of 1. The
worker checks this incarnation before key delivery, confirmation and adoption;
the guest verifies its persistent marker. An old guest or catalog without this
identity must not be relabeled at startup. The restore coordinator and data
recovery remain to be delivered.

Creation goes through the durable LUKS2 container, an immutable host
registration (inode, size and resources), then a restricted boot. The worker
delivers the key over the authenticated channel after checking the SQL lease and
the physical lock held by the VMM. After initialization and catch-up of
revocations, it removes the restricted boot and activates the agent in a
transaction that re-reads the current catalog. A lost response leaves these
steps replayable. The `provision` job uses the same tickets and backoffs as the
other jobs, without monopolizing the head of the queue on error. The API's
wake/sleep commands also go through this queue: only the first open command of
each agent is discovered. The worker re-reads its status after host admission
and does not re-run a finished command. The success of wake follows the durable
publication of the boot; that of sleep follows the physical removal. A deletion
cancels the open commands.
For sleep, the worker keeps the authenticated client of the current boot before
committing `STOPPING`, then requests quiescence under exclusive host admission.
It then removes the VMM and verifies its absence before publishing `STOPPED`.
Only a clean acknowledgment allows `unclean_stop=false`; a lost response, an
error or an exceeded timeout lead to a forced removal reported as unclean. A
recovery after a crash may conservatively classify the stop as unclean. The
forced recovery paths remain available. This wiring is tested in SQL/mTLS and in
the product path on KVM.

The loop performs one pass immediately, then waits `poll_interval` after each
pass. Each attempt has its own `attempt_timeout`; a failure keeps the SQL job
and the other jobs in the list are still attempted. The logs contain the fixed
codes `maintenance_started`, `maintenance_complete` and `maintenance_retry`,
with no DSN, raw SQL error, certificate or user content. `SIGTERM` and `SIGINT`
stop the loop and release its listeners; confirmed VMMs remain adoptable.

A replacement request is committed with `STOPPING`. It stays present after the
SQL confirmation of the new VMM: the durable `RUNNING` publication in the host
registry must precede its acknowledgment. An explicit stop or a deletion cancels
this request in the corresponding transaction. A delayed worker must re-verify
the request under SQL lock before claiming a boot.

A full capacity defers the replacement without evicting another guest. Its
progress therefore assumes that a slot becomes available again. Maintenance does
not automatically wake `fence_only` boots; the barrier manifests carry this
need. Nor does it restart every guest stopped for another cause: the general
desire to run and business fairness remain to be built. The pass interval is not
an availability bound: outages, contention, clock drift and the number of jobs
influence the effective time.

After the renewals, a pass discovers business intents and processes at most
`dispatch_batch` jobs. `worker_hosts` assigns tickets in the same transaction as
the mutations of `worker_jobs`. A claim moves the job to the end of the queue
before its execution; a crash or an error therefore does not reserve the first
place indefinitely. The `work_lease` lease and the exponential backoff
`retry_base` to `retry_max` use the SQL clock. Acknowledgment and resumption
refuse an expired or replaced lease. This coordination lease replaces neither
the delivery lease nor the barriers that neutralize delayed effects.

The dispatcher prepares the recipient under exclusive admission before
consuming a delivery attempt: wake, capacity, certificates and channel health.
It may remove another VMM to free a slot. The control callback must finish its
local SQL transaction without waiting for a platform call. The guest's outgoing
tasks are asynchronous. The host registry v2 uses a common queue for shared and
exclusive calls; only consecutive readers at the head coexist. Migration from v1
keeps the barriers present; stop the old workers before upgrading, as they
cannot read v2.

This first coordination assumes that all manifest stores are on the same host.
It does not prove a real delay or the success of each request: an expiration or
a final failure is possible, and a notification can also exhaust its attempts.
Eviction can interrupt the guest's computation; the SQLite intent survives, but
its general wake and a sufficient residence time are not yet guaranteed. The
FIFO model checks a three-client component, under weak fairness and callback
termination, not the refinement of the Go service.

To deliver owner instructions and keep their encrypted results, add to the
worker configuration file:

```json
"transit": {
  "active_key": "v1",
  "keys": {"v1": "/private/path/transit-v1.key"}
}
```

These private 32-byte files must match the keys explicitly activated with
`agentcapsule-admin activate-transit-keys` and provided to the API. The worker
refuses an unknown or replaced key or a stale active identifier; its startup
activates no key. During a rotation, also provide all the keys needed for the
contents still retained. Each pass purges at most
`min(dispatch_batch * 4, 1000)` expired contents.

The instruction shares the events FIFO. Boot preparation precedes the
consumption of an attempt; the first authorized send creates a stable mandate.
The encrypted result, the success of the operation and the removal of the queue
head are committed together. An old attempt can no longer publish its result.
Abandoning waits for a durable barrier, revokes the mandate and keeps the
uncertainty about an effect whose result was never acknowledged.

To publish the organizations' agents to the private Directory and answer the
agents' searches (INT-02, [deploy/interop](../deploy/interop)), add:

```json
"directory": {
  "address": "127.0.0.1:8443",
  "ca": "/etc/agentcapsule/interop/control-plane/directory-ca.pem",
  "cert": "/etc/agentcapsule/interop/control-plane/directory.crt",
  "key": "/etc/agentcapsule/interop/control-plane/directory.key",
  "publish_interval": "5s"
}
```

The address is the Directory's mutual-TLS edge; the key must be private to the
worker. The worker then runs the publisher (one claim of up to 16 agents per
interval, at once again while work remains, leases of one minute, backoff from 5
seconds to 5 minutes while the Directory is unreachable) and serves
`/v1/directory/find` on the platform channel. Without this section, searches
answer `unavailable` and nothing is published; descriptions are still kept.
See [Directory publication](api/agents-assignments.md#directory-publication-int-02).

To carry deliveries between agents over SLIM (INT-04), run the SLIM bridge
([runtime/slimbridge](../runtime/slimbridge), see
[docs/interop.md](interop.md#the-slim-bridge-int-04)) under its own user, with
the units of [deploy/systemd](../deploy/systemd)
([Running on a host](interop.md#running-on-a-host)), and add:

```json
"slim": {
  "bridge_socket": "/run/agentcapsule-slim/bridge.sock",
  "worker_socket": "/run/agentcapsule-worker/slim.sock",
  "bridge_uid": 990
}
```

`bridge_uid` is the bridge's user (`id -u agentcapsule-slim`). The two
directories come from `agentcapsule-slim.tmpfiles`. The worker's directory
belongs to root, so the bridge can reach the worker's socket but cannot remove
or replace it.

The worker creates `worker_socket` for the bridge's user (mode 0600) and checks
the peer's user on every connection, in both directions; `bridge_uid` cannot be
root. Requests, replies and status events between agents then cross the bridge
and the SLIM node before reaching the recipient's VM over vsock; owner
instructions do not. Once the recipient's VM is ready and before an attempt is
spent, the worker asks the bridge to answer on the recipient's SLIM name: while
the bridge or the node is away, deliveries wait with backoff and spend no
attempt. Without this section, deliveries go straight to the VM.

Harness calls now transmit structured private contents (`payload.content`)
rather than references chosen by the client. When transit is configured, the
worker itself encrypts the request/response before the commit and refuses
references supplied by the client. Delivery decryption requires the current
lease, the dispatch authorization and the parties that are still active. The
outgoing channel is used in the background by the harness, after the commit of
the SQLite intent: no platform call blocks the callback that must first return
its delivery acknowledgment.

## Deleting a product volume

After all distributed barriers, the worker seals execution on the host: no new
boot, no remaining VMM and the file identity verified. With product
provisioning configured, it then revokes the key in the local authority, then
removes the single provisioned inode. A permanent journal keeps the
`REMOVING/REMOVED` steps; it forbids reformatting or recreating this identity
after an interruption. A replaced file, an extra link or a busy lock makes the
operation fail. The registries, tombstones and reserved UIDs are kept.

The final SQL receipt publishes `DELETED` and the `SUCCEEDED` operation
together. A crash between the physical removal and this receipt leaves a
resumable operation; a simple seal keeps `CLEANUP_PENDING`. The next barrier
acknowledgments on this agent re-check the absence of the file and the permanent
seal. Older hosts with manually supplied volumes and without a
provisioner/key authority attest only the execution seal.

These operations apply to the volume and key managed by this installation. They
do not destroy external copies, backups or the raw blocks of the medium.
Rollback-resistant restore remains the D5 workstream. The local journal/crash
and SQL publication tests run; the deletion scenario in a real VM is compiled
and remains to be run under KVM.

## Cold encrypted archive capture

The operator can capture an agent on demand with the same worker configuration
and the same protected PostgreSQL environment. This mode requires product
provisioning and both independent authorities. First stop the existing
maintenance worker so that it releases its listeners; its VMs may stay present
and will be reconciled by this command. Restart maintenance after the capture.
The targeted agent stays stopped on exit and can be woken through the usual
paths.

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -archive-agent "$AGENT_ID" \
  -archive-id arc_0123456789abcdef0123456789abcdef \
  -archive-root /var/lib/agentcapsule-archives
```

Choose a new `arc_` identifier followed by 32 lowercase hexadecimal digits for
each new backup point. Reuse exactly that identifier after a lost response: an
already published archive is verified and returned, never replaced by a more
recent state. The identifier above is an example. A failure after quiescence has
started can leave the agent stopped.

The command waits for the authenticated quiescence, physically removes the VMM
and checks the SQL observation of a clean stop. A forced or uncertain stop is
refused for capture; restore a startup followed by a clean stop before retrying.
It checks the registered inode and its exclusive lock, copies the encrypted LUKS
container, then atomically publishes `volume.luks` and `manifest.json` in a
directory named after the archive ID. The output manifest binds the authority,
the agent, the volume, the source incarnation, the release, the size and the
digest of the captured bytes.

The directory must be private and located outside the runtime and both
authorities. No decryption key is copied into the archive. The files and the
manifest are verified on read; a signature never exempts you from inspecting the
recovered data or from respecting the restore barriers.

This local storage provides an encrypted source for the future restore. It is
not an off-VPS backup, a retention policy, a restore test on a second host or a
proof of erasure of all key copies. The command brings back no backup as an
active VM. The restricted coordinator, the history inspection/repair and the
tenant rules of the product spec ([product.md](product.md)) remain to be wired
before declaring this restore operational.
