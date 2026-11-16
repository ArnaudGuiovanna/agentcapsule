# D-05 — The authority service

Date: November 16, 2026. **Status: accepted by the product owner on November
16, 2026** (see [Questions](#questions-for-the-product-owner)); waves 1 to 6
are built ([Implementation status](#implementation-status)). This record designs
item 3 of [ADR 005 §5](005-keys-outside-restored-domain.md#5-what-changes-in-code-and-docs)
and item 5 of its [What the code must do](005-keys-outside-restored-domain.md#what-the-code-must-do).
It changes no decision of ADR 005. It is a record of its own, not a section
of ADR 005: that one holds the decision and the model, this one designs one
component, with its own options and questions. The product owner's answers
are at the [end](#questions-for-the-product-owner). References: ADR 005,
[ADR 004](004-recovery-objectives.md), the model
[restore_authority.qnt](../../spec/restore_authority.qnt), D-05 of the
[roadmap](../../ROADMAP.md).

## Context

Today the worker opens both authority directories in its own process
(`OpenVolumeKeys`, `OpenRestoreAuthority` and `replicate` in
`internal/worker/service_config_linux.go`). That process also holds the link
to the replica, runs degraded mode and the barrier that keeps every
transaction behind the replica (`admit`,
`internal/restoreauthority/degraded_linux.go`), and exports the replication
metrics. On the standby, `agentcapsule-authority serve` holds the replica.

This has three limits.

1. **Only the worker reaches the authorities.** The next waves need the API
   and `agentcapsule-admin` too. An access revocation appends a record before
   its PostgreSQL commit, and the API confirms it only once the replica
   holds it (items 6 to 8). The API takes the daily receipt key from the
   authorities. It refuses to open until PostgreSQL is reconciled for the
   current epoch (item 15). The API runs as an unprivileged account. It
   cannot open directories that belong to root, and must not.
2. **Nothing makes one process the owner.** The maintenance worker, the
   archive and restore commands (`-archive-agent`, `-restore-agent`) and
   `agentcapsule-authority snapshot` each open the directories. Only the docs
   ask the operator to stop the maintenance worker first. Each process keeps
   its own view of the replica and of degraded mode.
3. **The view of the replica dies with the worker.** Restarting the worker
   for any reason throws away what the authorities knew about the replica.
   Then nothing runs until the standby answers (finding 2).

## Decision

- **One process per host owns both authorities**: `agentcapsule-authority
  serve`. On the primary it is the writer, on the standby the replica. Its
  configuration says which. It is not a worker mode.
- It runs as the account `agentcapsule-authority`, which owns both
  directories. It holds the link to the standby, runs degraded mode, the
  barrier and the replication metrics. Nothing else opens the directories
  while it runs.
- It serves two local sockets. The **worker socket** admits root. The **API
  socket** admits the API's account and root. The socket gives the role; the
  peer's credentials (`SO_PEERCRED`) are checked on every connection.
- The wire format is the replication link's: one JSON object behind a 4-byte
  length (`internal/authoritylog/transport.go`). No new dependency.
- Each callback of today becomes a **hold**: the service runs today's
  function, and its callback waits on the connection until the client
  releases it, the connection ends, or the hold's cap passes.
- Volume keys reach the worker as 32 raw bytes on the worker socket, never
  inside JSON.
- The service checks the seal before it destroys a key (item 5).
- The worker's in-process authorities leave production, small installs
  without a standby included. They stay as the test double. Standalone mode,
  without a standby, stays the default.
- An upgrade or a crash of the service pauses the host's authority
  operations for a few seconds; there is no hitless handover.
- An access revocation fails while the service is down: nothing is committed
  in PostgreSQL before its record.
- If the standby is unreachable when a day's receipt key is due, the service
  creates it on the primary alone.

## 1. The process

**A subcommand, not a worker mode.** `agentcapsule-authority` already holds
the replica and the commands that prepare and promote it. The service runs:

- unprivileged. The worker runs as root because of the jailer. The
  authorities need no privilege, and the API must reach them without any;
- independently of the worker. A worker restart must not reset the
  authorities' view of the replica. The API needs the authorities even while
  no worker runs;
- under the same name and account on both hosts. After a promotion, the
  standby's service changes role by configuration.

**The roles.** A configuration of version 1 is the replica, as today. Version
2 names the role:

| Role | Opens | Serves | Links |
| --- | --- | --- | --- |
| `primary` | The key authority and the restore authority | The worker socket and the API socket | To the standby, when `authority_replica` is set; standalone without it |
| `replica` | The replica's directory | The replication listener (TCP, mutual TLS), as today | From the primary |

**What runs in the service, primary role.** Everything that today runs in the
worker's process on behalf of the authorities: the `restoreauthority.Catalog`
and the `keyauthority.Files` it journals, the replicator, the monitor that
keeps reaching the standby, the barrier (`admit`), degraded mode, and the
replication metrics. The worker and the API run none of it. They see degraded
mode only through errors (`ErrWaitsForReplica`) and the `status` operation.

**One owner.** At start, the service takes an exclusive lock (`flock`) on a
lock file in each authority directory, and keeps it while it runs. Every
command that opens a directory takes the same lock and refuses with
`authority_in_use` while it is held: `snapshot`, `promote`, `init-replica`,
`agentcapsule-admin init-key-authority` and `init-restore-authority`. The
lock is taken by the commands, not by `restoreauthority.Open`: the package
tests open two handles in one process to stand for two processes.

The lock file is `owner.lock`. In the replica role, the service holds the
lock of the replica's directory, so `promote` and `init-replica` refuse
while it runs: [recovery.md](../recovery.md#promote-the-replica) already
asks to stop it before a promotion. `promote` takes the locks of the
replica's directory and of its two targets. A directory that does not exist
has no lock to take: nothing runs on it, and the lock does not create it.

**The account.** The directories, the catalogue file and the key files belong
to `agentcapsule-authority` (the existing checks compare them with the
process's UID). No other account could read them before either, and root
still can. What changes: the process that holds the keys has no privilege,
and the API reaches the authorities only through its socket's operations.

## 2. The sockets

### Roles

| Operation | Worker socket | API socket | Wave |
| --- | --- | --- | --- |
| `status`: identities, roots, epoch, mode (`standalone`, `synchronous`, `degraded`, `waiting`), start of degraded mode, protocol | yes | yes | 1 |
| Bindings: `lookup`, `check_binding`, `hold_binding` | yes | no | 1 |
| Volume keys: `ensure_key`, `hold_key`, `destroy_key` | yes | no | 1 |
| Catalogue: `register`, `reserve_incarnation`, `begin_revocation`, `scan`, `record_fence`, `hold_fences`, `subject_barrier`, `hold_revocation`, `record_outcome`, `record_rerun`, `record_seal`, `losses`, `outcome_status`, `sign_archive`, `validate_archive` | yes | no | 1 |
| Activation: `recorded_outcomes`, `declare_losses`, `hold_activation` | yes | no | 1 |
| Access revocation records: `append_access`, `on_replica` | yes | yes | 5 |
| Daily receipt key: `receipt_key` | no | yes | 6 |
| Reconciliation and announcement: export of access records, subjects, seals and stores; import of PostgreSQL's own revocations; `announcement` | no | yes | 7 |

The worker socket admits UID 0 only. The API socket admits the configured
`api_uid` and UID 0. `agentcapsule-admin` uses the API socket when it runs as
the API's account, and either socket as root. Root can read the directories
anyway: the roles protect against the API's account, not against root.

**Files.** The directory `/run/agentcapsule-authority` belongs to
`agentcapsule-authority`, with the group `agentcapsule-authority-clients`,
mode 2750 (systemd-tmpfiles). The set-group-ID bit gives that group to the
sockets the service creates. `worker.sock` is mode 0600: only root reaches it.
`api.sock` is mode 0660: the API's account joins
`agentcapsule-authority-clients`. The peer check runs at each accept, as
`slimlink.Listen` does (`internal/slimlink/peer_linux.go`). A refused peer is
closed and counted.

### Wire format

- A stream socket. Each frame is a JSON object behind a 4-byte big-endian
  length, as on the replication link. The decoder refuses unknown fields.
- **Hello.** The first frame of a connection names the protocol version, the
  role, and the two identities the client pins. The service checks the role
  against the socket and the identities against its own, then answers with
  `status`. A mismatch closes the connection: a worker never talks to another
  installation's authorities. `status` reads no database, so a hold never
  delays a hello: the epoch is read at start (only a promotion changes it,
  and a promotion builds another catalogue), and the mode is in memory.
- **One request at a time** per connection: `{"op": …, "timeout_ms": …,
  "args": {…}}`, then one response: `{"result": {…}}` or `{"error": "<code>"}`.
  The client keeps a small pool of connections. A hold takes one out of the
  pool for its duration.
- **The deadline travels.** `timeout_ms` becomes the operation's context in
  the service, so a wait at the barrier ends at the caller's deadline, and
  `ErrWaitsForReplica` and `_degraded_refused_total` keep their meaning. A
  timeout is at most 10 minutes; a client without a deadline sends that one.
  The client waits one second past its deadline for the service's answer,
  which says why the operation ended.
- **Errors** are a closed vocabulary: `input`, `unavailable`, `conflict`,
  `stale`, `revoked`, `sealed`, `history`, `not_declared`, `not_sealed`,
  `waits_for_replica`, `replica_required`, `not_armed`, `diverged`, the key
  authority's `key_unavailable`, `key_revoked`, `key_conflict`,
  `key_input`, and `hold_expired`, `role`, `protocol`, `identity`. The
  client turns each back into the same sentinel error as today
  (`restoreauthority.ErrStale`, …), so
  every `errors.Is` in the worker keeps working: `RestoreFailure`,
  `archiveRetryReason`, `platformError` and the adoption's split between a
  stale binding and an outage (`internal/worker/placements_linux.go:143`). A
  connection that fails, or ends, is `unavailable`: an outage, never a stale
  binding. For the same reason, an error that carries `ErrUnavailable` is
  sent as `unavailable` (or the more precise `waits_for_replica`,
  `replica_required`, `diverged`) even when it also carries a refusal. On
  the client's side, `hold_expired`, `role`, `protocol` and `identity` are
  also `ErrUnavailable`.
- **A key** follows its `held` frame as exactly 32 raw bytes. The client
  reads them with `io.ReadFull` into a buffer it owns and clears at release.
  No key ever goes through `encoding/json`, which would leave base64 copies
  that cannot be cleared.
- **Versions.** The service accepts its protocol version and the previous
  one. A client refuses a service older than it needs.

## 3. Callbacks across the boundary

### The hold

A hold is today's callback, run in the service. The service calls the same
function as today, with a callback that:

1. sends `held` to the client, and for a key its 32 bytes;
2. waits for `release`, for the end of the connection, or for the cap;
3. returns.

While it waits, what held in the worker's process now holds in the service:
the catalogue's write transaction (`BEGIN IMMEDIATE` on its single SQLite
connection), and for a key the shared lock on the key's lock file. So the
exclusions are exactly today's. Holds need no change in the authority
packages: no new lock, no new state.

The client runs its own callback with a **hold context**. It is canceled when
the connection ends, and 5 seconds before the hold's end (a fifth of a hold
shorter than 25 seconds). The hold's end is the shorter of the request's
deadline and the cap; the `held` frame gives it (`hold_ms`). The worker's
publish runs in it, so a client that loses its hold stops its PostgreSQL
transaction. The
callbacks of the worker's interface therefore take a context
(`func(context.Context) error`). When the callback returns, the client sends
`release` and waits for `released`. Only then does the operation succeed. A
callback that failed sends `release` too; no hold writes anything in the
root, so the outcome is the same. A hold that ended before its callback
returned fails as an outage, even when the callback succeeded: the
exclusion did not cover all of it.

Rules:

- **The end of the connection releases the hold.** Today the end of the
  worker's process releases the transaction and the lock the same way.
- **Caps.** A hold that covers a PostgreSQL publish lasts at most 30
  seconds. A hold that covers a key in use (a boot's unlock, the formatting of
  a new volume) lasts at most `max_key_hold`: 2 minutes by default, from 30
  seconds to 10 minutes. The client asks for the shorter of its deadline and
  the cap. At the cap the service ends the hold, closes the connection and
  counts it.
- **The quiet period.** A restarted service cannot know which holds its
  previous process granted, nor whether their publishes are still running.
  So, after it starts, a write that a hold excludes waits for the cap of the
  holds it conflicts with: a new revocation subject waits 30 seconds;
  reservations, seals and key destruction wait `max_key_hold`. Only a call
  that would write waits: a repeated `begin_revocation` of a known subject, or
  a repeated reservation with the same operation ID, answers at once.
  Everything else runs as soon as the service has reached the replica.
- **No re-entry.** A callback must not call the authorities, as today. The
  cap turns a mistake into a failure at the cap, not a hang.

### Each callback

| Today | Used by | Across the socket | What holds while it runs | The worker dies, or the socket drops | The service restarts | Model |
| --- | --- | --- | --- | --- | --- | --- |
| `WithBinding` with an empty callback (`catalog_linux.go:629`) | Deliveries (`authority_linux.go:37`), `ResolveIncarnation` (`placements_linux.go:131`), the capture of an archive (`archives_linux.go:71`) | `check_binding`: one request, no hold | Nothing after the answer, as today | Nothing held | The request fails as an outage; the caller retries | None: the gate was released at once already |
| `WithBinding` around PostgreSQL | Adoption (`placements_linux.go:141`), every platform call of a VM (`platform_linux.go:60`) | `hold_binding`: a publish hold | The catalogue's write transaction: no reservation, no seal (and, as today, no other write) | Released at the end of the connection; the publish is canceled if not sent | The client loses the hold and cancels its publish; reservations and seals wait the quiet period | An identity gate, not a model action. PostgreSQL moves first too: a restore marks the volume `RESTORING` before the reservation |
| `WithBinding` around `WithKey` (`files_linux.go:360`) | Formatting a new volume (`provisioning_linux.go:85`), unlocking it at boot (`volume_boot_linux.go:65`) | `hold_key`: one hold for both; the key follows `held` | The transaction, and the shared lock on the key: `destroy_key` waits | Released; the worker clears its buffer. A guest that received the key keeps it in dm-crypt: retiring it before destruction stays the worker's duty | The boot or the format fails and is retried; key destruction waits the quiet period | `destructionWaitsForAllCachedCopiesTest`, in part as today (`TestDestructionWaitsForAllCachedCopies`) |
| `WithCurrentFences` (`catalog_linux.go:837`) | Confirming a boot (`volume_boot_linux.go:146`), activating a new agent (`provisioning_linux.go:169`) | `hold_fences` | The transaction: no new revocation subject, no reservation | Released; the confirmation is retried with a new scan | New subjects wait 30 seconds | `activate` with `RECHECK`: `activationRechecksNewRevocationTest` (`TestPublicationSerializesConcurrentRevocation`) |
| `WithRevocation` (`catalog_linux.go:890`) | The completion of a revocation (`authority_linux.go:125`), publish from `internal/controlplane` | `hold_revocation`. Its kind, `revocation_done`, still waits for the replica in degraded mode | The transaction: no reservation of a target | Released; the barrier runs again | Reservations wait the quiet period | `finishRevocation`; `subjectRevocationCompletesAfterResyncTest` |
| `Activate` with `Inspect`, `Repair` and `Publish` (`losses_linux.go:70`, `WithActivation` at `catalog_linux.go:955`) | Restoring an agent (`restore_linux.go:427`) | Three steps, below | Only the last step holds | Each step can be repeated; the restore resumes | The restore command waits for the service, then resumes | `declareLoss`, `activate`; see below |
| `WithSubjectKey` (`catalog_linux.go:988`) | Nothing outside the package's tests | Not exposed. A future caller gets a hold like `hold_binding` | — | — | — | `revokedSubjectCannotAcquireNewKeyTest` stays in the package (`TestSubjectKeyGateUsesIndependentIntent`) |
| The journal (`Catalog.Append`, used by `Ensure` and `Revoke`) | Key creation and destruction | Inside the service only: `ensure_key`, `destroy_key` | — | — | — | Unchanged |

`hold_key` names the key's agent, volume and incarnation: it holds the
binding {agent, volume, incarnation} around the key, as the worker binds an
agent's store to the agent's ID. Without an incarnation it is refused
(`input`, since wave 2): a key held alone would keep its lock without the
catalogue's transaction, and an armed destruction would then wait for it
inside that transaction, with every catalogue operation behind it.

**The activation.** Today `Inspect` asks the guest which outcomes its image
holds, inside a catalogue transaction, up to three times: before the repair,
when declaring losses, and at the activation. Across the socket, the
inspection runs in the worker, outside any hold:

1. `recorded_outcomes(receipt)`: the outcomes the authority recorded for the
   store, and a digest of that list. Pages of 1000 outcomes; the client
   checks the whole list against the digest.
2. The worker inspects the guest, then calls the repair, as today.
3. `declare_losses(receipt, digest, missing)`: the service runs today's
   `declareLosses`, with an inspection that checks the digest against the
   list in its transaction and returns the worker's `missing`.
4. `hold_activation(receipt, digest, missing)`: the same, through
   `WithActivation`. The worker publishes in PostgreSQL, then releases.

A changed list is `stale`, and the worker starts again at step 1, at most
three times. This is
equivalent to today. The image boots restricted, with no delivery and no
writer, so what it holds cannot change between the inspection and the
step. In the model, a store in `Reconciling` has no writer (`canBeginEffect`
needs `Ready`). The service still refuses an ID it never recorded for the
store (`missingOutcomes`), so `lossesNameAcknowledgedWork` and the history
guard (`accounted`) hold as before.

### What a lost hold can do

Today the lock lasts until the callback returns, or until the worker's
process dies. A dead process sends no more SQL. Only a `COMMIT` already sent to
PostgreSQL can land after the authority's lock is gone, a few milliseconds
later. The same window exists when a caller's context ends during its
publish.

With the service, a dead worker behaves the same. A dead service is new: the
worker lives on. The hold context cancels the publish, and the quiet period
keeps the excluded writes away until every earlier hold has reached its cap.
What remains is a worker paused for longer than the quiet period between its
last check and its `COMMIT`. Then a publish could land after a write it
should have preceded. For each hold, what still protects:

- **Fences and activation.** A store would be published without the newest
  revocation subject. The revocation cannot complete without it: its barrier
  finds the store's acknowledged revision behind and fences it first
  (`CommitBarrier`). In steady state PostgreSQL refuses the publish too; for
  example `ActivateProvisionedAgent` checks `revocation_catalogue`
  (`internal/controlplane/provisioning.go:463`): PostgreSQL records each
  subject before the authority does. In the model's terms this breaks
  `activationCurrent`; the completion still waits for the fence, which is
  what `noStaleEffect` needs.
- **Bindings.** PostgreSQL marks the volume `RESTORING`, or the agent
  `QUIESCING`, before the authority's reservation or seal, and the host
  retires or seals the VM under its barrier first.
- **Revocations.** A target restored meanwhile is fenced with every subject
  before its activation (`synchronizeAuthority`).

The root's hold is the guard that does not depend on PostgreSQL being
current, which matters after a failover. The window is the same class as
today's crash window, made longer only by a pause beyond the quiet period.

### How keys reach the worker

**Bytes over the worker socket.** The worker needs the key in its memory
anyway. At boot it sends the key to the guest over the per-boot mutual-TLS
control channel (`capsuleprotocol.Client.OpenVolume`), and it formats new
volumes with libcryptsetup on the host (`volumestore.Prepare`). The socket is
local and admits root only.

Consequences:

- The key is in the service's memory and the worker's, during the hold only.
  Both clear their buffers. The kernel's socket buffer is freed once read.
- The service's unit disables core dumps. The service never logs or exports a
  key.
- Volume keys stay in clear on the primary's disk, as today, now owned by
  `agentcapsule-authority` instead of root.

Rejected:

- **A file descriptor (`memfd`, passed with `SCM_RIGHTS`).** The worker must
  read the bytes to send them over TLS or to libcryptsetup. A descriptor adds
  code and no protection.
- **The service opens LUKS itself.** At boot the guest opens the volume, not
  the host. The service would need the per-boot credentials of every VM and
  access to the runtime root, so root. That undoes the separation.

### Key destruction checks the seal

`destroy_key(binding)` refuses unless the restore authority holds the store
sealed with that volume. A seal is permanent, so checking it and then
destroying needs no transaction across both authorities. Armed, the
destruction's record already goes through the catalogue's transaction
(`Catalog.Append`), and the check runs in it. This completes
`destructionRequiresPermanentSealTest`, which ADR 005 projects only in part
because `keyauthority.Revoke` takes no seal (`TestDestructionRequiresPermanentSeal`,
`internal/restoreauthority/key_runs_test.go`). The worker's order (seal, then
destruction, `internal/worker/removals_linux.go`) stays; the service no
longer relies on it.

As built (wave 3):

- `destroy_key` names the binding {agent, volume, incarnation}, as
  `hold_key` does. Without the incarnation it is refused (`input`). A store
  the catalogue holds with that binding, but not sealed, is refused with
  `not_sealed`; another binding is `stale`. Both are refusals, not
  outages: the worker's deletion job retries.
- The interface's `DestroyKey(binding)` replaces the key authority's
  `Revoke(agent, volume)` for the worker. `Revoke` names no binding, so both
  implementations refuse it (`keyauthority.ErrInput`; the client sends
  nothing, as for a bare key hold).
- `restoreauthority.Local` checks the seal in a catalogue transaction, then
  destroys the key: the rule for a standalone authority, and the same in the
  test double and in the service. Armed, the key authority's journal names
  the change's agent and volume before it runs the write
  (`keyauthority.Journal`), and `Catalog.Append` checks the seal there,
  before the tombstone. So the key authority's own `Revoke` cannot destroy
  an unsealed store's key either, and the seal's record precedes the
  destruction's in the stream: a replica that holds the destruction holds
  the seal.

## 4. Restarts and upgrades

**The service restarts under a running worker.** Requests in flight fail as
outages. Holds are lost and their publishes canceled. Deliveries are not
acknowledged and retry with the same digest. Running VMs stay: adoption treats
an outage as an outage, never as a stale binding. Platform calls from VMs fail
with a retryable error until the service answers. The restarted service
reaches the replica before it runs anything, reads included (finding 2,
unchanged), then applies the quiet period. In standalone mode there is no
replica to reach. The restore command treats an outage of the service as a
pause: it waits for the service, then resumes, since every step of a restore
can be repeated. Today an authority error ends the command
(`restore_failed_authority`); a refusal still does.

**The worker restarts under a running service.** Its holds end with its
connections, as its process did. The service keeps its view of the replica:
degraded mode goes on, and a worker restart no longer forces a wait for the
standby. Finding 2 is about the process that owns the authorities: that is now
the service.

**Upgrades.**

- Upgrade the authority service before the worker and the API. It accepts the
  previous protocol version.
- Upgrade the standby's service before the primary's when a release adds a
  statement or a table to the stream. The replica refuses a statement it does
  not know (`conflict`), and that refusal stops the primary. The access
  revocation records (wave 5) are the first such release.
- A schema upgrade of the catalogue (`agentcapsule-admin
  init-restore-authority`) runs with the service stopped, as the service's
  account.
- Each upgrade restarts the service, with the pause of question 1, which
  the product owner accepted.

## 5. Modes

- **Standalone stays the default.** The service without `authority_replica`
  writes alone and gives no protection against the host's loss, as the worker
  does today. Armed authorities without the section refuse to start
  (`authority_replica_required`), as today, now from the service.
- **The in-process mode leaves production.** The worker no longer opens the
  directories. A worker configuration that still names their roots is refused
  (`authority_service_required`), so that no worker writes behind the
  service. Product installs, with provisioning or archives, need the service.
  The preprovisioned laboratory path without authorities does not change.
- **In tests it stays.** The worker depends on an interface,
  `restoreauthority.Authority`, as it depends on `keyauthority.Provider` for
  keys. `restoreauthority.Local`, the catalogue and the key authority opened
  in process, implements both; the client implements both over the socket.
  `*restoreauthority.Catalog` alone does not: the key hold needs both
  authorities, and today's `With*` functions keep their signatures. The
  interface's holds are named after their operations (`CheckBinding`,
  `HoldBinding`, `HoldKey`, `HoldFences`, `HoldRevocation`), the activation
  is `ActivateRestored`, and each callback takes the hold's context. The
  worker's tests run against both.

## 6. Installation

### Configuration

The service, primary role, `/etc/agentcapsule/authority.json`, owned by root,
not writable by others:

```json
{
  "version": 2,
  "role": "primary",
  "key_authority": { "root": "/var/lib/agentcapsule-key-authority", "identity": "keyauth_…" },
  "restore_authority": { "root": "/var/lib/agentcapsule-restore-authority", "identity": "restoreauth_…" },
  "worker_socket": "/run/agentcapsule-authority/worker.sock",
  "api_socket": "/run/agentcapsule-authority/api.sock",
  "api_uid": 990,
  "max_key_hold": "2m",
  "authority_replica": {
    "address": "standby.internal:7443",
    "certificate": "/etc/agentcapsule/authority-primary.crt",
    "key": "/etc/agentcapsule/authority-primary.key",
    "replica_certificate": "/etc/agentcapsule/authority-replica.crt",
    "degraded_after": "30s"
  },
  "metrics_listen": "127.0.0.1:9466"
}
```

`authority_replica` moves unchanged from the worker's configuration.
`api_uid` is required, and is not 0. The
replica role keeps today's file, with `"role": "replica"` in version 2. The
metrics port is the same on both hosts: one scrape job,
`agentcapsule-authority`.

The worker replaces `key_authority`, `restore_authority` and
`authority_replica` with:

```json
{
  "authority": {
    "socket": "/run/agentcapsule-authority/worker.sock",
    "restore_authority_id": "restoreauth_…",
    "key_authority_id": "keyauth_…"
  }
}
```

The worker checks its runtime and archive roots against the authorities'
roots, which `status` gives, with today's `CheckSeparation`. From wave 4, the
API takes `-authority-socket` and the same two identities.

### systemd

New files in `deploy/systemd`:

- `agentcapsule-authority.service`, the same on both hosts: `User=` and
  `Group=agentcapsule-authority`, `ExecStart=… serve -config
  /etc/agentcapsule/authority.json`, `Restart=always`, `RestartSec=1s`,
  `UMask=0077`, `LimitCORE=0`. The hardening of the SLIM bridge's unit, with
  `ReadWritePaths=` for the authority directories (the replica's on the
  standby) and `/run/agentcapsule-authority`. `IPAddressAllow=localhost`,
  and the other host's address in a drop-in.
- `agentcapsule-authority.sysusers`: the user `agentcapsule-authority` and the
  group `agentcapsule-authority-clients`.
- `agentcapsule-authority.tmpfiles`: `d /run/agentcapsule-authority 2750
  agentcapsule-authority agentcapsule-authority-clients`.

The worker's and the API's units get `Wants=` and `After=` on
`agentcapsule-authority.service`, not `Requires=`: a restart of the service
must not restart the worker. A worker that starts before the service answers
waits for it; it refuses to start only when the identities do not match.

### Migration of an existing install

1. Install the new binaries, the sysusers and tmpfiles files, and the unit.
2. Stop the worker, and any archive or restore command.
3. Give both authority directories to `agentcapsule-authority`
   (`chown -R`), and the link's private key `authority-primary.key` (mode
   0600). The old worker can no longer open them: their owner is not its UID.
4. Write `authority.json` from the worker's three sections. In `worker.json`,
   replace them with `authority`.
5. Start the service. Check `agentcapsule_authority_replication_enabled` and
   that `_acknowledged_sequence` follows `_committed_sequence`. Start the
   worker. Add the scrape job.

On the standby: rename `authority-replica.json` to `authority.json` and run
the shipped unit. Nothing else changes there.

Rollback until wave 5: stop both, give the directories back to root, restore
the old `worker.json` and binary. The service writes the same catalogue
format; wave 5 adds a table.

**After a promotion** ([recovery.md](../recovery.md#promote-the-replica)):
`promote` runs as `agentcapsule-authority`, so the promoted directories
belong to it and step 3 (giving the replica to root) disappears. The unlock
key file is owned by that account, mode 0600. Then the operator switches
`authority.json` to the primary role and restarts the unit. The quiet period
delays the first reservations by `max_key_hold`, a small part of the hour.

## 7. The next waves on this service

**Access revocation records** (items 6 to 8). `append_access(kind, IDs)`
commits the record in the service, then waits for the replica up to the
caller's deadline, and returns `{seq, on_replica, degraded}`. The record's
kind continues in degraded mode: the revocation takes effect on the primary at
once. The API commits in PostgreSQL once the record is committed, and
confirms it if `on_replica`, or if it is a bearer token's and `degraded`.
Otherwise it reports the revocation as pending, and learns later with
`on_replica`, which names the record by its ID (as built, wave 5). A record that the service did not commit fails the
request, and nothing is committed in PostgreSQL. So does a service that does
not answer: the API answers "try again in a moment" (question 2). The
model's acknowledged access revocation is the confirmed one: a pending one is
like any unacknowledged write. The projection must show that the API never confirms a
standing grant's revocation before the replica holds it
(`grantRevocationWaitsForReplicaTest`, `grantRevocationResumesAfterResyncTest`).

**The daily receipt key.** A key of the key authority bound to a day instead
of a volume, wrapped and replicated like a volume key, destroyed after 24
hours like one. The service creates the next day's key a day ahead.
`receipt_key(day)` gives the API today's and yesterday's keys; the API keeps
them in memory. If the standby does not hold the next day's key when it is
due, the service creates it on the primary alone (question 4, option (b)): the
creation of a receipt key continues in degraded mode, and the destruction of
the old key waits for the standby. As built (wave 6): `receipt_key(day)`
also gives tomorrow's key, for an API whose clock runs a little ahead, and
a day's key is destroyed an hour after its last receipt expired.

**The announcement and the reconciliation** (items 14 and 15). `promote`
writes the announced window and the blanket revocation of bearer tokens into
the promoted catalogue. `agentcapsule-admin reconcile`, as the API's account,
reads them and the access records, subjects, seals and stores through the API
socket. It writes PostgreSQL's own revocations into the authority, then
records in PostgreSQL that it reconciled the current epoch. The API compares
that epoch with `status` before it listens, and in its readiness probe
(`REPLAY_FIRST`).

None of these needs a hold. They need the API socket, `status`, and writes
that report whether the replica holds them.

## 8. The model

**No change for the service.** The model has one root and atomic steps. The
service keeps the root's code and its transactions as they are; a hold is the
same transaction, held in another process. The service also makes "one
writer of the root" true by construction, which today rests on the operator.

Two places differ from an atomic step, both argued above:

- the end of a hold before its publish commits: the same class as today's
  crash window. If reviewers want it in the model, a broken-guard witness can
  show which invariants a late publish breaks (expected: `activationCurrent`
  only);
- the activation's inspection outside the transaction: equivalent, because a
  restored image in `Reconciling` has no writer, and the service checks the
  recorded list's digest.

**Go projections.** `TestDestructionRequiresPermanentSeal` is full since
wave 3. The runs of the reconciliation (`reconciliationReplaysRootTest`,
`shippedGrantRevocationSurvivesTest`, `shippedDatabaseNeedsNoReportTest`,
`restoreWitnessEarlyOpenGuard`) and `tokenRevocationCoveredByBlanketTest` get
theirs in wave 7; `degradedOutcomeIsAnnouncedAsWindowTest` becomes full there.
The daily receipt key is outside the model: it protects old backups'
receipts, not the restore invariants.

## 9. Docs that change

Each wave updates its docs:

- [worker.md](../worker.md): the `authority` section replaces the three
  sections; "Replica of the authorities", "Degraded mode" and the metrics move
  to the service; a worker restart no longer touches degraded mode; the
  archive and restore commands still stop the maintenance worker, for its
  listeners only. Also its sentence saying that finding 1 awaits the product
  owner: it was decided on November 15.
- [key-authority.md](../guest/key-authority.md): the directory belongs to
  `agentcapsule-authority`; the worker borrows a key through a hold on the
  worker socket; destruction checks the seal.
- [recovery.md](../recovery.md): install the service on the primary; the
  snapshot stops the service instead of the worker; degraded mode says "do
  not restart the authority service"; the promotion without `chown` to root,
  then the switch to the primary role; the failover starts the service before
  the reconciliation and the API; "What is not built yet" loses the service.
- [observability.md](../observability.md): the endpoint table, the metric
  descriptions ("the authority service" instead of "the worker's
  authorities"), the hold metrics
  (`agentcapsule_authority_service_holds{kind}`,
  `_hold_expired_total{kind}`, `_refused_peers_total{socket}`), and a new
  alert `AgentCapsuleAuthorityServiceDown`
  (`up{job="agentcapsule-authority"} == 0` for 2 minutes, critical);
  `deploy/prometheus/prometheus.yml`, `alerts.yml` and `alerts_test.yml`.
- [ADR 005](005-keys-outside-restored-domain.md): its implementation status,
  and the projection table for item 5.
- [ROADMAP.md](../../ROADMAP.md): the D-05 row, at each wave.
- [api/README.md](../api/README.md), from wave 4: the API's socket, account
  and identities.

## 10. Waves

Each wave lists tests that fail without it.

**Wave 1 — the service and its protocol**, used by tests only: the primary
role of `serve`, `internal/authorityservice` (the server) and
`internal/authorityclient` (the client, implementing
`restoreauthority.Authority` and `keyauthority.Provider`).

- `TestServiceOwnsTheAuthoritiesAlone`: `snapshot`, `promote` and a second
  `serve` refuse with `authority_in_use` while the service runs. Today
  nothing stops a second process.
- `TestSocketRoleFollowsPeerCredentials`: the API socket refuses a worker
  operation; a peer of another UID is closed at accept.
- `TestHelloRefusesAnotherInstallation`.
- `TestBindingHoldSerializesReservation` and
  `TestFencesHoldSerializesRevocation`: today's
  `TestBindingGateSerializesReservationAndNeverEnrolls` and
  `TestPublicationSerializesConcurrentRevocation`, across two connections.
- `TestKeyHoldDelaysDestructionAndClearsTheKey`:
  `destructionWaitsForAllCachedCopiesTest` across the socket.
- `TestKilledHolderReleasesItsHold`: a child process holding a key is killed
  (`SIGKILL`); the destruction proceeds.
- `TestLostHoldCancelsThePublish`: the service stops during a hold; the
  callback's context ends before its commit.
- `TestHoldEndsAtItsCap`.
- `TestRestartedServiceWaitsTheQuietPeriod`: a new subject, a reservation, a
  seal and a destruction wait; an outcome, a fence and a known subject do
  not.
- `TestRestartedServiceRunsNothingUntilItReachesTheReplica`: finding 2,
  across the socket.
- `TestActivationRefusesAChangedRecordedList`, and the projections of
  `undeclaredLossPreventsActivationTest` and `declaredLossAllowsActivationTest`
  (`TestUndeclaredLossPreventsActivation`, `TestDeclaredLossAllowsActivation`)
  through the client.
- `TestEveryErrorKeepsItsSentinel`.

**Wave 2 — the worker on the service.** The worker's interface, its
`authority` section, the refusal of the old sections, the units, the metrics
and alerts, the migration and the docs.

- The worker's authority tests (`authority_test.go`,
  `authority_barriers_test.go`, `authority_outcomes_test.go`,
  `volume_boot_test.go`, `restore_test.go`) run against both
  implementations.
- `TestWorkerRefusesTheOldAuthoritySections`.
- `TestWorkerKeepsItsVMsWhileTheServiceIsDown`: the outage case of
  `TestBootAuthorityAdoptionDistinguishesStaleFromOutage`, with the service
  stopped.
- `TestWorkerRestartKeepsDegradedMode`.
- `TestAuthorityReplicaConfiguration` and `TestWorkerRunsOnPromotedAuthorities`
  move to the service.
- `promtool test rules` on the new alert.
- On KVM: the worker's product tests through the service, including
  `TestProductWorkerRestoresAgentFromArchive` and the nightly archives.

**Wave 3 — destruction checks the seal** (item 5).
`TestDestructionRequiresPermanentSeal` refuses the destruction of an unsealed
store's key: before wave 3, `keyauthority.Revoke` took no seal.

The next waves of D-05 build on these:

- **Wave 4 — the API reaches the service**: its socket, `status`, the pinned
  identities, the readiness probe. `TestAPIRefusesAnotherInstallationsAuthority`.
- **Wave 5 — access revocation records** (items 6 to 8), a new catalogue table
  and statements. The projections of `grantRevocationWaitsForReplicaTest`
  and `grantRevocationResumesAfterResyncTest`; a standby without the new
  statements refuses the first record (upgrade order).
- **Wave 6 — the daily receipt key.** A receipt older than a day no longer
  decrypts; the key's destruction reaches the replica. Built: see the
  [Implementation status](#implementation-status).
- **Wave 7 — the announcement and the reconciliation** (items 14 and 15),
  with the runs of [§8](#8-the-model).

**Later, optional: holds per store.** In wave 1 a hold keeps the catalogue's
single write transaction, as today, so one agent's boot or platform call waits
for another's. Once one process owns the catalogue, a hold could take a lock
per store, and the revocation's revision a lock of its own. That changes which
operations exclude each other, so it needs its own argument against the model
and its own tests. It is not needed for D-05.

## Implementation status

November 16, 2026. **Wave 1 is built**, used by tests only: the worker and
the API still open the authorities in process, and no unit or production
configuration changed.

- `internal/authorityservice`: the server, the protocol, the owner lock,
  the link to the standby (`Link`, the worker's `replicate`, which stays
  in the worker until wave 2), and the service's metrics:
  `agentcapsule_authority_service_holds{kind}`, `_hold_expired_total{kind}`,
  `_refused_peers_total{socket}`, beside the replication metrics. They
  reach [observability.md](../observability.md) with wave 2.
- `internal/authorityclient`: the client, implementing
  `restoreauthority.Authority` and `keyauthority.Provider`.
- `restoreauthority.Authority`, `Activation` and `Local` (§5), and the
  reads the service needs: `RecordedOutcomes`, `DeclareLosses` (the
  declaration step of `Activate`), `KnownSubject` and `KnownReservation`
  (the quiet period), `ReplicationMode` (`status`), and `Root`. The holds
  changed nothing else in the authority packages.
- `agentcapsule-authority serve` reads the configuration of §6: version 1,
  or version 2 with `role`. The primary role runs the service, with the
  replication metrics on `metrics_listen`. Both roles, `snapshot`,
  `init-replica`, `promote` and `agentcapsule-admin`'s init commands take
  the owner lock (§1).
- Tests: those of wave 1 above, and `TestKeyBytesNeverTravelInJSON` (the
  stream between client and service, read frame by frame),
  `TestBothImplementationsAgree` (an agent's life through `Local` and
  through the client), `TestActivationRepairsBeforeItDeclares`,
  `TestServiceRunsDegradedMode` (degraded mode, `waits_for_replica` and the
  replication metrics through the socket), `TestServeConfigurationNamesItsRole`,
  `TestInitCommandsRefuseWhileTheServiceRuns`, `TestOwnerLockIsExclusive`.
  Each mechanism was disabled in turn, and its test failed.

Building it changed this record in five places, each time for the safer
variant: `Local` rather than `*Catalog` implements the interface (§5);
`key_input` joins the codes, and an outage is sent as one even when it also
carries a refusal (§2); the hold context's margin for short holds, and a
lost hold is an outage even when its callback succeeded (§3); the replica
role holds the lock of its directory (§1); `status` reads no database (§2).
The model needs no change (§8).

November 16, 2026. **Wave 2 is built**: the worker on the service.

- The worker depends on `restoreauthority.Authority` and
  `keyauthority.Provider` only; `Authority` gains `SeparateFrom`, which
  checks a root against both directories (the client takes them from
  `status`). Its `authority` section (§6) gives the socket and the pinned
  identities. A worker configuration with `key_authority`,
  `restore_authority` or `authority_replica` is refused
  (`authority_service_required`). The worker waits for a service that does
  not answer, logging `authority_service_waiting` once, and refuses another
  installation's (`authority_identity_mismatch`). The worker's
  `OpenVolumeKeys`, `OpenRestoreAuthority` and its copy of the link
  (`replicate`) are gone; `TestWorkerNeverOpensTheAuthorities` checks that no
  worker code opens or initializes an authority directory.
- **A key is held under its binding only.** A bare key hold
  (`Provider.WithKey` across the socket) kept the key's lock without the
  catalogue's transaction: an armed destruction then waited for the key
  inside that transaction, and every catalogue operation behind it, up to
  `max_key_hold`. The service refuses `hold_key` without an incarnation
  (`input`), and the client's `WithKey` refuses without sending it
  (`TestServiceRefusesABareKeyHold`); so does the in-process `Local`
  (`TestBothImplementationsAgree`). The worker formats and unlocks volumes
  with `HoldKey`. §3 says so.
- The restore command pauses while the authorities are unavailable, logs
  `restore_paused` (`authority_unavailable`, `waits_for_replica`), and
  resumes from its last durable step; a refusal ends it (§4,
  `TestRestorePausesWhileTheServiceIsDown`). The archive command goes through
  the service too.
- `deploy/systemd`: the service's unit (exposure 1.1 under
  `systemd-analyze security`), its sysusers and tmpfiles files, and a drop-in
  for the worker's and the API's units (`Wants=`, `After=`). No unit of the
  worker or the API exists in the repository yet, so the `Before=` of the
  service's unit and the drop-in stand for §6's change to their units.
  `deploy/prometheus`: the `agentcapsule-authority` job on 9466 and
  `AgentCapsuleAuthorityServiceDown`, with its promtool test. Examples:
  `runtime/authority/primary.example.json` and `replica.example.json`.
- Docs (§9): worker.md, recovery.md (the install and the migration, the
  snapshot and the promotion as `agentcapsule-authority`, degraded mode),
  key-authority.md, observability.md, ADR 005's status.
- Tests: the worker's authority tests (`authority_test.go`,
  `authority_barriers_test.go`, `authority_outcomes_test.go`,
  `volume_boot_test.go`, `restore_test.go`) run against both
  implementations; `TestWorkerRefusesTheOldAuthoritySections`,
  `TestWorkerKeepsItsVMsWhileTheServiceIsDown`,
  `TestWorkerRestartKeepsDegradedMode`, `TestWorkerChecksItsRootsAgainstTheService`;
  `TestAuthorityReplicaConfiguration` and `TestWorkerRunsOnPromotedAuthorities`
  moved to `cmd/agentcapsule-authority`, on `openPrimary`. The KVM product
  tests reach the authorities through a service run in the test process,
  as root.

Not done in wave 2:
- The revocation's publish (`CommitBarrier`'s callback, from
  `internal/controlplane`) takes no context: a lost hold does not cancel it.
  The quiet period still keeps the excluded reservations away (§3, What a
  lost hold can do). Passing the hold's context needs a change to
  `controlplane.BarrierCommitter` and its four callers.
- The KVM product tests have not run through the service yet.
- The worker's preflight (ADR 010) checks the authorities through the
  service; the checks of the link to the standby (`authority_replica_tls`,
  `authority_replica`) left with the link and have no home yet: the service
  has no preflight.
- `scripts/verify-interop.py --systemd` does not check the service's unit;
  the same checks were run by hand.

November 16, 2026. **Wave 3 is built**: key destruction checks the seal
(§3, item 5 of ADR 005's [What the code must do](005-keys-outside-restored-domain.md#what-the-code-must-do)).

- `destroy_key` names the binding and refuses without its incarnation
  (`input`), before the seal (`not_sealed`, `restoreauthority.ErrNotSealed`)
  and under another binding (`stale`). The client's `DestroyKey` sends it;
  its `Revoke`, without a binding, refuses without sending, and so does
  `Local`'s.
- `Local.DestroyKey` checks the seal, then destroys the key. Armed,
  `Catalog.Append` checks it again in the transaction that records the
  destruction: `keyauthority.Journal.Append` now receives the change's
  agent and volume before the write, and a refusal there publishes no
  tombstone.
- The worker's removal records the seal, then calls `DestroyKey` with the
  same binding (`internal/worker/removals_linux.go`).
- Tests: `TestDestructionRequiresPermanentSeal`, now a full projection, in
  `internal/restoreauthority` (in process, standalone and armed; armed, the
  key authority's own `Revoke` is refused and nothing reaches the stream)
  and in `internal/authorityclient` (in process and through the service);
  `TestServiceRefusesADestructionWithoutASealedBinding` (the worker socket,
  frame by frame); `TestJournalRefusesADestructionBeforeItsTombstone`
  (`internal/keyauthority`). `TestBothImplementationsAgree` refuses the
  destruction before the seal in both implementations. Before the change,
  the service and `Local` destroyed an unsealed store's key, and so did an
  armed key authority. With the check removed from `Catalog.Append`, the
  armed projection fails; with it removed from `Local.DestroyKey`, the
  standalone one and both of `internal/authorityclient` fail.
- The authorities' tests that destroyed a key without a seal now seal the
  key's store first, as a deletion does.

Building it changed this record in one place: `not_sealed` joins the
error codes (§2). The protocol's version stays 1: no release carries waves
1 and 2. The model needs no change: `destroyKey` already requires the seal.

Not done in wave 3, and left to the key rotation and sealing policy
(ADR 018, being written):

- the model's `destroyKey` also requires the store's agent to be revoked
  (`root.revoked`); the code checks the seal only, which the worker records
  after the deletion's barrier;
- the daily receipt key of wave 6 has no store: its destruction will need
  its own operation, bound to its day (built in wave 6: the service
  destroys it, by its day, without a seal);
- a key registered but never sealed (an abandoned provisioning) cannot be
  destroyed until something seals its store.

November 16, 2026. **Wave 4 is built**: the API reaches the service.

- `agentcapsule-api` takes `-authority-socket`, `-restore-authority-id` and
  `-key-authority-id` (§6), all three or none (`configuration_required`).
  Production requires them (`authority_required_in_production`, answer
  3(a)). Development may run without them, and writes
  `development_mode_without_authority_service_never_use_in_production` on
  standard error at each start, after ADR 010's own warning.
- At start, before it opens the database, the API waits for a service that
  does not answer, logging `authority_service_waiting` once. It refuses
  another installation's authorities (`authority_identity_mismatch`), the
  worker's socket (`authority_socket_role_mismatch`) and an older protocol
  (`authority_protocol_unsupported`) at once.
- The readiness probe reports the service's mode:
  `{"status":"ready","authority":"synchronous"}`, or `standalone`,
  `degraded`, `waiting`. While the service does not answer with the pinned
  identities, it answers 503 `authority_unavailable`; it asks the service
  for at most 2 seconds. Degraded mode and the wait for the standby leave
  the API ready. Default pending the product owner (question 5).
- `-preflight` gains an `authority` check: the flags, the identities, the
  socket's role, a socket this account may not open (the group
  `agentcapsule-authority-clients`), and the mode.
- `internal/authorityclient.API` is the API socket's client. It offers
  `Status` and `Wait` only; waves 5 to 7 add their operations there. `Wait`
  is the worker's former loop, now shared (`worker.WaitForAuthority` uses
  it). A socket path must be clean and at most 100 bytes, as in the
  service's configuration.
- **The service reaches its standby at start.** Before, a service reached
  the replica only at its first operation. An idle primary then reported
  `waiting` with its standby up, and the API's readiness and the worker's
  preflight said so. With the standby down, it made no attempt, so
  `AgentCapsuleAuthorityReplicationStopped` did not fire. `LinkTo` now
  starts the catalogue's monitor (`Catalog.ReachReplica`). Until the replica
  answers, nothing runs and degraded mode cannot begin, as before (finding
  2). The model needs no change: it has no `waiting` state, and the
  monitor's exchange is the one an operation runs, earlier.
- `deploy/systemd`: the drop-in already ordered the API's unit after the
  service (`Wants=`, `After=`); the sysusers file now asks to add the API's
  account to `agentcapsule-authority-clients`.
- `scripts/verify-install.py` starts the service before the API, and shows
  the API's refusals and its readiness. `scripts/verify-failover.py` runs the
  authorities' replica on the standby, promotes it at the failover and
  starts the API on the promoted service, with the same identities.
- Docs: [api/README.md](../api/README.md#the-authority-service),
  [install.md](../install.md), [bootstrap.md](../bootstrap.md),
  [recovery.md](../recovery.md) (the failover starts the service before the
  API), [observability.md](../observability.md), `openapi/openapi.yaml`.
- Tests: `TestAPIRefusesAnotherInstallationsAuthority`,
  `TestAPIRequiresTheAuthorityServiceInProduction`,
  `TestAPIWaitsForTheAuthorityService`,
  `TestPreflightReachesTheAuthorityService` (`cmd/agentcapsule-api`);
  `TestReadinessReportsTheAuthorityService` and the authority service in
  `TestAPIBinariesBootstrapServeAndShutdown` (`internal/api`, PostgreSQL);
  `TestAPIClientReachesTheAPISocketOnly`, `TestAPIClientWaitsForTheService`,
  `TestServiceReachesItsReplicaWithoutAnOperation`, and the API's view of
  degraded and waiting modes in `TestServiceRunsDegradedMode` and
  `TestRestartedServiceRunsNothingUntilItReachesTheReplica`
  (`internal/authorityclient`). Each failed before its change.

Building it changed one behaviour of wave 1, for the safer variant: the
service reaches its standby at start (above), not at its first operation.
§1's monitor now also runs from the start.

Not done in wave 4:
- The API's own unit does not exist in the repository yet: the drop-in
  stands for its ordering, as in wave 2.
- In `verify-install.py` the service runs in a user namespace where the
  run's account is root, so it sees the API as root, which the API socket
  admits too: that run does not show the admission of `api_uid`. The Go
  tests do (`TestSocketRoleFollowsPeerCredentials`).
- The API builds with cgo now: `internal/authorityclient` needs it, as the
  worker does. The release already builds the API with cgo.

November 16, 2026. **Wave 5 is built**: the access revocation records (§7;
ADR 005, "What the code must do", items 6 to 8).

- **The records.** The catalogue's schema version 4 adds
  `access_revocations` and `outcome_events`, and the stream two statements
  of kind `access` and `outcome`. A record holds its ID (`arv_…`, the
  caller's), its kind, the organization, the revoked objects (each named by
  the parts of its identity, [api/README.md](../api/README.md#revocations-pending-and-confirmed)),
  its time, and the epoch and sequence number of the stream's record that
  carried it: what the reconciliation of wave 7 replays. Triggers refuse to
  change or delete one. The kind `access` continues in degraded mode. The
  kinds are a closed vocabulary (`authoritylog.AccessKinds`): four bearer
  tokens' (`api_token`, `service_token`, `platform_credential`,
  `delegated_token`) and nine standing grants' (`member`, `principal`,
  `organization`, `team`, `team_membership`, `assignment`, `mandate`,
  `delegation_trust`, `llm_provider`).
- **The operations**, on both sockets. `append_access` fails only when the
  record was not committed; once committed it always answers
  `{epoch, seq, on_replica, degraded}`, `on_replica` false when the wait for
  the replica ended first or the replica refused the record. Appending the
  same record again changes nothing; another record under its ID is
  `conflict`. Without a standby (standalone, or promoted before a new
  standby) `on_replica` is true: nothing more can be waited for, as the
  model acknowledges any write without a standby. `on_replica` takes the
  record's ID: a record of an older epoch, brought by a promotion, is on
  the replica, whatever its sequence number.
- **Every revoking transaction appends its record before its PostgreSQL
  commit**, in the transaction, after the rows it changes: members, the
  service tokens a member issued (also on a role change), technical
  accounts and their tokens, teams and team memberships, assignments
  (revoked, replaced or reassigned), LLM providers (disabled, or rotated:
  the previous generation), organizations, the legacy domain's API tokens,
  mandates, and in `agentcapsule-admin` the platform credentials and the
  delegation changes (`revoke-token`, `revoke-trust`, `rotate`,
  `retire-key`). One record per kind: a member's offboarding appends a
  `member` record and a `service_token` one. A transaction that revokes
  nothing new appends nothing. The API waits for the service at most 5
  seconds, within the request's 10.
- **The answers.** A record the service did not commit fails the request:
  503 `authority_unavailable`, `Retry-After: 5`, nothing committed, no
  answer stored for the key. Otherwise the answer's `revocations` gives each
  record's `state`, `confirmed` or `pending`, and PostgreSQL keeps it
  (migration 0040, `access_revocations`, rows only confirmed, never
  deleted). The API asks about pending ones every 5 seconds, and when one is
  read (`GET /v1/access-revocations/{id}`); a replay gives the current
  state. `agentcapsule_api_access_revocations_pending` and
  `_oldest_pending_seconds` count them.
- **`agentcapsule-admin`** takes the API's three flags for its revoking
  commands; in production it refuses them without
  (`authority_required_in_production`).
- **Upgrade order** (§4). A replica opened by this release gains the new
  tables. A replica of the previous release refuses the first record
  (`conflict`), and the refusal stops the primary until the standby is
  upgraded; the record stays committed on the primary, its revocation
  pending. The service refuses a catalogue older than version 4
  (`restore_authority_upgrade_required`): `init-restore-authority`
  upgrades it, with the service stopped.
- **Outcome records keep the event ID** (item 8): the worker records the
  mailbox's ID with each outcome, and a declared loss names it.
- Tests: `TestGrantRevocationWaitsForReplica` and
  `TestGrantRevocationResumesAfterResync` (`internal/api`, PostgreSQL and a
  real service with its replica and degraded mode: the projections of the
  two runs); `TestRevocationAppendsItsRecordBeforeItsCommit`,
  `TestRevocationTriesAgainWithoutTheAuthorityService`,
  `TestRevocationIsPendingUntilTheReplicaHoldsIt`, and `TestRBACMatrix`,
  which checks the kind every revoking route records; in
  `internal/restoreauthority` `TestAccessRecordsAreKeptForGood`,
  `TestAccessRecordReachesTheReplicaAndSurvivesThePromotion`,
  `TestAccessRecordContinuesInDegradedMode`,
  `TestAccessRecordWithinTheDelayFailsUncommitted`,
  `TestStandbyWithoutTheAccessStatementRefusesTheFirstRecord`,
  `TestOutcomeRecordKeepsTheEventID`, `TestVersionThreeUpgradesForAccessRecords`;
  `TestAccessRecordsThroughTheService` (`internal/authorityclient`);
  `TestRevokingCommandsAppendTheirRecord` (`cmd/agentcapsule-admin`); the
  admin's revocations through a real service in
  `TestOperatorBootstrapFromEmptyDatabase`,
  `TestDelegationOperatorCLIAndRealAPI` and
  `TestCredentialCLIListRevokeAndReplaceWithNewFile`. Each mechanism was
  disabled in turn, and its test failed.

Building it changed this record in three places, each for the safer or the
simpler variant: `on_replica` takes the record's ID, not its sequence
number (§7); `append_access` answers once the record is committed, even
when the replica refused it, so that a revocation that took effect is never
reported as failed; and the kinds add `team`, for a team disabled with its
memberships. The model needs no change: its acknowledged access revocation
is the API's confirmed one, and a standing grant's is confirmed only once
the replica holds it.

Not done in wave 5:
- The reconciliation that replays the records into PostgreSQL after a
  failover, and the announcement of the window of pending revocations
  (wave 7).
- **A write that waits for the standby holds the records back.** In
  degraded mode nothing runs behind a record that degraded mode does not let
  through and the replica lacks (the barrier of ADR 005, item 17): a
  registration, a seal or a key's creation committed just as the standby
  went away. Until the standby returns, every revocation then answers
  "try again". An access record depends on no such write, so it could pass
  it; that changes the barrier, and is left to the product owner
  (question 6).
- Not recorded, because ADR 005's list does not name them: a role lowered
  (only the service tokens it revokes are), an LLM alias disabled or its
  grant revoked, an agent's deletion (its revocation subject already is),
  and a mandate used up (question 7).
- The KVM product tests have not run with the event ID recorded.

November 16, 2026. **Wave 6 is built**: the daily receipt key (§7; ADR 005,
Decision of November 13 and answer 4(b) here).

- **The key.** The key authority keeps a day's receipt key as the key of a
  reserved binding: the agent `agt_000…0`, which no agent has, and a volume
  ID that names the day, `vol_` then 24 zeros then `YYYYMMDD` (UTC). So it
  is written, wrapped to the unlock key, replicated, carried by a snapshot,
  promoted and destroyed exactly as a volume key, with no new format on
  disk, in the stream or in the replica, and no schema change. Its writes
  have their own kinds, `receipt_key_create`, which continues in degraded
  mode, and `receipt_key_destroy`, which waits (`authoritylog/degraded.go`).
  Its destruction needs no seal: it has no store. The catalogue refuses to
  register the reserved agent, the worker's `ensure_key` refuses it, and
  the stream refuses it with a volume that names no day. A destroyed day's
  key is never created again: its tombstone stays.
- **`receipt_key(day)`**, on the API socket only (the worker's socket
  answers `role`): a frame, then the key's 32 raw bytes, as `hold_key`
  sends a volume key. By the service's clock it gives yesterday's, today's
  and tomorrow's keys, the last for an API whose clock runs ahead. Reading
  a key that exists waits for nothing, not even for a restarted service to
  reach its standby: it changes nothing. Today's key is created if it is
  missing; another day's never is. A day before yesterday, or yesterday's
  when the service does not hold it, is gone (`key_revoked`); a day after
  tomorrow is `key_input`.
- **The service tends the keys** every minute (`KeepReceiptKeys`, primary
  role): it creates today's key if missing, tomorrow's while the standby
  answers (not in degraded mode, nor while a restarted service waits for
  its standby), and destroys each day's key at 01:00 UTC two days after the
  day began: 24 hours after its last receipt expired, and an hour for the
  clocks of the API, PostgreSQL and the service. A step bounded at 30
  seconds that fails, or waits for the standby, is tried again at the next
  pass. Events `receipt_key_created`, `receipt_key_destroyed` (standard
  output) and `receipt_key_failed` (standard error); metrics
  `agentcapsule_authority_receipt_key_ready{day="today"|"tomorrow"}` and
  `agentcapsule_authority_receipt_keys_overdue`, with three alerts
  ([observability.md](../observability.md)).
- **The API** (`controlplane.Accounts.UseDailyReceiptKeys`, given the
  service's client) encrypts each new receipt, of both domains, with
  today's key, and records its day: migration 0041 adds `key_day` to
  `http_receipts` and `tenant_http_receipts`. It keeps today's and
  yesterday's keys in memory, asks the service at most 5 seconds for one it
  does not hold, and forgets older ones. A new request whose day's key the
  service does not give fails before it runs: 503 `authority_unavailable`.
  A replay whose day's key is gone, or was created again under another
  value after a failover lost a key the old primary held alone, answers 409
  `idempotency_receipt_unreadable`, and the request does not run again.
- **Migration.** A receipt that names no day, written before this release
  or by an API without the service (development), keeps the installation's
  receipt key, and stays readable until it expires, 24 hours after it was
  written. The installation's key stays, unchanged: it reads those
  receipts, and derives the LLM credential key and the download link key
  (ADR 016), which keep today's behaviour. A rotatable key for LLM
  credentials stays "later, not blocking" (ADR 005 §5 item 10, LLM-01).
- **What a backup then holds.** A receipt's token secret is readable,
  with the backup's passphrase, until its day's key is destroyed: a backup
  taken on day D holds no readable secret once 01:00 UTC on day D+2 has
  passed, between 25 and 49 hours after it was taken. ADR 005 said "a backup
  older than a day": the receipt's 24 hours and the key's day add up to two
  days at most.
- **Two fixes in the stream**, needed once a record with a wrapped key can
  continue in degraded mode: such a record was deleted from the primary's
  log once its write returned, acknowledged or not; it is now deleted only
  once the replica holds it, and the monitor drops the log once the replica
  holds all of it. Without them, a key created in degraded mode never
  reached the standby, which then refused every later record as a gap.
- **Upgrade order** (§4): a standby of an older release applies receipt
  key records as volume keys' (same operations), so no order is needed.
- Tests: `TestReceiptKeyCreationContinuesInDegradedMode`,
  `TestReceiptKeyDestructionWaitsForTheStandby` (the destruction reaches
  the replica and removes its wrapped copy), `TestReceiptKeyBindingIsReserved`,
  `TestStandaloneReceiptKeys`, `TestReceiptKeysSurviveThePromotion` and the
  receipt keys in `TestEveryStatementAndKeyWriteIsClassified`
  (`internal/restoreauthority`); `TestReceiptKeyBindingNamesOneDay`,
  `TestReceiptKeysListsTheDaysHeld` (`internal/keyauthority`);
  `TestAPIGetsTheDailyReceiptKeys`, `TestServiceTendsTheDailyReceiptKeys`,
  `TestReceiptKeyOfANewDayIsCreatedWithoutTheStandby`,
  `TestReceiptKeyNeverTravelsInJSON` (`internal/authorityclient`);
  `TestPrimaryKeepsTheDailyReceiptKeys` (`cmd/agentcapsule-authority`);
  `TestReceiptKeyRingKeepsTodayAndYesterday`, `TestReceiptsUseTheKeyOfTheirDay`,
  `TestTenantReceiptsUseTheKeyOfTheirDay`, `TestReceiptOfAGoneDayKeyIsNotReplayed`,
  `TestNewReceiptWaitsForTheKeyOfItsDay`,
  `TestReceiptsOfTheInstallationKeyStayReadable` (`internal/controlplane`,
  PostgreSQL); `TestHTTPReceiptsOfTheDailyKeys` (`internal/api`).
  `scripts/verify-failover.py` replays, on the promoted standby, a request
  acknowledged by the old primary. Each test failed before its change.

The model needs no change (§8): the daily receipt key protects old backups'
receipts, not the restore invariants, and its creation in degraded mode is
a write that continues, like an outcome's.

Not done in wave 6:
- **The blanket revocation at a failover** that covers the tokens of a day
  whose key was lost (answer 4(b)) is ADR 005's item 14, wave 7. Until
  then, a token issued in that period stays valid, and its receipt answers
  409.
- **A destruction committed as the standby goes away holds the records
  back**, as in wave 5's notes: `receipt_key_destroy` waits, and runs every
  day, at about 01:00 UTC. The window is the time between its commit and the
  standby's acknowledgment.
- The key authority keeps, per day, an empty lock file, an allocation
  marker and a tombstone, and the replica one row: about 1,100 small files a
  year, as for volume keys.

## 11. Options considered

| Option | Why not |
| --- | --- |
| A worker mode | Root, and the lifetime of the worker; the API could not reach it without the worker |
| A new binary | `agentcapsule-authority` already holds both roles' commands |
| HTTP over the socket (`net/http`, as the SLIM link) | Request and response fit; a hold does not: it is a long exchange that ends with a release, bound to its connection |
| gRPC | A new dependency, for a few operations |
| Moving each publish into the service | The service would need PostgreSQL and `internal/controlplane`: the process that holds the keys would grow the most |
| Prepare, then commit, with an undo | A confirmed placement or an activated restore cannot be undone cleanly |
| Check, act, then check again that nothing changed | Kept only for the activation's inspection, which changes nothing outside the guest's restricted boot |
| Keys through a file descriptor, or LUKS opened by the service | See [How keys reach the worker](#how-keys-reach-the-worker) |
| Holds per store now | Changes the exclusions; a later, separate step |

## Questions for the product owner

Answered on November 16, 2026: **1 (a), 2 (a), 3 (a), 4 (b)**, the
recommended options. Questions 5, from wave 4, and 6 and 7, from wave 5,
are open; their recommended or safest options are built as the defaults.

1. **The authority service restarts** (an upgrade, or a crash that systemd
   restarts). For a few seconds, more if the standby does not answer at that
   moment: no agent boots; running agents' calls to the platform (a model
   call, a message to another agent) fail with an error they can retry;
   deliveries wait. A restore in progress pauses and continues by itself.
   Then restoring or deleting an agent waits up to 2 minutes before it
   starts, and closing a request or giving up a delivery up to 30 seconds.
   - (a) Accept this pause at each upgrade. It is like a worker restart today,
     and rarer.
   - (b) Build a handover between the old process and the new one, so that
     an upgrade causes no pause. More code, in the most sensitive process.

   Recommended: (a).
2. **An administrator removes a member while the authority service is down.**
   - (a) The removal fails with "try again in a moment". Nothing is half
     done. The service is local and restarts in seconds, and an alert fires
     if it does not.
   - (b) The removal takes effect in PostgreSQL at once, is shown as pending,
     and its record is written when the service returns. If the host is lost
     before that, the member can come back after the failover. This would
     change ADR 005's rule "the record before the commit".

   Recommended: (a).
3. **A small install, one host, no standby**, runs one more service
   (`agentcapsule-authority`), with its own account.
   - (a) Always. One way to run the platform. The API reaches the
     authorities, and the revocation records and the daily receipt key need
     it.
   - (b) Keep the worker's in-process authorities for such installs. Two
     ways to test, and those installs get neither the revocation records nor
     the daily receipt key.

   Recommended: (a).
4. **The standby is unreachable at midnight, when the daily receipt key
   changes** (wave 6).
   - (a) Issuing tokens waits until the standby returns.
   - (b) The service creates the new day's key on the primary only, and
     tokens are issued. If the primary is lost before the standby returns,
     the receipts of that period cannot be replayed; the blanket revocation
     at the failover revokes their tokens anyway. The old key's destruction
     still waits for the standby, so during the outage it lives more than 24
     hours on the primary. This adds one kind of write that continues in
     degraded mode: the creation of a receipt key, not of a volume key.

   Recommended: (b). The service creates each key a day ahead, so this
   happens only when the standby stays away for a day.
5. **The authority service stops answering for good** (it crashed and does
   not come back), while the database is fine. No agent boots and platform
   calls fail anyway; what should the API's readiness probe say?
   - (a) Not ready (503 `authority_unavailable`). A load balancer that
     watches it stops sending requests to this API, so every caller gets an
     error until the service is back. The alert
     `AgentCapsuleAuthorityServiceDown` fires as well.
   - (b) Ready, with `"authority": "unavailable"`. Calls that do not need
     the authority keep working; from wave 5, removing someone's access
     answers "try again in a moment".

   Recommended: (a), built as the default. Most of the product stops without
   the service, the API does not start without it either, and from wave 7
   the API needs the service to know whether it may serve after a failover.
   Degraded mode and the wait for the standby keep the API ready in both
   options.
6. **The standby goes away while an agent is being created** (wave 5). The
   creation's write reached the primary, not the standby. For as long as
   the standby is away (minutes, or hours), removing a member or revoking a
   token answers "try again in a moment"; deliveries and boots go on.
   - (a) Keep it: a revocation waits, like the creation, for the standby.
   - (b) Let a revocation's record pass such a write: it depends on
     nothing the write changed. Revocations then take effect in degraded
     mode in every case, as decided for finding 1.

   Built: (a), the barrier as it stands. Recommended: (b), in a later
   change with its own test.
7. **Which changes count as revocations** (wave 5). An administrator
   lowers someone from `org_admin` to `agent_user`, or disables a model
   alias, an hour before the primary is lost; the database restored on the
   standby is 10 minutes old.
   - (a) Only what the product spec names: memberships, assignments,
     tokens, delegations, keys. The person is `org_admin` again after the
     failover until someone lowers them again; the alias works again.
   - (b) Also record role reductions and LLM alias changes, so that the
     reconciliation (wave 7) replays them.

   Built: (a). Recommended: (b), with wave 7.
