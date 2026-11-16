# REC-02, REC-03 — Restoring a lost host's agents on the standby

Date: November 16, 2026. **Proposed.** Two defaults wait for the product
owner ([below](#questions-for-the-product-owner)). References: the MVP outcome
and §3 of [product.md](../product.md); [ADR 003](003-restore-rpo.md) (declared
losses), [ADR 004](004-recovery-objectives.md) (RPO, RTO),
[ADR 005](005-keys-outside-restored-domain.md) and
[ADR 006](006-authority-service.md) (the authorities, their replica and their
service), [ADR 008](008-redelivering-lost-agent-requests.md) (lost
agent-to-agent events), [ADR 018](018-key-lifecycle-and-archive-deletion.md)
(deleted agents); [recovery.md](../recovery.md).

## Context

What was in place before this record:
- **On its own host**, an agent restores from a local archive into a new
  incarnation, and every outcome the archive lacks is declared lost
  (`-restore-agent`, ADR 003). It passed on KVM.
- **Off the host**, every archive reaches S3 and the standby's disk within the
  hour, encrypted again with rclone crypt, and a fetch brings one back
  (`agentcapsule-archive-ship.py`).
- **The authorities** replicate synchronously to the standby and can be
  promoted there under the next epoch (ADR 005). The worker reaches them only
  through the authority service (ADR 006, waves 1 to 3).
- **PostgreSQL and the API** fail over to the standby: the RTO measured on one
  machine is 1.6 seconds (`verify-failover.py`).

What was missing: restoring the agents on the standby. Placements name a host
in several places, and the worker serves only its own:
- `agent_specs.host_id` and `agent_placements.host_id`: where the agent runs;
- `platform_operations.host_id` and `worker_jobs.host_id`: whose queue holds
  its operations and jobs (`DiscoverWork` projects deliveries, closures,
  deletions and expirations from the placement's host);
- `placement_renewals`, `placement_control_contracts`: observations of a VM
  of that host;
- `store_enrollments.volume_device` and `volume_inode`: the identity of the
  volume file on that host, fixed once provisioned;
- the host's own registry, in its runtime root: each agent's volume path,
  UID, harness and generation watermark;
- `volume_archives.host_id`, `volume_restores.host_id`, `store_seals.host_id`:
  history.

## Decision

### 1. A takeover is a record, and it is final

The operator records that host B takes over the lost host A, once A is
fenced: `agentcapsule-admin take-over-host -lost-host A -host B -confirm A`
(`host_takeovers`, migration 0039). It is an audited operator command, as
those of ADR 014: `-dry-run` checks it, and the audit keeps who took which
host over, and every refusal. From its commit:
- **A gets no work.** `DiscoverWork` and `ClaimWork` on A fail
  (`ErrHostLost`), and a worker whose `host_id` is A refuses to start
  (`host_taken_over`). A worker of A that reached the promoted database by
  mistake would claim nothing.
- **No agent is reserved on A.** A reservation through an API still started
  with `-host-id A` fails with 503.
- **Nothing moves yet.** Each agent moves with its own restore (§2).
- **It is final.** The row is never changed or deleted. A second successor is
  refused, and so is a lost host as a successor. If B is lost in turn, C takes
  B over, and A's remaining agents go to C: the chain of takeovers ends at the
  live host.

### 2. Each agent moves with its restore

A restore that begins on B, for an agent whose placement is on a host whose
chain of takeovers ends at B, moves the agent in the transaction that takes
its volume out of service (`BeginVolumeRestore`):
- its placement goes to B, `STOPPED`: its VMs went with A. Its renewal and its
  observed control contract go;
- its specification names B, and so do its unfinished operations;
- its jobs move to B's queue, in their order, with their failure counts and
  without a lease;
- its volume becomes `RESTORING` at the next incarnation, as for any restore:
  nothing serves it until the restore activates;
- a relocation record keeps A and the identity of A's volume file
  (`volume_relocations`). The relocation is pending.

Then the restore runs its usual steps, with one more:
1. **Reservation**: the restore authority reserves the next incarnation.
2. **The new volume file** (new): B creates the agent's volume as provisioning
   does, under the same volume ID and size, formatted with the agent's key,
   which the key authority holds under the reserved incarnation. B registers
   it with the agent's harness and a UID of its own range, and records its
   identity (`RecordRelocatedVolume`). This is the only change of a volume
   file's identity, and it happens once, before the install: the enrollment
   guard allows it only while a relocation is pending and a restore of that
   incarnation is `DRAINING` or `INSTALLING`.
3. **Install, restricted boot, activation, completion**, as on the agent's own
   host. The archive's bytes replace the empty container: it is the original
   LUKS container, which opens with the same key.

The harness is not asked before the restore: its VM went with A. The
restricted boot asks it, as for any restore. An agent whose harness cannot
report its outcomes stays `RESTORING` on B, as unserved as it was on A.

An agent that is not restored stays on A, out of service: nothing boots it,
no job of A runs, and nothing it holds is lost by waiting.

### 3. Which archive

For each agent, the archives that the restored database records
(`volume_archives`), newest capture first, on any host. A record that says the
host's retention removed its archive still counts: the stores keep their
copies by age. For each archive, in this order:
1. the worker's archive root, if it is there;
2. the standby's copy, fetched by the shipper (`fetch --store standby`): on
   the standby's own disk, no network;
3. S3's copy (`fetch --store s3`).

A copy is used only once the restore authority verifies it
(`ValidateArchive`: the manifest's MAC under the catalogue's secret, the
binding, and the store not sealed) and its bytes match its manifest (size and
SHA-256). A copy that does not verify is removed, and the next store is tried.
A refusal of the authorities ends the agent's attempt: a sealed store is an
agent deleted after the database's last replayed commit. When no store holds
an archive, the next older one is tried. The worker never reads the stores'
secrets: the shipper runs rclone as its own account.

This is "the newest archive in the standby's copy, or from S3 if the
standby's copy is missing or older": the newest archive is tried on the
standby first, then on S3, before any older one.

Not considered: an archive that a store holds but the restored database does
not record. It was captured in the database's loss window, and shipped in it
too: within about 15 minutes before the disaster. Its agent restores from the
previous archive, about a day older, and the losses are declared.
`-restore-agent -archive-id` restores from a given archive.

### 4. The command

`agentcapsule-worker -restore-host A -archive-root … -archive-fetch …` on B,
the maintenance worker stopped, as for `-restore-agent`:
- **Order.** Unfinished restores on B first: they resume. Then the agents by
  the capture time of their newest recorded archive, **oldest first**, then by
  ID; agents without an archive last. Default pending the product owner
  (question 2).
- **Restore IDs.** Derived from A, the agent and the archive
  (`HostRestoreID`): running the command again finds the same restore and
  resumes it. An unfinished restore resumes with its own archive.
- **Report.** One JSON line per agent as it goes: `restored` (by this run or an
  earlier one, with the incarnation, the losses and the reruns), `skipped`
  (`no_archive`, `provisioning`, `deleting`, `elsewhere`) or `failed`
  (`archive_unavailable`, or a restore failure: `archive`, `newer_archive`,
  `busy`, `authority`, `unsupported_harness`, `state`, `error`). Then the
  totals. It exits 1 when an agent failed: run it again.
- **One agent's failure does not stop the others.** `SIGINT` stops it between
  steps; the same command resumes.

`-restore-agent` takes `-archive-fetch` too: a missing archive is fetched and
verified the same way, and the receipt says where it came from.

### 5. What a restored agent declares

Unchanged, and independent of the host. The restore authority declares lost,
for the new incarnation, every outcome it recorded that the archive lacks
(ADR 003). The restore copies those losses into PostgreSQL, queues the lost
invocations again and the lost agent-to-agent events (ADR 008), in the
transaction that puts the volume back in service.

A host loss has **two windows**, and both show:
- the agent's: from its archive to the disaster, up to about 25 hours. Its
  outcomes there are declared lost, per agent;
- the database's: about `archive_timeout` before the disaster. Work recorded
  there is lost from PostgreSQL too: a loss without a mailbox
  (`unmatched_losses`) is such work, and the operator announces that window
  for the whole platform ([recovery.md](../recovery.md#announce-the-databases-loss)).

## The procedure and its time

The commands are in [recovery.md, the procedure](../recovery.md#the-procedure).
The RTO of ADR 004 runs from the decision to the service answering on the
standby; the agents come back after it, one by one.

| Step | Time | Basis |
| --- | --- | --- |
| Decide; fetch the unlock key and the API's keys from the safe | 10 min | Estimate: the human part, not measured |
| Fence the old primary at the provider; remove its SSH keys and S3 credentials | 2 to 5 min | Estimate: provider API; 0.23 s measured for the credentials on one machine |
| Promote the authorities | under 1 min | The command; tested in Go, not between two hosts |
| Promote PostgreSQL, its own repository | 1 to 2 min | 0.5 s and 0.7 s measured on one machine; network on real hosts |
| Install the API's keys, start it, check it | 1 to 2 min | 0.1 s measured on one machine; typing on real hosts |
| Move the address | 5 min | Estimate: DNS TTL or a floating address |
| **The service answers** | **about 20 to 25 min** | |
| Take the lost host over | seconds | One transaction |
| Restore the agents | per agent: about 5 s, plus 15 s per GiB of volume from the standby's disk; plus the transfer for a copy from S3 | Estimate, below |
| Start the maintenance worker | seconds | Reruns start at once |

**The agents' share.** Each restore reads its archive four times (the
shipper's check, the authority's check, the coordinator's check, the install)
and writes it twice (the fetch, the install), then boots once, restricted.
With local disks at a few hundred MB/s that is about 15 seconds per GiB, plus
about 5 seconds of LUKS format, boot and activation. The local qualification
measured 2.6 seconds for a 64 MiB volume, fetched from S3 through rclone
crypt, with a fake host (no VM). With 35 minutes left in the hour, sequential
restores bring back about 2,100 / (5 + 15 × S) agents of S GiB: about 100 at
1 GiB, about 30 at 4 GiB. A host with more agents than that exceeds the hour
for its last agents: parallel restores are a follow-up. To be measured on real
hosts (REC-03).

## What stays undone

**Until ADR 006 waves 5 to 7 exist** (not built here):
- **Access revocation records** (wave 5). A revocation committed in
  PostgreSQL in the database's loss window (a member removed, a token or a
  delegation revoked) is lost with the primary: after the failover, that
  access works again. Until wave 5, the operator re-applies the revocations
  of the window from what the organizations report, and the announcement
  says so.
- **The daily receipt key** (wave 6). The API's receipt key is the long-lived
  one, copied by hand to the safe and installed on the standby. A receipt it
  sealed before the failover stays readable after it.
- **The reconciliation of PostgreSQL with the authorities** (wave 7). The
  restored database may be behind the authorities by its loss window:
  - an agent deleted in the window: the authority sealed its store, so its
    archive is refused (`failed`, `authority`). It stays out of service; its
    deletion is not resumed;
  - an agent restored in the window: the authority's incarnation is ahead, and
    the reservation is refused (`authority`);
  - an agent created in the window: PostgreSQL does not know it; nothing
    restores it;
  - a revocation subject the authority holds and `revocation_catalogue`
    lacks: the restored agent is fenced against it (the restricted boot
    fences with the authority's subjects), but PostgreSQL's own checks do not
    know it until the reconciliation copies it.
- **The announcement after a degraded period** (wave 7). When the standby was
  out of reach before the disaster, the outcomes of that period existed on
  the primary only, and are lost. The operator announces the window from the
  standby's last contact to the failover by hand; bearer tokens issued before
  the failover are not revoked.

**Not done here either:**
- **Imported harness packages on the standby.** The standby's worker boots an
  agent's release from its own cache, which the lost host's importer filled.
  Until the standby imports the releases its agents pin, the operator copies
  the cache to the standby in advance ([recovery.md, Prepare](../recovery.md#prepare));
  an agent whose package is missing fails with `state`, and stays out of
  service until it is there.
- **Agents still provisioning** stay on the lost host (`skipped`,
  `provisioning`). `agentcapsule-admin abandon-provisioning` removes one that
  never obtained a volume; its owner creates it again.
- **Agents being deleted** stay on the lost host (`deleting`): their deletion
  does not end. Finishing it needs the seal and the key's destruction without
  the host, as the reconciliation's resumed deletions will.
- **An activated restore on the lost host** (the disaster came between its
  activation and its end) is not finished on the new host: `failed`, `state`.
- **Agents without an archive** stay out of service (question 1).
- **Parallel restores** (above), and the measurement on real hosts.

## Tests

- PostgreSQL (`internal/controlplane/host_takeovers_test.go`): the takeover's
  rules, the lost host's queue and reservations refused, the chain; a restore
  that moves an agent with its placement, specification, operations and jobs
  in order; the new volume recorded once, before the install, and the guard;
  a superseding restore keeps the pending relocation.
- The coordinator with a fake host, real PostgreSQL, authorities and guest
  protocol (`internal/worker/host_restore_test.go`): `-restore-host` with five
  agents, a damaged copy on the standby replaced by S3's, an archive no store
  holds, an agent never archived, one still provisioning; the order, the
  report, a crashed restore resumed with its ID, a restored agent not
  restored twice; a fetched copy verified, a forged manifest refused.
- With the shipping qualification's stores (`verify-archive-shipping.py
  --restore-from-copies`, `TestRestoreFromShippedCopies`): archives shipped by
  the shipper to SeaweedFS and an SFTP server, the host lost, the newest
  archive fetched from S3 (the standby's copy removed) through rclone crypt,
  verified, installed on the new host, the loss after it declared; an older
  one fetched from the standby's disk.
- The failover exercise (`verify-failover.py`) takes the lost host over on
  the promoted database, with the API started under the standby's host ID.
- KVM, written, not run:
  `TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost` archives a
  real agent, ships the archive with rclone crypt, loses the host, and
  restores the agent on a second worker host with its own runtime root, from
  the standby's copy; the lost invocation runs again there.

## Options considered

| Choice | Options | Chosen |
| --- | --- | --- |
| The new host's identity | Reuse the lost host's ID; a new ID and a takeover record | A new ID: a stray worker of the lost host gets no work, and the takeover is dated |
| When agents move | All at the takeover, out of service until restored; each with its restore | With its restore: one transaction moves it and takes its volume out of service, and an agent never restored stays where nothing serves it |
| Which archive is newest | PostgreSQL's records; the stores' listings | PostgreSQL's: the stores' times are upload times, and one run uploads an agent's archives newest first |
| Where the fetch runs | In the worker, with the stores' secrets; the shipper, as its own account | The shipper: the worker never holds the stores' secrets |
| The new volume file | Write the archive into a new file; create the volume as provisioning does, then install | As provisioning does: the volume store's journal, the registration and the install's digest check stay as they are |

## Questions for the product owner

1. **An agent created this morning, before its first nightly archive, when
   the host is lost.** Its memory exists nowhere off the host. Options:
   (a) it stays out of service, listed in the restore report, until its owner
   deletes it; (b) the platform restarts it empty and declares every recorded
   outcome lost; (c) the platform takes a first archive right after each
   agent is created, so that every agent has an off-host copy within about an
   hour. **Default: (a).** Recommendation: (c), with (a) until it is built.
2. **Who comes back first.** With 100 agents to restore, the last one comes
   back about half an hour after the first. Options: (a) by the age of their
   newest archive, oldest first (deterministic); (b) agents with work waiting
   first; (c) an order per organization, set by the operator. **Default:
   (a).** Recommendation: (b), once restores run in parallel.
