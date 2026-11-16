# REC-04 — Key lifecycle, rotation, sealing and archive deletion

Date: November 16, 2026. **Status: proposed and built, with five defaults
pending the product owner** (see
[Questions](#questions-for-the-product-owner)). This record closes the
remaining work of REC-04: the rotation and sealing policy, and what happens
to a deleted agent's archives. It changes no decision of
[ADR 005](005-keys-outside-restored-domain.md) or
[ADR 006](006-authority-service.md). References: product spec §3
"Operations and recovery", §6 "No secrets in guests", §7 "Honest deletion"
and "Retention by data class" ([product.md](../product.md)); REC-02, REC-03,
REC-04, D-05 and LLM-01 of the [roadmap](../../ROADMAP.md);
[recovery.md](../recovery.md), [worker.md](../worker.md),
[key-authority.md](../guest/key-authority.md).

The product spec asks:
- "Deletion: blocks new work, stops the VM, destroys the volume, its key and
  temporary credentials, and removes the Directory record. Backups expire per
  policy, not instantly."
- "A restore never revives memberships, assignments, tokens, delegations or
  keys revoked since the backup."
- "Honest deletion: live data is removed promptly; immutable backup
  generations expire per policy." "Backup retention and purge are
  documented."
- "A capsule gets only its volume key and short-lived boot credentials."

## 1. The lifecycle before this record

File and line references are those of `mvp-integration` at `d6da2c3`, with
ADR 006 waves 1 and 2 built: the worker reaches both authorities through the
authority service (`internal/authorityclient`, `internal/authorityservice`).

### A volume key

- **Created** at provisioning, while the volume is `INSTALLING`: the restore
  authority registers the store (`internal/worker/provisioning_linux.go:73`),
  then the key authority creates the key (`:80`, the service's `ensure_key`,
  which runs `keyauthority.Files.Ensure`,
  `internal/keyauthority/files_linux.go:318`; journaled to the replica by
  `ensureJournaled`, `internal/keyauthority/journal_linux.go:96`).
- **Used** to format the LUKS container on the host
  (`provisioning_linux.go:84`), and at each boot to open it in the guest
  (`internal/worker/volume_boot_linux.go:94`). Both take a key hold
  (`HoldKey`): the service holds the store's binding and runs `WithKey`
  (`files_linux.go:360`), which holds a shared lock and clears its buffer. A
  restore writes an archive into the same volume file: the key stays.
- **Never rotated.** Nothing re-keys a volume.
- **Destroyed** by the deletion job (`internal/worker/dispatch_linux.go:131`),
  inside the host's removal of the sealed volume: the restore authority
  records the seal (`internal/worker/removals_linux.go:48`), the key
  authority destroys the key (`:52`, the service's `destroy_key`,
  `internal/authorityservice/operations_linux.go:86`, which runs `Revoke`,
  `files_linux.go:386`; `revokeJournaled`, `journal_linux.go:158`), the
  volume file goes (`:55`),
  then PostgreSQL records the removal and the agent becomes `DELETED` (`:65`,
  `internal/controlplane/store_removals.go:80`). `Revoke` writes a permanent
  tombstone first, so a restored copy of the key file is refused. With the
  replica, the replica deletes its wrapped copy in the same record, and
  destruction waits for the replica in degraded mode.

So the key is destroyed **at deletion**, usually minutes after the request:
as soon as every agent's store has fenced the deletion and the host has
stopped the VM for good. Nothing measured how long a deletion stayed
unfinished. The worker's order is the only thing that puts the seal before
the destruction: neither `destroy_key` nor `Revoke` checks a seal.

### A seal

A store is sealed only by an agent's deletion, at one point: after the
deletion barrier (`deletion_operations` at `TOMBSTONED`: every store fenced
the subject `agent/<id>`), and after the host retired its execution for good
(`internal/worker/seals_linux.go:29`, `SealAgent`: no VM, admission banned,
inode checked). The worker then records the seal in the restore authority
(`seals_linux.go:41`, `RecordRetiredSeal`,
`internal/restoreauthority/catalog_linux.go:974`), then in PostgreSQL
(`seals_linux.go:45`). The removal records it again before destroying the
key (`removals_linux.go:48`); the write is idempotent.

A seal never lifts (the model's `permanentSeals`). A sealed store refuses a
reservation, so a restore (`catalog_linux.go:595`), a lookup, so a boot
(`:618`), and the authentication of its archives
(`internal/restoreauthority/archive_linux.go:93`). Nothing else seals: a
restore moves to a new incarnation, a failover promotes the authorities, a
stop puts the agent to sleep.

### A deleted agent's archives

| Where | Before this record |
| --- | --- |
| The host's archive root | **Kept for ever.** Retention runs only after a new capture of the same agent (`internal/worker/archive_schedule_linux.go:319`, `pruneArchives` at `:357`), and only `LIVE` agents are captured (`internal/controlplane/volume_archives.go:67`). [worker.md](../worker.md#nightly-encrypted-archives) asked the operator to delete them. |
| S3 | 30 days after their upload, by age (`deploy/backup/agentcapsule-archive-ship.py:314`, `--keep=s3=30d`). With object lock, a deleted version stays until its lock ends (30 days from the upload) and one more day. |
| The standby, over SFTP | 7 days after their upload, by age (`--keep=standby=7d`). |
| An archive fetched onto the standby | Kept in that host's archive root. |

The shipper sends only the archives younger than a store's retention
(`agentcapsule-archive-ship.py:291`), so the copies on the stores expire
whatever the host keeps.

### Can a deleted agent's archives still be decrypted?

**No, from the destruction of its key.** An archive is the agent's LUKS2
container: AES-XTS with a volume key that libcryptsetup generated, stored in
the header under one key slot, which opens with the 32 random bytes of the
key authority (Argon2id; `internal/volumestore/luks_linux.go:33` and `:80`).
The manifest holds no key. Once those 32 bytes are gone from the key
authority and the replica, no archive opens: on the host, on S3, on the
standby. Even with the key, the restore authority would refuse the archive
of a sealed store (`ErrSealed`).

The key is gone from everything the platform writes: the key authority's
files (`TestDestroyedKeyCannotDecryptOldBackup`), the replica and the
primary's log (`TestWrappedKeysLeaveNoCopyBehind`), and the authorities
promoted after a failover (`TestAcknowledgedWritesSurviveTheFailover`). It
survives only in copies outside the platform:
- a **provider snapshot or backup of a host's disk**: the primary keeps the
  keys in clear, the standby wrapped to the unlock key. key-authority.md
  asked to keep the directory "out of data backups", but no doc named the
  provider's copies;
- the **authority snapshot** of the replica's installation: it holds every
  key of its time, wrapped. recovery.md asked to delete it on the primary,
  not on the standby, and `init-replica` keeps it;
- the **old primary's directories** after a failover: recovery.md already
  asks to wipe them;
- freed disk blocks and a former guest's memory, which no file-based
  authority can scrub ([key-authority.md](../guest/key-authority.md)).

### The other keys

| Key | Where | Rotation before this record |
| --- | --- | --- |
| **Transit keys**: invocations, results, messages between agents, **and attachments** | Files given to the API (`-transit-key`, `cmd/agentcapsule-api/main.go:41`) and the worker (`transit.keys`); PostgreSQL keeps each one's SHA-256 and the active ID | **Yes, with an overlap.** `agentcapsule-admin activate-transit-keys` (`cmd/agentcapsule-admin/transit.go:15`) activates a new ID with every key still needed; each content keeps its key ID. **Bug:** the coverage check looked at payloads only (`internal/controlplane/transit.go:79`), not at attachments, which are sealed with a transit key too (`internal/controlplane/attachments.go:143`). A rotation could drop the key of a live attachment, and the API would start without it. Nothing said when an old key could go. |
| **Receipt key**: idempotency receipts, including token secrets for 24 hours | A file (`-receipt-key-file`); PostgreSQL keeps its SHA-256 (`internal/controlplane/users.go:61`) | **No.** The installation is bound to it. ADR 005 replaces it with a daily key in the authorities, destroyed after 24 hours (ADR 006, wave 6). |
| **LLM credential key** | Derived from the receipt key (`users.go:45`) | **No.** The provider credentials it seals rotate through the API (LLM-007); the key that seals them does not ([llm.md](../api/llm.md#known-limits)). |
| **Catalogue secret**: fence receipts and archive manifests (HMAC) | The restore authority's catalogue, replicated wrapped | No. Old manifests must keep verifying. |
| **Unlock key** | Off both hosts; the catalogue keeps its recipient | Only through a failover: the new standby gets a new one. A snapshot with another recipient is refused (`internal/restoreauthority/snapshot_linux.go:131`). |
| **Replica link certificates** | Self-signed, 10 years (`internal/authoritylog/transport.go:171`), one pinned per side | By hand: a new certificate, copied and pinned on the other host. Nothing warns before they expire: the worker's preflight did, until the link moved to the authority service in ADR 006 wave 2. |
| **API TLS certificate** | `-tls-cert`, `-tls-key` | Renewed by the operator, reloaded on `SIGHUP`; the preflight warns 30 days before expiry. |
| **Boot credentials** | Per VM, 24 hours (`internal/runtime/firecracker_control_linux.go:36`) | New at every boot. |
| **Backup passphrases** (pgBackRest, rclone crypt) | `/etc/pgbackrest`, `/etc/agentcapsule-archive-ship` | Not in place: a new passphrase means a new repository or bucket, and the old one expires by age. |

### Other findings

- **No undo.** From the commit of the deletion request, the agent's messages,
  results and files are purged (`internal/controlplane/revocation.go:79`),
  the subject `agent/<id>` is revoked for good (`:114`), and no restore can
  start (`internal/controlplane/volume_restores.go:181`). The key goes
  minutes later.
- **An orphan key after an abandoned provisioning.** `abandon-provisioning`
  removes a reservation still at `INSTALLING`
  (`internal/controlplane/abandon_provisioning.go:16`). If a worker crashed
  after `Ensure` (`provisioning_linux.go:81`) and before recording the volume,
  the key and the registered store stay in the authorities for ever, with no
  seal: under ADR 006 wave 3, nothing could destroy that key. The volume holds
  no agent data yet.

## 2. The policy

### Deleting an agent

**Scenario.** An owner deletes an agent on Monday at 10:00.

- 10:00, in the commit of the request: no new work; its messages, results
  and files in the database are purged; it is no longer discoverable.
- Minutes later, once every agent's store has fenced the deletion: the host
  stops the VM for good; the restore authority seals the store; the key
  authority destroys the volume key, on the primary and on the replica in
  one write; the volume file goes; the agent is `DELETED`. From this moment
  no archive of the agent opens, anywhere.
- Within the hour: the worker deletes the agent's archives from its host
  (new, §3).
- Until Monday + 7 days at most: ciphertext copies stay on the standby; until
  Monday + 30 days at most (31 with object lock): on S3. Their age counts from
  their upload, before the deletion. Nothing can read them.
- Until Monday + 4 weeks: the database backups still hold the agent's
  messages and metadata, readable with a backup passphrase and the transit
  key. This is "backups expire per policy".

**The rule: crypto-shredding at deletion.** The key is destroyed as soon as
the store is sealed. The ciphertext copies then expire by age, each tier on
its own retention, and are unreadable meanwhile.

Compared with **keeping the key until the last archive expires** (30 days):

| | Destroy at deletion (chosen) | Keep the key 30 days |
| --- | --- | --- |
| Product spec §3 and key-authority.md: the key "is revoked on deletion" | Met | Broken |
| Honest deletion: a deleted agent's memory readable after deletion | By nobody | By anyone holding the authorities, for 30 days |
| An agent deleted by mistake | Lost | Could come back from an archive, but only as a new agent: the store is sealed and `agent/<id>` revoked for good (`permanentSeals`, `revocationsSurvive`), so the model needs a new action |
| What a stolen backup of the stores gives | Ciphertext | Ciphertext, readable with the authorities for 30 days |
| Code and model | As today | A "pending destruction" state, a timer, and a restore of a sealed store's archive into a new agent |

**An agent deleted by mistake.** Default: there is no undo window. Stopping
an agent is the reversible action (product principle 4, "stopping is not
deleting"). A grace period, if the product owner wants one, comes before the
deletion request, not after the seal: the agent is suspended (no work, VM
stopped, hidden), its content and key kept, and only at the end does the
deletion above run. That is a new state of the API and of the model, and
the privacy notice must say how long a deleted agent's data stays
(question 1).

**Archives on the host.** Deleted within the hour after the key's
destruction, by the maintenance worker (question 2). The local copies are
ciphertext nothing can open, but their manifests name the agent and its
volume in clear, and they fill the disk.

**Archives on the stores.** By age only, as today (question 3). They are
encrypted twice (LUKS, then rclone crypt, which also hides their names), and
object lock keeps S3's versions 30 days anyway: deleting them earlier would
need the shipper to know which encrypted name belongs to a deleted agent,
for no gain in what can be read.

**Copies outside the platform.** The operator keeps none: no provider
snapshot or backup of either host's disk, no backup of the authority
directories, the authority snapshot deleted on both hosts, the old primary
wiped after a failover, the unlock key off both hosts
([recovery.md](../recovery.md#deleting-an-agent-its-keys-and-its-archives-adr-018)).
Question 4 asks whether a provider snapshot may be allowed anyway.

### Key rotation

**Scenario: the yearly rotation of the transit keys.** In January, the
operator creates `v2`, activates it with `v1`
(`agentcapsule-admin activate-transit-keys -active-key v2 -key v1=… -key v2=…`),
and restarts the API and the worker with both keys, `v2` active. New content
is sealed with `v2`. Old content stays readable with `v1`: each payload and
each attachment names its key. `agentcapsule-admin transit-key-usage` (new)
lists, for `v1`, the unpurged payloads and attachments it still seals, how
many have no purge date yet, and the latest purge date of the others.
Delivered content goes 7 days after its delivery; an attachment at most 24
hours after its upload, or when its invocation ends. Once `v1` seals
nothing, the operator removes it from both configurations, deletes its file
on the hosts, and keeps the safe's copy 4 weeks more for the database
backups. The steps are in [api/README.md](../api/README.md#private-instructions).

**Scenario: a transit key may have leaked** (a host compromised, a file
copied by mistake). Rotate at once, as above. Content already sealed with the
old key stays sealed with it until its purge: the old key still opens it,
and it is in the database backups for 4 weeks. Re-encrypting live content
under the new key would shorten the first part only (question 5).

| Key | Rotates | How often (default) | Overlap | Command |
| --- | --- | --- | --- | --- |
| Volume key | No. It lives as long as the volume. The LUKS volume key that its key slot protects never changes, so a new 32-byte key for the slot would leave every archive openable with the old one | — | — | — |
| Transit keys | Yes | Once a year, and at once on a suspected leak (question 5) | Until the old key seals nothing live, then 4 weeks in the safe | `activate-transit-keys`, `transit-key-usage` |
| Receipt key | Not before ADR 006 wave 6. Then a daily key, destroyed after 24 hours | Daily | Today's and yesterday's | Automatic |
| LLM credential key | Not yet (follow-up 7). On a suspected leak of the receipt key, rotate every provider credential at its provider | — | — | — |
| Catalogue secret | No | — | — | — |
| Unlock key | At each failover; otherwise follow-up 5 | — | — | — |
| Replica link certificates | Before their 10 years end, or when a host is rebuilt | — | None: the replication pauses while one side waits for its new pin, and degraded mode starts after 30 seconds | `agentcapsule-authority certificate` |
| API TLS certificate | Before it expires | The issuer's | New connections on `SIGHUP` | — |
| Boot credentials | Every boot | 24 hours at most | — | Automatic |
| Backup passphrases | Only through a new repository or bucket; the old one expires by age | — | The old store's retention | — |

### Sealing

**The rule.** A store is sealed when, and only when, its agent is deleted:
after the deletion barrier (every store fenced `agent/<id>`), and after its
host retired the agent's execution for good. The seal reaches the restore
authority before PostgreSQL. It never lifts, survives a failover, and waits
for the replica in degraded mode. The volume key is destroyed only for a
sealed store, after every holder of the key let it go.

**What ADR 006 wave 3 enforces** (another piece of work; this record does not
build it):

1. `destroy_key(agent, volume)` refuses unless the restore authority holds
   the store `agent` sealed, with that `volume`. Armed, the check runs in the
   catalogue transaction that records the destruction. Standalone, it may run
   just before: a seal is permanent, so a check then a destruction needs no
   common transaction. The error says the store is not sealed, so the
   worker's deletion job retries.
2. The worker keeps its order: seal, key, volume, PostgreSQL. The service no
   longer relies on it.
3. The daily receipt key of wave 6 has no store: its destruction is bound to
   its day, not to a seal. `destroy_key` must tell the two kinds apart.
4. The projection `TestDestructionRequiresPermanentSeal` becomes full.

## 3. What this record builds

- **The transit coverage includes attachments.** A rotation keeps, and the
  API and the worker require at startup, the key of every live attachment
  (`checkCoverage`, `internal/controlplane/transit.go`). Test:
  `TestTransitRotationKeepsTheKeyOfALiveAttachment`, which failed before:
  the rotation dropped the key.
- **`agentcapsule-admin transit-key-usage`.** Prints, for each activated
  key, `active`, `payloads`, `attachments`, `undated` and `purge_by`, as JSON.
  It reads metadata only (`Store.TransitKeyUsage`). Tests:
  `TestTransitKeyUsageSaysWhenAnOldKeyCanGo`, and the command in
  `TestAdminRefusesAClearTextDatabaseInProduction`; both failed before.
- **A deleted agent's archives leave the host.** The archive pass, at its
  first pass and then once an hour, lists the archive root
  (`volumearchive.Store.List`), reads each manifest, and asks PostgreSQL
  which archives, recorded on the host or found on disk, belong to a volume
  whose key is destroyed (`store_removals`). It deletes each in one step
  (`Remove`), then records it (`PurgedVolumeArchive`): a settled capture is
  marked removed, an unsettled one adopted then marked, one that published
  nothing forgotten. It never marks a live agent's archive, and leaves an
  archive whose manifest it cannot read, or that names another volume, for
  the operator. Events `volume_archive_purged` and `volume_archive_retry`
  with reason `purge`. No migration: `volume_archives.removed_at` exists.
  Tests: `TestDeletedAgentArchivesArePurged`,
  `TestArchivePassPurgesDeletedAgentsHourly`, `TestListNamesOnlyPublishedArchives`;
  each failed before (the functions did not exist), and the first fails
  when the guard on `store_removals` is removed from `PurgedVolumeArchive`.
- **Unfinished deletions are measured.** Until a deletion finishes, the key
  exists and the archives open. `agentcapsule_worker_deletions_unfinished`
  and `agentcapsule_worker_deletion_oldest_seconds`, read from PostgreSQL at
  each scrape, count this host's deletions requested and not `DELETED` (on a
  host without a key authority, not sealed). `AgentCapsuleDeletionUnfinished`
  fires after 6 hours. Tests: `TestUnfinishedDeletionsAreMeasured`, which
  failed before (the functions did not exist), and the alert's unit test in
  `alerts_test.yml`, which fails with another threshold.
- **Docs.** [recovery.md](../recovery.md#deleting-an-agent-its-keys-and-its-archives-adr-018)
  (what goes and when, the copies to never keep, the snapshot deleted on the
  standby too, retired transit keys in the safe);
  [key-authority.md](../guest/key-authority.md) (the lifecycle);
  [worker.md](../worker.md) and [observability.md](../observability.md) (the
  purge); [api/README.md](../api/README.md) (the rotation steps).

The KVM product test of a deletion with archives is not written: a real
deletion needs the host's seal (`RemoveDeletedStore`). The PostgreSQL tests
play the deletion's records up to `RecordStoreRemoval`, and the authorities'
own tests cover the key's destruction.

**The model** ([restore_authority.qnt](../../spec/restore_authority.qnt))
does not change. It already destroys a key only after a permanent seal
(`destroyKey`), and an archive of a destroyed key never opens again
(`destroyedKeyCannotDecryptOldBackupTest`): deleting that archive later
changes no invariant. The transit keys and the deletion metrics are outside
the model.

## 4. Follow-ups

For ADR 006 wave 3 (the service owns both authorities):

1. The seal check of §2.
2. **Sealed stores whose key is not destroyed**, counted by the service from
   the authorities themselves. The worker's gauge of §3 reads PostgreSQL,
   which a failover may set behind the authorities.
3. **Orphan keys of abandoned provisioning**: a command that seals a
   registered store PostgreSQL no longer knows, then destroys its key, so
   that wave 3's check does not keep such a key for ever.
4. `init-replica` could delete its snapshot once the replica is created;
   recovery.md asks the operator to do it meanwhile.
5. **Rotating the unlock key** without a failover: the primary takes a new
   snapshot under a new recipient, the standby builds a new replica from it,
   then the old one is deleted. Today a snapshot with another recipient is
   refused.
6. **Pinning two link certificates** during a rotation, so that the
   replication does not pause.

Elsewhere:

7. **A rotatable key for LLM provider credentials** (ADR 005 §5 item 10,
   LLM-01): a key file with an ID, the credentials re-sealed by a command,
   instead of a key derived from the receipt key.
8. **Re-sealing live transit content** under the active key, if question 5
   asks for it.
9. **The grace period** of question 1, if chosen.

## Questions for the product owner

1. **An owner deletes an agent by mistake, and asks an hour later to have it
   back.** Today it is gone: its messages were purged at once, and its
   memory became unreadable minutes later.
   - (a) Keep deletion final. Stopping an agent is the reversible action.
   - (b) A grace period of, say, 7 days: the deletion first suspends the
     agent (no work, hidden), and the owner can cancel it; the purge and the
     key's destruction come at the end. Deleted data then stays 7 days
     longer, and the privacy notice must say so. A new state in the API and
     in the model.
   - (c) Keep the key until the last archive expires (30 days), so that an
     operator can restore the agent's memory into a new agent. Anyone holding
     the authorities can read it meanwhile.

   Recommended: (a). Default applied: (a).
2. **The host's archives of a deleted agent.** They can no longer be read.
   - (a) The worker deletes them within the hour.
   - (b) They stay until the operator deletes them, as before.

   Recommended and applied: (a). Their manifests name the agent, and they
   fill the disk.
3. **The copies on S3 and on the standby of a deleted agent's archives.**
   - (a) They expire by age: 7 days on the standby, 30 on S3. Nothing can
     read them meanwhile.
   - (b) They are deleted at once, from the standby, and hidden on S3, whose
     lock keeps them 30 days anyway. The shipper must then learn which
     encrypted names belong to a deleted agent.

   Recommended and applied: (a).
4. **The hosting provider offers automatic disk backups of the servers.**
   With them on, a deleted agent's key can be read back from the provider's
   copy for that copy's retention, and the provider holds every key in
   clear.
   - (a) Forbid them on both hosts; the platform's own backups suffice.
   - (b) Allow them, and say that deletion is final only after the
     provider's retention.
   - (c) Move the key authority to a disk the provider does not copy.

   Recommended and applied: (a), stated in recovery.md. The platform cannot
   check it.
5. **The transit keys, which seal messages, results and files.**
   - (a) The operator rotates them once a year, and at once if a key may have
     leaked. Content sealed with the old key stays sealed with it until its
     purge, 7 days after delivery.
   - (b) The same, and a command re-seals live content under the new key, so
     that a leaked key can be dropped at once. More code; the database
     backups still hold the old ciphertext for 4 weeks.
   - (c) Rotation only after a leak.

   Recommended and applied: (a).
