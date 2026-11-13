# D-05 — Keys, secrets and revocations outside the restored domain

Date: November 13, 2026. **Status: option (a) chosen by the product owner on
November 13, 2026** (see [Decision](#decision)). This record lists what the platform holds, states the requirement,
compares four options and recommends one. References:
[ADR 003](003-restore-rpo.md) (declared losses, question 1),
[ADR 004](004-recovery-objectives.md) (standby host, RTO 1 hour), product spec
§3 "Operations and recovery", §6 and §7 ([product.md](../product.md)), D-05,
LLM-01, REC-02 and REC-03 of the [roadmap](../../ROADMAP.md).

## Context

ADR 004 restarts the platform on a standby host within an hour after a
disaster. Two pieces of work wait for this decision: restoring an agent onto
another host, and the failover exercise of REC-03.

The **restored domain** is what the backups bring back: PostgreSQL (up to 15
minutes old, the **database window**) and the volume archives (up to 24 hours
old, the **volume window**). Anything that must never go back in time has to
live outside it, and still reach the standby.

Today the **key authority** and the **restore authority** (together, **the
authorities**) are two directories on the primary host. Nothing copies them.

## 1. Inventory

"In a disaster today" means: the primary is lost, and the operator follows
[recovery.md](../recovery.md) on the standby.

### The authorities

| Item | Where it lives | Read and written by | In PostgreSQL backups | In volume archives | In a disaster today |
|---|---|---|---|---|---|
| **Volume keys.** One random 32-byte LUKS key per volume, in clear, with a SHA-256 check. A permanent allocation marker per volume. A tombstone per destroyed key. A public `keyauth_` identity. | The `key_authority.root` directory of the worker's configuration: `records/<volume>`, `records/<volume>.allocated`, `revoked/<volume>`, `identity` (`internal/keyauthority/files_linux.go`, `identity_linux.go`). | `agentcapsule-admin init-key-authority` creates it (`cmd/agentcapsule-admin/main.go`). Then the worker only. `Ensure` at provisioning (`internal/worker/provisioning_linux.go`). `WithKey` at each boot sends the key to the guest over the authenticated control channel (`internal/worker/volume_boot_linux.go`); the guest opens the volume with `cryptsetup` (`internal/guestinit/volume_linux.go`). `Revoke` destroys it when the volume is removed (`internal/worker/removals_linux.go`). | No. | No. An archive is the LUKS container: its header holds the volume's master key wrapped under this key. The manifest holds no key (`internal/restoreauthority/archive_linux.go`). | **Lost.** Every archive on S3 and on the standby can no longer be opened. The agents' memory is lost entirely, not up to 24 hours. |
| **Restore catalogue.** A 32-byte secret that signs fence receipts and archive manifests (HMAC). Stores with their volume, incarnation and seal. Incarnation reservations. Revocation subjects (`agent/…`, `request/…`, `event/…`) and their revision. The revision each store has acknowledged (its **fence revision**). Outcome records. Declared losses and reruns (schema 2). The key authority's identity. | The `restore_authority.root` directory: `catalog.sqlite` and `identity` (`internal/restoreauthority/catalog_linux.go`, `losses_linux.go`). | The worker: boots, deliveries (`RecordOutcome`), archives (`SignArchive`, `ValidateArchive`), restores, removals (`internal/worker/authority_linux.go`). `agentcapsule-admin init-restore-authority` creates it (`cmd/agentcapsule-admin/main.go`). | No. PostgreSQL keeps its own copies: `revocation_catalogue`, `store_enrollments`, `volume_restore_losses`. | No. Each manifest carries a MAC made with the secret. | **Lost.** Archives can no longer be authenticated. Outcome records and declared losses are gone, so a restore elsewhere cannot declare losses. A new catalogue has a new identity and is empty; `Lookup` never registers an existing store, so no agent boots. |

### Installation secrets

| Item | Where it lives | Read by | In PostgreSQL backups | In volume archives | In a disaster today |
|---|---|---|---|---|---|
| **Receipt key.** It encrypts idempotency receipts, including the secrets of issued tokens for 24 hours. A key derived from it encrypts the LLM provider credentials (`internal/controlplane/users.go`, `llm_providers.go`). | A private 32-byte file: `-receipt-key-file` (`cmd/agentcapsule-api/main.go`, `cmd/agentcapsule-admin/main.go`), `llm.receipt_key` (`internal/worker/llm_linux.go`). | The API, the admin tool, the worker's LLM gateway. | Its SHA-256 (`api_receipt_key`) and everything it encrypts. Not the key. | No. | Survives only if the operator copied it. No document asks for it. Without it the API refuses the restored database (`receipt_key_does_not_match_installation`) and every provider credential is unreadable. It cannot be rotated. |
| **Transit keys.** They encrypt invocations, results and messages between agents (`transit_payloads`). | Private 32-byte files: `-transit-key ID=path` (`cmd/agentcapsule-api/main.go`), `transit.keys` (`internal/worker/transit_linux.go`). PostgreSQL holds each key's SHA-256 and the active ID (`internal/controlplane/transit.go`). | The API and the worker. | Hashes and ciphertexts. Not the keys. | No. | Same as the receipt key. Without them, startup refuses (`CheckKeys`) and stored content is unreadable. |
| **Backup secrets.** pgBackRest's cipher passphrases and S3 credential, the SSH keys, rclone's crypt passphrases and S3 credential. | `/etc/pgbackrest/conf.d/secrets.conf`, `/etc/agentcapsule-archive-ship/` ([recovery.md](../recovery.md)). | pgBackRest, rclone. | No: they protect the backups. | No. | **Survive.** recovery.md requires a copy off the host, and the standby holds what it needs to replay and fetch. |
| **Other host secrets.** The API's TLS key, the Directory client key, registry credentials, the database password, the interop CAs. | `-tls-key`; `directory.key` (`internal/worker/directory_linux.go`); `credentials_file` (`internal/worker/registry.go`); `AGENTCAPSULE_DATABASE_URL`; `deploy/interop/make-certs.sh` (CAs kept offline). | The API, the worker, the interop stack. | No. | No. | Lost, and replaceable: each can be issued again. No history depends on them. |

### Access state in PostgreSQL

All of these are rows in PostgreSQL only. They are in the PostgreSQL backups,
not in the volume archives. The API and the worker read them on every
authorization.

| Item | Tables |
|---|---|
| Organizations, members and teams | `organizations`, `principals`, `memberships`, `teams`, `team_memberships`, `users` |
| Assignments | `agent_assignments` |
| Bearer tokens (hashes; the secrets stay with the clients) | `api_tokens`, `service_tokens`, `platform_credentials` |
| Delegations | `delegation_trusts` (public key fingerprint, status, `minimum_iat`), `delegation_revocations` (revoked token IDs) ([0004_delegated_identity.sql](../../internal/controlplane/migrations/0004_delegated_identity.sql)) |
| Mandates | `mandates.valid` |
| LLM providers and aliases | `llm_providers` (credential ciphertext, status, generation), `llm_model_aliases` |
| Revocation subjects, PostgreSQL's copy | `revocation_catalogue` ([schema.sql](../../internal/controlplane/schema.sql)) |

**In a disaster today**, the promoted standby is up to 15 minutes behind,
about 5 minutes in practice (`archive_timeout`). A revocation committed in that
window is undone: the member, token, delegation, assignment or mandate works
again. A provider disabled or rotated in the window comes back with its older
credential. [service-accounts.md](../api/service-accounts.md) tells the
operator to invalidate or rotate tokens by hand before reopening.

### Short-lived material

| Item | Where it lives | In a disaster today |
|---|---|---|
| Boot credentials: a CA and two leaf keys per VM, valid 24 hours, bound to agent, generation, VM and incarnation (`internal/capsuleprotocol/credentials.go`) | The runtime root, `credentials/<vm>.json` (`internal/runtime/firecracker_control_linux.go`); the guest's boot configuration | Lost, harmless. Each boot makes new ones. |
| A volume key held by a running guest's dm-crypt | Guest memory | Lost with the host. |

### What this means today

1. **A disaster loses every agent's memory.** The archives reach S3 and the
   standby, but the keys that open them do not. ADR 004 promises 24 hours.
2. **The restored database cannot be opened** unless the operator kept the
   receipt key and the transit keys. recovery.md asks for a copy of the backup
   passphrases, but not of these.
3. **Revocations of access live only in PostgreSQL.** The last minutes of them
   are undone by a failover.
4. **Token secrets stay in the backups.** An encrypted receipt carries a newly
   issued token for 24 hours, then the live database purges it
   (`internal/controlplane/receipt_purge.go`). Its backups keep it for their
   retention, four weeks on S3. With the receipt key and a backup passphrase,
   someone can read a token issued in the day before a backup. It still works
   if it was neither revoked nor expired; lifetimes go up to 365 days.
5. **One key, two purposes, no rotation.** The receipt key also derives the
   LLM credential key, and it cannot be rotated
   ([llm.md](../api/llm.md#known-limits)).

Notes on the code:

- The platform holds **no delegation signing key**. Trusted clients sign; the
  platform keeps their public Ed25519 keys
  (`internal/delegatedidentity/verifier.go`, read from a file by
  `internal/operatorconfig/delegation_linux.go`).
- The key authority **does not wrap** the volume keys. They are in clear in
  its directory. The only wrapping is LUKS's key slot in the volume.
- The model has **one root**. The code has **two authorities**, written
  separately: a removal records the seal in the catalogue, then destroys the
  key (`internal/worker/removals_linux.go`).
- Revocation subjects flow **one way**: the worker copies PostgreSQL's
  `revocation_catalogue` into the restore authority
  (`synchronizeAuthority`, `internal/worker/authority_linux.go`). Nothing copies
  them back to a database that a failover set back.

## 2. The requirement

### What survives a disaster

| Record | Held by | Model invariant | Why |
|---|---|---|---|
| Revocation subjects and their revision | Restore authority | `revocationsSurvive`, `noRestoredRevocation` | A restored image is fenced against every revocation made since its backup. |
| Seals | Restore authority | `permanentSeals` | A deleted agent's store never runs again. |
| Incarnations and reservations | Restore authority | `identitiesFresh` | An old receipt or image never certifies a newer one. |
| Outcome records | Restore authority | `noUndeclaredLoss` | The restore declares losses from them. |
| Declared losses and reruns | Restore authority | `declaredLossesSurvive`, `rerunsFollowDeclaredLoss` | An announced loss is never withdrawn. |
| The catalogue's signing secret and identity | Restore authority | — | Archives are authenticated with them. |
| Volume keys of live volumes | Key authority | — (the run `liveKeyDecryptsBackupTest`) | Without them no archive opens. |
| Tombstones and allocation markers | Key authority | `keyDestructionSurvives`, `erasedKeysUnavailable` | A destroyed key never returns; no second key for a volume. |
| Revocations of access | PostgreSQL today | Outside the P2 model; D-02 assumes the registry of revocations is kept ([ADR 002](002-assignment-revocation.md#targeted-model)) | Product spec: "A restore never revives memberships, assignments, tokens, delegations or keys revoked since the backup." |
| Installation secrets | Files on the primary | — | The restored database is unreadable without them. |

### What never comes back from an older backup

- a revoked member, principal, organization or team membership;
- a revoked assignment;
- a revoked API token, service token or platform credential;
- a revoked delegation trust or delegated token ID;
- a revoked mandate;
- a revocation subject or a seal;
- a destroyed volume key;
- a declared loss or a recorded rerun, withdrawn;
- an incarnation, reused.

The rule: these records only grow. A copy that may be older than the live
state is never used alone. It is either current by construction, or merged
with a newer source before anything opens.

Data may go back in time, within the announced windows (ADR 004). Revocations
may not.

### How the standby reaches it within the RTO

ADR 004 gives one hour, from the decision to fail over, to promote the
database, install the configuration and the authorities, adopt the agents and
move the address. So:

1. The authority state is already on the standby, and current, when the
   decision is taken. Fetching and replaying it from S3 fits in an hour, but it
   is not current.
2. The installation secrets are installed on the standby in advance, as the
   backup secrets already are.
3. Before the API opens, the promoted database learns every revocation it
   lacks.
4. Then each agent is restored from its newest archive, which declares its
   losses ([recovery.md](../recovery.md#restoring-an-agent-from-an-archive)).
   This step is the longest; REC-03 measures it.

### What the P2 model assumes

[restore_authority.qnt](../../spec/restore_authority.qnt) states:

- **The root is never rolled back.** Every safe configuration has
  `ROOT_ROLLBACK=false`. With `ROOT_ROLLBACK=true`, `forgottenLossTest`
  ([restore_authority_test.qnt](../../spec/restore_authority_test.qnt)) and
  `restoreWitnessForgottenLossBroken`
  ([restore_witness.qnt](../../spec/restore_witness.qnt)) break
  `declaredLossesSurvive`.
- **The root may be unavailable** for a while (`rootUnavailable`,
  `rootAvailable`). Everything that needs it waits. No action loses it.
- **No global key can unwrap an old copy** (`RAW_KEK=false`). A key is
  destroyed only after the store is sealed and every cached copy is gone
  (`destroyKey`, `CACHE_GUARD`).
- **PostgreSQL set back behind the root is not modeled.**
  [store_enrollment.qnt](../../spec/store_enrollment.qnt) says so: it does not
  prove "rollback of the authoritative SQL catalogue". After a failover,
  PostgreSQL is behind the authorities, so this case needs rules and checks.

[revocation.qnt](../../spec/revocation.qnt) and
[store_seal.qnt](../../spec/store_seal.qnt) assume durable host and SQL
records; they leave restores to the model above.

## 3. Options

Each option says where the authority state lives, and then gives:

- the **RPO** of revocations and declared losses, and what it means for
  [ADR 003 question 1](003-restore-rpo.md#questions-for-the-product-owner):
  today a loss in the database window can only be announced as a time window;
- its **complexity** for a self-hosting operator;
- its **failure modes**;
- what the **P2 model** needs.

### (a) A synchronous replica on the standby

The authorities get their own small replicated store, separate from
PostgreSQL. The primary writes; the standby keeps a **replica**. A write
returns only once the replica has made it durable. Each write carries a
sequence number and an epoch; the replica refuses a gap or an older epoch.

How it could be built:

| Way | Licence | Note |
|---|---|---|
| Built in: the authorities send each write to a replica service on the standby | MIT (this project) | Keeps SQLite, the key files and their tests. The catalogue's operations already carry stable IDs and are retried safely. |
| A separate PostgreSQL cluster with synchronous replication | PostgreSQL | Rewrites the catalogue and the key files on PostgreSQL. |
| rqlite or etcd (Raft) | MIT, Apache-2.0 | Raft needs a majority: with two hosts, losing one stops writes. Fits (c) better. |
| Litestream | Apache-2.0 | Asynchronous: it loses the last writes. Does not meet the requirement. |

- **RPO.** Zero for every acknowledged write. Outcome records reach the
  standby before the delivery is acknowledged. So a restore on the standby
  declares, one by one, the outcomes that were delivered in the database
  window. They have no mailbox left in PostgreSQL; the authority knows each
  one by its hash and its store. To show the caller which invocation it was,
  the record must also keep the event ID (an opaque ID, no content).
- **Complexity.** Low. One link between the two hosts, one service on the
  standby, one alert. No new product to learn.
- **Failure modes.** The standby is down: writes wait, or the platform
  continues in an alerted **degraded mode** whose writes may be lost
  (question 2). The old primary comes back: the promoted replica has a new
  epoch and refuses it. The standby is compromised: it holds the keys, unless
  they are wrapped (question 3). Both hosts are lost: the keys are lost
  (question 4).
- **P2 model.** It holds as written while the replica is synchronous. A
  degraded mode is a bounded `ROOT_ROLLBACK`, and needs a declared window in
  the model.

### (b) An external secret store

A key management service holds the volume keys and the installation secrets.
The worker asks it for each boot.

| Candidate | Licence | Note |
|---|---|---|
| [OpenBao](https://github.com/openbao/openbao) | MPL-2.0, under OpenSSF (Linux Foundation) | Fork of Vault 1.14. The Transit engine can hold one key per volume and delete it. Storage: Raft, or a PostgreSQL of its own. Raft needs a majority of nodes. It must be unsealed after each start (key shares by default), unless another key service unseals it. |
| HashiCorp Vault | BUSL-1.1 since 2023 | Not an open-source licence. Not acceptable as a required dependency of an MIT, self-hosted product. |
| [Infisical](https://github.com/Infisical/infisical) | MIT, except its `ee` directories (commercial licence) | Secrets and a KMS API. Needs its own PostgreSQL and Redis. |
| [CyberArk Conjur](https://github.com/cyberark/conjur) | LGPL-3.0 (server) | Secrets only. Needs its own PostgreSQL and a master data key. |
| [Cosmian KMS](https://github.com/Cosmian/kms) | BSL 1.1, source-available | KMIP, PKCS#11, HSMs. Not open source. |
| SoftHSM2 | BSD-2-Clause | A local PKCS#11 token. No replication: the same problem as the key files. |
| A cloud KMS (AWS KMS, Google Cloud KMS, …) | Managed service | Only when the operator already has one: the product runs without managed services. AWS KMS waits 7 to 30 days before it deletes a key. Each key is billed per month. |

- **RPO.** For keys, that of the store: zero for a cloud KMS or a three-node
  OpenBao. A store holds secrets, not the catalogue. The catalogue's
  transactions (activation, revocation barriers) do not map onto a key-value API with
  check-and-set per key. So revocations, outcome records and declared losses
  still need (a) or (d), and their RPO is that option's.
- **Complexity.** Medium to high. A new service to install, unseal, upgrade,
  back up and monitor. Three nodes for high availability, so a third host.
- **Failure modes.** The store is sealed or unreachable: no agent boots. On
  two hosts, OpenBao's Raft loses its majority with either host and stops,
  reads included. A store restored from its own backup brings destroyed keys
  back. A cloud KMS delays destruction by its waiting period.
- **P2 model.** It holds for keys if each volume has its own key in the
  store. One store key that wraps every volume key, with wrapped copies in
  backups, is the negative case `RAW_KEK=true`.

### (c) The authorities on a third, small host

A small host (1 vCPU, 1 GB) in a third failure domain runs the authorities.
The primary, and the standby after a failover, call it over mutual TLS.

- **RPO.** Zero against the loss of the primary. If the third host is lost,
  everything is lost: every key, so every archive. It needs its own replica
  or backup, which brings back (a) or (d).
- **Variant.** The third host is the third voter of a two-of-three quorum
  with the primary and the standby (Raft: etcd, rqlite or OpenBao). Any one
  host may fail without blocking or losing a write. This is the most robust
  form, and the natural next step after (a).
- **Complexity.** Medium. A third host to rent, patch, secure and monitor;
  with the quorum, a consensus store too.
- **Failure modes.** The third host down: no boot, no delivery. The third
  host lost, without a replica: total loss of agents' memory.
- **P2 model.** It holds while the third host lives. The model has no action
  that loses the root, so a single third host is outside it.

### (d) The authorities in the backups, with a replayed revocation log

The authority directories are captured with the database backups and shipped
encrypted to S3 and the standby. An append-only log of revocations, seals,
tombstones and declarations is shipped like the WAL. After a restore, the log
is replayed over the older copy, and is never rolled back.

- **RPO.** The log's shipping interval: about 5 minutes, at most the
  15-minute RPO. Revocations, declarations and destructions made in it are
  lost. Outcome records too, so a loss in the database window can only be
  announced as a time window.
- **Complexity.** The lowest: it reuses pgBackRest's and rclone's patterns.
- **Failure modes.** The last minutes of revocations are undone after a
  disaster. Volume keys are in the backups: a destroyed key stays readable
  from S3 for the backup retention (four weeks), by anyone holding the backup
  passphrases. This contradicts
  [key-authority.md](../guest/key-authority.md) ("kept out of data
  backups/restores").
- **P2 model.** Broken: this is `ROOT_ROLLBACK=true`. It needs a revision like
  ADR 003's: "revocations, declared losses and destroyed keys survive, except
  within an announced window". The product spec forbids it for revocations.
  The only way to honor it for tokens: after a failover, revoke every bearer
  token and raise every delegation trust's `minimum_iat` to the failover time.
  Every client then signs in again.

### Summary

| | (a) Synchronous replica | (b) External store | (c) Third host | (d) In the backups |
|---|---|---|---|---|
| RPO of revocations and declared losses | 0; a window only in degraded mode | Keys: the store's. Catalogue: needs (a) or (d) | 0 for the primary's loss; total loss with the third host, unless replicated | About 5 minutes, at most 15 |
| Losses in the database window (ADR 003 Q1) | Delivered outcomes declared one by one | As (a) or (d) | One by one | A time window |
| A destroyed key | Gone from both hosts in the same write | Gone if one key per volume; a cloud KMS waits 7 to 30 days | Gone at once | Readable from backups for four weeks |
| Operator complexity | Low | Medium to high | Medium | Lowest |
| Main failure mode | The standby down blocks or degrades writes | Sealed or unreachable store: no boot | Third host down: nothing runs; lost: everything lost | Last minutes of revocations undone |
| P2 model | Holds | Holds for keys, with per-volume keys | Holds while the host lives | Needs a weaker model |
| On the standby, within the RTO | Seconds, plus the unlock key | Reach the store; unseal it | Nothing to move | Fetch and replay: minutes |

### What no option changes

Invocations admitted in the database window, but not yet delivered, leave no
outcome record. Under every option they can only be announced as a time
window. Only synchronous replication of PostgreSQL itself would remove the
database window. That is a change to ADR 004, not to D-05 (question 5).

## 4. Recommendation (non-binding)

**Option (a), built into the platform**, with these rules:

1. **One authority service per host** owns both authority directories. On
   the primary it writes; on the standby it is the replica.
2. **A write returns only once the replica has it on disk.** The authorities'
   writes are rare except outcome records and fence revisions, one each per
   delivery or boot. Each costs one round trip and one `fsync` on the
   standby. REC-03 measures it.
3. **Revocations of access join the authority.** Each transaction that
   revokes access, in the API, the worker or `agentcapsule-admin`, appends a
   record (kind and IDs, no content, no secret) before it commits in
   PostgreSQL. A record whose transaction then fails only revokes more. After a promotion, the records are replayed into PostgreSQL
   before the API opens.
4. **Secrets on the standby are wrapped** to an **unlock key** that the
   operator keeps off both hosts. The primary holds only its public part
   (age X25519 recipient; age is BSD-3-Clause). The operator gives the unlock
   key at failover. Volume keys never go to S3 or to any versioned or locked
   store. Destroying a key removes the replica's wrapped copy in the same
   write. The unlock key is a global key in the model's sense (`RAW_KEK`). It
   stays harmless only because no wrapped copy outlives its key: none in S3,
   none in a log.
5. **The installation secrets** (receipt key, transit keys) are installed on
   the standby in advance, wrapped the same way. recovery.md lists them with
   the backup passphrases under "keep a copy off the host".

Reasons:

- (a), and the quorum variant of (c), are the only options that meet the P2
  model as it stands: no rollback, RPO 0 for revocations, declared losses and
  destroyed keys.
- It uses the two hosts ADR 004 already requires. No new host, no new
  product.
- It keeps the authorities' code and tests. It adds a transport, not a
  storage engine.
- It answers ADR 003 question 1 for delivered work: outcome records reach the
  standby before the acknowledgment, so their losses are declared one by one.
- (b) solves keys only, and on two hosts it adds unsealing and quorum
  problems. Vault is not open source. OpenBao or a cloud KMS can come later,
  as an optional backend behind `keyauthority.Provider` (an interface:
  `Ensure`, `WithKey`, `Revoke`).
- (d) is the simplest, but it weakens the model and breaks the product
  promise on offboarding and key destruction.
- The secret store "usable in self-hosting" of the roadmap is then the
  replicated authority itself.

Costs accepted: the standby's availability now matters to the primary
(question 2); a failover needs one human secret (question 3); the project
writes and tests its own replication. If the coupling to the standby proves
costly, a third small host becomes the third voter of (c). The record format
stays the same.

## 5. What changes in code and docs

For option (a), once decided:

1. **Replication log.** In `internal/restoreauthority` and
   `internal/keyauthority`, every write gets a sequence number and an epoch,
   one stream for both authorities, and returns after the replica's
   acknowledgment. A crash between the local commit and that acknowledgment
   resends from the replica's last sequence. Secrets leave the primary only
   wrapped. Neither side keeps key material in the log once it is applied.
2. **Replica mode** for both authorities: apply in order, `fsync`, refuse a
   gap or an older epoch. A replica is never opened as a writer until it is
   promoted.
3. **Authority service.** A new binary, or a worker mode, that owns both
   directories, serves the worker and the API on a local socket, and holds
   the link to the standby (mutual TLS, or SSH as the backups use). Today the
   worker opens the directories itself (`internal/worker/service_config_linux.go`).
4. **Revocation records** for access: every transaction that revokes a
   member, principal, organization, team membership, assignment, token,
   service account, platform credential, delegation trust or token ID,
   mandate, or LLM provider appends one before it commits. That covers
   `internal/controlplane` (members, service accounts, delegation authority,
   platform credentials, mandates, LLM providers) and the commands of
   `cmd/agentcapsule-admin`. Outcome records also keep the event ID.
5. **`agentcapsule-admin`**: create the replica from a snapshot; promote it
   (new epoch, unwrap with the unlock key); replay the revocation records into
   PostgreSQL; reconcile PostgreSQL with the authority (copy revocation
   subjects back into `revocation_catalogue`, resume deletions, report stores
   whose registration or incarnation differs).
6. **Degraded mode**, as question 2 decides, with metrics (replica lag, last
   acknowledged sequence, degraded since) and alerts in
   `deploy/prometheus/alerts.yml`.
7. **Model.** In `spec/restore_authority.qnt`: a replica and a promotion; the
   degraded window if it is allowed; PostgreSQL behind the root after a
   failover. Go projections for the key runs that have none yet
   (`destructionWaitsForAllCachedCopiesTest`,
   `destructionRequiresPermanentSealTest`,
   `destroyedKeyCannotDecryptOldBackupTest`, `liveKeyDecryptsBackupTest`,
   `oldImageDoesNotReviveDestroyedKeyTest`).
8. **Tests.** Kill the primary between its commit and the acknowledgment;
   stop the standby; bring the old primary back after a promotion; replay
   twice; check that a destroyed key is gone from the replica.
9. **Docs.** recovery.md: install the replica, the failover steps for the
   authorities, the list of secrets to keep off the host.
   [key-authority.md](../guest/key-authority.md) and
   [worker.md](../worker.md): the replica and the service.
   [service-accounts.md](../api/service-accounts.md): drop the manual token
   rotation after a restore. REC-03's exercise times the authority steps.
10. **Later, not blocking.** Give LLM provider credentials their own
    rotatable key, instead of one derived from the receipt key (LLM-01).

## 6. Questions for the product owner

1. **The option.** Is (a), built in, the choice, with the third host of (c)
   as a later step if needed?
2. **The standby unreachable.** Should every authority write wait until it
   returns? Or, after a short delay (proposed: 30 seconds), should some
   writes continue in an alerted degraded mode, and reach the replica when it
   returns? Proposed:
   - continue: outcome records, fence revisions and revocations. Blocking a
     revocation would leave access open. If a disaster ends a degraded
     period, its losses are announced as a time window, every bearer token
     issued before the failover is revoked, and every delegation trust's
     `minimum_iat` moves to the failover time;
   - wait: seals, new keys and key destruction. Creating or deleting an agent
     then waits too. A destroyed key that only the replica still held would
     come back after a failover.
3. **Secrets on the standby.** Wrapped to an unlock key kept off both hosts
   (one more human step at failover; a compromised standby does not expose
   agents' memory), or in clear (no human secret at failover; the standby is
   as sensitive as the primary)? Proposed: wrapped.
4. **Both hosts lost.** Should volume keys also be escrowed in S3, wrapped to
   the unlock key, so that agents' memory survives with S3 alone? A
   destroyed key would then stay recoverable from S3 until its old version
   expires: about a day, in a bucket without object lock and with a one-day
   rule for old versions. Proposed: no escrow.
   With both hosts lost, the database is restored from S3, but not the
   agents' memory.
5. **ADR 003 question 1.** With (a), delivered outcomes lost in the database
   window are declared one by one. Invocations admitted but not delivered in
   that window are still announced as a time window. Is that enough, or
   should ADR 004 move PostgreSQL to synchronous replication (no database
   window on failover; each commit waits for the standby)?

## Decision

November 13, 2026. The product owner chose:

- **Option (a): a synchronous replica of the authorities on the standby,**
  built into the platform (question 1). The third host of (c) stays a later
  step if depending on the standby proves costly.
- **The token secrets in idempotency receipts** (section 1, "Short-lived
  material"): they stay in the receipt, encrypted with a **daily key kept in
  the authorities and destroyed after 24 hours**. A backup older than a day
  then holds receipts that nothing can decrypt. The replay of a request keeps
  its current behaviour.

Questions 2 to 5 take the proposed answers until the product owner says
otherwise:
- (2) degraded mode after 30 seconds without the standby, for outcome
  records, fence revisions and revocations; seals, new keys and key
  destruction wait;
- (3) secrets on the standby are wrapped to an unlock key kept off both hosts;
- (4) no escrow of volume keys in S3;
- (5) the database window stays announced as a time window; PostgreSQL keeps
  its asynchronous WAL archiving.
