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

The model now has the replica, the promotion, degraded mode and PostgreSQL
behind the root: see [Model revision](#model-revision-d-05-option-a).

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

### Implementation status

November 13, 2026. The synchronous path of §5, items 1 to 3, is built:
- **The stream** (`internal/authoritylog`). One stream for both authorities.
  Each record has an epoch, a sequence number and the digest of the record
  before it. A catalogue write commits its record in its own SQLite
  transaction; a key write goes through the same transaction. The write
  returns once the replica holds the record on disk. Every transaction first
  resends what the replica lacks, so a crash between the commit and the
  acknowledgment is resent from the replica's last sequence. The log drops a
  record once acknowledged.
- **Wrapping.** HPKE from Go's standard library (`crypto/hpke`):
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. No new
  dependency. The primary holds the recipient only.
- **The replica** (`restoreauthority.Replica`): one SQLite file, created from
  a snapshot of the primary. It applies in order and refuses a gap, another
  epoch, or a changed duplicate. Destroying a key deletes its wrapped copy in
  the same record. It never opens as an authority. `restoreauthority.Promote`
  is the internal promotion: unlock key, same identities, next epoch.
- **Transport.** Mutual TLS 1.3 over TCP with pinned self-signed
  certificates that name both identities. The replica runs as
  `agentcapsule-authority serve` on the standby. On the primary, the worker
  keeps its authorities in process (`authority_replica` in its
  configuration).
- **Standalone mode** stays the default, with no disaster protection. A
  snapshot arms both authorities; armed, they refuse to run without the
  replica.

Later waves: degraded mode and its alerts (question 2), revocation records
for access (§5.4), the promotion and reconciliation commands (§5.5), the
daily receipt key, and the authority service on a local socket (§5.3).
[recovery.md](../recovery.md#the-authorities-replica-d-05) installs the
replica.

## Model revision (D-05, option (a))

November 13, 2026. **Status: written by the modeling session; not yet
reviewed. Two findings need the product owner (see
[Findings](#findings-for-the-product-owner)).** This is the contract diff
of §5 item 7, written like
[ADR 003's](003-restore-rpo.md#model-revision-option-b). Files:
[restore_authority.qnt](../../spec/restore_authority.qnt) (the model),
[restore_authority_test.qnt](../../spec/restore_authority_test.qnt) (runs) and
[restore_witness.qnt](../../spec/restore_witness.qnt) (fixed schedules).

### Contract diff

| Guarantee | Before | Now |
| --- | --- | --- |
| The root survives the loss of the primary | Assumed (`ROOT_ROLLBACK=false`); nothing in the model lost the root | Earned: every acknowledged write is on the replica's disk (`acknowledgedWritesReplicated`), and the promotion makes the replica the root. The exceptions are the writes degraded mode lets through. |
| `revocationsSurvive`, `keyDestructionSurvives`, `permanentSeals`, `identitiesFresh`, `declaredLossesSurvive`, `rerunsFollowDeclaredLoss` | Hold while the root is never rolled back | Unchanged in meaning, and now hold across a promotion, a resent log and a return of the old primary |
| `noUndeclaredLoss` | An acknowledged outcome missing from an active store is declared lost for this image | **Weaker:** or it was acknowledged in a degraded period that a disaster ended, and that period is announced as a time window |
| `noSilentRerun` | An acknowledged event runs again only after its loss is declared | **Weaker:** or it falls in an announced time window |
| Revocations of access | Outside the model | `noRevivedAccess`: once the API opens, PostgreSQL holds every acknowledged access revocation |
| PostgreSQL behind the root | Not modeled ([store_enrollment.qnt](../../spec/store_enrollment.qnt) says so) | Reconciled before the API opens: `noRevivedAccess`, `subjectsCopiedBack`, `deletionsResumed`, `divergenceReported` |
| The old primary | Not modeled | `oldPrimaryFenced`: the promoted authority never takes its writes |
| Fence receipts | Bound to a store and an incarnation | Also bound to an **epoch**: a receipt signed under another epoch is refused |

What may be lost when a disaster ends a degraded period, by kind of write:

| Write | In degraded mode | If lost with the primary |
| --- | --- | --- |
| Outcome record (and a rerun's record) | Continues | Announced as a time window. The job may run again. |
| Fence revision | Continues | Nothing to cover: every store is restored into a new incarnation, and old receipts are refused by epoch |
| Start of a revocation (its subject and revision) | Continues: fences and key grants stop at once on the primary | Never confirmed as done. PostgreSQL's copy survives if the WAL shipped it. |
| Revocation of a bearer token | Continues | Covered by the blanket revocation of every token issued before the failover |
| Completion of a revocation; revocation of a standing grant | **Waits** in the model. The decision lets it continue: see [finding 1](#findings-for-the-product-owner). | — |
| Incarnation reservation, declared loss, seal, new key, key destruction | Waits | — |

### New state and actions

The root gains `accessRevoked`: the records of access revocations. A
**bearer token** (`TOKENS`) stands for an API token, a service token, a
platform credential or a delegated JWT. A **standing grant** (`GRANTS`)
stands for a membership, team membership, assignment, mandate, delegation
trust, organization or LLM provider.

New state, outside the root:

- `epoch`: the writer's epoch. Receipts carry it.
- The standby: `hasStandby`, `link` (reachable), `received` (what it has) and
  `replica` (what is on its disk).
- `degraded`, and the writes acknowledged in degraded mode and not yet on the
  replica: `degradedAcks`, `degradedRevoked`, `degradedAccess`.
- The disaster: `primaryLost`, `failedOver`, and the old primary's host:
  `oldUp`, `oldEpoch`, `oldRoot`.
- PostgreSQL: `pg` (its revocations, revocation subjects, deleted stores and
  incarnations), `pgBackup` (what the standby can promote: the database
  window), `apiOpen`, `reconciled`, `reported`.
- Announcements: `window` (outcomes acknowledged in a degraded period that a
  disaster ended), `blanket`.
- Ghosts: `everRevokedAccess` (acknowledged access revocations),
  `blanketCovered`, `staleWriter`.

Every root write names its kind (`WriteKind`). `canWrite` lets it proceed when
the replica is in step, when no standby exists (after a promotion, until a
new one is seeded), or in degraded mode for the kinds degraded mode allows.
`replicated` is the replica's side of the write: with `SYNC_ACK` the write
returns once the replica has it on disk.

New actions:

| Action | What it models |
| --- | --- |
| `loseLink`, `restoreLink` | The standby becomes unreachable, then reachable |
| `enterDegraded` | The delay (30 seconds) passes without the standby |
| `resync` | The replica catches up from its last sequence; degraded mode ends |
| `crashStandby`, `flushReplica` | The standby restarts and loses what was not on disk; or writes it. Both are disabled while `SYNC_ACK` holds. |
| `losePrimary` | A disaster: the primary host is lost with its stores, worker, API and PostgreSQL |
| `promote` | The operator promotes the standby once the old primary is stopped. New epoch. PostgreSQL is promoted from `pgBackup`. After a degraded period: the window is announced and every bearer token is revoked. The authority then runs alone. |
| `oldPrimaryReturns`, `oldPrimaryResends` | The old host comes back and resends its log under its epoch |
| `seedStandby` | A new standby starts from a snapshot of the root |
| `shipWal` | PostgreSQL's WAL reaches the standby |
| `revokeAccess(g)` | An access revocation: the record in the root, then the PostgreSQL commit |
| `reconcileDatabase` | Replays the root's access records into PostgreSQL, keeps PostgreSQL's own in the root, copies revocation subjects back, resumes deletions, reports stores whose incarnation differs |
| `openApi` | The API opens; with `REPLAY_FIRST`, only after the reconciliation |

New switches: `SYNC_ACK`, `FENCE_OLD`, `NEW_EPOCH` and `REPLAY_FIRST` (guards),
`DESTROY_DEGRADED` (broken: destruction continues in degraded mode) and
`DECIDED_REVOCATIONS` (degraded mode exactly as decided). The safe
configuration is `restoreAuthorityOk`. The focused simulation uses
`restoreAuthorityFailover`, the same with three incarnations.

### Invariants

All of them are part of `safety`.

| Invariant | Meaning |
| --- | --- |
| `acknowledgedWritesReplicated` | While a standby exists, every acknowledged write is on its disk: outcomes, revocations, access revocations, seals, destroyed keys, declared losses and reservations. Only what degraded mode let through since the last resync is missing. |
| `oldPrimaryFenced` | The promoted authority never takes the old primary's writes |
| `noRevivedAccess` | Once the API is open, PostgreSQL holds every acknowledged access revocation: the older database revives no access |
| `subjectsCopiedBack` | ... and every revocation subject of the root |
| `deletionsResumed` | ... and every seal of the root: no deleted agent, and so no destroyed key, comes back |
| `divergenceReported` | ... and every store whose incarnation in PostgreSQL differs from the root's is reported |
| `noUndeclaredLoss`, `noSilentRerun` | As in option B, plus the announced time window |

The other invariants are unchanged: `retiredBeforeInstall`,
`identitiesFresh`, `permanentSeals`, `revocationsSurvive`, `acksSound`,
`noRestoredRevocation`, `activationCurrent`, `noStaleEffect`,
`keyDestructionSurvives`, `erasedKeysUnavailable`, `declaredLossesSurvive`,
`lossesNameAcknowledgedWork` and `rerunsFollowDeclaredLoss`.

**A destroyed key never comes back.** Destruction waits for the replica, so
`keyDestructionSurvives` holds after any promotion
(`destroyedKeyNeverReturnsAfterFailoverTest`). With destruction allowed in
degraded mode, the promotion brings the key back
(`restoreWitnessDegradedDestructionBroken`).

**A bearer token's lost revocation is covered.** The token is revoked in
degraded mode, the revocation is lost with the primary, the blanket revokes
it again at the promotion, and the reconciliation writes it into PostgreSQL
before the API opens (`tokenRevocationCoveredByBlanketTest`). This holds for
bearer tokens only: see finding 1.

### Checks

Every `spec/*.qnt` typechecks. `quint test`: `restoreAuthorityTests` (34
runs), `restoreAuthorityRepeatedRestoreTests` (3),
`restoreAuthorityMissingHistoryTests` (2), `restoreAuthorityRollbackTests`
(1), the new `restoreAuthorityReplicaTests` (15) and
`restoreAuthorityDecidedDegradedTests` (3). All pass.

New positive runs: `acknowledgedWriteIsOnReplicaTest`,
`destroyedKeyNeverReturnsAfterFailoverTest`,
`destructionResumesAfterResyncTest`,
`oldPrimaryCannotResendAfterPromotionTest`,
`restoredImageRescansUnderNewEpochTest`,
`tokenRevocationCoveredByBlanketTest`, `grantRevocationWaitsForReplicaTest`,
`grantRevocationResumesAfterResyncTest`,
`subjectRevocationCompletesAfterResyncTest`,
`degradedOutcomeIsAnnouncedAsWindowTest`,
`syncOutcomeIsDeclaredOneByOneTest`, `resyncEndsDegradedModeTest`,
`reconciliationReplaysRootTest`, `shippedDatabaseNeedsNoReportTest`,
`promotedAuthorityRunsAloneUntilSeededTest`.

Negative witnesses. Each guard runs on the safe configuration and ends with
the step its guard refuses; each broken schedule removes that guard and
violates the named invariant at its last step, and not before.

| Broken guard | Schedule | Violated invariant | At step |
| --- | --- | --- | --- |
| The replica acknowledges before the write is on disk (`SYNC_ACK=false`) | `restoreWitnessEarlyAckBroken`: a seal, the standby restarts, the primary is lost, promotion | `permanentSeals` | 6 of 6 |
| The old primary is not fenced (`FENCE_OLD=false`) | `restoreWitnessUnfencedBroken`: a key is destroyed after the promotion, the old primary returns and resends | `keyDestructionSurvives` | 11 of 11 |
| Promotion without a new epoch (`NEW_EPOCH=false`) | `restoreWitnessSameEpochBroken`: in degraded mode the old primary gives revision 1 to subject 0 and a restoring image keeps the signed receipt; the promoted root gives revision 1 to subject 1; the old receipt binds; the image activates without fencing subject 1 | `activationCurrent` | 15 of 15 |
| Key destruction in degraded mode (`DESTROY_DEGRADED=true`) | `restoreWitnessDegradedDestructionBroken` | `keyDestructionSurvives` | 11 of 11 |
| PostgreSQL opened before the replay (`REPLAY_FIRST=false`) | `restoreWitnessEarlyOpenBroken`: a membership revoked after the last WAL shipment | `noRevivedAccess` | 4 of 4 |
| Degraded mode as decided (`DECIDED_REVOCATIONS=true`), a standing grant | `restoreWitnessDecidedGrant` | `noRevivedAccess` | 7 of 7 |
| Degraded mode as decided, a revocation subject | `restoreWitnessDecidedSubject`: after the failover a restored image runs the revoked job | `noStaleEffect` | 19 of 19 |

The guards are `restoreWitnessEarlyAckGuard`, `restoreWitnessUnfencedGuard`,
`restoreWitnessSameEpochGuard`, `restoreWitnessDegradedDestructionGuard`,
`restoreWitnessEarlyOpenGuard`, `restoreWitnessDecidedGrantGuard` and
`restoreWitnessDecidedSubjectGuard`; all pass, with `safety` at every step.
The eight earlier schedules still violate their invariant at their last step.

Simulations of `safety` (rust backend), with `--witnesses` counting the traces
that reach each situation:

| Situation | Undirected: `restoreAuthorityOk`, `step`, 30 steps, 100,000 traces | Focused: `restoreAuthorityFailover`, `focusedStep`, 80 steps, 100,000 traces |
| --- | --- | --- |
| Violations | 0 | 0 |
| Degraded mode entered | 20,363 | 97,805 |
| A promotion | 79,938 | 74,087 |
| A promotion that ended a degraded period (blanket) | 9,267 | 43,766 |
| A lost token revocation covered by the blanket | 1,113 | 8,261 |
| An announced time window | 17 | 9,439 |
| PostgreSQL reconciled after a promotion | 32,710 | 67,039 |
| The API reopened after a promotion | 9,681 | 59,947 |
| A store restored and active after a promotion | 6 | 29,652 |
| ... in a trace with an announced window | 0 | 1,486 |
| A loss declared after a promotion | 0 | 7,545 |
| A new standby seeded | 36,139 | 70,770 |
| A second promotion | 9,100 | 38,915 |

The undirected simulation rarely restores a store after a promotion: that
needs ten steps in order. The focused step gives each step of a restore, of a
delivery and of a failover its own branch, and lets a disaster happen only
after an acknowledged outcome. It explores fewer behaviors, not other ones.
Neither simulation is exhaustive; `quint verify` needs Java, which this
environment lacks. The seeds are `0x5eed1` (undirected) and `0x5eed2`
(focused).

The focused simulation also finds every broken configuration within its
first traces. The first invariants to fail: `acknowledgedWritesReplicated`
for `restoreAuthorityEarlyAck` and `restoreAuthorityDegradedDestruction`;
`oldPrimaryFenced` (with `revocationsSurvive`) for `restoreAuthorityUnfenced`
and `restoreAuthoritySameEpoch`; `divergenceReported` for
`restoreAuthorityEarlyOpen`; `revocationsSurvive` for
`restoreAuthorityDecidedDegraded`.

### Go projections of the key runs

Written by hand from the runs, against the packages as they are today, in new
files only.

| Quint run | Go test | Coverage |
| --- | --- | --- |
| `liveKeyDecryptsBackupTest` | `TestLiveKeyDecryptsBackup` (`internal/keyauthority/model_runs_test.go`) | Full. A backup is symbolic: the master key sealed under the volume key, as in a LUKS header. |
| `destructionWaitsForAllCachedCopiesTest` | `TestDestructionWaitsForAllCachedCopies` (same file) | In part. `Revoke` waits for every active `WithKey` holder and publishes no tombstone meanwhile. A guest's copy after the callback is the worker's obligation (physical retirement before `Revoke`). |
| `destroyedKeyCannotDecryptOldBackupTest` | `TestDestroyedKeyCannotDecryptOldBackup` (same file) | Full on the primary: the backup no longer opens, no second key is made, and no file of the authority still holds the key. The same check on the replica waits for the replica. |
| `destructionRequiresPermanentSealTest` | `TestDestructionRequiresPermanentSeal` (`internal/restoreauthority/key_runs_test.go`) | In part. The catalogue gives the evidence (acknowledged, not sealed; sealed for good after `RecordRetiredSeal`). The refusal is not in these packages: `keyauthority.Revoke` takes no seal, and only the worker orders the seal first. It needs the authority service, which owns both directories. |
| `oldImageDoesNotReviveDestroyedKeyTest` | `TestOldImageDoesNotReviveDestroyedKey` (same file) | Full, on both authorities: the old image declares its loss and activates; the revocation, the seal and the key stay. |

None of the new runs (promotion, degraded mode, reconciliation) has a Go
projection yet: they need the replica code.

### Findings for the product owner

1. **Degraded mode as decided revives some revocations.** The decision lets
   every revocation continue without the standby. The blanket revocation at
   the failover covers bearer tokens and delegated JWTs only. It does not
   cover memberships, team memberships, assignments, mandates, delegation
   trusts, organizations, LLM providers, nor the restore authority's
   revocation subjects (`agent/…`, `request/…`, `event/…`). Two witnesses:
   - `restoreWitnessDecidedGrant`: a member is removed while the standby is
     unreachable; the primary is lost before PostgreSQL's WAL ships. After the
     failover the membership is active again. Their issuer signs a new JWT,
     newer than the moved `minimum_iat`, and they are back in.
   - `restoreWitnessDecidedSubject`: a request is revoked to completion in
     degraded mode; after the failover a restored agent runs its job.

   The exposure is narrow: a disaster must end a degraded period, and the
   revocation must fall in the database window (about 5 minutes, at most 15).
   PostgreSQL's copy survives otherwise, because the reconciliation keeps it
   (`shippedGrantRevocationSurvivesTest`). It still contradicts the product
   spec: "A restore never revives memberships, assignments, tokens,
   delegations or keys revoked since the backup."

   The model's safe configuration uses this rule instead: **in degraded
   mode, a revocation starts at once on the primary (access closes there,
   fences and key grants stop), but it is confirmed as done only once the
   replica holds it. A bearer token's revocation is confirmed at once: the
   blanket covers it.** Options for the product owner:
   - (a) adopt that rule. The API answers "pending" for such a revocation
     until the standby returns. The announcement after a disaster lists the
     window in which pending revocations must be made again;
   - (b) keep "continue", and also write each revocation record made in
     degraded mode to a copy off both hosts that does not need the standby
     (the S3 bucket of the WAL), before confirming it. The promotion replays
     those records. Revocations keep RPO 0 while S3 is reachable;
   - (c) accept the exception, and change the product spec to say so.

2. **Degraded mode cannot be fenced by epochs.** With two hosts, the primary
   cannot tell an unreachable standby from a promoted one. If the standby is
   promoted while the old primary still runs, the old primary enters degraded
   mode after 30 seconds and keeps confirming outcomes and revocations that
   the new side never sees, after the announced window has ended. The model
   assumes it away: `promote` requires the old primary to be lost. So the
   failover procedure must stop the old primary first (power it off through
   the provider), and an authority that restarts must not write, even in
   degraded mode, until it has reached its replica at the current epoch.

Two more consequences, for confirmation:

3. **After a promotion the authority has no replica** until a new standby is
   seeded. The model lets it write alone, every kind included: no replica
   exists, so nothing can roll it back, and losing that host is "both hosts
   lost" (question 4). If seals, new keys and key destruction waited there
   too, deleting or creating an agent would wait for a new standby, and so
   would the incarnation reservation of every restore: the failover could not
   finish within the RTO. The code must tell "no standby" from "standby
   unreachable".
4. **The decision does not name incarnation reservations, declared losses
   and reruns.** The model lets a rerun's record continue (it is an outcome
   record) and makes reservations and declarations wait: a lost reservation
   would reuse an incarnation, a lost declaration would withdraw an announced
   loss. So no agent is restored on the primary while the standby is
   unreachable.

### What the code must do

For the replication core (being built):

1. One ordered stream for both authorities. Each write carries an epoch and
   a sequence number. The replica applies writes in order, writes them to
   disk (`fsync`), then acknowledges. It refuses a gap, a sequence number
   already applied with other content, and any epoch but its own
   (`SYNC_ACK`, `restoreWitnessEarlyAckBroken`).
2. A write returns only after the replica has acknowledged its sequence
   number. Until then nothing on the primary acts on it: hold the write lock
   until the acknowledgment, or sign receipts and archives only from
   acknowledged state. The model's write is one step.
3. On restart the primary resends from the replica's last sequence number
   before any new write.
4. Destroying a key removes the replica's wrapped copy in the same write. The
   replica needs the check of `TestDestroyedKeyCannotDecryptOldBackup`: no
   file still holds the key.
5. One authority service owns both directories and checks the seal in the
   write that destroys a key (`destructionRequiresPermanentSealTest`, now
   only in the worker).

For revocation records:

6. Each access revocation appends a record before its PostgreSQL commit
   (§5 item 4). The record names its kind: bearer token (API token, service
   token, platform credential, delegated token ID) or standing grant (member,
   principal, organization, team membership, assignment, mandate, delegation
   trust, LLM provider).
7. The API confirms a revocation only once its record is on the replica,
   except a bearer token's in degraded mode (finding 1, pending the product
   owner).
8. Outcome records keep the event ID (§5 item 4).

For promotion and reconciliation:

9. Promotion writes a new, strictly greater epoch to disk before its first
   write (`NEW_EPOCH`).
10. Fence receipts carry the epoch inside their MAC.
    `RecordVerifiedFence` and the activation refuse a receipt from another
    epoch (`restoreWitnessSameEpochBroken`). Today `Receipt` has no epoch,
    and the catalogue's secret is replicated, so an old receipt would verify.
11. The promoted authority refuses every write, resend or replication stream
    of an older epoch, and stops its replica listener (`FENCE_OLD`,
    `restoreWitnessUnfencedBroken`). The old host comes back only wiped, as a
    new standby seeded from a snapshot.
12. The failover procedure stops the old primary before the promotion
    (finding 2). recovery.md says how.
13. After a promotion, and until a new standby is seeded, every write
    proceeds (finding 3).
14. If the standby's last contact with the primary is older than the
    degraded delay, the promotion assumes a degraded period ran. It
    announces the window from that contact to the failover, revokes every
    bearer token issued before the failover, and moves every delegation
    trust's `minimum_iat` to the failover time. The token revocation is an
    authority record, so the reconciliation replays it.
15. `agentcapsule-admin` reconciles before the API opens, and the API refuses
    to start until it has, for the current epoch (`REPLAY_FIRST`,
    `restoreWitnessEarlyOpenBroken`):
    - replay every access record into PostgreSQL;
    - keep PostgreSQL's own revocations and revocation subjects in the
      authority too, so that one shipped by the WAL but lost from the
      authority survives;
    - copy the revocation subjects into `revocation_catalogue`;
    - resume the deletion of every store the authority has sealed;
    - report every store whose registration or incarnation in
      `store_enrollments` differs from the authority's.

For degraded mode:

16. Entered only by a writer at the current epoch, after the delay, with the
    metrics and alerts of §5 item 6.
17. Continue: outcome records (reruns included), fence revisions, the start
    of a revocation, and a bearer token's revocation. Wait: the completion of
    a revocation, a standing grant's revocation (finding 1), incarnation
    reservations, declared losses, seals, new keys and key destruction
    (`restoreWitnessDegradedDestructionBroken`).
18. When the standby returns, resend the degraded writes before any other,
    and leave degraded mode only once the replica has acknowledged the last
    one.

The model does not cover the unlock key, wrapping, both hosts lost, or
liveness: it shows what can be lost and what cannot, not that a restore
eventually completes.
