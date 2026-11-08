# Go API: installation, accounts and agents

This executable part provides accounts, personal tokens, agent reservation,
operation tracking, wake/sleep commands, encrypted instructions, consent, and
private reading of requests and responses. The end-to-end agent-to-agent
business flow is still in progress (see the [roadmap](../../ROADMAP.md)); this
API must not be presented as the complete PaaS.

The organization domains are documented separately:
[platform administration](organizations.md),
[tenant authentication](tenant-identity.md), [member management](members.md)
and [teams](teams.md).
Their credentials grant no rights on the legacy routes described below.
Tenant agents and their assignments are described in
[agents-assignments.md](agents-assignments.md).

```sh
go build -trimpath -o bin/agentcapsule-admin ./cmd/agentcapsule-admin
go build -trimpath -o bin/agentcapsule-api ./cmd/agentcapsule-api
```

Provide `AGENTCAPSULE_DATABASE_URL` through the service's protected
environment. The installation command is local; it is not an HTTP endpoint.
First create a private directory owned by the account that will run the API:

```sh
install -d -m 700 "$HOME/.local/state/agentcapsule"
bin/agentcapsule-admin bootstrap \
  -receipt-key-file "$HOME/.local/state/agentcapsule/receipt.key" \
  -token-file "$HOME/.local/state/agentcapsule/admin.token"
bin/agentcapsule-api \
  -receipt-key-file "$HOME/.local/state/agentcapsule/receipt.key" \
  -host-id local \
  -listen 127.0.0.1:8080
```

Bootstrap applies the migration and writes the secrets to private files
without printing them. Retrying with the same files confirms the same token
without extending its lifetime. After an unknown commit result, keep these
files and rerun the same command. Existing files are never overwritten. Do not
replace the receipt key: it is needed to re-read idempotent responses, notably
the issuance of a personal token.
Its fingerprint is bound to the installation; a lost or replaced file cannot
silently reset this key. The API refuses to start with a different key, and its
readiness probe also checks this binding.

**Stuck provisioning.** A reservation whose worker can never finish creation
(for example an unserved release) used to leave the agent in `PROVISIONING`,
undeletable, and the owner could not reserve another one.
`agentcapsule-admin abandon-provisioning -agent-id <id>` removes it, but only
while no physical resource exists: step `INSTALLING`, no registered volume, no
placement, no seal and no active work lease. Beyond that point the command
refuses and regular deletion applies. A volume file that was created and then
lost before being registered is not tracked: the operator removes it.

**Tenant audit trail.** `GET /v1/audit` (scope `audit:read`, role `org_owner`,
`org_admin` or `auditor`) lists the organization's events with an opaque
cursor: members, teams, agents, assignments, service accounts and organization
lifecycle. Each event carries only the actor, the action, the target and a
reference: never a token, a secret or content. An event is written only in the
transaction of the mutation it describes.

**Tenant service accounts.** See [service-accounts.md](service-accounts.md).

**Tenant agents and assignments.** See [agents-assignments.md](agents-assignments.md).

**Receipt retention.** On each pass the worker deletes, in bounded batches, the
expired idempotency receipts (24 h) of both the legacy and tenant domains
(`Store.PurgeExpiredReceipts`). The private transit content of requests that
were refused or expired without delivery has no purge deadline yet: this
depends on the future of the legacy owner messaging and on EVT-04.

**Credential rotation and revocation.** `agentcapsule-admin list-credentials`
prints, without secrets or fingerprints, the platform and service credentials
(type, identifier, account, expiry, state). `agentcapsule-admin revoke-credential
-kind platform|service -id <id>` permanently and idempotently revokes one. To
replace it, rerun `bootstrap-platform` or `bootstrap` with a **new** token file:
a secret that was already stored is never accepted again, and a second active
credential is refused. An expired credential is replaced the same way. Permanent
errors are reported with a `..._rejected_<reason>` code, and only an unknown
commit result invites a retry.

The API runs under an unprivileged account with no access to the runtime. It
expects an already migrated schema. HTTP without TLS is limited to a loopback IP
address; a remote listener requires `-tls-cert` and `-tls-key`. An HTTPS reverse
proxy can also reach the local listener. Keep `/v1/health/ready` on the internal
network. Logs contain only fixed codes and never tokens, DSNs, request bodies or
private responses.

The available routes are described in the canonical contract
[openapi/openapi.yaml](../../openapi/openapi.yaml). Creations require an
`Idempotency-Key`. The same identity, route, key and input replay the initial
response for 24 hours; a different body gives `422`, and a concurrent call
already in a transaction gives `409`. A revocation is checked before an old
receipt is read again. Personal tokens are stored as hashes; their replayable
issuance responses are encrypted with the receipt key.

## Private instructions

`POST /v1/agents/{id}/messages` accepts the format
`{"content":[{"type":"text","text":"Hello"}]}`. Only the owner can send it;
service tokens are refused. The `202` receipt contains an operation reference.
The encrypted content, this operation, the event in the shared FIFO queue and
the receipt are recorded in a single commit. No mandate is created at this
step; the first authorized send creates it and replays do not renew it. The
worker must be configured with the transit keys. The `202` receipt means the
request is stored; the `SUCCEEDED` status means the harness result was recorded
together with the end of the operation.

A lost response leaves the request to be resumed with the same event and the
same mandate. The harness keeps the effect and the result in a single SQLite
transaction. Before abandoning an uncertain instruction, the worker revokes its
mandate and waits for its durable barrier. `delivery_outcome_unknown` means the
effect may have happened; it is not proof of non-execution.

`GET /v1/operations/{id}/result` is reserved for the owner. It returns `404`
while no completed result is available, after expiry, or after deletion.
The administrative service can read the technical status, never this content
directly. With `user:manage`, however, it can issue a user token
(`POST /v1/users/{id}/tokens`), and that token opens that user's content.
Issuance is therefore traced (`api_tokens.issued_by_token_id`, migration 0008);
forbidding or limiting it remains an open decision.

Admission requires a distinct transit key, supplied in a private 32-byte file
kept outside PostgreSQL. For existing files:

```sh
bin/agentcapsule-admin activate-transit-keys \
  -active-key v1 -key v1=/private/path/transit-v1.key
bin/agentcapsule-api \
  -receipt-key-file /private/path/receipt.key -host-id local \
  -transit-active-key v1 -transit-key v1=/private/path/transit-v1.key
```

Rotation explicitly activates a new identifier together with all the keys still
needed for unpurged content. Activation never replaces the secret associated
with an existing identifier. An old process can no longer write with the
previously active identifier. Ordinary opening initializes nothing. Transit keys
are distinct from volume keys and from API receipt keys.

Bodies are encrypted with AES-GCM and bound to their business reference and
their parties. Deleting an agent immediately removes the current ciphertexts
that concern it; its business finality still waits for the revocation barriers.
Retention after delivery is seven days in the API binary; a read does not push
back the deadline. Each pass of a worker configured for transit purges a bounded
batch of expired content.
This SQL purge does not delete copies held in backups and is not a
rollback-resistant authority: that remains the D5 workstream.
This installation key is not a key for erasing an agent's data.

Before the first creation, configure the capacity of the same host as the worker
and approve the verified local image. These commands require an already
migrated schema:

```sh
bin/agentcapsule-admin configure-host -host-id local -storage-mib 4096
bin/agentcapsule-admin approve-local-harness \
  -name reference -version 1.0.0 -artifact /path/to/product.initrd
```

A version cannot be reassigned to a different digest. The worker must be
configured with this same image, the key authority and the dedicated UID range,
as described in [its documentation](../worker.md).

`POST /v1/agents` returns `202` with `agent_id` and `operation_id`. Poll
`GET /v1/operations/{operation_id}` until it reaches an outcome; the initial
receipt stays `PENDING` on a replay, even after completion. The agent stays
`PROVISIONING` during volume creation and revocation catch-up. Once activated,
it stays stopped unless `auto_start=true` was requested.

`POST /v1/agents/{id}/wake` and `/sleep` take a JSON body `{}` and an
`Idempotency-Key`. These commands are ordered per agent and resumable after a
crash. Deletion cancels those that are still open. Sleeping keeps the volume; a
later event can wake the agent. The completed operation reports
`unclean_stop=false` only after the quiesce is acknowledged and the VM is
physically removed. An error, a timeout or a lost response forces removal with
`unclean_stop=true`. The physical KVM campaign for this flow has yet to be run.

Tests use real PostgreSQL/SQLite, not an in-memory database:

```sh
python3 scripts/verify-postgres.py --pg-bin /path/to/postgresql/bin --native-tools <tools-dir>
```

This command creates its own cluster on a private Unix socket, runs the tests
with the Go race detector, forces an immediate shutdown of that cluster and
checks WAL recovery. It touches no existing PostgreSQL server. The HTTP tests
also launch the two real executables, then stop the API with SIGTERM. KVM tests
are a separate campaign.

Idempotency locks use [PostgreSQL transactional advisory locks](https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS),
released at the end of the transaction. The HTTP boundary uses the body limits
and routing of the [Go standard library](https://pkg.go.dev/net/http).

## Private exchanges and consent

`DELETE /v1/agents/{id}` requires an `Idempotency-Key` and accepts an empty body
or `{}`. The owner and the administrative service can request it.
The `202` receipt references a single operation even if several keys request
the deletion. It confirms the durable intent, not completed erasure.
Deleting an agent that is still `PROVISIONING` is not handled yet.

`GET /v1/operations/{id}` exposes `deletion_phase`: `FENCING` during the
distributed barriers, `RETIRING` during removal of the runtime, then
`CLEANUP_PENDING`. At this last stage the operation stays `RUNNING` and the
agent `DELETING`: destruction of the key and removal of the volume file are not
yet confirmed. The producing worker durably revokes the key, removes the exact
file, then publishes `SUCCEEDED/COMPLETE` and `DELETED` in a single commit.
An interruption resumes this cleanup without recreating a key or a volume. The
receipt does not claim to delete external copies or backups; D5 is still
required. Physical KVM integration of this chain is prepared but has yet to be
run. A lost barrier is retried; no timeout counts as an acknowledgment. Open
instructions are canceled only after the barriers.

`POST /v1/agent-requests/{id}/cancel`, body `{}` and `Idempotency-Key`, is
reserved for the sending owner. Its `202`/`PENDING` receipt keeps the same value
on replays. Reading the request exposes `closure_state=FENCING` until the
barriers, then `COMMITTED` with the final state `CANCELED`. An already acquired
response or an incompatible closure gives `409`; cancellation does not rewrite
an acquired outcome. The receiving owner and services cannot cancel in place of
the sender.

The owner manages `GET/PUT /v1/me/messaging-settings` with the two fields
`discoverable` and `inbound_mode` (`manual` or `auto`). These routes update the
SQL source used by access checks; the ADS projection and public search have yet
to be wired in. The owner reads `GET /v1/me/inbox` (metadata, `after` cursor,
`state` filter, `limit` <= 100). They accept or decline with a body `{}` and an
`Idempotency-Key`: `POST /v1/me/inbox/requests/{id}/accept` or `/decline`.

`GET /v1/agent-requests/{id}` returns the state, the message and the response
only to the owners of the two agents. Private fields are omitted after purge;
this read does not extend their retention. A third party receives 404 and the
administrative service 403. The mandate and the encrypted message are recorded
with the request in a single transaction; replays do not consume the budget a
second time. Before manual acceptance, no business event is delivered to the
recipient.

The reference harness understands one deterministic instruction:
`/ask <agent-id> <text>`. The owner sends it to their own companion through
`POST /v1/agents/{id}/messages`. The companion stores a send intent, then uses
the platform channel. The immediate result means "recorded", not "delivered".
After consent, the recipient returns the text it received. Even if that text
contains `/ask`, it creates no new request. The return can be read on the
request. The companion also leaves a private message in the owner's inbox,
retried with the same key if its receipt is lost.

A test runs the two real `capsule-echo` processes, the Unix/mTLS gateway,
PostgreSQL and SQLite, with receipt loss and a restart of the sender. The
provisioning observations in it are explicit fixtures. This test does not
replace the complete flow with two VMs and their encrypted volumes.

The `agent_message` items of `GET /v1/me/inbox` carry `message_id` and, where
applicable, `request_id`. Their content is read with
`GET /v1/me/inbox/messages/{message_id}`. Only the owner of the companion that
produced the message can read it; the peer's owner has no such access.
The first read starts the seven-day retention, without renewal on later reads.
Deleting either of the linked agents also purges the current summary. The
metadata and the receipt stay stable.

The `/v1/owner/messages` deposit belongs to the harness's authenticated
platform channel, not to this user API. It takes an idempotency key and text
content, with an optional `request_id`. The owner is derived from the current
boot. Linking to a request requires an acquired response and the sending
companion; it creates no mandate. In the echo harness, the summary reuses the
response text; for a response that is too large, it indicates its presence and
keeps the link to the full request.
