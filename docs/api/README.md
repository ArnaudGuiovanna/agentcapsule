# Go API: installation, accounts and agents

[Building, reviewing and mounting corpora](corpora.md)

The API serves organizations: the platform operator's administration
([organizations.md](organizations.md)), and each organization's members,
teams, agents, invocations and models ([tenant authentication](tenant-identity.md),
[member management](members.md), [teams](teams.md),
[agents-assignments.md](agents-assignments.md)). A new installation follows
[bootstrap.md](../bootstrap.md), from an empty database to an organization's
first owner.

What every role and kind of caller gets on every route is in the
[authorization matrix](rbac.md), which a test checks. Every MVP feature is
shown with curl in [examples.md](examples.md), which a test runs as written.

Where this page speaks of owners, personal tokens, user or service tokens
(`acp_`), `/v1/users` or `/v1/me`, it describes the historical single-owner
accounts. That legacy owner domain is closed: `agentcapsule-api` refuses its
tokens, and no command creates them. Its code remains for tests until they move to
organizations ([ADR 001](../adr/001-organization-identity.md#tenant-transition-and-operator-bootstrap-d-01)).

```sh
go build -trimpath -o bin/agentcapsule-admin ./cmd/agentcapsule-admin
go build -trimpath -o bin/agentcapsule-api ./cmd/agentcapsule-api
```

Provide `AGENTCAPSULE_DATABASE_URL` through the service's protected
environment, naming the API's own role, `agentcapsule_api`
([install.md](../install.md#postgresql)). The installation commands are local; they are not HTTP
endpoints. First create a private directory owned by the account that will run
the API:

```sh
install -d -m 700 "$HOME/.local/state/agentcapsule"
bin/agentcapsule-admin migrate
bin/agentcapsule-admin bootstrap-platform \
  -receipt-key-file "$HOME/.local/state/agentcapsule/receipt.key" \
  -token-file "$HOME/.local/state/agentcapsule/platform.token"
bin/agentcapsule-api \
  -receipt-key-file "$HOME/.local/state/agentcapsule/receipt.key" \
  -host-id local \
  -listen 127.0.0.1:8443 \
  -tls-cert /etc/agentcapsule/api.crt -tls-key /etc/agentcapsule/api.key \
  -tls-server-name api.example.net \
  -authority-socket /run/agentcapsule-authority/api.sock \
  -restore-authority-id restoreauth_… -key-authority-id keyauth_…
```

The last three flags reach the authority service
([below](#the-authority-service)). On a development machine,
`AGENTCAPSULE_MODE=development` lets the API listen in plain HTTP on a
loopback address instead, without the TLS flags
([install.md](../install.md#modes)), and without the authority service.

Add `-metrics-listen 127.0.0.1:9464` to serve Prometheus metrics on loopback
([observability.md](../observability.md)). Each request writes one JSON event,
with its `X-Request-ID`, on standard output.

`bootstrap-platform` applies the migrations and writes the secrets to private
files without printing them. Retrying with the same files confirms the same
token without extending its lifetime. After an unknown commit result, keep
these files and rerun the same command. Existing files are never overwritten.
Do not replace the receipt key: it is needed to re-read the idempotent
responses written without the authority service's daily keys
([below](#the-daily-receipt-keys)), and it seals the LLM providers'
credentials.
Its fingerprint is bound to the installation; a lost or replaced file cannot
silently reset this key. The API refuses to start with a different key, and its
readiness probe also checks this binding.

**Stuck provisioning.** A reservation whose worker can never finish creation
(for example an unserved release) used to leave the agent in `PROVISIONING`,
undeletable, and the owner could not reserve another one.
`agentcapsule-admin abandon-provisioning -agent-id <id> -confirm <id>` removes it, but only
while no physical resource exists: step `INSTALLING`, no registered volume, no
placement, no seal and no active work lease. Beyond that point the command
refuses and regular deletion applies. A volume file that was created and then
lost before being registered is not tracked: the operator removes it. An
organization's agent is not erased, since its audit trail names it: it ends
`DELETED`, its provisioning `CANCELED` with `provisioning_abandoned`, and its
reservation no longer counts against the host.

**Destructive operator commands** ([ADR 014](../adr/014-operations-capacity-diagnostics-audit.md)).
`revoke-credential`, `abandon-provisioning`, `set-audit-retention` and
`configure-delegation` with `rotate`, `revoke-trust`, `revoke-token`, `add-key`
or `retire-key` run only when `-confirm` repeats their target: the credential
ID, the agent ID, the number of days, the issuer (`rotate`, `revoke-trust`),
the token ID (`revoke-token`) or the key ID (`add-key`, `retire-key`). Without it they print `confirmation_required` and touch
nothing. `-dry-run` checks everything and prints what the command would do,
without changing or recording anything. Each command that runs prints its
outcome as JSON (`done`, `unchanged` or `refused` with its reason) and is
audited with it, refusals included, under the local user ID:
`agentcapsule-admin list-audit` prints it with the operator's other actions,
the platform's harness imports and deprecations, and the operator's replays
of dead letters.
Delegation changes stay audited in the organization's trail
(`delegation_audit`).

**Storage pressure.** While a file system of the host is past the worker's
`storage_pressure` ([worker.md](../worker.md#storage-pressure)), creating an
agent and requesting a harness import are refused with `503
storage_pressure` and `Retry-After`, before any reservation.

**Request limits** (v0.1.0 audit, [ADR 014](../adr/014-operations-capacity-diagnostics-audit.md#changes-after-the-v010-audit)).
One caller must not starve the others:

| Limit | Default | Flag of `agentcapsule-api` | Refusal |
|---|---|---|---|
| One principal's requests | 200 at once, then 20 a second | `-principal-burst`, `-principal-rate` | `429 rate_limited` |
| One organization's requests, all its principals together | 1,000 at once, then 100 a second | `-organization-burst`, `-organization-rate` | `429 organization_rate_limited` |
| Failed authentications of one source address (an IPv4 address, or an IPv6 /64) | 60 a minute | `-authentication-failures-per-minute` | `429 authentication_rate_limited` |
| Attachment bodies read at once, in the process and per principal | 16, and 2 | `-max-uploads`, `-max-principal-uploads` | `503 upload_capacity`, `429 too_many_uploads` |
| Event subscriptions per principal and per organization | 32, and 200, under `-max-event-streams` (1,000) | `-max-principal-event-streams`, `-max-organization-event-streams` | `429 too_many_principal_streams`, `429 too_many_organization_streams` ([ADR 022](../adr/022-native-streaming.md#changes-after-the-v010-audit)) |

- Each request limit is a token bucket. A refusal carries `Retry-After`: the
  seconds until the bucket holds a request again. A rate of `0` turns its
  limit off. The health probes and `/v1/version` are never limited.
- The limits apply before the database work, as far as authentication
  allows. A credential that authenticated in the last 15 minutes is charged
  to its principal and organization before the database looks it up again,
  so a caller past its limit costs no SQL; a credential's first request is
  charged after its lookup, before its handler's work. Knowing a credential
  never admits a request: the database still authenticates every request the
  limits let through, so a revocation takes effect at once.
- A source past its failed authentications has its unknown credentials
  refused before they are looked up; a credential that authenticated
  recently still passes. An enrollment proof and an invitation's token count
  as attempts too. A download link's requests count against the principal
  that minted it, read from the link itself.
- An upload is checked before its body is read: its headers, the caller's
  rights and the room under the organization's quota for its declared
  `Content-Length` ([agents-assignments.md](agents-assignments.md#attachments-evt-04)).
- **Each API process keeps its own buckets**, in memory. Behind a load
  balancer, N processes admit up to N times each rate. Behind a proxy, the
  source address is the proxy's: turn the failure limit off there
  (`-authentication-failures-per-minute 0`) and limit at the proxy.
- `agentcapsule_api_limited_requests_total{limit}` counts the refusals, and
  each failed authentication writes an `authentication_failed` event with a
  pseudonym of its source, never the address ([observability.md](../observability.md#events)).

**Tenant audit trail.** `GET /v1/audit` (scope `audit:read`, role `org_owner`,
`org_admin` or `auditor`) lists the organization's events with an opaque
cursor: members, teams, agents, assignments, service accounts, queue limits
(`queue.limits.set`), organization lifecycle, the operator's changes of its
quotas (`organization.quotas_set`), and the replays of dead letters
(`invocation.replayed`, by an administrator or by `operator`, with the
invocation as `reference`). Each event carries only the actor, the action, the target, a
reference and its `outcome`: never a token, a secret or content. An event of
outcome `done` is written only in the transaction of the mutation it
describes.

**Refused attempts** (TEN-009, [ADR 014 §10](../adr/014-operations-capacity-diagnostics-audit.md#10-refused-attempts-in-the-organizations-trail)).
When a route of an audited action refuses a member or a technical account of
the organization, for want of a right (403, or 404 for what it may not see)
or for its input (400, 409, 413, 415, 422), the trail gets an event of
outcome `refused`: the action the route would have recorded, the actor, the
identifiers its path named, and the problem code as `reason`. The request's
body is never recorded, and a path value that is not a platform identifier
(an alias's name, for example) is replaced by the organization's ID. Reads,
invocations, messages and unauthenticated requests leave no event. The event
is written after the answer, in its own transaction. Repeated attempts are
counted: in each minute, an actor's first refused attempt at each target of
an action, for one reason, is an event in full, up to ten targets; the other
attempts of that minute become one event at its end, with the organization
as target and their number in `attempts` (1 for an event in full).

```json
{"id":"audit_…","created_at":"2026-11-16T10:00:00Z","action":"assignment.created",
 "actor":"prn_…","target":"agt_…","outcome":"refused","reason":"not_found","attempts":1}
```

**Audit export** (TEN-06). `GET /v1/audit/export?from=<RFC 3339>&to=<RFC 3339>`,
with the same rights as `GET /v1/audit`, returns every event of the
organization created in `[from, to)`, at most 366 days, as one JSON document
to download (`Content-Disposition: attachment`). A range of more than 100,000
events is refused with `413 audit_export_too_large`: export shorter ranges.

```bash
curl -fsS -H "Authorization: Bearer $AUDITOR_TOKEN" -o audit-2026-q3.json \
  "https://capsule.example/v1/audit/export?from=2026-07-01T00:00:00Z&to=2026-10-01T00:00:00Z"
```

**Audit retention.** Every audit event is kept until the operator sets a
retention (product §7: audit follows the legal context; default pending the
product owner, [ADR 014](../adr/014-operations-capacity-diagnostics-audit.md)).
`agentcapsule-admin set-audit-retention -days 400 -confirm 400` keeps events
400 days (30 to 36500); `-dry-run` prints how many events that would delete
now; `-keep-all` goes back to keeping everything. The worker then deletes older
events of every audit table, tenant and operator alike (the capability policy
changes and the replays of dead letters among them), in batches, and
records each purge in the operator's audit. An export carries
`retention_days` when a retention is set.

**Tenant service accounts.** See [service-accounts.md](service-accounts.md).

**Tenant agents and assignments.** See [agents-assignments.md](agents-assignments.md).

**Receipt retention.** On each pass the worker deletes, in bounded batches, the
expired idempotency receipts (24 h) of both the legacy and tenant domains
(`Store.PurgeExpiredReceipts`). The private transit content of a request is
kept 7 days from its delivery. Content of a request closed before it was
delivered (refused, canceled, expired or failed) is kept 7 days from its
closure, then purged: a default pending the product owner
([ADR 007](../adr/007-delivery-closure-and-priority.md#7-closure-scope-review-fixes-and-closed-requests-content)).
A reply has one purge deadline, 7 days from its delivery or from the death of
its delivery. The worker starts a retention that was never started (a request
closed before delivery, a reply that died before ADR 007) on its first pass
after the closure or the death, and purges on the same pass once a deadline
has passed.

**Credential rotation and revocation.** `agentcapsule-admin list-credentials`
prints, without secrets or fingerprints, the platform credentials (and the
legacy service credentials of a test database): type, identifier, account,
expiry, state. `agentcapsule-admin revoke-credential -kind platform -id <id>
-confirm <id>` permanently and idempotently revokes one, and audits it. To
replace it, rerun `bootstrap-platform` with a **new** token file:
a secret that was already stored is never accepted again, and a second active
credential is refused. An expired credential is replaced the same way. Permanent
errors are reported with a `..._rejected_<reason>` code, and only an unknown
commit result invites a retry.

The API runs under an unprivileged account with no access to the runtime. It
expects an already migrated schema. In production it serves HTTPS only, TLS 1.2
or 1.3, and refuses to start without `-tls-cert` and `-tls-key`, even on
loopback; a reverse proxy in front of it talks HTTPS to it too. It checks the
files at start and reads them again on `SIGHUP`
([install.md](../install.md#api-certificate)). It reaches PostgreSQL over a Unix
socket or with `sslmode=verify-full`. `-preflight` checks this configuration and
exits. In development mode only, HTTP without TLS is allowed on a loopback IP
address. Keep `/v1/health/ready` on the internal network. Logs contain only fixed codes and never tokens, DSNs, request bodies or
private responses.

The available routes are described in the canonical contract
[openapi/openapi.yaml](../../openapi/openapi.yaml); a test checks that the
server serves exactly its routes and methods. Every mutation requires an
`Idempotency-Key`; without one it is refused with `400
idempotency_key_required` before anything happens. The same identity, route,
key and input replay the initial response for 24 hours; a different body
gives `422 idempotency_key_reused`, and a concurrent call already in a
transaction gives `409`. A key reused on another target of the same route is
refused with `422`, or, where the target is part of the route's receipt
(organization disable, organization quotas, release deprecation, agent deletion, wake, sleep,
invocation cancel and replay, held request decisions, attachment deletion),
runs as a new request: it never gives back the first target's answer. The
only routes other than `GET` without a key are the two download-link routes,
which store nothing ([ADR 016](../adr/016-content-links-capabilities.md)),
and `PUT /v1/me/messaging-settings`, of the closed legacy domain. A test
checks all of it on every route. A revocation is checked before an old
receipt is read again. Personal tokens are stored as hashes; their replayable
issuance responses are encrypted with the key of their day
([below](#the-daily-receipt-keys)).

### The daily receipt keys

With the authority service, the API encrypts each new idempotency receipt
with the **daily receipt key** of the day it writes it (UTC), and records
the day with the receipt ([ADR 006](../adr/006-authority-service.md) §7).
The service keeps these keys in the key authority, replicates them to the
standby with the volume keys, and destroys each day's key at 01:00 UTC two
days after its day began, once every receipt of the day has expired. So a
database backup holds no token secret anyone can read once that time has
passed, at most 49 hours after the backup.

- The API keeps today's and yesterday's keys in memory, and asks the
  service for a key it does not hold, at most 5 seconds.
- A replay within 24 hours returns the first response, secrets included,
  as before. After a failover, the promoted authorities hold the same keys.
- A new request whose day's key the service does not give fails before it
  runs: 503 `authority_unavailable`, `Retry-After: 5`. Nothing is
  committed; try again with the same key.
- A replay whose day's key is gone answers 409
  `idempotency_receipt_unreadable`. The request took effect the first time,
  and does not run again: read its result through the API, or send a new
  request with a new key. This happens only after a failover that lost a
  key the old primary created alone while the standby was away
  ([recovery.md](../recovery.md#the-daily-receipt-keys)).
- A receipt written before this release, or by an API in development mode
  without the service, names no day: the installation's receipt key reads
  it until it expires. That key also still derives the key of the LLM
  provider credentials and of the download links, which do not rotate
  ([llm.md](llm.md#known-limits)).

## The authority service

The API reaches the authority service
([ADR 006](../adr/006-authority-service.md)) on its API socket, with three
flags: `-authority-socket`, `-restore-authority-id` and `-key-authority-id`.

- The identities are the ones `agentcapsule-admin init-restore-authority`
  and `init-key-authority` printed: those of the service's `authority.json`
  and of the worker's `authority` section.
- The API's account must be the service's `api_uid`, and a member of the
  group `agentcapsule-authority-clients`, which may open the socket
  ([recovery.md](../recovery.md#install-the-authority-service)). The service
  checks the account on every connection.
- In production the API refuses to start without the three flags
  (`authority_required_in_production`). In development it may run without
  them, and writes
  `development_mode_without_authority_service_never_use_in_production` on
  standard error at each start.
- At start, the API waits for a service that does not answer yet, and logs
  `authority_service_waiting` once. Before it opens the database, it refuses
  a service that holds other authorities (`authority_identity_mismatch`) and
  a socket of another role (`authority_socket_role_mismatch`).
- The readiness probe, `GET /v1/health/ready`, reports the service's mode:
  `{"status":"ready","authority":"synchronous"}`. The mode is `standalone`
  without a standby, `degraded` while the standby is away, and `waiting`
  while a restarted service has not reached its standby yet. While the
  service does not answer with the pinned identities, the probe answers 503
  (`authority_unavailable`).
- **After a failover**, the API refuses to start (`authority_not_reconciled`)
  until `agentcapsule-admin reconcile` has brought the database up to the
  promoted authorities, for their epoch, and the probe answers 503
  `authority_not_reconciled` meanwhile ([recovery.md](../recovery.md#reconcile-the-database)).
  `reconcile` runs as root, with the owner's database role and the API's
  three flags. The authorities of an installation never promoted are at
  their first epoch, which the migrations record as reconciled.
- `-preflight` asks the service once (the `authority` check).
- Every route that revokes access records the revocation with the service
  once it has committed ([below](#revocations-pending-and-confirmed)).

The API takes the daily receipt keys from the same socket
([above](#the-daily-receipt-keys)), and `reconcile` reads the access
revocation records, the revocation subjects and the stores there (ADR 006
§7).

## Revocations: pending and confirmed

A restore never revives an access revoked since the backup
([product.md](../product.md) §3). So every transaction that revokes access
also writes an **access revocation record**, which the API appends to the
authority service once the transaction has committed
([ADR 006](../adr/006-authority-service.md) §7, wave 5, and "Changes after
the v0.1.0 audit"). The service replicates it to the standby, as every
authority write. The API waits for the service with no lock held: a slow or
absent service holds up no other request of the organization.

- **The revocation takes effect at once**, whatever the service does: the
  next call of the revoked member, token or assignment fails. The answer
  carries `revocations`, one entry per record:

  ```json
  {"principal_id":"prn_…","status":"revoked",…,
   "revocations":[{"id":"arv_…","kind":"member","state":"pending","recorded_at":"…"}]}
  ```

  `recording`: the service has not recorded it yet. It did not answer, or
  the standby held the record back before degraded mode began (the first
  30 seconds of a standby's outage). The API records it every 5 seconds
  until the service answers; a restore of the database or a failover before
  it does could undo the revocation ([recovery.md](../recovery.md#revocations-the-authority-service-has-not-recorded)).
  `confirmed`: the standby's replica holds the record (or no standby
  exists). `pending`: it does not yet. A failover before it does could
  undo the revocation; the announcement after a disaster lists the window
  in which pending revocations must be made again. A bearer token's
  revocation (`api_token`, `service_token`, `platform_credential`,
  `delegated_token`) is confirmed at once while the service runs in
  degraded mode: a failover after a degraded period revokes every bearer
  token anyway. A standing grant's (`member`, `principal`, `organization`,
  `team`, `team_membership`, `assignment`, `mandate`, `delegation_trust`,
  `llm_provider`) stays pending until the standby holds it.
- **After a failover**, `agentcapsule-admin reconcile` replays into the
  promoted database each record it lacks, with its row. When the promotion
  assumed a degraded period, it also replays the **blanket** revocation
  (kind `blanket`, recorded by the promotion, read by the platform
  operator): every API token, service token and platform credential issued
  before the failover is revoked, and every delegated token issued before
  it is refused.
- **Later.** Every 5 seconds the API records the recording revocations,
  then asks the service about the pending ones, and confirms them once the
  standby holds their record. `GET /v1/access-revocations/{id}` reads one,
  with its `state` and `confirmed_at`; reading a recording or a pending one
  asks the service again. An
  organization's revocations are read with the rights of `GET /v1/audit`;
  the platform's own (an organization disabled, an operator's credential
  or delegation change) with the platform credential. A replay of the
  revoking request gives each revocation's current state.
- **Metrics.** `agentcapsule_api_access_revocations_pending`,
  `agentcapsule_api_access_revocation_oldest_pending_seconds`,
  `agentcapsule_api_access_revocations_unrecorded` and
  `agentcapsule_api_access_revocation_oldest_unrecorded_seconds`
  ([observability.md](../observability.md)).

The routes that revoke, and the record each appends:

| Route | Kind | Objects |
|---|---|---|
| `POST /v1/members/{id}/revoke` | `member`, and `service_token` for the tokens the member issued | the principal; the tokens |
| `POST /v1/members/{id}/role` | `service_token`, for the tokens the new role no longer manages | the tokens |
| `POST /v1/teams/{id}/disable` | `team` | the team (its memberships go with it) |
| `POST /v1/teams/{id}/members/{principal_id}/revoke` | `team_membership` | the team and the principal |
| `POST /v1/service-accounts/{id}/disable` | `principal`, and `service_token` for its tokens | the account; the tokens |
| `POST /v1/service-accounts/{id}/tokens/{token_id}/revoke` | `service_token` | the token |
| `POST /v1/agents/{id}/assignments/{assignment_id}/revoke`, `/replace`, `/reassign` | `assignment` | the revoked or replaced assignment |
| `POST /v1/llm/providers/{id}/rotate` | `llm_provider` | the provider, `generation`, the previous credential's generation |
| `POST /v1/llm/providers/{id}/disable` | `llm_provider` | the provider |
| Personal volume allocation during invitation acceptance or retry | `personal_volume` | agent ID, immutable volume ID, member ID. Allocation requires confirmation: this claim alone is recorded before the commit, since the service's answer decides it, and fails with 503 `authority_unavailable` when the service does not record it. |
| `POST /v1/organizations/{id}/disable` (platform) | `organization` | the organization |
| `agentcapsule-admin revoke-credential` | `platform_credential`, or `api_token` for a legacy service credential | the credential |
| `agentcapsule-admin configure-delegation` | `delegated_token` (`revoke-token`); `delegation_trust` (`revoke-trust`; `rotate`: `generation` and the new one; `retire-key`: `key`, the key and its end) | the issuer, then the token ID or the audience |

A request that revokes nothing new (an already revoked member, say)
appends nothing and carries no `revocations`. In development without the
authority service, nothing is recorded outside PostgreSQL and no answer
carries `revocations`. `agentcapsule-admin` takes the same three flags as
the API for `revoke-credential` and the revoking actions of
`configure-delegation`; in production it refuses them without the flags
(`authority_required_in_production`). Its answer gives each revocation's
state, `recording` included.

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
  -transit-active-key v1 -transit-key v1=/private/path/transit-v1.key \
  -tls-cert /etc/agentcapsule/api.crt -tls-key /etc/agentcapsule/api.key
```

Rotation explicitly activates a new identifier together with all the keys still
needed for unpurged content: payloads and attachments. Activation never
replaces the secret associated with an existing identifier. An old process can
no longer write with the previously active identifier. Ordinary opening
initializes nothing; the API and the worker refuse to start without the key of
any unpurged content. Transit keys are distinct from volume keys and from API
receipt keys.

**Rotating the transit keys** ([ADR 018](../adr/018-key-lifecycle-and-archive-deletion.md)):
once a year by default, and at once if a key file may have leaked.

1. Create the new key, a private 32-byte file, and copy it to the safe off the
   hosts ([recovery.md](../recovery.md#prepare)):
   `head -c 32 /dev/urandom > transit-v2.key` under `umask 077`.
2. Activate it with every key still needed:
   `agentcapsule-admin activate-transit-keys -active-key v2 -key v1=… -key v2=…`.
   From then on the running API and worker can no longer write content: their
   active key is no longer the installation's.
3. Restart the API (`-transit-active-key v2`, both `-transit-key`) and the
   worker (`transit.active_key` and both `keys`) at once. A request that
   stores content fails in between, and commits nothing: its client retries
   it.
4. Old content stays readable with its own key. Watch
   `agentcapsule-admin transit-key-usage`: for each key, the unpurged payloads
   and attachments it seals, how many have no purge date yet (not delivered,
   or attached to a running invocation), and the latest purge date of the
   others. Delivered content is purged 7 days after its delivery.
5. Once `v1` seals nothing (`payloads` and `attachments` at 0), remove it from
   both configurations and restart them. Delete the file on the hosts. Keep the
   safe's copy for 4 weeks more: a database restored from an older backup still
   holds content sealed with it, and the API refuses to start without it.

Bodies are encrypted with AES-GCM and bound to their business reference and
their parties. Deleting an agent immediately removes the current ciphertexts
that concern it; its business finality still waits for the revocation barriers.
Retention after delivery is seven days in the API binary; a read does not push
back the deadline. A reply whose delivery dies is kept seven days from its death,
as a delivered reply is from its delivery
([ADR 007](../adr/007-delivery-closure-and-priority.md)). Each pass of a worker
configured for transit purges a bounded batch of expired content.
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

When a restore of either agent lost one of the request's events, reading the
request gives `lost_at`. A request its recipient lost while working on it is
`DELIVERING` again until it is delivered again; a final request never changes
([ADR 008](../adr/008-redelivering-lost-agent-requests.md),
[recovery.md](../recovery.md#the-lost-agent-to-agent-events)).

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
