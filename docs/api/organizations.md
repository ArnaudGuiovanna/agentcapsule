# Initial organization administration

The platform operator creates, reads and disables organizations. The
operator has no access to their content. The steps of a new installation,
from an empty database to an organization's first owner, are in
[bootstrap.md](../bootstrap.md); the other documents in this directory
describe the organizations' own routes.

## Local bootstrap

The operator uses trusted local PostgreSQL access and reuses the existing
receipt key, or initializes it on a new installation (it migrates first, like
`agentcapsule-admin migrate`):

```bash
agentcapsule-admin bootstrap-platform \
  -receipt-key-file /private/path/receipt.key \
  -token-file /private/path/platform.token \
  -platform-account platform-operator \
  -token-lifetime 720h
```

The connection is supplied by `AGENTCAPSULE_DATABASE_URL`. The private files
must be accessible only to their owner; the token is written and synced before
its hash is published in PostgreSQL. It has the prefix `acpp_`, followed by 32
random bytes encoded in unpadded base64URL (48 characters in total). The command
does not print it. The initial scope is `platform:admin`. The creation is
audited, with the local account that ran the command (`local-uid:<uid>`); a
retry that confirms it is not.

A retry must keep the same files and the same account. It confirms a commit
whose response was lost, without extending the expiry. A different identity, or
an expired or revoked token, is refused. This command creates only the first
platform credential; later credential administration is covered by
`agentcapsule-admin list-credentials` and `revoke-credential` (see the
[README](README.md)). A revocation is audited too. In production
`revoke-credential` needs the authority service's flags: it records the
revocation there before it commits ([README](README.md#revocations-pending-and-confirmed)). So does
`POST /v1/organizations/{id}/disable`, whose answer carries `revocations`.

## Available routes

All these routes require `Authorization: Bearer <platform-token>` and the
`platform:admin` scope. Conversation content is never returned by these routes.

| Route | Input and result |
|---|---|
| `POST /v1/organizations` | JSON below and mandatory `Idempotency-Key`; 201 response with `id`, `name`, `status`, `policy_version`, `created_at`, `owner_principal_id` |
| `GET /v1/organizations` | `limit` from 1 to 200, default 100; `after` = last opaque ID received; response `{ "items": [...] }` sorted by ID |
| `GET /v1/organizations/{id}` | Organization metadata, including if disabled; 404 if absent |
| `POST /v1/organizations/{id}/disable` | JSON `{}` and mandatory `Idempotency-Key`; 200 response with the disabled metadata |
| `GET /v1/organizations/{id}/quotas` | The organization's quotas (`limits`) and `usage`; see [Quotas](#quotas) |
| `PUT /v1/organizations/{id}/quotas` | JSON of every quota and mandatory `Idempotency-Key`; 200 response with the quotas saved |

```json
{
  "name": "Engineering",
  "initial_owner": {
    "issuer": "https://identity.example",
    "subject": "opaque-subject",
    "display_name": "Initial Owner"
  }
}
```

The `initial_owner` field **records the intended identity without authenticating
it**. It creates a `user` principal and an `org_owner` membership in this
organization; it creates no token, legacy user account or access to agent
content. Verifying the identity with a trusted issuer is a separate concern
(see [tenant-identity.md](tenant-identity.md)). Names and display names: 100
characters at most; issuer and subject: 1 024 UTF-8 bytes at most, with no
surrounding whitespace. Empty values, control characters and unknown JSON fields
are refused.

Organization creation, initial principal, membership, administrative audit and
encrypted HTTP receipt are atomic. An audit failure rolls back the whole
transaction. An identical retry returns the initial response; same key with
other content: 422; identical transaction still in progress: 409. Receipts
expire after 24 h, like the existing receipts. An active organization's name
is unique, compared without case: a creation with another key and the name of
an active organization returns 409 `organization_name_taken`, so that running
the bootstrap twice by mistake makes no second organization. A disabled
organization's name can be used again.

Disabling is persistent and increments `policy_version` exactly once. A new
command on an already disabled organization has no effect on that version and
leaves an audit entry with `changed=false`. Replaying the same receipt adds no
audit. Members are kept. Forbidding future tenant operations
for a disabled organization relies on this status in the tenant routes; this
route does not itself offboard anything.

The credential hash, its scopes, its expiry and its revocation are checked again
in each transaction, including before a receipt is returned. An already
committed revocation therefore forbids the replay; an admitted operation holds
the credential's read lock until its commit. Legacy service or user tokens
cannot administer organizations, and platform tokens cannot use the legacy
routes to reach their accounts or agents.

## Quotas

The operator bounds what an organization's agents may hold on the
installation's hosts (TEN-007, [ADR 021](../adr/021-organization-quotas.md)).
The organization cannot change these quotas; its owners, administrators and
auditors read them with `GET /v1/organizations/current/quotas` (`usage:read`).
Its own queue limits and model budgets stay its own (`quota:manage`).

```json
{"max_agents": 20, "max_active_vms": 4, "max_vcpus": 8, "max_memory_mib": 8192, "max_storage_mib": 65536}
```

| Quota | Counts | Past it |
|---|---|---|
| `max_agents` (1 to 100 000) | agents not yet deleted, those being provisioned or deleted included | `POST /v1/agents` answers 409 `organization_quota_exceeded`, `"quota": "max_agents"`, before anything is reserved |
| `max_storage_mib` (64 or more) | their data volumes | the same, `"quota": "max_storage_mib"` |
| `max_active_vms` (1 to 100 000) | their VMs booted for work, starting, running or stopping, on every host | work waits: the agent is `QUEUED`, `queue_reason` `organization_quota` |
| `max_vcpus` (1 to 1 000 000), `max_memory_mib` (128 or more) | the vCPUs and RAM of those VMs | work waits; creating an agent that alone needs more answers 409 with that quota |

A field absent or `null` has no limit, and an organization the operator never
limited has none. `PUT` replaces every quota. A quota below current usage is
accepted: nothing running stops and nothing is deleted; new creations are
refused and new boots wait until usage falls under it. A `max_vcpus` or
`max_memory_mib` below what one of the organization's agents needs alone is
refused with 409 `quota_below_agent` and that `quota`: the agent could never
boot. Out-of-range values and unknown fields answer 400. The organization is
part of the receipt: the same key on another organization is a new request.
A boot only for a barrier (a fence, a provisioning's initialization, a
restore, a deletion) is neither counted nor refused.

Work past the active VMs, vCPUs or RAM is never refused: it waits in its
host's capacity queue ([worker.md](../worker.md)) without holding back other
organizations, in order within its own, and may stop the organization's own
idle VMs on its host. It dies at its deadline with `capacity_unavailable`
like work that waits for a full host.

Each change is audited (`organization.quotas_set`, with `changed`) and shows
in the organization's trail when the values changed.

The audit keeps the organization, the platform account, the credential ID, the
action, whether it changed the state, and the time. It keeps no secret and no
conversation body. The operator reads it with `agentcapsule-admin list-audit`,
the organization with `GET /v1/audit`. Refused attempts are not audited yet.
Migration 0003 extends the receipt
constraint; it changes neither the format nor the authenticated data of the old
encrypted receipts.
