# Initial organization administration

This part adds a platform administration domain distinct from the legacy
owner/service accounts. It does not provide OIDC authentication, tenant tokens,
agent assignment or migration of legacy owners (see the other documents in this
directory for the tenant domain).

## Local bootstrap

The operator uses trusted local PostgreSQL access and reuses the existing
receipt key, or initializes it on a new installation:

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
does not print it. The initial scope is `platform:admin`; legacy `acp_` tokens
receive no new rights.

A retry must keep the same files and the same account. It confirms a commit
whose response was lost, without extending the expiry. A different identity, or
an expired or revoked token, is refused. This command creates only the first
platform credential; later credential administration is covered by
`agentcapsule-admin list-credentials` and `revoke-credential` (see the
[README](README.md)).

## Available routes

All these routes require `Authorization: Bearer <platform-token>` and the
`platform:admin` scope. Conversation content is never returned by these routes.

| Route | Input and result |
|---|---|
| `POST /v1/organizations` | JSON below and mandatory `Idempotency-Key`; 201 response with `id`, `name`, `status`, `policy_version`, `created_at`, `owner_principal_id` |
| `GET /v1/organizations` | `limit` from 1 to 200, default 100; `after` = last opaque ID received; response `{ "items": [...] }` sorted by ID |
| `GET /v1/organizations/{id}` | Organization metadata, including if disabled; 404 if absent |
| `POST /v1/organizations/{id}/disable` | JSON `{}` and mandatory `Idempotency-Key`; 200 response with the disabled metadata |

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
expire after 24 h, like the existing receipts. Organization names are not
unique.

Disabling is persistent and increments `policy_version` exactly once. A new
command on an already disabled organization has no effect on that version and
leaves an audit entry with `changed=false`. Replaying the same receipt adds no
audit. Members are kept. Legacy agents, which are not attached to tenants, are
neither stopped nor deleted by this route. Forbidding future tenant operations
for a disabled organization relies on this status in the tenant routes; this
route does not itself offboard anything.

The credential hash, its scopes, its expiry and its revocation are checked again
in each transaction, including before a receipt is returned. An already
committed revocation therefore forbids the replay; an admitted operation holds
the credential's read lock until its commit. Legacy service or user tokens
cannot administer organizations, and platform tokens cannot use the legacy
routes to reach their accounts or agents.

The audit keeps the organization, the platform account, the credential ID, the
action, whether it changed the state, and the time. It keeps no secret and no
conversation body. Auditing of refused attempts and reading it with the tenant
`auditor` role are not available yet. Migration 0003 extends the receipt
constraint; it changes neither the format nor the authenticated data of the old
encrypted receipts.
