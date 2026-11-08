# Tenant teams

This part adds management of teams and their human memberships. A membership is
administrative metadata: it grants no implicit right over agents, their
conversations, their files or their results. Agent assignments are described in
[agents-assignments.md](agents-assignments.md); service accounts in
[service-accounts.md](service-accounts.md).

All routes use the delegated identity of the current tenant. Identifiers in the
body or path cannot select another tenant. Platform credentials and legacy
service credentials are not accepted.

| Method and path | Scope | Roles | Body | Response |
| --- | --- | --- | --- | --- |
| `GET /v1/teams` | `team:read` | owner, admin, auditor | — | 200, `{"items":[Team]}` |
| `POST /v1/teams` | `team:manage` | owner, admin | `{"name":"Support"}` | 201, Team |
| `GET /v1/teams/{id}` | `team:read` | owner, admin, auditor | — | 200, Team |
| `POST /v1/teams/{id}/disable` | `team:manage` | owner, admin | `{}` | 200, Team |
| `GET /v1/teams/{id}/members` | `team:read` | owner, admin, auditor | — | 200, `{"items":[TeamMembership]}` |
| `POST /v1/teams/{id}/members` | `team:manage` | owner, admin | `{"principal_id":"prn_…"}` | 201 on first add, otherwise 200 |
| `POST /v1/teams/{id}/members/{principal_id}/revoke` | `team:manage` | owner, admin | `{}` | 200, TeamMembership |

The full role names are `org_owner`, `org_admin` and `auditor`. The scopes
`team:read` and `team:manage` are independent; neither `org:read` nor
`member:manage` replaces them. An admin can manage the membership of an owner or
of another admin: this changes neither their role in the organization nor the
last-owner rule.

Both lists accept `after` (exclusive identifier) and `limit` (1 to 200, default
100), sorted by ascending identifier. They include disabled or revoked metadata.
An empty list contains `"items":[]`.

```json
{"id":"team_…","name":"Support","status":"active","created_at":"2026-11-08T12:00:00Z"}
```

```json
{"team_id":"team_…","principal_id":"prn_…","status":"active","created_at":"2026-11-08T12:00:00Z"}
```

`team:read` exposes the internal identifiers needed for memberships, but no
issuer, external subject, role, scope or content. Reading members' full
identities requires the rights specific to `/v1/members`.

## Lifecycle and replay

Mutations require `Idempotency-Key`. Their namespace is
`(tenant, principal, operation, key)`; the request hash includes the path
identifiers. Two credentials of the same principal share this namespace. A key
reused with another body or another target returns 422 after the current rights
checks. Receipts are kept according to the existing 24 h contract. After expiry,
a creation can produce a new team of the same name.

Adding requires an active team and an active human member in this tenant. An
already revoked relationship can be explicitly re-enrolled with a **new key**.
Replaying an old add returns its historical response, with
`Idempotency-Replayed: true`, without reactivating the membership. Consult the
list for the current state. If the team or the member has been disabled/revoked
in the meantime, even the replay of that add is refused.

Revocation keeps the relationship with `status: "revoked"`. It allows cleanup of
a member already revoked from the organization. A missing relationship returns
404; an already revoked relationship is a no-change operation. Disabling sets the
team to `disabled` and revokes all its memberships in the same transaction.
There is no reactivation route. Replaying an old creation does not undo this
disabling. Names are not unique: a new same-name creation has an independent
identifier.

## Authorization, transaction and errors

Mutations first lock the organization with `UPDATE`, then check the identity, the
delegation authority and the current permissions before any replay. Reads are
protected by the existing shared lock. The mutation, the `policy_version`
increment when a state changes, the dedicated `tenant_team_audit` audit and the
encrypted receipt are atomic. A replay creates no new audit; a new key for a
no-change operation is audited without a version increment. The encrypted format
of tenant receipts is unchanged.

| Status | Case |
| --- | --- |
| 400 | Invalid/missing JSON, unknown field, name, pagination or key |
| 401 | Delegated identity, member, tenant or authority revoked/invalid |
| 403 | Insufficient scope or role, platform/service credential |
| 404 | Team, human principal or relationship absent from the current tenant |
| 409 | Add to an inactive team or an inactive human member |
| 422 | Same key namespace with a different request |

Migration 0006 adds only the dedicated audit and reuses the existing
`teams`/`team_memberships` tables. The Go/PostgreSQL tests verify the real route
contract, replay, transactions and targeted concurrency. The existing D-02 tests
serve as a guard on the contract; they are not a proof of the Go code.
