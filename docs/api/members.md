# Human organization members

These routes register and administer existing organization identities. They do
not authenticate a requested subject or issue a credential. JWT authentication
continues to require an independently installed issuer trust and an already
registered active principal and membership. The authenticated delegation fixes
the tenant; no request parameter can select another organization.

| Route | Request | Response | Required scope and current role |
| --- | --- | --- | --- |
| GET /v1/members | `after` principal ID; `limit` 1–200, default 100 | 200 `{"items":[Member]}` | `member:read`; owner, admin or auditor |
| POST /v1/members | `issuer`, `subject`, `display_name`, `role` | 201 Member | `member:manage`; owner or admin, subject to target policy |
| POST /v1/members/{id}/role | `{"role":"agent_user"}` | 200 Member | `member:manage`; target policy |
| POST /v1/members/{id}/revoke | `{}` | 200 Member | `member:manage`; target policy |

Member contains `principal_id`, `issuer`, `subject`, `display_name`, `role`,
`status` and `created_at`. Status describes the membership (`active` or
`revoked`). Listing includes revoked human memberships, ordered by principal ID.
These are administrative metadata, not agent assignments or private content.
Issuer and subject follow the delegation profile (1–1024 UTF-8 bytes, no control
characters or surrounding whitespace). Display name is at most 100 characters.

Owners can grant/manage every supported role. Administrators can grant/manage
only agent_operator, agent_user and auditor, and cannot modify an existing
owner/admin. Other roles cannot manage members. An active organization retains
at least one active owner: demoting or revoking the last owner returns 409
`invalid_transition`. A duplicate registered issuer/subject, including a revoked
membership, also returns 409 unless this is an authorized exact receipt replay.
The role policy is evaluated first: an administrator who registers an identity
that already holds the owner or admin role receives 403, not 409.

All mutations require `Idempotency-Key` (1–200 printable non-space ASCII bytes).
The namespace is `(tenant, principal, operation type, key)`; operation types are
`member.create`, `member.change_role`, `member.revoke`. A target ID belongs to
the input hash, so reusing one key on another target for the same operation
returns 422 `idempotency_key_reused` once current target rights are checked.
Different principals can use the same key independently. Exact replay returns
the original status/body and `Idempotency-Replayed: true`. It is a historical
operation response, not a fresh read of the member. Receipts expire after 24h;
expiry does not permit duplicate identity creation or membership reactivation.

The organization row is locked FOR UPDATE before any current actor/candidate
authorization in a mutation. This serializes owner-count decisions and waits
for admitted FOR SHARE readers. The transaction rechecks the signed identity,
current trust/generation/JTI/time, organization, membership, scopes and current
target role before reading a receipt. It commits the member mutation, policy
version change, tenant audit record and encrypted receipt together. Parallel
mutations may wait rather than returning the legacy receipt API's in-progress
409. A previously authorized response may arrive after a later revocation.

Migration 0005 adds durable tenant receipts and member audit tables. Receipts
use AES-GCM with a dedicated domain and explicit AAD version 1 binding tenant,
principal, operation, key, request hash (lowercase SHA-256 hex) and response
status; the legacy receipt schema and AAD are unchanged.
An exact replay adds no audit row. A new key for an already revoked member
records an authorized no-op. Audit contains metadata, never JWTs or plaintext
private content.

Revocation retains the historical principal, revokes the membership and all of
its team memberships, and neither deletes agents nor transfers historical
content. There is no reactivation route. A future reactivation feature needs a
signed/current member or credential generation before enabling access again,
so previously issued JWTs cannot regain access. Database operators remain
trusted; direct SQL reactivation bypasses this API contract. Team management,
service accounts, tenant agents and tenant private-content APIs are not part of
this increment. [ADR D-02](../adr/002-assignment-revocation.md) and the D02 model supply
the transaction/revocation discipline;
role administration and the last-owner rule are tested in Go/PostgreSQL and
are not proved by that model.
