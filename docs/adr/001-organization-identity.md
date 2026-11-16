# ADR — Foundations of organization identity

Date: November 7, 2026. Status: foundations implemented; tenant transition
activated and operator bootstrap built on November 16, 2026
([D-01](#tenant-transition-and-operator-bootstrap-d-01)); the legacy owner
domain's code remains to be removed. References: TEN-01/TEN-02/TEN-03 of the
[roadmap](../../ROADMAP.md), product spec §2.2, §7.1 and §9
([product.md](../product.md)).

## Context

The historical accounts and `agents.owner_user_id UNIQUE` describe one agent
per individual owner. The HTTP receipts and the encrypted transit data also
include this owner in their authenticated context. Replacing this field with a
tenant would change both the authorization and the meaning of the data already
written.

## Decisions of this slice

1. The historical schema becomes migration **1**, kept in `schema.sql`.
   Migration **2** adds the organization domain. Future changes are appended to
   the list; an installed migration is never rewritten. `.gitattributes` keeps
   the LF line endings of the migrations so that their digests stay identical in
   Linux and Windows clones. Evidence archives undergo no text normalization.
2. Version, name, SHA-256 digest and application date are recorded in
   `schema_migrations`, in the same transaction as the DDL and backfills. The
   existing exclusive lock prevents migrations and application transactions
   from interleaving. An error rolls back the whole transaction.
3. An earlier installation without a registry is adopted by running the
   idempotent baseline and its historical backfills. Subsequent runs check the
   history without replaying applied migrations. A gap, an unknown version, or a
   different name or digest causes a refusal.
4. Organizations, principals, memberships, teams and team members are added
   without converting the existing users. Composite tenant references prevent a
   membership or a team from linking two tenants. External identity is unique
   per tenant; the technical account does not usurp an end-user identity through
   `issuer/subject`.
5. A principal holds a single administrative role in an organization.
   Assignments and content permissions remain distinct. The roles `org_owner`,
   `org_admin`, `agent_operator`, `agent_user` and `auditor` are recognized; no
   hierarchy implicitly grants access to conversations.

The registry does not protect against a PostgreSQL administrator who
deliberately rewrites the schema and its history. Deleting it is not a repair
procedure. A newer database must be opened with the matching software; the
registry check described here is performed by `Migrate`, and is not proof that
all old binaries would refuse this database.

## Prepared role policy

`internal/authorization` is a pure module; it replaces neither authentication
nor the locks of the consuming transaction.

| Role | Administration allowed, under exact scopes |
|---|---|
| org_owner | Metadata, members/roles, teams, assignments, agents, providers, quotas, audit and usage |
| org_admin | Same current administration; cannot create, modify or remove an owner/admin |
| agent_operator | Agent metadata, creation, configuration, wake and sleep; no delete |
| agent_user | No global administrative right; access to agents according to assignments |
| auditor | Redacted metadata, audit and usage; no administrative mutation |

Invocation and content reading each require an explicit assignment permission,
an exact scope and active identities in the same tenant. `agent:create`,
`agent:operate` and `agent:delete` are independent; the historical scope
`agent:manage` is reserved here for configuration. An owner role does not
exempt from these checks. The resolution of teams and assignments, the rights on
history and the preservation of the last owner remain to be implemented in the
control plane transactions.

## Remaining transition before product exposure

- Integrate the Ed25519 signed delegation, the option chosen among those of the
  product spec. The independent verifier uses a JWT library and binds the keys,
  issuer/audience, scopes and TTL to a configured tenant. The `issuer/subject`
  columns do not verify an identity by themselves; a valid signature does not
  exempt from re-checking memberships and current trust.
- Provide an explicit mapping of the old data, with no global fallback tenant
  and no automatic inference from the user ID.
- Introduce tenant authentication and remove the paths where a mere
  `Kind == service` gives global power.
- Migrate the uniqueness, lock and encrypted context of the receipts while
  keeping the idempotency history. An invalidation must still recognize/refuse
  an old key, otherwise a retry could recreate an already validated mutation.
- Preserve the historical participants of transit v1; a new version or an
  explicit migration with the keys, never a silent replacement of the binding.
- Link agents and derived resources to tenants; add the assignments, adapt `/me`
  and remove per-owner uniqueness after the checks.
- Settle reassignment and access to history in D-02 before the dependent paths;
  test revocation during admission and the replay of a receipt.

No organization route is activated by migration 2. The SQL tests of this slice
demonstrate the constraints and the resumption of migrations, not yet the
product's tenant isolation. The existing Quint models remain unchanged.

## Tenant transition and operator bootstrap (D-01)

Date: November 16, 2026. References: D-01, TEN-01, TEN-02, TEN-05 of the
roadmap; TEN-001 and TEN-008 of the product spec (§4). The steps are in
[bootstrap.md](../bootstrap.md).

### What the code held

Two domains lived side by side.

- The **legacy owner domain**: the `users` and `api_tokens` tables, `acp_`
  user and service tokens, one agent per owner (`agents.owner_user_id`), the
  owner's inbox and requests (`/v1/me/...`, `/v1/agent-requests/...`). An
  installation entered it with `agentcapsule-admin bootstrap`, which made an
  `acp_` service token; that token created users (`POST /v1/users`) and their
  tokens. A legacy service token saw every owner's agents (`Kind ==
  "service"` in `agent_catalog.go`).
- The **organization domain**: the platform credential
  (`bootstrap-platform`), organizations, members, teams, tenant agents and
  assignments, service accounts, delegated identity.

"Tenant transition not activated" meant that a new installation could still
enter the legacy domain and that the API accepted its tokens. "Migration of
legacy data" meant mapping legacy users, agents, receipts and transit
content to organizations (the list above).

A trust's public keys were in a file that the API read at start; PostgreSQL
held its fingerprint and generation. Adding an organization or a key meant
editing that file and restarting the API, and any change of keys raised the
generation, which refused every token signed before: there was no overlap.

### No legacy data to migrate

No installation can hold legacy owner data: no release was ever made (VAL-03),
and no production installation exists (the roadmap's known limits). So there
is no migration command and no mapping; the items of the previous section
about mapping old data, receipts and transit v1 participants are dropped. A
development database that holds legacy rows keeps them, unused.

### Decisions

1. **The legacy owner domain is closed, not yet removed.** `agentcapsule-api`
   refuses every `acp_` token (401) before serving
   (`Store.CloseLegacyOwnerDomain`). `agentcapsule-admin bootstrap` is gone:
   it answers `bootstrap_removed_use_bootstrap_platform`. No command creates
   legacy data, so a running installation serves only organizations, and the
   global power of a legacy service token is unreachable. The code stays
   because about 30 test files, among them KVM tests of the worker, still
   set up their agents through it; removing it means moving them to
   organizations first.
2. **A trust's keys are in PostgreSQL** (migration 0034, `delegation_keys`
   and the trust's scopes and lifetime). The API builds the verifier of the
   one key a token names, in the transaction that consumes it. The API has no
   trust file any more (`-delegated-identity-file` is removed), and a change
   needs no restart. An issuer and audience serve one organization only.
3. **Keys rotate with an overlap.** `add-key` adds a key; `retire-key` ends
   one after an overlap (0 by default, 30 days at most). Neither changes the
   generation or the issuance threshold, so tokens of the other keys keep
   working. An end is never pushed back, a key ID is bound to its key for
   good, a retired key never returns, and the last key without an end cannot
   be retired (`revoke-trust` stops every sign-in). `rotate` retires the keys
   absent from its file.
4. **One path from an empty database**: `migrate`, `bootstrap-platform`,
   `POST /v1/organizations` with the first owner's issuer and subject,
   `configure-delegation -action install`, then the owner signs in and names
   administrators (`POST /v1/members`). Each step confirms a repeat or refuses
   it. A second active organization of the same name is refused (409
   `organization_name_taken`). No step has a default password: the receipt
   key and the platform token are random and written to private files.
5. **The operator's actions are audited.** `platform_audit` records the
   platform credential's creation and revocation with the local account
   (`local-uid:<uid>`); a confirmed retry is not a new action.
   `agentcapsule-admin list-audit` shows it with `organization_audit` and
   `delegation_audit` (which now records key changes); each organization sees
   its own in `GET /v1/audit`.

TEN-008 holds: a user is whom a registered key's signature names, and a
registered member. A name as a bearer token, a header, an unsigned token, a
token signed by another key or for a non-member is refused
(`TestOperatorBootstrapFromEmptyDatabase`, `TestFreeFormUserIDsAreRefused`).

### Defaults pending the product owner

- An active organization's name is unique, compared without case.
- A retired key keeps working for the overlap given, 0 by default and 30 days
  at most.
- Only the platform operator, on the host, registers and rotates an
  organization's keys; there is no API route for an organization's owner.

### The previous section's list, now

| Item | State |
|---|---|
| Integrate the Ed25519 signed delegation | Done; keys in PostgreSQL |
| Explicit mapping of the old data | Dropped: there is none |
| Tenant authentication; no global power for `Kind == service` | Done; unreachable in a running installation, removed with the legacy code |
| Receipts' uniqueness, lock and encrypted context | Dropped with the mapping |
| Historical participants of transit v1 | Dropped with the mapping |
| Agents and derived resources linked to tenants; assignments | Done (TEN-05) |
| Adapt `/me`; remove per-owner uniqueness | With the removal of the legacy code |
| Reassignment and history (D-02) | [ADR 002](002-assignment-revocation.md) |

### What remains

- Remove the legacy owner domain's code and routes, after moving its tests to
  organizations.
- OIDC discovery (JWKS) and other algorithms than EdDSA: P1 ("advanced
  OIDC/SSO", product spec §5).
- Auditing refused attempts.
- A retired key, like every revocation held in PostgreSQL, comes back with
  an older database backup: D-05's revocation records
  ([ADR 005](005-keys-outside-restored-domain.md)).
