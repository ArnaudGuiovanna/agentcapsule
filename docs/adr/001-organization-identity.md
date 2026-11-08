# ADR — Foundations of organization identity

Date: November 7, 2026. Status: foundations implemented; tenant transition not
activated. References: TEN-01/TEN-02/TEN-03 of the
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
