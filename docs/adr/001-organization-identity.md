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

## Changes after the v0.1.0 audit

### Database roles (SEC-3, finding S-04)

Until v0.1.0 the API, the worker and `agentcapsule-admin` connected as one
role, `agentcapsule`, which owns the database. Tenant isolation rested on the
`tenant_id` predicates alone, and the guard triggers that keep revocations,
seals and access revocations permanent belonged to the role every service
used: `TRUNCATE` skips them, and that role could drop or disable them.

Now three roles reach the database ([install.md](../install.md#postgresql)):

- `agentcapsule` owns the database and every object. It alone runs the
  migrations (`agentcapsule-admin migrate`); only `agentcapsule-admin` uses
  it, as root.
- `agentcapsule_api` (the API) and `agentcapsule_worker` (the worker) are
  login roles with no cluster privilege. They own nothing and cannot create
  in the schema. Each reads every table, and holds `INSERT`, `UPDATE` and
  `DELETE` exactly where the code its process runs writes (a row lock counts
  as `UPDATE` on the tables it locks, as PostgreSQL requires: every table
  its statement reads, or the tables its `OF` names). Neither holds `TRUNCATE`,
  `REFERENCES` or `TRIGGER`, nor any right on `schema_migrations` but read.
- The migration `service-roles` states the policy in two functions:
  `agentcapsule_service_privileges()` lists each role's privileges per
  table, and `agentcapsule_service_grants()` applies it, again each time
  `agentcapsule-admin migrate` runs: a role created after the migration gets
  its privileges at the next run. A table a later migration creates gets the
  default privileges (read and write rows) until a migration lists it, so a
  new table never fails in production for want of a grant. A role that does
  not exist is skipped.
- `service_roles_analysis_test.go` derives each role's writes from the
  sources: the packages each command imports, the functions of
  `internal/controlplane` they name, the statements of those functions, and
  the triggers of the tables they write with the functions those call (no
  function is `SECURITY DEFINER`: a trigger runs with the privileges of the
  role that fired it). `TestServiceRolesHoldWhatTheirProcessWrites`
  fails when the database grants more or less than that;
  `TestServiceRolesCannotTruncateAlterDropOrDisableTheGuards` tries every
  such statement as each role. A change that writes a new table, or writes a
  table its process did not write, adds a migration that replaces
  `agentcapsule_service_privileges()`.
- The worker no longer migrates (its `-migrate` flag is gone). Like the API,
  it refuses a schema whose ledger differs from its binary's.
- The installer creates the roles, maps root to the owner and the worker's
  role and the API's account to the API's role only (`pg_ident.conf`), and
  writes each unit's connection string (`api.env`, `worker.env`, and
  `admin.env` for the owner). An update of an installation that used one
  role does the same before it migrates. An external database names the
  three roles' connections (`database_url_file`, `api_database_url_file`,
  `worker_database_url_file`).

What it gives: a compromised or faulty API cannot erase the revocation
history, a seal or an access revocation, change the schema or a guard, nor
write the worker's tables (placements, seals, store enrollments,
restores...). It does not contain root: the worker runs as root, which can
reach the database as any role (S-05 and A-03 confine the worker).

**Integration with the performance fixes.** Migration 0073
(`service-privileges-activity-retention`) replaces
`agentcapsule_service_privileges()` for the code of both domains. Both roles
insert and update `agent_activity`, which the triggers of
`platform_operations`, `agent_requests` and `llm_usage` keep (PERF-3A). The
worker deletes the finished records its retention removes (PERF-3A): finished
operations, requests, invocations and what hangs on them. The analysis now
follows the functions a trigger calls (`agent_activity_upsert`), and counts
a lock that names its tables (`FOR UPDATE OF r`) as `UPDATE` on those tables
only. That removes eight grants nothing used: the API's `UPDATE` on
`corpus_review_segments` and `volume_restore_losses`, and the worker's on
`agent_deployments`, `agent_template_revisions`, `attachment_segments`,
`corpora`, `transit_parties` and `volume_restore_losses`. Without that rule,
the retention's `FOR UPDATE OF` locks would have given the worker `UPDATE`
on `instruction_replays`, `owner_messages`, `peer_redeliveries` and
`tenant_agent_audit`.

**Fresh installs and joined tables (FIX-1).** A run of the migrations that
applied `service-roles` skipped the grants at its end. On a fresh install,
which applies every migration in one run, a relation that a later migration
created kept the default privileges (read and write rows, also on a view)
until the next `agentcapsule-admin migrate`; 0073 hid it by calling the
grants itself. The grants now run at the end of every run once the function
exists (`migrations.go`; `TestAFreshInstallGrantsWhatLaterMigrationsCreate`).
The analysis also saw only the first table of a comma-joined list
(`FROM a x, b y`) and took the `JOIN` after a table without an alias for
that alias, so a lock naming such a table fell back to every table read. It
now sees each table (`TestTheRoleAnalysisSeesEveryTableAStatementReads`).
The derived privileges did not change: 0073's list stays exact.

### Row-level security: considered, not adopted

The audit asked to consider policies on the tenant tables keyed by a
`SET LOCAL` tenant setting: on each table with a `tenant_id`,
`tenant_id = current_setting('agentcapsule.tenant_id')`, the setting set
once the transaction has authenticated the tenant. It is not adopted:

1. **It does not contain the API.** The API's role would set the setting
   itself, and any role can set a custom setting (`set_config` is open to
   all). A compromised API sets any tenant, or none. PostgreSQL has no
   session state that a role cannot forge, without an extension or one role
   per organization.
2. **The platform paths read every organization**: the worker (dispatch,
   scheduling, deliveries, idle sleeps across organizations), the platform
   operator's routes, the reconciliation and the retention purges. The API
   itself reads across organizations before it knows the tenant, in the
   same transaction as the tenant's work: a credential is looked up by its
   hash, an application by its issuer and client ID, an invitation finds its
   organization through its application. A policy that does not break these
   paths needs "no setting, every row", which a path that forgets to set the
   tenant also gets. What would remain is the case of a statement that
   forgets its tenant predicate after the tenant is set.
3. **That case is tested route by route**: `TestRBACMatrix`, and the tests
   that ask for another organization's objects
   (`TestAnotherOrganizationsNumbersStayOutOfEveryAnswer`,
   `TestLLMRoutesDoNotCrossTenantsAndAliasDisableIsImmediate`,
   `TestCorpusOfAnotherOrganizationCannotBeMounted`, among others).
4. **Its cost is not small for what it would add**: one more statement in
   each tenant transaction, whose preamble the performance work is cutting
   down (P-06); policies to keep right on the 70 or so tables with a
   `tenant_id`; and the PostgreSQL campaign runs as a superuser, which
   bypasses every policy, so the tests would not exercise them unless the
   API's tests ran as its role.

To contain a compromised API per organization, the next step is not a
policy on a setting but a check the database makes itself: one role per
organization, or a `SECURITY DEFINER` function that verifies a signed
tenant claim before it sets the tenant.
