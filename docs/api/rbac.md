# Authorization matrix

This page lists, for every route of the API, what each kind of caller gets.
The table is generated from the test that checks it,
[`internal/api/rbac_matrix_test.go`](../../internal/api/rbac_matrix_test.go)
(`TestRBACMatrix`): the test runs every route as every caller against
PostgreSQL, and `TestRBACMatrixIsDocumented` fails when this table differs
from the test's. `TestRBACMatrixCoversEveryRoute` fails when a route of the
server has no row.

## Rules

- **The organization comes from the credential.** No route reads an
  organization from a path, a query or a body. Every lookup is limited to the
  caller's organization, so an identifier of another organization answers
  404, like one that does not exist.
- **Roles administer, assignments give access.** The five roles
  (`org_owner`, `org_admin`, `agent_operator`, `agent_user`, `auditor`) decide
  administration. No role, not even `org_owner`, invokes an agent or reads a
  result: only an assignment with `invoke` or `read_content` does
  ([ADR 002](../adr/002-assignment-revocation.md)).
- **Both the role and the scope.** A route needs the scope of its action in
  the credential and a current role that allows the action. A technical
  account's token carries only the scopes it was issued with, and a
  technical account never manages identities.
- **Current state, in the transaction.** Status, role, membership, team and
  assignment are read in the transaction that acts, under the organization's
  shared lock. A revoked member, token, team membership or assignment fails
  the next request, including a replay of an idempotency key.
- **Results and files belong to their requester.** A private result is read
  only by the principal who asked, and only while it holds `read_content` on
  the agent. Its requester sees an invocation's, operation's or file's
  metadata only while it still sees the agent through an assignment. Roles
  that read agent metadata (`org_owner`, `org_admin`, `agent_operator`,
  `auditor`) see the metadata of every invocation and file, never the content.
- **A caller that cannot see an agent learns nothing about it.** It gets 404
  on the agent and on everything under it, as if it did not exist. A caller
  that sees the agent but lacks the right gets 403.

## Callers

| Column | Who |
|---|---|
| owner, admin, operator, auditor | A member with that role and every scope, assigned to nothing |
| user | An `agent_user` assigned to the agent with `read_metadata`, `invoke` and `read_content` |
| team | An `agent_user` holding the same permissions through a team |
| former | An `agent_user` who held them, invoked the agent and uploaded a file, then lost the assignment |
| unassigned | An `agent_user` never assigned to anything |
| service | A technical account with role `org_admin`, a token limited to `org:read member:read team:read agent:read agent:operate agent:invoke agent:content:read audit:read`, and a `read_metadata` + `invoke` assignment |
| foreign | The owner of another organization, with every scope, using the first organization's identifiers |
| revoked | A member who was assigned to the agent, then revoked |
| revoked-token | A revoked token of the technical account |
| platform | The platform operator |

The agent is the same for every caller. Routes marked "the caller's own,
else the user's" read the caller's own invocation or file when it has one
(user, former), otherwise the user's. Routes marked "disposable" act on a
resource created for each call, so that one caller's success does not change
another's case.

## Cells

- **yes**: the route's success status (200, 201 or 202);
- **filtered**: the success status, with only what the caller may see (its
  own invocations, the agents assigned to it, its own organization);
- **400, 401, 403, 404**: the status returned. 401 is an unknown, expired or
  revoked credential, or a revoked member. 403 is a missing scope or role.
  404 hides a resource the caller may not see. The platform operator gets 400
  on some organization routes, which refuse a non-organization credential
  before reading it; it gets no access either way.

The historical owner domain (`/v1/users`, `/v1/me...`, `/v1/agent-requests`)
answers only its own `acp_` credentials, never an organization's or the
platform's.

A success of a route that revokes access also carries the `revocations` it
recorded with the authority service before its commit
([README](README.md#revocations-pending-and-confirmed)); the test checks
their kinds route by route. `GET /v1/access-revocations/{id}` reads one of
the organization's with the rights of `GET /v1/audit`; the platform reads
only its own.

## Matrix

<!-- rbac-matrix:begin -->
| Route | owner | admin | operator | auditor | user | team | former | unassigned | service | foreign | revoked | revoked-token | platform |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `GET /v1/version` (no authentication) | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `GET /v1/platform/diagnostics` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/platform/session` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/platform/sessions` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/platform/sessions/{id}/revoke` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/health/live` (no authentication) | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `GET /v1/health/ready` (no authentication) | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| `GET /v1/organizations` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/organizations` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/organizations/{id}` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/organizations/{id}/disable` (a disposable organization) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/organizations/{id}/quotas` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `PUT /v1/organizations/{id}/quotas` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/harness-imports` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/harness-imports/{id}` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/harness-releases` (the platform's catalog) | yes | yes | yes | yes | 403 | 403 | 403 | 403 | yes | yes | 401 | 401 | yes |
| `POST /v1/harness-releases/{id}/deprecate` (a disposable release) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `GET /v1/system-images` | yes | yes | yes | yes | 403 | 403 | 403 | 403 | yes | yes | 401 | 401 | yes |
| `POST /v1/system-images` | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | yes |
| `POST /v1/templates` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `POST /v1/deployment-plans` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/deployment-plans/{id}/apply` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/deployments/{id}` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/deployments/{id}/rollouts` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/rollouts/{id}/members` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/rollouts/{id}` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/rollouts/{id}/resume` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/pools` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/pools/{id}` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/organizations/current` (the caller's own organization) | yes | yes | yes | yes | yes | yes | yes | yes | yes | filtered | 401 | 401 | 403 |
| `GET /v1/members` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | filtered | 401 | 401 | 403 |
| `POST /v1/members` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `POST /v1/members/{id}/role` (a disposable agent_user) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/members/{id}/revoke` (a disposable agent_user) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/teams` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | filtered | 401 | 401 | 403 |
| `POST /v1/teams` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/teams/{id}` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/teams/{id}/disable` (a disposable team) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/teams/{id}/members` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/teams/{id}/members` (a disposable team and member) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/teams/{id}/members/{principal_id}/revoke` (a disposable team membership) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/service-accounts` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/service-accounts` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `POST /v1/service-accounts/{id}/disable` (a disposable agent_user account) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/service-accounts/{id}/tokens` (an agent_user account) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/service-accounts/{id}/tokens` (an agent_user account) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 400 |
| `POST /v1/service-accounts/{id}/tokens/{token_id}/revoke` (a disposable token) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/audit` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | filtered | 401 | 401 | 403 |
| `GET /v1/audit/export` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | filtered | 401 | 401 | 403 |
| `GET /v1/access-revocations/{id}` (a revocation of the organization) | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 404 |
| `GET /v1/llm/providers` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/llm/providers` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `POST /v1/llm/providers/{id}/rotate` (a disposable provider) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/providers/{id}/disable` (a disposable provider) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/llm/aliases` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/llm/aliases` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/aliases/{alias}/disable` (a disposable alias) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/aliases/{alias}/access` (a disposable alias) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/aliases/{alias}/prices` (a disposable alias) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/llm/aliases/{alias}/grants` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/aliases/{alias}/grants` (a disposable alias, to the agent) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/aliases/{alias}/grants/{id}/revoke` (a disposable grant) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/llm/calls/unresolved` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/llm/calls/{id}/settle` (a disposable call of unknown outcome) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/calls/{id}/release` (a disposable call of unknown outcome) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/llm/budgets` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/llm/budgets` (for a disposable alias) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/llm/budgets/{id}/disable` (a disposable budget) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/llm/usage` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/queue` | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/organizations/current/quotas` (the caller's own organization) | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | 403 | filtered | 401 | 401 | 403 |
| `POST /v1/queue/limits` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/agents` | yes | yes | yes | yes | yes | yes | filtered | filtered | yes | filtered | 401 | 401 | 403 |
| `POST /v1/agents` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 400 |
| `GET /v1/agents/{id}` | yes | yes | yes | yes | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 403 |
| `DELETE /v1/agents/{id}` (a disposable agent) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/wake` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/sleep` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/idle-policy` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/release` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/agents/{id}/directory` | yes | yes | yes | yes | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `PUT /v1/agents/{id}/directory` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 400 |
| `GET /v1/agents/{id}/capabilities` | yes | yes | yes | yes | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `PUT /v1/agents/{id}/capabilities` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 400 |
| `GET /v1/organizations/current/capabilities` (the caller's own organization) | yes | yes | 403 | yes | 403 | 403 | 403 | 403 | yes | yes | 401 | 401 | 403 |
| `PUT /v1/organizations/current/capabilities` (the caller's own organization) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/agents/{id}/inbound` | yes | yes | yes | yes | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `PUT /v1/agents/{id}/inbound` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 400 |
| `GET /v1/agents/{id}/assignments` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/assignments` (to a disposable member) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/assignments/{assignment_id}/revoke` (a disposable assignment) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/assignments/{assignment_id}/replace` (a disposable assignment) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/assignments/{assignment_id}/reassign` (a disposable assignment, to a disposable member) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/messages` | 403 | 403 | 403 | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 403 |
| `POST /v1/agents/{id}/invocations` | 403 | 403 | 403 | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `GET /v1/agents/{id}/invocations` (a requester sees only its own) | yes | yes | yes | yes | yes | filtered | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `GET /v1/invocations/{id}` (the caller's own, else the user's) | yes | yes | yes | yes | yes | 404 | 404 | 404 | yes | 404 | 401 | 401 | 404 |
| `GET /v1/operations/{id}` (the caller's own, else the user's) | yes | yes | yes | yes | yes | 404 | 404 | 404 | yes | 404 | 401 | 401 | 403 |
| `GET /v1/invocations/{id}/result` (the caller's own, else the user's) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 403 |
| `GET /v1/operations/{id}/result` (the caller's own, else the user's) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 403 |
| `POST /v1/invocations/{id}/cancel` (a disposable invocation of the user) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 404 |
| `POST /v1/invocations/{id}/replay` (a disposable dead letter of the user) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/agents/{id}/requests/{request_id}/diagnostics` | yes | yes | yes | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `GET /v1/agents/{id}/held-requests` | yes | yes | yes | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `POST /v1/agents/{id}/held-requests/{request_id}/accept` (a disposable held request) | yes | yes | yes | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `POST /v1/agents/{id}/held-requests/{request_id}/decline` (a disposable held request) | yes | yes | yes | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 400 |
| `POST /v1/agents/{id}/attachments` | 403 | 403 | 403 | 403 | yes | yes | 404 | 404 | yes | 404 | 401 | 401 | 404 |
| `GET /v1/attachments/{id}` (the caller's own, else the user's) | yes | yes | yes | yes | yes | 404 | 404 | 404 | yes | 404 | 401 | 401 | 404 |
| `DELETE /v1/attachments/{id}` (a disposable file of the user) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 404 |
| `POST /v1/attachments/{id}/link` (the caller's own, else the user's) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 404 |
| `POST /v1/invocations/{id}/result/link` (the caller's own, else the user's) | 404 | 404 | 404 | 404 | yes | 404 | 404 | 404 | 404 | 404 | 401 | 401 | 404 |
| `GET /v1/downloads/{token}` (the link is the credential: a bearer opens nothing) | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /v1/users` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/users` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/users/{id}/tokens` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `GET /v1/me` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `GET /v1/me/messaging-settings` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `PUT /v1/me/messaging-settings` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `GET /v1/me/inbox` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `GET /v1/me/inbox/messages/{id}` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/me/inbox/requests/{id}/accept` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/me/inbox/requests/{id}/decline` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `GET /v1/agent-requests/{id}` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/agent-requests/{id}/cancel` (historical owner domain) | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 401 | 401 | 403 |
| `POST /v1/pools/{id}/expand` | yes | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/applications` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `POST /v1/applications` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | yes | 401 | 401 | 403 |
| `GET /v1/applications/{id}` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/applications/{id}/rotate` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/applications/{id}/revoke` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/assignment-policies/plan` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/assignment-policies/{id}/apply` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/applications/{id}/invitations` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `POST /v1/applications/{id}/accept` (requires the recipient's OIDC access token and invitation proof) | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 | 401 |
| `GET /v1/applications/{id}/activations/{activation_id}` (also visible to its member and application backend) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `PUT /v1/applications/{id}/activations/{activation_id}` (also available to the authorized application backend) | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
| `GET /v1/access/explain` | yes | yes | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 404 | 401 | 401 | 403 |
<!-- rbac-matrix:end -->

## What the matrix does not show

- Target policies inside a route: an administrator cannot change, revoke or
  create an owner or another administrator, the last owner cannot leave, and
  an administrator cannot manage an `org_admin` technical account
  ([members.md](members.md), [service-accounts.md](service-accounts.md)).
- The legacy owner domain's own credentials.
- What a harness remembers in its volume: the API filters do not prove the
  separation of a harness's memory between the people who used it
  ([ADR 002](../adr/002-assignment-revocation.md#reading-and-reassignment)).
