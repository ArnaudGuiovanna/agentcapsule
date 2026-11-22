# D-02 — Assignments, revocation and private results

Date: November 7, 2026, reviewed November 8. **Contract and structure
validated by the user**; targeted model and transactional mapping integrated.
The conformance of the Go product to this contract is built and tested for
the HTTP routes, reassignment and its races: see
[Conformance of the Go product](#conformance-of-the-go-product). The existing
models are not modified. References: product spec §2.2,
TEN-005/TEN-006, SC-06 ([product.md](../product.md)) and TEN-04/TEN-05 of the
[roadmap](../../ROADMAP.md).

## Decision

The admission of an invocation is the PostgreSQL commit that records together
the authenticated identity, the current authorization, the durable job and its
idempotency receipt. An earlier HTTP check is not an admission.

A confirmed revocation forbids any **new call** by this member, including
reading a result and replaying an old receipt. The revocation transaction waits
for the already authorized transactions holding the corresponding shared locks.
A request that arrived before the revocation, but whose transactional
authorization occurs after it, is refused. A result already authorized or sent
cannot be recalled from the network or from the client.

Durable work accepted **before** this revocation commit may complete for the
organization, within the limits of its TTL and the other applicable
authorizations. Revoking a member deletes neither the agent nor automatically
its organizational jobs. This restores no right of the former member and allows
no new admission with its revoked delegations. The existing request
cancellations, agent-deletion barriers and mandate revocations keep their own
guarantees. No external effect already performed is presented as undone.

The alternative is to cancel the jobs still pending at revocation, letting
those whose execution has already started finish. It requires a defined
execution start point and additional transitions; it is not implicitly selected
by this document.

## Reading and reassignment

For the proposed MVP, each private result of a human invocation is bound to its
original requesting principal. Reading it requires both this historical
identity and the **current** rights: active tenant and member, read scope, and
an assignment authorizing content on this agent. The administrative role and a
new assignment therefore do not give access to another member's results.
Redacted technical statuses remain accessible to the authorized administrative
roles. Reassigning an agent does not rewrite the historical participants of the
encrypted data and does not change the author of an operation.

An explicit reactivation of the same principal and a new assignment can make its
own still-retained results accessible again. Its old tokens and revoked
delegations remain invalid. Explicit sharing of results between members is not
provided by assignment alone; it will need its own access contract if the
product requires it.

This rule applies to the contents and receipts controlled by the PaaS. An
arbitrary harness may keep an old exchange in its volume and then return it in a
new response. The API filter does not prove the isolation of this memory. A
reassignment that requires this separation must use a new agent/volume, or a
harness whose session separation is explicitly verified. A shared agent may have
shared memory according to its policy.

## Targeted model

The Quint models are in [spec/](../../spec/). Coordination is a shared
PostgreSQL state: plain Quint is enough, without simulating distributed
messages. Concurrent calls are represented separately to distinguish arrival,
authorization and commit.

| Element | What it represents |
|---|---|
| Organizations | Active state and policy version |
| Principals | Tenant, active state and administrative role |
| Teams and assignments | Direct or team access; invocation and reading separated |
| Agents | Tenant ownership, live or deleted state |
| Invocations | Tenant, agent, original author, durable phase and version at admission |
| Concurrent calls | Prior authentication, authorization locks, commit or refusal |
| Credentials | Principal, abstract scopes and revoked state; no simulated cryptography |
| Observations | Forbidden admissions/reads and duplicates, remembered for the invariants |

Bounded configuration used: two tenants, at least three principals in the first
and one in the second, two agents of the first tenant and a foreign one, one
team, four invocations and three concurrent calls. No production ceiling is
derived from it. A failure abandons the unvalidated calls and their locks; the
durable registry of invocations and revocations is kept. Restoring an old
database, the keys and the harness's internal effects stay in their other
models/recipes.

Properties checked: no admission or read after a confirmed revocation; no
cross-tenant disclosure; administration without implicit content rights; replay
subject to the current authorization; the same invocation identity without
double creation; agent kept after offboarding. The scenarios and witnesses reach
revocation during a call, the completion of an already admitted job,
reassignment and the refusal of an old receipt. The negative mutations remove
the re-check, the lock or the historical recipient filter, to verify that these
defects are detectable. The simulation is neither an exhaustive proof nor a
proof of the Go code.

## Consequence for development

Tenant authentication, organization metadata and the capsule contract advance
independently. The explicit answer "Validate this proposal" now authorizes
writing the transitions and the targeted verification before the reassignment
code that depends on them. The P1/P2/P3 models and their results remain
unchanged. The transactional mapping includes the product spec's idempotency
namespace tenant/principal/operation type/key. These checks are neither an
exhaustive proof nor a proof of the Go code; the PostgreSQL tests and the tenant
path tests are the next obligations.

## Conformance of the Go product

November 16, 2026. What the Go product does and how it is checked:

- **Every route, every caller.** `internal/api/rbac_matrix_test.go` runs
  every route of the API as each of the five roles, a member assigned
  directly and one through a team, a former assignee, an unassigned member, a
  technical account with a narrow token, the owner of another organization
  using this one's identifiers, a revoked member, a revoked token and the
  platform operator, against PostgreSQL. The expected matrix is
  [docs/api/rbac.md](../api/rbac.md), generated from the test. No role opens
  an invocation or a result; another organization's identifiers answer 404.
- **Historical recipient filter.** A result is read only by its requester
  holding `read_content` now. Since this date the requester also sees the
  metadata of its invocations, operations and files only while it still sees
  the agent through an assignment; before, a former assignee kept reading
  them. An agent the caller cannot see answers 404 on its invocation list,
  which answered an empty list before.
- **Reassignment.** `POST /v1/agents/{id}/assignments/{assignment_id}/reassign`
  moves an assignment to another member or team in one transaction
  ([agents-assignments.md](../api/agents-assignments.md#reassignment)). It
  rewrites no requester and opens no result to the new target.
- **Admission, replay and read against revocation and reassignment.** Every
  authority change (member, team membership, assignment, reassignment) takes
  the organization's row exclusively; every admission, replay and result read
  holds it shared from its authorization to its commit. The PostgreSQL tests
  in `internal/controlplane/assignment_reassignment_test.go` and
  `members_test.go` hold that row to order the transactions: an admission
  authorized first commits and the change waits; one that arrived earlier but
  is authorized later is refused, replay and result read included. Taking the
  row shared in the reassignment makes these tests fail.
- **Not modelled here.** The targeted Quint model this record describes is not
  among the models of [spec/](../../spec/README.md); `revocation.qnt` is the
  deletion barrier across stores. The tests above check the orders the model
  names on the real code; they are not an exhaustive exploration.

Defaults pending the product owner:

- Work admitted before a revocation or a reassignment runs, including a
  scheduled invocation not yet due, which runs when due on behalf of a
  requester who can no longer read its result or cancel it.
- Only the requester cancels an invocation, and only while it may still
  invoke: after a reassignment, nobody can cancel the old target's pending
  work.
- A sender who lost its assignment may still delete its own file not yet sent.
- Roles that read agent metadata see the metadata of every member's files,
  their names included.

## Changes after the v0.1.0 audit

### The admission holds its organization's row FOR KEY SHARE (PERF-3B, finding P-07)

The rule above is unchanged: every authority change takes the
organization's row exclusively (`FOR UPDATE`); every admission, replay and
result read holds it from its authorization to its commit. The admission now
holds it `FOR KEY SHARE`, the weakest lock that conflicts with `FOR UPDATE`,
instead of `FOR SHARE`, and no longer locks its principal, membership,
issuer, trust, key or token: no revocation of those rows runs without the
organization's row ([ADR 001](001-organization-identity.md#one-row-lock-per-admission-perf-3b-finding-p-07)).
The replay of a revocation after a failover now takes that row too. The
tests of this record still pass, and
`TestEachRevocationWaitsForAnAdmissionAuthorizedBeforeIt` orders an
admission and each kind of revocation.
