# D-02 — Assignments, revocation and private results

Date: November 7, 2026, reviewed November 8. **Contract and structure
validated by the user**; targeted model and transactional mapping integrated.
The conformance of the Go product to this contract remains to be built and
tested. The existing models are not modified. References: product spec §2.2,
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
