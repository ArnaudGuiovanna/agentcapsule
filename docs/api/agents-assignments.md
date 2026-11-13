# Tenant agents and assignments

This part gives an organization its own agents, several per member, and an
assignment mechanism. It covers TEN-01, TEN-04 and the first half of TEN-05;
see the [roadmap](../../ROADMAP.md) for what remains.

## Two agent domains

An agent belongs to **exactly one** domain (constraint `agents_one_domain`):

- **legacy**: `owner_user_id`, one agent per owner, `acp_` tokens;
- **tenant**: `tenant_id`, any number of agents, delegated JWT.

The legacy paths (`/v1/agents` with an `acp_` token, wake, sleep, deletion,
operations) filter on `tenant_id IS NULL`: a legacy service never sees, wakes or
deletes a tenant agent. A tenant principal never reaches the legacy lists.

## Routes (delegated JWT)

| Route | Scope | Current role required |
|---|---|---|
| `POST /v1/agents` | `agent:create` | `org_owner`, `org_admin`, `agent_operator` |
| `GET /v1/agents`, `GET /v1/agents/{id}` | `agent:read` | see below |
| `GET /v1/operations/{id}` | `agent:read` | requester of the operation, or a role that can read metadata |
| `POST /v1/agents/{id}/wake`, `POST /v1/agents/{id}/sleep` | `agent:operate` | `org_owner`, `org_admin`, `agent_operator` |
| `DELETE /v1/agents/{id}` | `agent:delete` | `org_owner`, `org_admin` |
| `POST /v1/agents/{id}/messages` | `agent:invoke` | none: `invoke` permission of an assignment |
| `GET /v1/operations/{id}/result` | `agent:content:read` | none: original requester AND `read_content` permission |
| `POST /v1/agents/{id}/assignments` | `agent:assign` | `org_owner`, `org_admin` |
| `GET /v1/agents/{id}/assignments` | `agent:assign` | `org_owner`, `org_admin` |
| `POST /v1/agents/{id}/assignments/{assignment_id}/revoke` | `agent:assign` | `org_owner`, `org_admin` |
| `POST /v1/agents/{id}/assignments/{assignment_id}/replace` | `agent:assign` | `org_owner`, `org_admin` |
| `PUT /v1/agents/{id}/directory` | `agent:manage` | `org_owner`, `org_admin`, `agent_operator` |
| `GET /v1/agents/{id}/directory` | `agent:read` | a role that can read metadata, or a `read_metadata` assignment |
| `PUT /v1/agents/{id}/inbound` | `agent:manage` | `org_owner`, `org_admin`, `agent_operator` |
| `GET /v1/agents/{id}/inbound` | `agent:read` | a role that can read metadata, or a `read_metadata` assignment |

Creation reuses the worker's existing provisioning (reservation, volume,
activation, automatic wake). The operations of a tenant agent have no owner
user: they record `requested_by_principal_id`.

## Visibility

The roles `org_owner`, `org_admin`, `agent_operator` and `auditor` read the
metadata of **all** agents in their organization. Any other member sees only the
agents on which they have an active assignment, either direct or through an
active team of which they are an active member. A non-visible agent answers 404,
like a nonexistent one. These views are redacted: no conversation content.

## Assignments

An assignment designates either `principal_id` or `team_id`, with permissions
among `read_metadata`, `invoke` and `read_content`, which are independent. There
is one active assignment per target and per agent (duplicate: 409). An
administrative role grants neither invocation nor content reading; only an
assignment does, and it does not give access to another member's historical
results (D-02).

The effective right is evaluated in the transaction that consumes it: removing a
member from a team, revoking the assignment or revoking the member ends access
at the next request. Revoking a member deletes no agent of the organization.
Mutation, audit (`tenant_agent_audit`) and receipt are atomic.

## Limits

- Covered: creation, metadata reading, wake, sleep, deletion, assignment
  management, invocation and reading the result.
- Widening a target's rights requires revoking its assignment and creating a new
  one; see "Atomic replacement" below for the single-transaction alternative.
- Messaging settings, the inbox and instructions of the legacy domain remain
  separate and do not concern tenant agents. Requests between the agents of one
  organization follow the organization's inbound policy (below).

## Invocation and private results

The right to invoke comes **only** from an assignment (`invoke`); no role,
including `org_owner`, grants it. It is read in the admission transaction,
before any receipt replay: a revoked member or assignment is refused even with
an idempotency key that was already used.

The encrypted (transit) content is bound to the **requesting principal**, not to
the agent's administrator. Its result is readable only by that principal, and
only while they still hold `read_content` on the agent: neither an
administrator, nor another member, nor a new assignee opens it (D-02), and
revoking the assignment or the member closes it again. Work accepted before a
revocation may complete for the organization without making its result readable
to the former member.

The legacy messaging settings and inbox (`/v1/me/...`) do not apply to tenant
agents. Their requests to each other run under the mandate of the invocation
being worked on and the recipient's inbound policy.

## Atomic replacement

`replace` takes `{"permissions": [...]}` and, in a single transaction, revokes
the active assignment then creates its replacement for the same target (person
or team). There is no instant without rights and no double set of active rights.
An already revoked assignment answers 409; the target must remain active. The
audit records `assignment.revoked` then `assignment.created`. As with any
authority decision, content already produced is not transferred: only the
original requester re-reads it, while they hold `read_content`.

## Structured invocations

`POST /v1/agents/{id}/invocations` admits a request exactly like `/messages`
(scope `agent:invoke` and `invoke` assignment, never a role), but answers with
an `Invocation` resource that is then tracked:

| Route | Scope | Who |
|---|---|---|
| `POST /v1/agents/{id}/invocations` | `agent:invoke` | `invoke` assignment |
| `GET /v1/agents/{id}/invocations` | `agent:read` | the requester (their own); a role reading metadata (all) |
| `GET /v1/invocations/{id}` | `agent:read` | same |
| `GET /v1/invocations/{id}/result` | `agent:content:read` | requester AND current `read_content` |

The states describe what the platform actually knows: `accepted` (persisted, not
processed), `working`, `completed` (the agent answered), `failed`, `canceled`,
and `lost` (a restore lost the outcome, see below). A delivery acknowledgment is
never presented as a business success. The metadata
contains neither the instruction nor the result; `result_available` only
indicates that a result exists. An invocation's identifier is that of the
underlying operation.

Idempotency of `/invocations` is distinct from that of `/messages`: the same key
on the two routes never replays the response of the other form. Same key and
same content replays the initial response; same key and different content
answers 409.

### Queues, deadlines and dead letters (EVT-02)

- **TTL**: `ttl_seconds` (1 to 86 400, default 3 600) bounds the *wait before
  delivery*, not the execution. The deadline is visible (`expires_at`). A
  different TTL with the same key is a different request (422).
- **Depth**: per organization, 100 pending instructions per agent and 1 000 in
  total by default; `POST /v1/queue/limits` (`quota:manage`) replaces them,
  `GET /v1/queue` (`usage:read`) gives limits and depth (counters only). Beyond
  that: **429 `queue_full`** with `Retry-After`, *before* any write: no
  operation, no content and no inbox entry is created. A replay of an
  already accepted request is never refused. Delivered, expired or dead
  instructions free their slot; lowering a limit abandons nothing, it only
  refuses new admissions.
- **Dead letters**: an instruction that was never executed closes with
  `close_reason` `expired`, `attempts_exhausted` or `closed` (state `expired` for
  the first); `expired` wins if the deadline has also passed. The operation's
  `error_code` stays `delivery_failed` / `delivery_outcome_unknown`: an unknown
  outcome is never presented as "not processed".
  `GET .../invocations?state=failed|expired` lists them.
- **No priority**: ordering within an agent stays FIFO. The verified delivery
  model has none and D-04 forbids adding one without revisiting it. Bounded
  retries, delay between attempts and fence closure were already in place
  (`attempt_limit`, `RetryBase`, `RetryMax`, `RetireInstruction`).

Limits: content remains text (the guest protocol has no JSON type); there is no
`/events` stream yet, no expiry signaled in the state, and no wake of a stopped
recipient driven by this resource (EVT-02/CAP-02).

### Lost in a restore (REC-02)

An agent restored from an archive may lack outcomes it produced after the
archive. Each one is declared lost
([recovery.md](../recovery.md#the-lost-invocations),
[ADR 003](../adr/003-restore-rpo.md)). The invocation then runs again under
the same identifier:
- its state is `lost` until the rerun ends, and `lost_at` gives the time of
  the loss. `?state=lost` lists these invocations. A lost invocation has no
  `completed_at`;
- the result that the database still holds stays readable through
  `/result`. The rerun's result replaces it;
- the rerun then ends like any invocation, `completed` for instance, and
  keeps `lost_at`. A `completed` invocation with `lost_at` ran again; its
  `completed_at` is the rerun's;
- it does not run again when the requester can no longer invoke the agent,
  the agent is being deleted, or its content is no longer stored. It then
  stays `lost`, and `error_code` says why: `requester_revoked`,
  `agent_unavailable`, `input_purged` or `attachments_purged`;
- the requester can cancel it until its rerun reaches the agent:
  `POST /v1/invocations/{id}/cancel`. The rerun then never runs, and the
  state becomes `canceled`, with `lost_at`.

The rerun keeps the invocation's mandate and its remaining budget: with its
first run, it makes no more agent requests than the requester allowed. These
rules are defaults that the product owner has not confirmed yet.

## Desired and observed state, lifecycle audit (CAP-02)

A tenant agent exposes `state` (observed: `STOPPED`, `STARTING`, `READY`, ...)
and `desired_state` (`running`, `stopped`, `deleted`), with `converged` when one
matches the other. The desired state comes from the operations **journal**, not
from a free-form wish: the last accepted wake or sleep that neither failed nor
was canceled, otherwise `auto_start`, and `deleted` as soon as a deletion is
requested. An agent created cold is therefore `stopped`/`STOPPED` and converged,
with no VM. `converged: false` after an accepted wake means "requested, not yet
observed"; this field **reports**, it does not restart a stopped agent.

Wake, sleep and deletion are audited (`tenant_agent_audit`:
`agent.wake_requested`, `agent.sleep_requested`, `agent.delete_requested`), in
the command's transaction: a refused command leaves no trace, a replay adds
none, and several deletion requests produce a single row since they share one
operation. Simultaneous commands receive strictly distinct sequences.

## Scheduling and idle shutdown (EVT-03)

**Scheduled execution.** `run_at` on `POST /v1/agents/{id}/invocations` (at
least 1 s in the future, at most 30 days, checked against the database clock).
The invocation immediately has its identity, its encrypted content and its place
in the depth queue (scheduling does not bypass the limit), but **no inbox
entry**: a future item at the head of the FIFO would block everything behind it.
At the deadline, `ReleaseDueInstructions` creates the entry exactly once, under
the row and agent lock, with the original identity: several workers or a restart
neither lose nor duplicate it, and nothing is released before time. The TTL runs
from the deadline. An agent being deleted closes its scheduled instructions
(`canceled`, `agent_unavailable`) and their content is destroyed.
`POST /v1/invocations/{id}/cancel` cancels before release (requester only);
afterwards, 409. State `scheduled`, filter `?state=scheduled`. Delivery order is
release order, not admission order.

**Idle shutdown.** `POST /v1/agents/{id}/idle-policy` (same right as sleep). The
scheduler cuts nothing: it writes the ordinary sleep command
(`cause: idle_policy`), executed with the quiesce acknowledged by the guest. The
idle clock starts when it sees the generation running, never before (it can
delay a stop, never stop an agent that has just woken), and restarts with each
new generation. Counted as work, hence blocking: a pending delivery, an open
lifecycle command (an open sleep also prevents a duplicate), an unclosed
exchange with another agent, a model call in progress, a scheduled instruction
due before the end of the window. Counted as activity that restarts the clock:
wake, instruction, exchange, model call. The decision is rechecked under the
agent's lock, the same one as admission: a concurrent invocation keeps the agent
awake, or wakes it afterwards through ordinary delivery. The principal who set
the policy answers for the sleeps (audit `agent.idle_sleep_requested`).

Limits: "critical task not checkpointed" is known to the platform only through
what it tracks (operations, inboxes, exchanges, model calls); an internal
harness computation with no platform-side trace is not seen, and it is the stop
with acknowledged quiesce that protects its data. The tests drive the clock; the
worker's real loop has not run under KVM.

## Attachments (EVT-04)

A file is sent **before** the invocation that carries it, then the invocation
cites it by its opaque identifier:

```http
POST /v1/agents/{id}/attachments?ttl_seconds=3600
Content-Type: application/pdf
X-Attachment-Name: annual%20report.pdf
X-Content-SHA256: <hex, optional>
Idempotency-Key: ...

<file bytes>
```

then `POST /v1/agents/{id}/invocations` with `"attachments": ["att_..."]` (at
most 8).

| Route | Scope | Condition |
|---|---|---|
| `POST /v1/agents/{id}/attachments` | `agent:invoke` | `invoke` assignment (like the invocation) |
| `GET /v1/attachments/{id}` | `agent:read` | the sender; a role reading metadata |
| `DELETE /v1/attachments/{id}` | `agent:invoke` | the sender, file still `pending` |

- **Storage**: at most 8 MiB per file. The body is split into 256 KiB segments,
  each encrypted with AES-GCM under the active transit key. The associated data
  binds each segment to its file, its position, the organization, the agent, the
  sender, the size and the digest: a segment that is moved or copied no longer
  opens. A declared digest that differs from the received one is refused before
  any storage. The API never returns the content.
- **Single use**: a `pending` file is usable only by its sender, for that agent,
  before its deadline, and by a single invocation. Attachment happens in the
  admission transaction: a single unusable file refuses the whole invocation
  (409 `attachment_unavailable`) and nothing is accepted.
- **Delivery**: the `capsule.v1` envelope received by the guest contains only
  references (`id`, name, type, size, digest), with no bytes or host path. The
  guest reads the segments with `POST /v1/attachments/read` on the authenticated
  platform channel (`PlatformClient.FetchAttachment` checks the segment count,
  the size and the digest). Reading is allowed only to the recipient agent, of
  the current generation, while the invocation is in progress (acknowledged
  "working" and before its deadline); before and after, 404.
- **Quota and purge**: the unpurged bytes of an organization are capped by
  `max_attachment_bytes` (`POST /v1/queue/limits`, default 512 MiB, 1 MiB to
  64 GiB). Exceeding it answers 429 `attachment_quota_exceeded`; concurrent
  uploads do not exceed it. The worker purges unattached expired files and those
  whose invocation is finished (completed, failed, expired or canceled: nobody
  can read them anymore). Deleting an agent erases the files in the request's
  transaction. A purged file keeps its metadata (`purged`).
- **Audit**: `attachment.uploaded` and `attachment.deleted`. These actions change
  no authorization policy and therefore do not advance the organization's policy
  version.

Limits: the file passes through the API's memory (8 MiB per simultaneous upload)
and is stored in PostgreSQL, with no external object storage or temporary link.
Media type parameters (`charset`, ...) are not kept. Results remain text: an
agent cannot return a file yet.

The guest reads its files **after** acknowledging "working" (next section):
during delivery, its platform calls wait for the host's exclusive turn.

## Deferred result: the `working` state

The worker delivers an instruction under an **exclusive admission turn** of the
host: nothing else is interleaved (stop, deletion, another delivery) between the
send and the acknowledgment. The guest's platform calls (reading a file, calling
the model, writing to another agent) wait for the end of this turn. An agent
that needs them to answer therefore cannot answer *within* the delivery.

It then answers exactly `{"status":"working"}` (`capsuleprotocol.WorkingResult`):
- the delivery is closed like any other, and the FIFO advances (the verified
  delivery semantics do not change);
- the operation stays `RUNNING`, the invocation is `working`, with
  `result_due_at` = acknowledgment + `work_timeout_seconds` (60 to 86 400;
  default 3 600);
- the agent then works (files, model) and files its outcome with
  `POST /v1/invocations/complete` on the platform channel: `completed` with
  content, or `failed`.

| Event | Effect | Subsequent refusal |
|---|---|---|
| Filing by the agent (current boot, before the deadline) | `completed` (result readable only by the requester) or `failed` `agent_failed` | same key and same content: replay; otherwise `conflict` |
| Deadline exceeded (worker) | `failed` `work_timeout` | late filing: `expired` |
| Cancellation by the requester (`POST /v1/invocations/{id}/cancel`) | `canceled` | filing: `transition` |
| Agent deletion | `canceled` `agent_unavailable` | filing: refused |

Each outcome is taken under the agent's lock and then those of the instruction
and operation rows: only one wins (model
[invocation_completion.qnt](../../spec/invocation_completion.qnt) and a race test
on PostgreSQL). A `working` agent is not put to sleep by its idle policy.
Canceling does not stop the computation in progress in the VM: the agent learns
of it when it files its result.

The reference harness answers `working` for an invocation that carries files or
begins with `/llm <alias> <text>`. It reads the files, calls the model and files
a response that gives, for each file, its size and digest, followed by the
model's text. The computation is kept before the filing: a replayed filing does
not call the model again.

## Directory publication (INT-02)

An organization makes an agent findable by the other agents of the same
organization with `PUT /v1/agents/{id}/directory`:

```json
{"visible": true, "description": "Summarizes documents.", "skills": [10302], "domains": [111]}
```

Skills and domains are OASF 1.1.0 class IDs (see
[docs/interop.md](../interop.md)). The worker's publisher then writes an OASF
record to the platform's private AGNTCY Directory. The record holds the
description, the skill and domain IDs, and an opaque name
`agentcapsule/<organization>/<agent>`; nothing else about the agent or its
organization. `GET` shows the description and the record's `publication`:

| `publication` | Meaning |
|---|---|
| `pending` | The Directory is behind the last change; the publisher retries with backoff while it is unreachable |
| `published` | The current description is the record in the Directory (`record_cid`) |
| `unpublished` | No record: the agent is hidden, no longer live, its organization is suspended, or it was never described |
| `invalid` | The OASF schema refused the record; `error` gives the schema server's reason, and the previous record was withdrawn |

Each change becomes a revision in PostgreSQL. Hiding the agent, deleting it or
suspending its organization creates one too, through triggers. The publisher
records each step before the next: the new record is recorded before the old
one is deleted. A crash therefore leaves at worst a record to delete again,
never a record the platform does not know about. Every change is audited
(`agent.directory_changed`, no policy version bump: who can find an agent is not
an authorization rule).

**Search from an agent.** A running agent searches through the platform
channel (`/v1/directory/find`, `find_agents(skills)` in the Python SDK) by
skill IDs; one of them suffices. The Directory narrows the candidates to the
caller's organization and skills. PostgreSQL then keeps only the current records
of agents that are still discoverable, live, of the caller's organization, not
the caller, and still offer one of the skills. Descriptions come from
PostgreSQL. Finding an agent grants no right: a request to it still goes through
consent and mandates. A host without Directory, or a Directory outage, answers
`unavailable`; requests to agents already known are not affected.

**Inbound policy.** Whether a request from another agent of the organization
is delivered at once or held for approval is the organization's decision, per
agent: `PUT /v1/agents/{id}/inbound` with `{"mode": "auto"}` or
`{"mode": "manual"}` (`agent:manage`; `GET` for whoever may read the agent's
metadata). `manual` is the default. A request to an `auto` agent is delivered at
once, still under the sender's mandate and only if the recipient is
discoverable and live. A change applies to requests submitted afterwards,
bumps the organization's policy version (who may deliver work to an agent is
an authorization rule) and is audited (`agent.inbound_changed`).

**Held requests.** A request held for approval waits for a person of the
organization: whoever may configure the recipient (`agent:manage`: owners,
administrators, agent operators) or whoever is assigned to it with `invoke`
(`agent:invoke`). Anyone else gets 404 if they cannot see the agent and 403
otherwise.

- `GET /v1/agents/{id}/held-requests` lists the requests the agent holds, the
  nearest deadline first (`after`, `limit` up to 100). Each one gives the
  sending agent, `requested_by` (the person whose invocation granted the
  sender's mandate), and when it was sent and expires. The content is not
  shown: it belongs to `requested_by` (D-02). A request past its deadline or
  closing is no longer listed.
- `POST /v1/agents/{id}/held-requests/{request_id}/accept` delivers it as
  `auto` would have, still under the sender's mandate.
  `.../decline` refuses it and tells the sender. Both take an empty body and an
  idempotency key, and answer `{"request_id", "state"}` (`DELIVERING` or
  `DECLINED`). Both agents must be live (409 `agent_unavailable`). A request
  already decided, closing or past its deadline is 409 `invalid_transition`.
  The same key for the opposite decision is 422. Each decision is audited
  (`agent.request_accepted`, `agent.request_declined`), with the request as
  the audit event's `reference`.

**Wake budget (INT-04).** The agents of an organization may wake sleeping
agents through requests at most `max_peer_wakes_per_hour` times per rolling hour
(default 60, 1 to 100 000, set with the other limits by
`POST /v1/queue/limits`, `quota:manage`). `GET /v1/queue` gives
`peer_wakes_last_hour`.
- **What counts.** A wake counts when the worker boots a sleeping agent for a
  request between agents of the organization. Nothing else does:
  - a request to an agent whose VM already runs;
  - a reply or a status, which completes work already admitted and always
    wakes its recipient;
  - an invocation by a person, which the queue limits bound;
  - an explicit wake;
  - a restart to renew credentials.
- **When the budget is used up.** The request waits, without spending a
  delivery attempt, until the rolling hour frees a wake, and expires at its
  deadline otherwise. Meanwhile its A2A task stays `SUBMITTED`. A boot that
  fails gives its wake back.
- **Logs.** The worker logs `wake_budget_exhausted` while one of its
  deliveries waits.

**Agent Cards and request state (INT-03).** Two more reads on the platform
channel serve the A2A endpoint of [capsule-adapter](../adapter.md#other-agents-a2a-endpoint):

- `/v1/directory/agent` (`agent_id`) describes one agent the caller may send
  requests to, with exactly the rules of a request: another agent, live,
  discoverable, of the caller's organization. Missing, hidden and foreign
  agents are the same `not_found`. It needs no Directory: the description and
  skills come from PostgreSQL, empty for an agent never described.
- `/v1/agent-requests/{id}/status` returns the state, recipient and deadline
  of a request the caller sent; any other request is `not_found`. The reply
  itself only arrives as an event.

Both pass the placement check of every VM call and decide nothing.

