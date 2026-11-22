# LLM-01, LLM-03 — Model access per agent and team, cost budgets, unknown outcomes

Date: November 16, 2026. **Status: built on November 16, 2026, with four
defaults pending the product owner** (see
[Questions](#questions-for-the-product-owner)). Amended on November 16,
2026: a provider's address (§5). This record closes the
remaining work of LLM-01 other than the dedicated secret store (D-05,
[ADR 005](005-keys-outside-restored-domain.md)), and of LLM-03. References:
product spec §4, LLM-001, LLM-004 to LLM-008 and TEN-007
([product.md](../product.md)), LLM-01 and LLM-03 of the
[roadmap](../../ROADMAP.md), [docs/api/llm.md](../api/llm.md),
[docs/observability.md](../observability.md).

## Context

When this record was written:

- **Access.** An organization's aliases were organization-wide: every agent
  of the organization could call every active alias. The product spec asks
  for calls "mediated by agent, scope and budget: unauthorized agents
  refused" (LLM-004), and "effective rights = harness capabilities ∩
  organization policy ∩ agent policy".
- **Budgets.** Budgets limited tokens only. An alias carried two prices, in
  micro-units of the organization's currency per million tokens, set once at
  its creation; the usage report estimated the cost of settled calls from
  them. The spec asks for hard and soft caps on tokens **and estimated cost**
  per organization, agent, model and period (§4 LLM gateway, LLM-005,
  TEN-007).
- **Unknown outcomes.** A timeout after the request left marks the call
  `unknown`: its reservation keeps counting, so uncertainty never reads as
  zero spend (LLM-02). Nothing ever settled such a call: `SettleLLM` could,
  but no route or command called it. A reservation whose worker died before
  the outcome stayed `reserved`, counted as in flight, until a retry with the
  same key turned it `unknown`.
- **Cost arithmetic.** `SettleLLM` computed `input*price + output*price` on
  64 bits. At the accepted bounds (10^12 tokens, 10^12 per million) the
  products overflow: 10^12 input and output tokens at 10^12 gave
  4,007,528,410,414 micro-units instead of 2 × 10^18.

## Decision

### 1. Access: an alias is open to the organization, or listed

An alias has an **access**: `organization` (every agent of the organization,
the default and the state of every existing alias) or `listed`. A listed
alias serves only the agents its active **grants** name. A grant names one
agent, or one team: it reaches the agents with an active assignment to that
team, while the team is active. Any assignment counts, whatever its
permissions.

- The check runs in the reservation's transaction, before the request key is
  read and before anything is reserved. A refusal is the typed error
  `LLMRefusal{Reason: "alias_access"}` (`ErrLLMAliasDenied`). On the VM
  channel it is the existing code `unauthorized`, so no guest changes.
- Revoking the last grant of a listed alias leaves it reachable by **no**
  agent. Opening it to the organization again is an explicit change of its
  access.
- The rights are those of the alias routes: `provider:manage` and the roles
  `org_owner` and `org_admin`. Every change is audited: `alias.access_set`,
  `alias.grant_created`, `alias.grant_revoked`.
- An agent operator creates agents but cannot grant aliases or assign agents
  to teams. So a new agent reaches no listed alias until an administrator
  says so.

The harness's `llm.invoke` capability is not checked by the gateway yet:
capability negotiation against the organization's policy is CAP-01's
remaining work. Access by alias is the organization and agent part of the
intersection.

### 2. Cost budgets

- A budget limits tokens (`limit_tokens`) **or** estimated cost
  (`limit_cost_micro`, in integer micro-units of the organization's
  currency), never both. Scopes and periods are those of the token budgets:
  organization, agent, alias, or agent and alias; UTC day or month. One
  active budget per scope, period and unit.
- **Prices.** An alias has two prices, input and output, in micro-units per
  million tokens. Anthropic's cached input counts as input, as the token
  counts already do. The organization sets them at the alias's creation or
  replaces both later (`POST /v1/llm/aliases/{alias}/prices`, audited
  `alias.prices_set`). An alias is **priced** once they are set; zero prices
  set on purpose are a free model.
- **Reservation.** A call reserves its estimated cost next to its tokens:
  its estimated input (about one token per three bytes) and its output cap,
  at the alias's current prices, rounded up once to the micro-unit. The cost
  check runs under the same budget row locks as the token check, in the same
  transaction.
- **Settlement.** A call keeps the prices of its reservation. Its settlement
  prices the provider-reported tokens at those prices, so a price change
  applies to calls reserved after it, and a reservation and its settlement
  never use two different prices.
- **What a window counts.** Settled calls count their estimated cost; calls
  in flight and of unknown outcome count their reserved cost; released calls
  count nothing.
- **Hard and soft.** A hard cost budget refuses before the provider is called
  (`budget_cost`). A soft one lets the call through and reports it: the
  answer's `soft_budget_exceeded`, a metric and a log line for the operator.
- **Exact arithmetic.** Costs are computed on big integers, then rounded up
  once per call. Prices are bounded by 10^12 per million tokens and tokens
  by 10^12 per call, so a call's cost fits in 64 bits.

### 3. Unknown outcomes: the organization settles or releases them

The provider's account belongs to the organization: only the organization
can read what a call of unknown outcome really cost. So the organization
reconciles it, through the API:

- `GET /v1/llm/calls/unresolved` (`usage:read`) lists the calls of unknown
  outcome, and the reservations older than 15 minutes, longer than any call
  can last (the bridge's 300 s), whose worker died before their outcome.
- `POST /v1/llm/calls/{id}/settle` (`quota:manage`) settles one at the
  tokens the organization read in its provider's account, at the prices of
  its reservation. `POST /v1/llm/calls/{id}/release` records that the
  provider billed nothing.
- A call already resolved, or still possibly running, is refused (409).
  When the organization and a late worker settlement race, one wins and the
  other is refused. Each resolution is audited (`usage.settled`,
  `usage.released`) and records who made it.
- Nothing is resolved automatically. An unresolved call counts in the window
  of its creation only: it stops weighing on the next day or month.

The platform operator does not settle calls. They see how many wait
(`agentcapsule_llm_unresolved_calls`), never whose.

### 4. Metrics: technical for the operator, per tenant in the API

[observability.md](../observability.md) forbids organization, agent and member
identifiers in metrics, and free text in logs. So:

- The operator's metrics count tokens and estimated cost by provider kind,
  outcomes, refusals by reason, soft budgets passed by unit, and unresolved
  calls. Aliases and models are tenant text: they are not labels.
- Each organization reads its own figures per agent and per alias (the alias
  names the model), per day or month, from `GET /v1/llm/usage`: settled,
  in-flight and unknown-outcome tokens and cost, with totals. A budget list
  gives each active budget's consumption.

### 5. A provider's address (amended on November 16, 2026)

A provider is reached only at a public address, or at an internal one the
operator allows ([ADR 010 §4](010-transport-security-and-preflight.md#4-providers-and-registries-over-https)).
For accounting:
- A call to a refused address is a refusal: nothing was sent, the
  reservation is released, and the guest gets `rejected`.
- A redirect (3xx) is a refusal too. It used to be an unknown outcome, which
  the organization had to release by hand, though a redirect is never an
  answer and is never followed.
- At registration, an `https` URL that writes an internal address out is
  refused (`provider_address_not_allowed`).

## What was built

| Item | Where |
| --- | --- |
| Migration 0032: alias access and `priced`, `llm_alias_grants`, cost budgets, prices and reserved cost per call, who resolved a call, audit actions | `internal/controlplane/migrations/0032_llm_access_and_cost.sql` |
| Access and grants, prices | `internal/controlplane/llm_access.go` |
| Cost reservation, settlement at the reservation's prices, exact cost, usage and budget consumption | `internal/controlplane/llm_budgets.go` |
| Reconciliation | `internal/controlplane/llm_reconcile.go` |
| Observer of each call's outcome | `internal/controlplane/llm_service.go` |
| Operator metrics and events, refusal codes | `internal/worker/llm_telemetry_linux.go`, `internal/worker/platform_linux.go` |
| Routes | `internal/api/llm.go`, `openapi/openapi.yaml` |

Tests against PostgreSQL (`internal/controlplane/llm_access_test.go`,
`llm_cost_test.go`, `llm_reconcile_test.go`, `internal/api/llm_test.go`):
access by agent and by team, the refusal before any reservation and before
the provider, grants revoked, assignments revoked and teams disabled; hard
and soft cost caps per organization and per agent; the unpriced alias; prices
fixed at reservation; the exact cost at the bounds; 30 concurrent
reservations against a hard cost cap; settlements racing reservations; three
outcomes racing for one call; reconciliation, its rights, and its race with
a late settlement; the migration on an installation that already has
aliases, budgets and calls.

## Not changed

- The guest: the refusal codes are those it knows. Its model endpoint still
  explains `quota_exceeded` as "the organization's token budget": it now
  also covers a cost budget.
- The secret store and the rotation of the key that encrypts provider
  credentials: D-05.
- The `llm.invoke` capability of the harness: CAP-01.
- Currency: an organization's prices and cost budgets share one unit by
  convention; no currency code is recorded.

## Questions for the product owner

Each is a default the code applies until the product owner answers.

1. **Who may use a model: listed per model, or per agent?** Scenario: your
   organization has an expensive alias `opus` and a cheap one `fast`. You
   want only the research agents on `opus`.
   - (a) *Chosen.* Mark `opus` listed and grant it to the Research team.
     Agents created later reach `opus` only when an administrator grants it;
     a new alias is open to every agent until it is listed.
   - (b) Restrict each agent to a list of aliases. A new agent, which an
     agent operator may create, reaches every alias until an administrator
     restricts it.
   - Recommendation: (a). The restriction stays with the expensive model and
     survives new agents.
2. **Which assignment puts an agent in a team for model access?** Scenario:
   an agent is assigned to the Auditors team with `read_metadata` only, and
   Auditors are granted `opus`.
   - (a) *Chosen.* Any active assignment: the agent may call `opus`.
   - (b) Only an assignment with `invoke`.
   - Recommendation: (a), simpler to explain. Choose (b) if teams are
     granted models for the people who invoke agents, not for the agents.
3. **A hard cost budget and a model without prices.** Scenario: you set a
   hard monthly cap of 50 € on the organization. Your local model `local`
   was declared without prices.
   - (a) *Chosen.* Calls to `local` are refused until you set its prices,
     zero included. The cap always holds.
   - (b) Calls to `local` go through and count zero.
   - Recommendation: (a). A hard cap that an unpriced model bypasses is not
     a cap.
4. **Who resolves a call of unknown outcome?** Scenario: a call timed out
   after it was sent. Its reservation, 4,000 tokens and 12 cents, counts
   against today's budgets until someone resolves it.
   - (a) *Chosen.* The organization's administrator, who can read the
     provider's account, settles or releases it. Nothing is automatic; it
     stops counting at the end of the day or month.
   - (b) In addition, settle it automatically at its reservation after 7
     days (counted as spent).
   - (c) Release it automatically (counted as free).
   - Recommendation: (a). (c) would read uncertainty as zero spend.

## Changes after the v0.1.0 audit

**Lot SEC-2 (findings S-11, S-12, S-13, L-06, L-07, L-08, and the gateway
part of P-12).** What a reservation counts and what a hard budget promises
changed:

- **Request policy, per alias.** A forwarded request passed every field
  except `stream`, `n` and the output caps: a guest could ask for a
  provider's web search, code execution or MCP connector, or a priority
  service tier, outside the VM's closed network and beyond any metered
  token. A forwarded request now passes only its API's plain fields and the
  client's own tools; anything else is refused before any reservation with
  the channel code `feature_denied`, unless the alias's request policy names
  it (`POST /v1/llm/aliases/{alias}/request-policy`, `provider:manage`,
  audited `alias.request_policy_set`, migration 0068). The organization, not
  the operator, decides, as for access and prices (§1, §2): the provider
  account and its bills are the organization's, and an alias is
  organization text the operator does not see. A provider-executed tool's
  own fees (per search, per container hour) are not metered.
- **Output cap.** A call that declares no output cap reserved 4,096 tokens
  (1,024 on the text route) and the provider could write more. The cap is now
  written into the request (`max_tokens`, or `max_completion_tokens` when the
  alias's `output_cap_field` says so), at the alias's `max_output_tokens`,
  or the old defaults, and reserved. A declared cap is moved to that field
  too: Ollama, for one, ignores `max_completion_tokens`, which OpenAI's SDKs
  write.
- **Input estimate.** One token per three ASCII bytes and one per other
  byte; each image the provider fetches itself counts 4,096 tokens and each
  document 300,000.
- **In flight.** An agent has at most 8 model calls in flight in its worker
  (`llm.max_calls_per_agent`, 1 to 64), every route counted; the next is
  refused before any reservation with `concurrency_limited`. Embeddings,
  transcription and OCR now take the request key's guard of chat calls.
- **What a hard budget guarantees** (§2, "Hard and soft"): the reservations
  of a window never pass the limit, under any concurrency. Its settled spend
  passes it only by what calls settle above their reservation: an input
  estimate passed, or an output past a cap the provider ignored; at most
  `max_calls_per_agent` calls of an agent can do so at once, and the next
  call is then refused. [api/llm.md](../api/llm.md#budgets-and-consumption-llm-03)
  states the cases.
- **Unknown outcomes** (§3): only a failure before any connection to the
  provider (DNS, refused connection, TLS handshake, refused address) is
  retried and released. Any transport error once connected is an unknown
  outcome; it used to be retried and released at zero unless it was a
  timeout.
- **Settlement.** A unary answer without usage, or with part of it, was
  settled at zero for what it left out; it is now settled at the
  reservation's input estimate and output cap. A call reserved under a host
  admission that then fails is released at once, instead of staying
  `reserved` until the organization resolves it. A credential rotated between
  a route's resolution and its reservation is resolved again: the reservation
  reads the provider again in its transaction. (A provider disabled in
  between was already refused: disabling a provider disables its aliases in
  the same transaction.)

**Lot PERF-3B (finding P-05).** A reservation summed each applicable
budget's window over `llm_usage` under the budgets' row locks: its cost grew
with the window's calls, and the reservations of an organization waited for
one another that long. Each budget now keeps a counter per UTC day or month
(`llm_budget_windows`, migration `llm-budget-windows`, which counts the
current windows from the calls already made). A reservation adds its amounts
to the counters of the budgets it locked and refuses when one of them passes
a hard limit; a settlement or a release (by the worker or by the organization)
adds the change of its call's amounts, in the same transaction. A new budget
counts its window from the calls already made, after it locked those still
in flight, so that none settles uncounted; reservations wait for it on the
organization's row. A counter is what the sum counted, exactly
(`TestBudgetWindowsCountWhatTheCallsSum` compares them under concurrent
reservations, settlements, releases, resolutions and new budgets), so the
guarantees of §2 and SEC-2's paragraph above hold as they were. The
reservations of one budget still take its row in turn: a hard limit needs
it; each now costs a few rows whatever the window holds.

The calls themselves are no longer kept forever: the worker deletes a settled
or released call `model_call_retention` after its reservation (90 days by
default, 35 days at least: longer than the month the usage report reads),
unless it is in flight or of unknown outcome, an audit event names it, or a
corpus build in progress counts it ([worker.md](../worker.md)), with the
windows that started before the retention (migration
`model-call-retention`).
