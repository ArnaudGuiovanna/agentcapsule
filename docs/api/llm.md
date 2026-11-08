# LLM providers and model aliases (LLM-01)

A tenant declares its providers and names the models its agents can reach.
Everything requires `provider:manage` and the roles `org_owner` /
`org_admin`; a service account can act only if both its role and its token
carry this scope.

| Route | Effect |
|---|---|
| `POST /v1/llm/providers` | declares a provider (`openai_compatible` or `anthropic`), https URL (or http to localhost), write-only credential |
| `GET /v1/llm/providers` | metadata, never the credential |
| `POST /v1/llm/providers/{id}/rotate` | new credential generation, effective on the next call |
| `POST /v1/llm/providers/{id}/disable` | permanent: erases the ciphertext, disables the aliases |
| `POST/GET /v1/llm/aliases`, `POST /v1/llm/aliases/{alias}/disable` | model policy: only an active alias is reachable |

## Guarantees
- The credential is encrypted (AES-256-GCM) with a key derived from the
  installation key by HMAC-SHA256 and a dedicated label; it is bound to the
  organization, the provider and the generation. It appears neither in
  responses, nor in idempotency receipts (only its SHA-256 fingerprint enters
  the comparison), nor in the audit, nor in a VM.
- Decryption exists only in `ResolveLLMRoute`, which the gateway calls with the
  tenant bound to the authenticated channel. Disabled organization, alias or
  provider: `ErrNotFound` from the next request.
- Audit: `llm.provider.created|rotated|disabled`, `llm.alias.created|disabled`.

## Known limits
- The encryption key derives from the installation key: losing it also loses the
  credentials (D-05 stays open for a dedicated secret store and rotation of this
  key).
- Aliases are organization-wide; there is no per-agent or per-team restriction
  yet, nor budgets (LLM-03).

## Outbound calls (LLM-02)
`internal/llmgateway` calls the provider resolved by `ResolveLLMRoute`.
- Adapters: `openai_compatible` (`/chat/completions`, `Authorization: Bearer`)
  and `anthropic` (`/v1/messages`, `x-api-key`, `system` role folded into
  `system`).
- Bounded retry (2 attempts by default) only before the provider has accepted
  the work: connection failure, 429, 5xx. A timeout after sending gives
  `ErrOutcomeUnknown` and is never replayed; the cost must then be treated as
  uncertain (LLM-03). A 4xx other than 429 is a permanent refusal.
- Per-provider circuit breaker: opens after N consecutive failures, a single
  probe in half-open state. Redirects are not followed.
- Nothing of the content or the credential is logged; there is no promise of
  exactly-once effect for an external call.

### Tests against a real provider

The `TestLive*` tests (`internal/llmgateway/live_test.go`,
`internal/controlplane/llm_live_test.go`) are compiled only with the `llmlive`
tag, hence never by the default campaigns. They target a real
`openai_compatible` endpoint, in practice a local Ollama, with no paid
credential:

```bash
python3 scripts/verify-postgres.py ... \
  --llm-base-url http://127.0.0.1:11434/v1 --llm-model tinyllama:latest
```

Against the real provider they verify:
- the usage reported by the provider and the respect of `max_tokens`;
- an unknown model = permanent refusal that does not open the breaker;
- a cut after sending = `ErrOutcomeUnknown`, a single request emitted;
- end to end with PostgreSQL:
  - exact settlement at the reported tokens and estimated cost;
  - a key already settled is never sent again;
  - `hard` budget refused with no outbound request, counted by a proxy;
  - reservation released on refusal, and kept `unknown` on a cut.

The content of the responses is not evaluated. Without these options,
`environment.json` records `llm_live: not_run`. A paid provider (HTTPS) goes
through the same phase, with `AGENTCAPSULE_TEST_LLM_SECRET`; this secret is never
recorded. The `anthropic` adapter has not yet been called against the real API.

## Budgets and consumption (LLM-03)
A budget limits the tokens (input + output) of an organization, an agent, an
alias, or an agent and an alias, per UTC day or month. It requires
`quota:manage` (roles `org_owner`/`org_admin`); consumption requires
`usage:read` (`org_owner`, `org_admin`, `auditor`).

Each call goes through `LLMService.Call`: alias resolution, **reservation**
(pessimistic estimate: about 1 token per 3 bytes + output cap), call, then a
single outcome:
- success: settlement with the usage reported by the provider;
- refusal, 429, 5xx, unavailability: release, the provider billed nothing;
- timeout after sending: `unknown`, the reservation **keeps counting** and
  cannot be released as free; a late settlement corrects it.

A `hard` budget refuses before any call (`ErrBudgetExceeded`), even under
concurrent calls (the applicable budgets are locked in a fixed order); a `soft`
budget lets the call through and reports the overrun. A request key already used
does not count again and never calls the provider again; a reservation left
`reserved` after a shutdown is treated as unknown.

`GET /v1/llm/usage` separates settled tokens, in-flight tokens and tokens of
unknown outcome; the cost is an **estimate** based on the alias's
`input_micro_per_mtok` / `output_micro_per_mtok` (rounded up), never an
invoice. Metrics carry no content.

## VM bridge (CAP-01)

A running capsule calls its model through the authenticated platform channel,
`POST /v1/llm/complete` (never through the guest network):

```json
{"alias":"fast","messages":[{"role":"user","content":"..."}],"max_tokens":256,"temperature":0.2}
```

and receives `{"text","finish_reason","input_tokens","output_tokens","soft_budget_exceeded"}`.
The idempotency header (`idempotency_key`, at most 200 characters) is the
ledger's request key.

- **Identity**: organization and agent come from the channel (generation and VM
  of the current boot), never from the payload. A `tenant_id`, `provider_secret`
  or equivalent field is refused (400) before the adapter. An agent of the legacy
  domain has no gateway (403).
- **Policy**: the only name the guest supplies is an alias defined by its
  organization; the alias carries the authorized model. The LLM-03 budgets
  apply. The provider credential never enters the VM.
- **Host lock**: placement and reservation happen under host admission; the
  provider call happens **outside** that lock, so that a slow model delays
  neither wake, sleep nor deletion. Accounting survives a cancellation by the
  caller.
- **During an invocation**: an instruction is delivered under an exclusive
  admission turn of the host, and this bridge waits for that turn. An agent that
  must call its model to answer therefore acknowledges "working", calls the
  model, then files its result
  (see [agents-assignments.md](agents-assignments.md#deferred-result-the-working-state)).
- **Timeouts**: 120 s in total (two attempts of 50 s); only this route extends
  the server's write deadline.
- **Errors** (enumerated codes, never a provider message): `quota_exceeded` and
  `rate_limited` (429), `rejected` (provider 4xx), `outcome_unknown` (timeout
  after sending: the reservation keeps counting; **do not** retry with the same
  key), `conflict` (key already processed: use a new key), `invalid`,
  `unauthorized`, `unavailable`.
- **Replay**: a settled key is never called again and the text is not kept; the
  guest repeats the request with a new key.
- **Activation**: the worker offers the bridge only if its configuration contains
  `"llm": {"receipt_key": "/absolute/path/key"}`, the same private 32-byte key as
  the API (provider credentials are encrypted under a key derived from it).
  Without it, the bridge answers `unavailable`.
