# Using the API with curl

This page shows each MVP feature used over HTTP with `curl` and `jq`,
without a UI. It follows one organization from its first harness release to
an agent that answers its members, its files, the requests of its other
agents, a technical account, its models and its audit trail.

A test runs this page as written, against the API over HTTPS on PostgreSQL
(`TestHTTPExamplesRunAsWritten` in `internal/api/examples_test.go`): every
block in order, every answer shown compared with the real one, and every
answer checked against [openapi/openapi.yaml](../../openapi/openapi.yaml).
What the worker or another agent does between two calls is marked in this
page's source; the test plays it. In an answer, a value that ends with `...`
stands for any value that starts the same, and only some fields are shown.

What every role may call is in the [authorization matrix](rbac.md). Every
call follows the same conventions:
- a mutation takes an `Idempotency-Key`: the same key and body give back the
  first answer, with `Idempotency-Replayed: true`; the same key with another
  body is refused with `422 idempotency_key_reused`;
- asynchronous work answers `202` with the identifier to follow;
- an error is `application/problem+json` with a stable `code`.

## Before you start

You need:
- the API's URL;
- the issuer of your identity provider, as the platform operator registered
  it for your organization ([tenant-identity.md](tenant-identity.md));
- two tokens your identity provider signs: one for alice, the
  organization's owner, and one for bob, whom alice adds below;
- the platform operator's credential, for the harness import only
  ([bootstrap.md](../bootstrap.md));
- when a technical account's token should expire, and the period of the
  audit export.

```sh
export API=https://capsule.example.com
export ISSUER=https://idp.example.com
export OWNER_TOKEN=eyJhbGciOiJFZERTQSIs...    # alice, org_owner
export BOB_TOKEN=eyJhbGciOiJFZERTQSIs...      # bob, agent_user
export PLATFORM_TOKEN=acpp_...                 # the platform operator
export TOKEN_EXPIRES=2026-12-31T00:00:00Z
export AUDIT_FROM=2026-11-01T00:00:00Z
export AUDIT_TO=2026-12-01T00:00:00Z
```

## Harness releases

An agent runs a harness release. The platform operator imports a package
pinned by its digest; the worker downloads and checks it in the background
([agentcapsule-harness](../../cmd/agentcapsule-harness/main.go) builds and
publishes packages).

```sh
IMPORT=$(curl -fsS -X POST "$API/v1/harness-imports" \
  -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Idempotency-Key: import-echo-1.0.0" \
  -H "Content-Type: application/json" \
  -d '{"reference":"ghcr.io/acme/echo@sha256:3b1f5c0a6ad2c4f0b1b6d5f0e4c6f2a1d9e8c7b6a5f4e3d2c1b0a9f8e7d6c5b4"}' \
  | jq -r .id)
```

```http
HTTP/1.1 202 Accepted

{
  "id": "imp_...",
  "reference": "ghcr.io/acme/echo@sha256:3b1f...",
  "state": "IMPORTING",
  "attempts": 0
}
```

<!-- worker: import echo 1.0.0 -->

Follow the import until its `state` is `READY`, or `REJECTED` with an
`error_code`:

```sh
curl -fsS "$API/v1/harness-imports/$IMPORT" -H "Authorization: Bearer $PLATFORM_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "imp_...",
  "state": "READY",
  "release_id": "rel_...",
  "attempts": 1
}
```

The organization's members see the releases they may run:

```sh
curl -fsS "$API/v1/harness-releases" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "rel_...",
      "name": "echo",
      "version": "1.0.0",
      "digest": "sha256:3b1f...",
      "state": "READY"
    },
    "..."
  ]
}
```

## Members

alice adds bob as an `agent_user`. bob signs in with his own token. His role
lets him use only the agents he is assigned to.

```sh
BOB=$(curl -fsS -X POST "$API/v1/members" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: add-bob" \
  -H "Content-Type: application/json" \
  -d '{"issuer":"'"$ISSUER"'","subject":"bob","display_name":"Bob","role":"agent_user"}' \
  | jq -r .principal_id)
```

```http
HTTP/1.1 201 Created

{
  "principal_id": "prn_...",
  "subject": "bob",
  "display_name": "Bob",
  "role": "agent_user",
  "status": "active"
}
```

## Agents

alice creates an agent on the release. The answer names the agent and the
operation that provisions it.

```sh
AGENT=$(curl -fsS -X POST "$API/v1/agents" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: create-support" \
  -H "Content-Type: application/json" \
  -d '{"name":"support","harness":{"name":"echo","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}' \
  | jq -r .agent_id)
```

```http
HTTP/1.1 202 Accepted

{
  "agent_id": "agt_...",
  "operation_id": "op_...",
  "status": "PENDING"
}
```

The same request with the same key gives back the same answer and creates
nothing more. Here it reads the operation's identifier:

```sh
OP=$(curl -fsS -X POST "$API/v1/agents" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: create-support" \
  -H "Content-Type: application/json" \
  -d '{"name":"support","harness":{"name":"echo","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}' \
  | jq -r .operation_id)
```

```http
HTTP/1.1 202 Accepted
Idempotency-Replayed: true

{
  "agent_id": "agt_...",
  "operation_id": "op_...",
  "status": "PENDING"
}
```

<!-- worker: provision $AGENT -->

Follow the operation until its `status` is `SUCCEEDED` or `FAILED`:

```sh
curl -fsS "$API/v1/operations/$OP" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "op_...",
  "agent_id": "agt_...",
  "kind": "provision",
  "status": "SUCCEEDED"
}
```

The agent is now stopped: no VM runs until there is work.

```sh
curl -fsS "$API/v1/agents/$AGENT" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "agt_...",
  "name": "support",
  "state": "STOPPED",
  "harness": {
    "name": "echo",
    "version": "1.0.0"
  },
  "resources": {
    "vcpus": 1,
    "memory_mib": 256,
    "data_volume_mib": 128
  },
  "desired_state": "stopped"
}
```

```sh
curl -fsS "$API/v1/agents?limit=20" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "agt_...",
      "name": "support",
      "state": "STOPPED"
    }
  ]
}
```

What the agent may do is what its harness requests, its organization
allows and it allows:

```sh
curl -fsS "$API/v1/agents/$AGENT/capabilities" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "release": {
    "name": "echo",
    "version": "1.0.0"
  },
  "requested": [
    "agents.delegate",
    "agents.discover",
    "llm.invoke"
  ],
  "effective": [
    "agents.delegate",
    "agents.discover",
    "llm.invoke"
  ]
}
```

## Assignments

No role invokes an agent: only an assignment does. alice assigns bob to the
agent, to read it, invoke it and read his own results.

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/assignments" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: assign-bob" \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"'"$BOB"'","permissions":["read_metadata","invoke","read_content"]}'
```

```http
HTTP/1.1 201 Created

{
  "id": "asg_...",
  "agent_id": "agt_...",
  "principal_id": "prn_...",
  "permissions": [
    "invoke",
    "read_content",
    "read_metadata"
  ],
  "status": "active"
}
```

```sh
curl -fsS "$API/v1/agents/$AGENT/assignments" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "asg_...",
      "principal_id": "prn_...",
      "status": "active"
    }
  ]
}
```

## Invocations

bob asks the agent a question. The invocation is accepted at once; the
worker wakes the agent to run it.

```sh
INV=$(curl -fsS -X POST "$API/v1/agents/$AGENT/invocations" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Idempotency-Key: question-1" \
  -H "Content-Type: application/json" \
  -d '{"content":[{"type":"text","text":"What is our refund policy?"}]}' \
  | jq -r .id)
```

```http
HTTP/1.1 202 Accepted

{
  "id": "op_...",
  "agent_id": "agt_...",
  "state": "accepted",
  "result_available": false
}
```

Poll the invocation until its `state` is final (`completed`, `failed`,
`expired` or `canceled`):

```sh
curl -fsS "$API/v1/invocations/$INV" -H "Authorization: Bearer $BOB_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "op_...",
  "state": "accepted",
  "result_available": false,
  "expires_at": "..."
}
```

<!-- worker: answer $AGENT -->

```sh
curl -fsS "$API/v1/invocations/$INV" -H "Authorization: Bearer $BOB_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "op_...",
  "state": "completed",
  "completed_at": "...",
  "result_available": true
}
```

Only bob reads the result, while he holds `read_content`. The `echo`
harness answers with what it was asked:

```sh
curl -fsS "$API/v1/invocations/$INV/result" -H "Authorization: Bearer $BOB_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "content": [
    {
      "type": "text",
      "text": "What is our refund policy?"
    }
  ]
}
```

A temporary link opens the result without the bearer token, for as long
as bob keeps the right to read it:

```sh
LINK=$(curl -fsS -X POST "$API/v1/invocations/$INV/result/link" -H "Authorization: Bearer $BOB_TOKEN" | jq -r .url)
curl -fsS -o answer.json "$API$LINK"
```

```http
HTTP/1.1 200 OK
Content-Disposition: attachment; filename*=UTF-8''result.json

{
  "content": [
    {
      "type": "text",
      "text": "What is our refund policy?"
    }
  ]
}
```

bob lists his invocations of the agent; alice sees the organization's queue:

```sh
curl -fsS "$API/v1/agents/$AGENT/invocations?limit=20" -H "Authorization: Bearer $BOB_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "op_...",
      "state": "completed",
      "result_available": true
    }
  ]
}
```

```sh
curl -fsS "$API/v1/queue" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "limits": {
    "max_pending_per_agent": 100,
    "max_pending_tenant": 1000
  },
  "pending_tenant": 0,
  "agents": []
}
```

## Files

bob uploads a file for the agent, then sends it with an invocation. The
file reaches only that agent, and only for that invocation. Send a file
from disk with `--data-binary @sales.csv`.

```sh
FILE=$(curl -fsS -X POST "$API/v1/agents/$AGENT/attachments" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Idempotency-Key: upload-sales" \
  -H "Content-Type: text/csv" \
  -H "X-Attachment-Name: sales.csv" \
  --data-binary 'region,total' \
  | jq -r .id)
```

```http
HTTP/1.1 201 Created

{
  "id": "att_...",
  "agent_id": "agt_...",
  "name": "sales.csv",
  "media_type": "text/csv",
  "size": 12,
  "sha256": "a4ce0c15...",
  "state": "pending"
}
```

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/invocations" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Idempotency-Key: question-2" \
  -H "Content-Type: application/json" \
  -d '{"content":[{"type":"text","text":"Sum the totals."}],"attachments":["'"$FILE"'"]}'
```

```http
HTTP/1.1 202 Accepted

{
  "id": "op_...",
  "state": "accepted",
  "attachments": [
    "att_..."
  ]
}
```

## Wake and sleep

An agent wakes for its work and sleeps after its idle delay. An operator can
also wake it or put it to sleep; each command is an operation to follow.

```sh
WAKE=$(curl -fsS -X POST "$API/v1/agents/$AGENT/wake" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: wake-1" \
  -H "Content-Type: application/json" \
  -d '{}' \
  | jq -r .operation_id)
```

```http
HTTP/1.1 202 Accepted

{
  "agent_id": "agt_...",
  "operation_id": "op_...",
  "status": "PENDING"
}
```

```sh
curl -fsS "$API/v1/operations/$WAKE" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "id": "op_...",
  "kind": "wake",
  "status": "PENDING"
}
```

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/sleep" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: sleep-1" \
  -H "Content-Type: application/json" \
  -d '{}'
```

```http
HTTP/1.1 202 Accepted

{
  "agent_id": "agt_...",
  "operation_id": "op_...",
  "status": "PENDING"
}
```

The agent sleeps after 15 idle minutes:

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/idle-policy" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: idle-15m" \
  -H "Content-Type: application/json" \
  -d '{"idle_timeout_seconds":900}'
```

```http
HTTP/1.1 200 OK

{
  "agent_id": "agt_...",
  "idle_timeout_seconds": 900
}
```

## Requests from other agents

The organization's other agents find the agent by its skills once it is
visible in the Directory, and send it requests. alice publishes its profile,
and holds every request for approval:

```sh
curl -fsS -X PUT "$API/v1/agents/$AGENT/directory" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: directory-1" \
  -H "Content-Type: application/json" \
  -d '{"visible":true,"description":"Answers questions about refunds.","skills":[10302],"domains":[111]}'
```

```http
HTTP/1.1 200 OK

{
  "visible": true,
  "description": "Answers questions about refunds.",
  "skills": [
    10302
  ],
  "domains": [
    111
  ],
  "publication": "pending"
}
```

```sh
curl -fsS -X PUT "$API/v1/agents/$AGENT/inbound" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: inbound-manual" \
  -H "Content-Type: application/json" \
  -d '{"mode":"manual"}'
```

```http
HTTP/1.1 200 OK

{
  "agent_id": "agt_...",
  "mode": "manual"
}
```

<!-- worker: request $AGENT -->

Another agent of the organization sent a request. It waits:

```sh
HELD=$(curl -fsS "$API/v1/agents/$AGENT/held-requests" -H "Authorization: Bearer $OWNER_TOKEN" | jq -r '.items[0].id')
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "arq_...",
      "sender_agent_id": "agt_...",
      "expires_at": "..."
    }
  ]
}
```

alice accepts it, and it is delivered to the agent (`decline` refuses it):

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/held-requests/$HELD/accept" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: accept-1" \
  -H "Content-Type: application/json" \
  -d '{}'
```

```http
HTTP/1.1 200 OK

{
  "request_id": "arq_...",
  "state": "DELIVERING"
}
```

## Technical accounts

A technical account calls the API from a program, with a token the
organization issues. alice creates one with the role `agent_user`:

```sh
BOT=$(curl -fsS -X POST "$API/v1/service-accounts" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: bot-nightly" \
  -H "Content-Type: application/json" \
  -d '{"name":"nightly-report","role":"agent_user"}' \
  | jq -r .id)
```

```http
HTTP/1.1 201 Created

{
  "id": "svc_...",
  "name": "nightly-report",
  "role": "agent_user",
  "status": "active"
}
```

The token is shown once, in this answer. Keep it secret:

```sh
BOT_TOKEN=$(curl -fsS -X POST "$API/v1/service-accounts/$BOT/tokens" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: bot-token-1" \
  -H "Content-Type: application/json" \
  -d '{"scopes":["agent:read","agent:invoke"],"expires_at":"'"$TOKEN_EXPIRES"'"}' \
  | jq -r .token)
```

```http
HTTP/1.1 201 Created

{
  "id": "stk_...",
  "service_account_id": "svc_...",
  "scopes": [
    "agent:invoke",
    "agent:read"
  ],
  "status": "active",
  "token": "acps_..."
}
```

Like a member, the account invokes only the agents it is assigned to:

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/assignments" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: assign-bot" \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"'"$BOT"'","permissions":["read_metadata","invoke"]}'
```

```http
HTTP/1.1 201 Created

{
  "id": "asg_...",
  "principal_id": "svc_...",
  "permissions": [
    "invoke",
    "read_metadata"
  ],
  "status": "active"
}
```

```sh
curl -fsS -X POST "$API/v1/agents/$AGENT/invocations" \
  -H "Authorization: Bearer $BOT_TOKEN" \
  -H "Idempotency-Key: nightly-2026-11-16" \
  -H "Content-Type: application/json" \
  -d '{"content":[{"type":"text","text":"Write the nightly report."}]}'
```

```http
HTTP/1.1 202 Accepted

{
  "id": "op_...",
  "state": "accepted"
}
```

alice revokes the token. The next call with it is refused at once:

```sh
TOKEN_ID=$(curl -fsS "$API/v1/service-accounts/$BOT/tokens" -H "Authorization: Bearer $OWNER_TOKEN" | jq -r '.items[0].id')
curl -fsS -X POST "$API/v1/service-accounts/$BOT/tokens/$TOKEN_ID/revoke" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: bot-token-1-revoke" \
  -H "Content-Type: application/json" \
  -d '{}'
```

```http
HTTP/1.1 200 OK

{
  "id": "stk_...",
  "status": "revoked",
  "revocations": [
    {
      "id": "arv_...",
      "kind": "service_token",
      "state": "confirmed"
    }
  ]
}
```

```sh
curl -sS "$API/v1/agents/$AGENT" -H "Authorization: Bearer $BOT_TOKEN"
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json

{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "code": "authentication_required"
}
```

## Models

An organization brings its own model providers. Agents call a model by an
alias, never with the provider's key: the key stays on the host. alice
registers a provider; no answer ever shows its key.

```sh
PROVIDER=$(curl -fsS -X POST "$API/v1/llm/providers" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: provider-main" \
  -H "Content-Type: application/json" \
  -d '{"name":"main","kind":"openai_compatible","base_url":"https://llm.example.com/v1","secret":"sk-example-0123456789abcdef"}' \
  | jq -r .id)
```

```http
HTTP/1.1 201 Created

{
  "id": "llmp_...",
  "name": "main",
  "kind": "openai_compatible",
  "base_url": "https://llm.example.com/v1",
  "status": "active",
  "secret_generation": 1
}
```

The alias `fast` names a model of that provider. A listed alias serves
only the agents and teams it is granted to:

```sh
curl -fsS -X POST "$API/v1/llm/aliases" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: alias-fast" \
  -H "Content-Type: application/json" \
  -d '{"alias":"fast","provider_id":"'"$PROVIDER"'","upstream_model":"small-model-1","access":"listed"}'
```

```http
HTTP/1.1 201 Created

{
  "alias": "fast",
  "provider_id": "llmp_...",
  "upstream_model": "small-model-1",
  "status": "active",
  "access": "listed"
}
```

```sh
curl -fsS -X POST "$API/v1/llm/aliases/fast/grants" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: grant-fast-support" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"'"$AGENT"'"}'
```

```http
HTTP/1.1 201 Created

{
  "id": "llmg_...",
  "alias": "fast",
  "agent_id": "agt_...",
  "status": "active"
}
```

A hard budget refuses a call before the provider sees it once the agent has
used 200,000 tokens of `fast` in the day:

```sh
curl -fsS -X POST "$API/v1/llm/budgets" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: budget-support-day" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"'"$AGENT"'","alias":"fast","period":"day","limit_tokens":200000,"mode":"hard"}'
```

```http
HTTP/1.1 201 Created

{
  "id": "bud_...",
  "agent_id": "agt_...",
  "alias": "fast",
  "period": "day",
  "limit_tokens": 200000,
  "mode": "hard",
  "status": "active"
}
```

```sh
curl -fsS "$API/v1/llm/usage" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "period": "day",
  "lines": [],
  "totals": {
    "calls": 0,
    "settled_input_tokens": 0,
    "settled_output_tokens": 0
  }
}
```

A new key takes effect on the next call:

```sh
curl -fsS -X POST "$API/v1/llm/providers/$PROVIDER/rotate" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: provider-main-rotate-1" \
  -H "Content-Type: application/json" \
  -d '{"secret":"sk-example-rotated-0123456789"}'
```

```http
HTTP/1.1 200 OK

{
  "id": "llmp_...",
  "secret_generation": 2,
  "revocations": [
    {
      "id": "arv_...",
      "kind": "llm_provider",
      "state": "confirmed"
    }
  ]
}
```

## Audit

The audit trail says who did what to which resource, and when: never a
token, a key or any content. A page goes on from its `next` cursor
(`?after=`).

```sh
curl -fsS "$API/v1/audit?limit=3" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK

{
  "items": [
    {
      "id": "audit_...",
      "created_at": "...",
      "action": "organization.created",
      "actor": "platform:...",
      "target": "org_..."
    },
    {
      "action": "delegation.install",
      "actor": "operator"
    },
    {
      "action": "member.created",
      "actor": "prn_...",
      "target": "prn_..."
    }
  ],
  "next": "..."
}
```

The export holds every event of a period, as one JSON document:

```sh
curl -fsS -o audit.json "$API/v1/audit/export?from=$AUDIT_FROM&to=$AUDIT_TO" -H "Authorization: Bearer $OWNER_TOKEN"
```

```http
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="audit-export.json"

{
  "organization_id": "org_...",
  "items": [
    {
      "action": "organization.created"
    },
    "..."
  ]
}
```

## Deleting an agent

Deletion refuses new work, stops the VM and destroys the agent's volume and
key. It is an operation to follow:

```sh
curl -fsS -X DELETE "$API/v1/agents/$AGENT" \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Idempotency-Key: delete-support"
```

```http
HTTP/1.1 202 Accepted

{
  "agent_id": "agt_...",
  "operation_id": "op_...",
  "status": "PENDING"
}
```
