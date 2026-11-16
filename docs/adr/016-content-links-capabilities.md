# JSON content, temporary download links, capabilities and the guest's tmpfs

Date: November 16, 2026. **Status: built on November 16, 2026**, with
defaults pending the product owner (see [Questions](#questions-for-the-product-owner)).
The KVM tests that show these on a real VM have not run yet (see [Tests](#tests)).
References: EXT-001, EXT-002, EXT-003 and the API conventions of the
[product spec](../product.md) (§3 Harnesses, §4), EVT-01, EVT-04 and CAP-01 of
the [roadmap](../../ROADMAP.md), [capsule-control.md](../guest/capsule-control.md),
[agents-assignments.md](../api/agents-assignments.md).

## Context

What existed before this record (lines of `mvp-integration`):

| Subject | State | Where |
|---|---|---|
| Content | text parts only, `{"type":"text","text":...}`; any other type refused, by the API and by every guest | `internal/capsuleprotocol/invoke.go:15-37`, `peer.go:15-34` |
| Guest features | `health`, `fences`, `events`, `invoke.message.user.text`, `outcomes`; a client accepted at most five, and refused an unknown one | `internal/capsuleprotocol/capabilities.go:31-37`, `:170-191` |
| Download links | none: the API never returned a file; a result only through `GET .../result` with the bearer | `docs/api/agents-assignments.md` (Attachments, "Limits") |
| Capabilities | not in `harness.yaml`; the platform channel checked placement, mandates, LLM aliases and budgets, never what a harness asked for or what a policy allowed | `internal/harnesspkg/package.go:66-75`, `internal/worker/platform_linux.go` |
| `/tmp`, `/run` | tmpfs without `size=`: each could grow to half of the guest's memory | `cmd/capsule-init/main.go:69-70` |

## Decision

### 1. Structured JSON content (EXT-001, EVT-01)

**Shape.** A content part is text or a JSON value; its `type` is its content
type:

```json
{"type":"text","text":"..."}          text/plain
{"type":"json","json":<any value>}    application/json
```

A text part encodes exactly as before, so hashes of stored text content do
not change (`ContentPart`, `TextContent` kept as an alias). The JSON value is
kept as its encoded text (`JSONValue`), so parts still compare with `==`.

**Bounds.** As text was bounded: 1 to 32 parts; text plus the compact form of
the JSON values at most 32 KiB for invocations, results and owner messages; a
request or reply between agents at most 64 KiB encoded, counted in its text
form (below), so the text form always fits. A value is any JSON value but
`null`, nested at most 32 levels, in UTF-8. The API validates before it
stores anything (400). The transit encryption is unchanged.

**Negotiation.** A harness opts in (`Server.AcceptJSONContent`,
`Harness(json_content=True)`) and then offers the control feature
`content.json`. It offers it only to a client that lists it in the new
optional header `X-Capsule-Accept-Features`: a capsule-init or a worker built
before it sends no such header and sees exactly the five features it
validates, so a new harness release still boots on an older platform. The
worker records the contract each boot negotiated (`Client.Accepts`).

**Old guests: text, never a crash (the choice).** A harness that did not
negotiate `content.json` receives each JSON part as a text part holding the
value's compact JSON (`TextOnlyEvent`, in `Placements.deliverToGuest`, the
one path of every delivery to a guest, SLIM included). It never receives a
part it would refuse. We chose text over refusing the invocation because a
refusal would need a new way to close a delivery that was never sent, in the
modelled delivery paths, and because the agents most likely to run old
harnesses (adapted agents and model-driven ones) read JSON as text anyway.
The requester's stored content stays JSON. A harness that did not opt in
refuses JSON it is sent anyway (`invalid_envelope`), as a second guard.

**Where JSON goes.** API input and results; completions; owner messages;
requests and replies between agents; the reference harness (echoes JSON
parts); the Python SDK (`Invocation.values`, `json_part`, `content_result`);
`capsule-adapter`: a command reads JSON parts as text, an A2A server agent
receives them as A2A data parts (supported by the pinned a2a-go v2.8.0, A2A
1.0) and its data parts come back as JSON parts; the adapter's A2A endpoint
maps data parts to JSON parts and back, and still refuses file parts.

### 2. Temporary download links (API conventions, EVT-04)

`POST /v1/attachments/{id}/link` and `POST /v1/invocations/{id}/result/link`
mint a link for whoever may read the content now (the file's sender, or the
invocation's requester, with `read_content`); `GET /v1/downloads/{token}`
serves it without a bearer.

- **Stateless and sealed.** The link is AES-GCM sealed with a key derived from
  the installation's receipt key (as the LLM provider key is). It carries the
  resource, the purpose, the expiry and the credential that minted it
  (delegated identity or service token), narrowed to `agent:content:read`. It
  shows none of them. Minting stores nothing, so it takes no
  `Idempotency-Key`: it is not a mutation.
- **Bound to the identity, checked at each use.** A download rebuilds the
  principal and reads through the same checks as a read with the bearer:
  organization, member or service account, token revocation and expiry,
  trust, assignment, resource. A revoked token, member or assignment closes
  the link at once; it never outlives its credential.
- **Short.** 5 minutes by default, 30 s to 15 min.
- **Nothing in logs.** Every refusal is the same 404. Logs and metrics carry
  the route pattern `/v1/downloads/{token}`, never the link. The answer is
  `Content-Disposition: attachment`, with `X-Content-SHA256`,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

Files as results and external object storage stay P1.

### 3. Capabilities (CAP-01, EXT-003, product.md §3)

- **Vocabulary** (`internal/capability`): `llm.invoke` (model calls),
  `agents.delegate` (send and follow requests to other agents),
  `agents.discover` (search and describe agents). Answering delivered work
  (replies, completions, owner messages, the invocation's own files) needs
  none.
- **Requested** in `harness.yaml` (`capabilities: [...]`), checked at import
  (unknown or repeated names reject the package) and recorded on the release
  (migration `0036_capabilities.sql`). A manifest without the field predates it
  and is treated as requesting everything; an empty list requests nothing.
- **Allowed** by the organization (`PUT /v1/organizations/current/capabilities`,
  `quota:manage`) and by the agent (`PUT /v1/agents/{id}/capabilities`,
  `agent:manage`). No policy allows everything. Each change bumps the
  organization's policy version and is audited (`capability_audit`, in
  `GET /v1/audit`).
- **Effective** = requested ∩ organization ∩ agent, computed by one function
  for the catalog (`GET /v1/agents/{id}/capabilities`) and the check. We store
  the inputs, not the result: a stored effective set would go stale at the
  next policy change. The release's request is recorded once, at import.
- **Enforced** on the host's platform channel, before the call reaches its
  effect, at each call (`CapabilityAPI`, `Store.RequireCapabilityFromVM`): a
  policy change applies to the next call, without a reboot. A refusal is the
  typed code `capability_denied` (HTTP 403 on the channel). The reference
  harness, python-echo and capsule-adapter treat it as final. `llm.invoke` is
  checked before, and independently of, the alias access of
  [ADR 011](011-llm-access-and-cost-budgets.md).
- **Limit.** The check reads the release the agent is pinned to. A release
  change applies to the capabilities of a VM still running the previous
  harness, until it stops.

### 4. The guest's tmpfs

`/tmp` is mounted with `size=25%` of the guest's memory, which is the agent's
`memory_mib` (64 MiB for 256 MiB), and `/run` with `size=8m`: the harness
cannot write in `/run`, which holds the supervisor's sockets. The table is
`guestinit.BootMounts`, so a test checks it. A harness does not choose its
sizes.

## Consequences

- The guest changes: `internal/capsuleprotocol` (content, negotiation, gate
  codes), `internal/guestinit` (mounts), `cmd/capsule-init`, `cmd/capsule-echo`
  (opts in; test behaviours `fill-tmp` and `text-only`),
  `internal/referenceharness`, `internal/agentadapter` and `cmd/capsule-adapter`,
  the Python SDK and the example harnesses' manifests. One integrated guest
  image and new harness packages (python-echo, the a2a and adapted harnesses)
  are needed.
- A new harness on an older platform boots (the features header), but an older
  platform rejects a `harness.yaml` with `capabilities:` at import (strict
  parsing).
- An older capsule-init maps `capability_denied` to `unavailable`; the guest
  image ships with the platform, so this lasts only until the image is
  rebuilt.
- If an agent's release changes between two attempts of one delivery and
  only one of the two harnesses accepts JSON, the second attempt conflicts on
  the same event ID and the delivery ends `delivery_outcome_unknown`.
- No formal model changes: the delivery, closure and placement paths are
  untouched; the JSON rewrite happens after a delivery is authorized and is
  deterministic per boot.

## Tests

Unit and PostgreSQL tests: `internal/capsuleprotocol` (content parts, text
form, negotiation, the platform channel's gate, the Python SDK end to end),
`internal/capability`, `internal/harnesspkg` (manifests, examples),
`internal/controlplane` (recorded requests, intersection, policies, audit,
sealed links), `internal/api` (JSON invocation and result, catalog and
policies, links, the RBAC matrix), `internal/worker` (the text fallback at
delivery), `internal/agentadapter`, `internal/referenceharness`,
`internal/guestinit` (mount sizes, the real reference harness accepting JSON),
`cmd/capsule-echo`.

KVM tests, written, not yet run (`verify-product-guest.py` requires them):
`TestProductWorkerBoundsTheGuestTmp`, `TestProductWorkerDeliversJSONContent`,
`TestProductWorkerEnforcesCapabilities`.

## Questions for the product owner

1. **JSON to an older agent.** Someone sends `{"type":"json","json":{"order":42}}`
   to an agent whose harness predates JSON content. (a) It receives the text
   `{"order":42}` and answers as usual (built). (b) The invocation fails with
   `content_type_unsupported` and the sender resends as text. Recommendation:
   (a).
2. **A manifest that says nothing.** A third-party harness built before this
   change declares no capabilities. (a) It gets every capability, within the
   organization's and the agent's policies (built). (b) It gets none until
   its developer declares them. Recommendation: (a) now, and make the field
   mandatory in the next manifest schema.
3. **Who sets the organization's policy.** (a) Owners and administrators with
   `quota:manage`, as for queue limits and budgets (built). (b) A new scope,
   `policy:manage`, which identity providers must then issue. Recommendation:
   (a) for the MVP.
4. **A link used twice.** A member opens a download link, the transfer breaks,
   and they open it again a minute later. (a) The link works until it expires
   (built). (b) A link works once. Recommendation: (a); 5 minutes by default.
5. **Who may download a file back.** (a) Its sender, while they hold
   `read_content`, the rule of results (built). (b) Its sender, with `invoke`
   alone. Recommendation: (a).
