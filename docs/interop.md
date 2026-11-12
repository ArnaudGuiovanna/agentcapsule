# Interoperability profile (INT-01)

Agent Capsule supports one pinned interoperability profile, `agentcapsule-int-1`
([profile.json](../runtime/interop/profile.json)), qualified on a single host.
It covers OASF records, a private AGNTCY Directory, A2A and SLIM. The platform
publishes and searches agent records through the Directory (INT-02, see
[Directory publication](api/agents-assignments.md#directory-publication-int-02)).
Inside each VM, [capsule-adapter](adapter.md#other-agents-a2a-endpoint) serves
the organization's agents as A2A agents, built on the A2A Go SDK v2.8.0 (INT-03,
first part). Between its own endpoints (the SLIM bridge), the platform does not
use A2A or SLIM yet (INT-03 to INT-05), so gate G2 is not reached.

## The profile

| Component | Pinned version | Role in Agent Capsule |
| --- | --- | --- |
| A2A | [Specification v1.0.1](https://github.com/a2aproject/A2A/releases/tag/v1.0.1), wire `1.0`, [Go SDK v2.8.0](https://github.com/a2aproject/a2a-go/releases/tag/v2.8.0) | Agent Cards and tasks between agents. Supported: JSON-RPC binding, `SendMessage`, `GetTask`, text parts and artifacts. Not advertised: REST, gRPC, streaming, push notifications, resubscription, signed cards. |
| A2A over SLIM | [slim-a2a-go v0.5.2](https://github.com/agntcy/slim-a2a-go/tree/v0.5.2), binding `a2aslimrpc/v1` | The same A2A tasks carried over SLIM. Compiles only with A2A Go SDK v2.1.0–v2.2.0, so it lives in its own module ([a2aslim](../runtime/interop/a2aslim)) and later in the SLIM bridge process; the platform keeps v2.8.0. |
| OASF | Schema 1.1.0 ([source v1.1.3](https://github.com/agntcy/oasf/releases/tag/v1.1.0)), [schema server v2.0.0](https://github.com/agntcy/oasf-server/releases/tag/v2.0.0) | Describes each visible agent. Skills `10301` (text completion) and `10302` (summarization), domain `111` (artificial intelligence). Validated by a private schema server, never the public one. |
| Directory | [v1.8.0](https://github.com/agntcy/dir/releases/tag/v1.8.0) API server, Go API v1.8.0 | Private search of agent records, including stopped agents. |
| SLIM | [Node 3.4.6](https://github.com/agntcy/slim/releases/tag/slim-v3.4.6), [Go bindings v3.3.9](https://github.com/agntcy/slim-bindings-go/tree/v3.3.9) with native core 3.4.6 | Transport between the platform's endpoints. |

The services run from images pinned by digest in
[deploy/interop/compose.yml](../deploy/interop/compose.yml). Go modules are
locked by their `go.sum`; the SLIM native archive is verified by SHA256, as its
published build metadata has an empty commit field.

## Decisions

**The platform stays the authority.** An OASF record, a Directory search
result, an Agent Card or a SLIM name grants no right. Every search result is
filtered again in PostgreSQL by organization, assignment and caller, and every
request goes through the existing consent, mandate, quota and cross-organization
checks. Records hold only what the organization chose to publish: a
description and skill and domain IDs, under an opaque name (A2A-011).

**Directory is an index the platform can rebuild.** PostgreSQL remains the
source of truth and publishes each visible agent's record. The API server
therefore uses its embedded SQLite database and a local OCI layout, with no
PostgreSQL or registry of its own; losing it means publishing again, not losing
data. Directory has no notion of organization, so record names carry one
(`agentcapsule/<organization>/<agent>`): a search is confined to the caller's
organization on the server, then filtered again by the platform.

**The mailbox, not SLIM, guarantees delivery.** The qualification measured what
SLIM does and does not do:

- The node keeps nothing. A session to a name nobody subscribed fails after its
  retries; a message sent while the recipient is down is never delivered after
  it comes back.
- Acknowledgments are optional. Without them a publish succeeds even if nobody
  receives it. With them, exhausted retries are still reported as success, and
  later publishes on that session wait forever unless bounded by the caller.
- Clients do not reconnect after a node restart; only a new client process
  recovers.

The platform's durable mailbox therefore stays the only delivery guarantee:
a task is stored before the sender gets an answer, redelivered with the same
request ID until the recipient's side records it, and marked delivered on an
application-level receipt (the A2A task returned by the recipient's endpoint),
never on a SLIM acknowledgment.

**SLIM lives in a separate bridge process.** The bindings need CGO, a 336 MiB
static library, glibc 2.39 or later, and add about 77 MiB to a binary; their
client must be restarted when the node restarts; and the A2A transport pins an
older A2A SDK. The control plane, the worker and `capsule-init` stay pure Go
without CGO. Harnesses in the guest never see SLIM: they keep talking to the
platform over `capsule.v1`.

**Authentication.**

- **Directory.** The API server authenticates only through a SPIFFE Workload
  API (SPIRE), which would add two services to run and register. Instead:
  - the server runs alone on an internal network, unauthenticated;
  - in front of it, an HAProxy edge requires a client certificate from the
    Directory authority with the control plane's common name;
  - the edge listens on loopback only.
- **SLIM.** The node requires a client certificate from a separate SLIM
  authority, so a Directory credential cannot open SLIM and the reverse.
  - Inside SLIM, application identity is a shared secret, and any holder can
    claim any name.
  - Only the platform's bridge holds that secret; no agent connects to SLIM
    directly.

**Network.**

- **Directory and schema server.** They have no route out, so they cannot
  reach the internet. Directory v1.8.0 always starts a libp2p host, so:
  - its routing is isolated: no bootstrap peer, loopback listener, no
    GossipSub, no automatic sync, no relay;
  - it must never run with host networking, because it announces itself over
    mDNS and asks the router for a UPnP mapping.
  - A packet capture of about four minutes of a lab variant (PostgreSQL and
    zot storage instead of SQLite) showed no DNS and no unicast traffic outside
    private ranges.
- **SLIM node.** It needs a normal Docker network to publish its port. It
  opens no outbound connection itself; blocking egress for it is the host
  firewall's job.

**A2A states.** Peer requests keep their internal states (A2A-008); the A2A
adapter projects them as follows and repeats the internal state in the task's
metadata (`agentcapsule.request_state`), since an A2A 1.0 task status has no
metadata of its own.

| Peer request state | A2A task state | Meaning |
| --- | --- | --- |
| `PENDING_APPROVAL` | `TASK_STATE_SUBMITTED` | Waiting for the recipient side's consent; nothing delivered |
| `DELIVERING` | `TASK_STATE_SUBMITTED` | Stored; waking or delivering. Delivery is not success |
| `PROCESSING` | `TASK_STATE_WORKING` | Delivered to the recipient's harness |
| `REPLIED` | `TASK_STATE_COMPLETED` | The reply is the task's artifact; until the reply event reaches the sender, the task stays `WORKING` |
| `DECLINED` | `TASK_STATE_REJECTED` | Refused by the recipient side |
| `CANCELED` | `TASK_STATE_CANCELED` | Canceled before an outcome |
| `EXPIRED`, `FAILED` | `TASK_STATE_FAILED` | A2A has no expired state; the metadata says which |

## What the qualification checks

`scripts/verify-interop.py --services` starts the private services with fresh
lab certificates, then runs Go tests against them:

| Test | Checks |
| --- | --- |
| `TestDirectoryPublishesSearchesAndDeletes` | Push of two records; the server and the client compute the same content ID; search by skill ID and skill name confined to one name scope; pull; delete; a deleted record is neither pulled nor found |
| `TestDirectoryValidatesRecordsAgainstThePrivateSchema` | Unknown skill, missing description and missing skills are refused (`InvalidArgument` with the schema server's message) |
| `TestDirectoryEdgeAdmitsOnlyTheControlPlane` | Plaintext, no client certificate, another workload of the same authority and a foreign authority are all refused |
| `TestSLIMExchangeThroughThePrivateNode` | 100 requests and replies, in order, between two processes with their own mutual-TLS connections |
| `TestSLIMNodeAdmitsOnlyTheSLIMAuthority` | The bridge certificate connects; no certificate, a foreign authority and the Directory authority are refused |
| `TestSLIMKeepsNothingForAnAbsentRecipient` | A session to an absent name fails; a message sent while the recipient is down is never delivered after it returns |
| `TestA2AOverSLIMThroughThePrivateNode` | A2A `SendMessage` and `GetTask` over SLIM: completed task with its artifact, and the recipient sees the sender's verified identity |
| `TestPublisherAgainstThePrivateDirectory` | The platform's own publisher (`internal/directory`): its records pass the real schema, a new description replaces the old record, an unknown skill is refused and withdraws the record, a hidden agent is no longer found, and a neighbouring organization's scope finds nothing |

The library tests also run, without Docker:
- the A2A JSON-RPC round trip;
- OASF decoding;
- Directory client construction;
- the SLIM native library's version.

To check that the tests detect real gaps, a mutation run removed three
protections from a copy of the deployment:
- the edge's name check;
- the node's client authority;
- Directory's schema validation.

Each made its test fail, while the positive tests still passed.

Footprint measured in the lab (Docker Desktop on WSL2, not VPS figures):

| Service | Idle | After the tests | Image |
| --- | --- | --- | --- |
| OASF schema server | 114 MiB | 114 MiB | 89 MB |
| Directory API server | 16 MiB | 23 MiB | 135 MB |
| Directory edge (HAProxy) | 16 MiB | 15 MiB | 58 MB |
| SLIM node | 3.4 MiB | 5.4 MiB | 88 MB |

About 150 MiB in total. In separate runs:
- a SLIM client holding a connection used about 30 MiB;
- 50 Directory pushes plus searches through the edge took about 39 ms per
  pair.

## Upstream limits found

- **Directory v1.8.0.**
  - Routing cannot be disabled.
  - At every start the server tries to publish a built-in record written for
    schema 1.0.0, which the 1.1.0 schema refuses. It is logged as a warning and
    has no effect.
  - The upstream Compose health check needs a shell the image does not have.
  - A read-only root needs a writable `/home/nonroot`.
- **SLIM bindings v3.3.9.**
  - The asynchronous app constructor panics outside a Tokio runtime; use the
    blocking one.
  - Every refusal surfaces as the same opaque `datapath error`.
  - There is no reconnection after a node restart.
  - A binary linked against the archive requires glibc 2.39.
- **slim-a2a-go v0.5.2.** It does not compile with A2A Go SDK v2.2.1 or later,
  because of API changes in that SDK (for example a push-notification request
  type it still references).

## Reproduce

Prerequisites:
- Linux amd64 with glibc 2.39 or later;
- Go 1.27.3 and a C compiler;
- Python 3.11 or later;
- for `--services`, Docker with Compose v2 and `openssl`.

The first run downloads the Go modules, the SLIM native archive (about 90 MB,
verified by SHA256) and the images (about 400 MB).

```sh
# Libraries only (no Docker): status passed_libraries_only.
python3 scripts/verify-interop.py --go /path/to/go1.27.3/bin/go --output <new-dir>
# With the private services: status passed, int01_complete true.
python3 scripts/verify-interop.py --go /path/to/go1.27.3/bin/go --services --output <new-dir>
```

The output directory keeps for every run:
- the logs;
- the source digests;
- the running image references, checked against the profile;
- the footprint before and after the tests;
- the services' own logs.

The script refuses:
- a missing, skipped or failed test;
- a module that Go would modify;
- a port published beyond loopback;
- an image that is not the pinned one.

It always removes the services, their volumes and networks. CI runs it with
`--services` on every push.

To run the services on a host:
1. Run [make-certs.sh](../deploy/interop/make-certs.sh), or provide the same
   file layout from your own authorities.
2. Start them with `INTEROP_CERTS=<dir> docker compose -f deploy/interop/compose.yml up -d --wait`.

The lab certificates expire after 30 days, and their keys are readable by the
container users. On a host:
- give each key to its container user (HAProxy 99, SLIM 65532) with mode 0400;
- keep the authorities' keys offline.

## Next steps (gate G2)

| Item | Work |
| --- | --- |
| INT-02 | Done: one OASF record per described, discoverable agent, published from PostgreSQL by the worker and withdrawn when the agent is hidden, deleted or its organization suspended; search by skill from a running agent, filtered again in PostgreSQL; schema refusals shown to the organization. |
| INT-03 | In the guest, done: an Agent Card per agent the caller may reach, `SendMessage` and `GetTask` mapped onto peer requests with the state table above, and agents that are A2A servers themselves, each job one message; qualified with the A2A Go SDK v2.8.0 on both sides. Remaining: the same mapping on the platform's side, for the SLIM bridge; the KVM journey. |
| INT-04 | SLIM bridge process: SLIM names for live recipients, delivery from the mailbox through SLIM to the worker and the guest over vsock, receipts, supervision and restart. |
| INT-05 | The flagship journey: agent A finds agent B, which is stopped, and gets its answer over A2A and SLIM; then the same journey with Directory or SLIM down. |
