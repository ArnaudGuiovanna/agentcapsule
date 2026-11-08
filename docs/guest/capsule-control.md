# capsule.v1 control contract and application admission

`GET /v1/capabilities` and `capsuleprotocol.Client.Negotiate` describe the
operations of the **harness control protocol** available for an authenticated
boot. This information is neither business skills, nor tool permissions, nor
tenant scopes. It does not implement the future manifest / tenant policy /
agent rights intersection planned by the product spec
([product.md](../product.md)).

The authenticated product path now requires this negotiation before exposing
the local proxy, confirming volume preparation and admitting application use.
An older image without this endpoint is refused. The physical presence of a VMM
remains a separate observation: it allows its maintenance and removal even when
its contract is unreachable.

## Request and response

The client uses its channel already bound to the boot: mTLS on the host side or
a private Unix socket with `SO_PEERCRED` checking on the supervisor side. No
`agent_id` or `tenant_id` in a payload selects the identity of the negotiation.

```http
GET /v1/capabilities HTTP/1.1
X-Capsule-Accept-Protocol: capsule.v2, capsule.v1
Accept: application/json
```

The header must be unique, contain between one and eight distinct versions and
take at most 256 bytes. The format is `capsule.v<positive integer>` with at most
six digits and no leading zero. HTTP whitespace around elements is allowed.
Wildcards, duplicate versions, empty elements, bodies, query strings and
methods other than GET are refused. The current server selects only
`capsule.v1`.

```json
{
  "protocol": "capsule.v1",
  "identity": {
    "incarnation": 1,
    "agent_id": "agent-example",
    "generation": 1,
    "vm_id": "0123456789abcdef"
  },
  "features": ["health", "fences", "events", "invoke.message.user.text"],
  "limits": {"message_bytes": 1048576, "content_bytes": 524288}
}
```

A successful response carries `X-Capsule-Protocol: capsule.v1`,
`Cache-Control: no-store` and deterministic JSON. It contains no timestamp, host
path, secret or message content. The client limits the response to 4,096 bytes
and verifies the complete boot identity, the selected version, the limits and
the features without duplicates. It refuses a missing, ambiguous, non-offered
or incompatible selection.

| Feature | Existing operation described | Limit of the current contract |
|---|---|---|
| `health` | `GET /v1/health` | Identity/protocol and explicit observation of the previous shutdown; the volume and the harness must already be prepared |
| `fences` | `POST /v1/fences` | Transactional tombstone of a subject; no proof of key destruction or VMM stop |
| `events` | `POST /v1/events` | Existing durable envelope `Event{ID,Subjects,Body}`, SQLite guards and deduplication unchanged |
| `invoke.message.user.text` | `POST /v1/invoke` | Existing `message.user` instruction, text content and mandate; not yet an arbitrary JSON invocation |

A `fence_only` boot advertises only `health` and `fences`, and keeps refusing
events and invocations. The list contains neither quiesce nor volume
preparation: these operations belong to the `VolumeServer` supervisor, not to
the harness server. It does not advertise A2A, LLM or outgoing capabilities
that are still to be integrated.

## Compatibility and errors

The existing health, events, invoke, fences and quiesce requests/responses are
unchanged. Old strict decoders receive no new field on these routes. No change
to the identity, the boot version, the signed body, the volume marker or the
event format is introduced.

| Case | Result of `Negotiate` |
|---|---|
| Old server: HTTP 404 `unknown_operation`, expected identity/protocol | `ErrCapabilitiesUnavailable`; no automatic fallback to health |
| No common protocol: HTTP 406 `unsupported_protocol` | `ErrUnsupportedProtocol` |
| Malformed offer, selection or response | `ErrProtocol` |
| Different identity/generation/incarnation | `ErrIdentity` |
| Authentication refused, boot not ready, shutdown in progress or transport unavailable | `ErrTransport` |

`NewClient`, `NewLocalClient`, `Health` and the existing primitives do not
trigger this negotiation automatically. The product path uses
`RequireControlContract(ctx)`: `health` and `fences` are mandatory in
restricted mode; an ordinary boot also requires `events` and
`invoke.message.user.text`. Both limits must equal those of the current client
(1,048,576 and 524,288 bytes), which does not yet adapt its sends to a reduced
limit. `Negotiate` alone remains a discovery and accepts narrower valid
profiles.

A separate consumer can explicitly choose its profile:

```go
contract, err := client.Negotiate(ctx, []string{capsuleprotocol.Version})
if err != nil {
    return err
}
if !contract.Supports(capsuleprotocol.ControlEvents) {
    return capsuleprotocol.ErrUnsupportedProtocol
}
```

This metadata never replaces authority checks at the time of the effect. The
negotiation changes neither the client, nor the persistent fences, nor the
identity and body used to replay an event.

## Controlled paths and SQL observation

1. `guestinit.StartHarness` compares health and `previous_shutdown`, requires
   the local contract, then exposes the proxy. A permanent refusal terminates
   the child process; a transport error stays bounded by the preparation
   timeout.
2. `worker.withVolumeBoot` requires the contract after the volume open/health,
   before the transient ACK that authorizes its SQL initialization receipt.
   This check does not claim to precede the key delivery needed for startup.
3. The runtime requires the contract on a new boot and on a `Start` that reuses
   a boot. The reuse probe is done outside `host.lock`, under host admission.
   `Control` renegotiates before returning each application session.
4. The worker's outgoing API requires `Control` and the exact identity of the
   caller before the authority locks and effect transactions. The physical
   census may itself read the authority/SQL before this probe; no effect lock
   is then held. A network error never means `ErrGeneration` or an absent VMM.
5. Migration `0007_placement_control_contract.sql` creates an observation bound
   to `(agent, host, generation, vm_id, incarnation)`. A new boot publishes it
   after SQL confirmation and durable publication of the host registry; a
   reused session publishes it after negotiation. `AgentCatalog` projects
   `READY` only for an ordinary `RUNNING` placement with this exact observation.
   The end-of-operation compare-and-set of `wake` also requires it. No inherited
   boot is retroactively declared compatible by the migration or by adoption.

`READY` means here **compatibility observed for this boot**, not heartbeat or
instantaneous availability. A known probe error invalidates its SQL reference
with a cleanup bounded to two seconds, even if the probe's context has expired.
If SQL is also unavailable, admission is refused and the errors are returned;
the old observation may remain until a successful invalidation or
revalidation. A late observation from another generation/VM can neither
validate nor erase that of the replacement. The incarnation is compared with
the current store to prevent the reuse of an observation from an old image.

`Reconcile`, the physical adoption validation and `CredentialRotations` do not
depend on a network probe. They can keep a physically `RUNNING` VMM while the
API exposes `STARTING` and `wake` remains unfinished. `ControlForRetirement`
derives the authenticated session only from the registry and the current
placement. It is reserved for stopping: SQL `STOPPING` precedes `Quiesce`, then
the physical removal is verified independently. The application probe's budget
therefore cannot prevent the stop intent. The forced paths for removal, physical
sealing and rotation remain independent of the contract. Complete deletion keeps
its distributed barriers: a fence may stay pending on an incompatible guest
until its controlled replacement. No fence receipt is invented from a network
error.

The generic envelopes of the product spec (`request_id`, `event_id`,
`idempotency_key`, `deadline`, `content_type`, `payload_ref`, `trace_id`), the
tenant identity, the intersection of business capabilities and the second
language remain to be built in coordinated slices. None of these points is
established here.

## Rebuilding and switching images

An image built before the capabilities endpoint existed does not contain it.
Do not modify it, re-tag it or bypass the verifier's source check. Build the
new image into a new directory:

```bash
CPATH=<tools-dir>/guest-build/usr/include \
python3 scripts/build-product-guest.py \
  --go <go-binary> \
  --cryptsetup <tools-dir>/guest-build/usr/sbin/cryptsetup \
  --output <output-dir>/product-guest-build-new
```

The script refuses to overwrite a directory and records the SHA-256 of
capsule-init, capsule-echo and product.initrd in `artifacts.json`. Recompiling
these two binaries and the initrd is enough for this change; the kernel and
Firecracker remain separately validated artifacts. Building alone validates no
KVM boot.

The reserved release and the `InitrdSHA256` SHA-256 must designate this new
image. Provisioning of an enrollment that is already `READY` does not migrate
its release: changing only the global initrd path does not deploy the existing
agents. Adopting an older image explicitly fails for the application; the
operator keeps the removal/rotation paths. Switching the release of existing
enrollments needs its own controlled product path.

After review and resource coordination, the KVM check takes the explicit build
directory:

```bash
sudo python3 scripts/verify-product-guest.py --guest-build <output-dir>/product-guest-build-new ...
```

It verifies the source digests before starting the VMs, starts its private
PostgreSQL and also requires the scenario
`TestProductWorkerContractOutagePreservesCensusAndMaintenance`. That scenario
masks the transport of a real VMM and verifies physical adoption, refusal and
resumption of wake, rotation despite the outage, then forced removal after the
quiesce expires. It does not simulate an old image: a legacy refusal is covered
separately on the real TLS/Unix channels. A KVM run with a legacy image must
explicitly identify that other artifact.

## Validation

The tests use the real TLS transports on loopback and Unix/SO_PEERCRED, and
SQLite to keep the deduplication and fence assertions. They cover refusal of
versions/identities, auth, restricted mode, bounded responses, absence of the
legacy endpoint, profiles that are too narrow, an unprepared volume and closing
after quiesce. A healthy but incompatible real Unix child process is terminated
before the proxy is exposed. PostgreSQL covers the absence of an initialization
receipt after a contract refusal, the `READY` projection, late observations,
the end of `wake` and the independence of the physical state. The
preparation/quiesce callback in these tests is controlled: they are not
mount, Firecracker, KVM or tenant-isolation runs.

```bash
go test -race ./internal/capsuleprotocol ./internal/referenceharness ./internal/guestinit \
  ./internal/runtime ./internal/worker ./internal/controlplane ./cmd/capsule-init ./cmd/capsule-echo
```

The PostgreSQL tests require `AGENTCAPSULE_REQUIRE_POSTGRES=1` and a dedicated
DSN in `AGENTCAPSULE_TEST_POSTGRES`; without this configuration they are
skipped. Compiling with the KVM tags and `-run '^$'` is not executing them.
[scripts/verify-postgres.py](../../scripts/verify-postgres.py) runs the Go
tests with race detection and the PostgreSQL phases (including immediate
shutdown and WAL recovery) in a private cluster.

Nine existing Quint scenarios were also replayed with the Rust backend and seed
`0x2a`: P1 `oldChannelTest`, `admittedPhysicalDeathTest`,
`orphanedConfirmedBootTest`, `expiredStartLeaseCleanupTest`,
`publicationAfterStopIntentTest`; P2 `activationRechecksNewRevocationTest`,
`authorityOutageBlocksOtherwiseReadyActivationTest`,
`authorityRecoveryAllowsActivationTest`, `physicalRetirementAbortsOldWriterTest`.
They pass without any change to the models (see [spec/](../../spec/)). This is
not a new exhaustive campaign nor a proof of refinement of the Go code.

The existing models do not change. `effectOnce`, the fence receipts and the
exclusivity/restore constraints remain applicable to the business paths; a
read-only discovery is not a new formal proof.
