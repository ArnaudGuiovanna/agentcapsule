# Formal models

These [Quint](https://github.com/informalsystems/quint) models specify the
protocols whose failures would be hardest to see in tests: event delivery and
idempotency, inter-agent messaging, VM lifecycle and fencing, revocation across
stores, restore authority, and deferred invocation results. Each model states
its invariants explicitly and most include "broken" instances that disable one
mechanism and must produce a counterexample.

The models are design documentation, not a proof of the Go code. The link to
the code is made by conformance tests: traces generated from some models are
replayed against the real implementation and PostgreSQL in
`internal/controlplane/*_itf_test.go`, with the traces checked in under
`internal/controlplane/testdata/`, and Go tests named after a run
(`TestFooBar` for `fooBarTest`) drive the code through that run's steps.
[projections.md](projections.md) lists every run and witness with the Go
tests that project it, or why none does; `scripts/check-model-projections.py`
fails when a run or witness is missing from it. Section numbers (`§6.3`, …) in model headers
refer to the original design specification, which is not published.

## Running

Quint 0.33.1 is pinned in `package.json`:

```bash
cd spec
npm ci
npx quint typecheck delivery.qnt
npx quint run --main=invocationCompletion --init=init --step=step \
  --invariant=safety --max-steps=12 --max-samples=20000 invocation_completion.qnt
# Bounded model checking needs a Java runtime for Apalache (see below):
npx quint verify --main=invocationCompletion --init=init --step=step \
  --invariant=safety --max-steps=10 invocation_completion.qnt
```

`npm run typecheck` checks every model; CI runs it on each change, and
`scripts/check-repo-hygiene.py` checks [projections.md](projections.md).

The concurrent protocol (P1) and service progress (P3) models are checked by
their runs and by simulation of `safety`:

```bash
npx quint test --main=concurrentProtocolTests concurrent_protocol_test.qnt
npx quint run --main=concurrentProtocolFour --init=init --step=step \
  --invariant=safety --max-steps=40 --max-samples=100000 concurrent_protocol.qnt
npx quint test --main=serviceProgressTests service_progress_test.qnt
npx quint run --main=serviceProgressOk --init=init --step=step \
  --invariant=safety --max-steps=40 --max-samples=200000 service_progress.qnt
```

Runs are checked with `quint test`. A witness module of `restore_witness.qnt`
is either a guard (`run guardTest`, a `quint test`) or a fixed schedule
(`traceInit`, `traceStep`) whose `checked` invariant must fail at its last
step. The restore authority has an undirected and a focused simulation:

```bash
npx quint test --main=restoreAuthorityReplicaTests restore_authority_test.qnt
npx quint test --main=restoreWitnessSameEpochGuard restore_witness.qnt
npx quint run --main=restoreWitnessSameEpochBroken --init=traceInit \
  --step=traceStep --invariant=checked --max-steps=15 restore_witness.qnt
npx quint run --main=restoreAuthorityOk --invariant=safety \
  --max-steps=30 --max-samples=100000 restore_authority.qnt
npx quint run --main=restoreAuthorityFailover --step=focusedStep \
  --invariant=safety --max-steps=80 --max-samples=100000 \
  --witnesses promotedWitness windowRestoredWitness restore_authority.qnt
```

### Bounded and exhaustive checks

`quint test` and `quint run` explore samples. Apalache (`quint verify`) checks
every execution up to a number of steps, and TLC (`quint verify
--backend=tlc`) every reachable state of a finite instance; both need a Java
runtime. `scripts/check-models.py` runs every such check the models declare,
one at a time, and fails unless each ends as the repository expects:

- the fixed witness schedules (`traceInit`, `traceStep`) of
  `concurrent_witness.qnt`, `restore_witness.qnt` and `protocol_witness.qnt`:
  `checked` must fail at the schedule's last step (Apalache);
- the depth wrappers of `concurrent_bounded.qnt`, `concurrent_focused.qnt` and
  `bounded.qnt`: `safety` (or `checked`) holds in every state up to the depth
  (TLC; the frontier is a deadlock, which TLC's `-deadlock` ignores);
- P3's temporal properties (`progress`, `observed`, `deletionCompletes`,
  `successfulDelivery`) hold, and fail without priority, without the outbox,
  for endless arrivals and in the two controls of
  `service_progress_controls.qnt` (TLC);
- `liveness.qnt` (TLC), the inductive invariants of `induction.qnt` and the
  three obligations of `protocol_induction.qnt` (Apalache);
- each other model: every reachable state of its correct instance (TLC), and
  a counterexample from each broken configuration within a stated number of
  steps (Apalache).

`python3 scripts/check-models.py --list` prints each check with its bounds,
backend, expected result and time limit. `scripts/test_check_models.py`, run
by CI, fails when a witness schedule or a module of the checkers' files has no
check.

**Tested toolchain** (installed without root, recorded with these digests in
`~/.local/share/agentcapsule-tools/model-checkers.json`, which the script
checks before any run):

| Tool | Version | Where | SHA-256 |
|---|---|---|---|
| Quint | 0.33.1 | `spec/node_modules` (`npm ci`) | `spec/package-lock.json` |
| Eclipse Temurin JDK | 21.0.13+9 (LTS) | `jdk/jdk-21.0.13+9` | `OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz`: `d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c` |
| Apalache | 0.62.4, the version Quint 0.33.1 pins | `apalache/apalache-dist-0.62.4/apalache` | `apalache.tgz`: `8ac8488422c30d552735bae11b92a2d014d8e02e8608702acc08f9a2d8a9abb2`; `lib/apalache.jar`: `e5223915507b65cc5f1638bd037ede60f8a4fc1644aff46355779f9b05df9262` |
| TLC | the one inside `apalache.jar` | | Quint runs `java -cp apalache.jar tlc2.TLC`; it never uses a separate `tla2tools.jar` |

The JDK is the Temurin tarball of the Adoptium API, the Apalache archive the
`apalache.tgz` of its GitHub release; each digest above matches the one its
publisher lists. Quint finds Apalache under `QUINT_HOME`
(`apalache/` here) instead of downloading it into `~/.quint`. The script sets
`QUINT_HOME`, puts the JDK first on `PATH`, and keeps TLC's files under the
check's own directory, never in `/tmp`.

## Models

| Model | What it covers |
|---|---|
| `delivery.qnt` | Per-agent event queue: at-least-once delivery, FIFO, dead letters, API idempotency keys |
| `leased_delivery.qnt` | Delivery with expiring leases, delayed RPCs from two workers, retirement fences |
| `outbox.qnt` | Request + outbox + idempotent response written in one PostgreSQL transaction |
| `durability.qnt` | Local transactional effects: commit, flush, ACK and recovery |
| `fencing.qnt` | One harness database serializing local effects and revocation |
| `messaging.qnt` | Inter-agent requests: consent, mandates, single final state, directory visibility |
| `lifecycle.qnt` | VM lifecycle on the worker: exclusive lease, generations, crash, reconciliation, admission |
| `fair_admission.qnt` | Fairness of the host admission queue |
| `barrier_capacity.qnt` | Store barriers competing for VM capacity |
| `composition.qnt`, `protocol_composition.qnt` | Deletion, requests and delivery composed over shared state |
| `concurrent_protocol.qnt` (+ `_bounded`, `_focused`, `_loaded`, `_witness`, `_test`) | Concurrent SQL coordination with delayed RPCs; bounded and witness variants for TLC. A request's closure fences its two parties only: no other store receives an event carrying its subject (`closureScope`, `closedSafe`, [ADR 007 §7](../docs/adr/007-delivery-closure-and-priority.md#71-a-requests-closure-fences-its-two-parties-only)). A reply or status no RPC carried dies at its deadline without a fence, anywhere in its queue (`retireUnsent`). An event a restore lost goes back to its queue under the same ID; a final request never reopens (`loseOutcome`, `redeliver`, [ADR 008](../docs/adr/008-redelivering-lost-agent-requests.md)) |
| `revocation.qnt` (+ `_test`) | Deletion barrier for one subject across several stores |
| `store_seal.qnt`, `store_enrollment.qnt` | Permanent store seal; restoration blocking new work before retiring a store |
| `restore_authority.qnt` (+ `_test`, `_witness`) | External restore authority, outcome records and declared losses within the RPO window (D-03 option B). Its synchronous replica on the standby, promotion under a new epoch, degraded mode, and PostgreSQL reconciled with the authority after a failover (D-05 option (a), [ADR 005](../docs/adr/005-keys-outside-restored-domain.md#model-revision-d-05-option-a)) |
| `credential_renewal.qnt` | Credential replacement of a live boot |
| `service_progress.qnt` (+ `_controls`, `_test`) | Progress of observation and notification slots. A restore may deliver a request or a notification again before the run stabilizes (ADR 008) |
| `invocation_completion.qnt` | Deferred results: an agent acknowledges "working" and posts one outcome; expiry, cancellation and deletion race to exactly one outcome |
| `bounded.qnt`, `induction.qnt`, `protocol_induction.qnt`, `liveness.qnt` | Depth-bounded wrappers, inductive invariants and temporal checks over the original relations |
