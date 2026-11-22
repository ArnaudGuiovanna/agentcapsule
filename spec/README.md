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
`scripts/check-repo-hygiene.py` checks [projections.md](projections.md) and
the copies of the models kept with traces ([pinned-models.json](pinned-models.json)).
CI also runs `python3 scripts/check-model-runs.py` (about four minutes with
four jobs): `quint test` of every module that declares a run, and a replay
of every fixed schedule of `internal/controlplane/testdata/` on the current
model, which must give the pinned trace's states and refusals. It uses
Quint's TypeScript evaluator, which downloads nothing.

A change to a model that a fixture copies makes the copy stale: copy the
model into the fixture and regenerate its traces with the commands of its
`manifest.json`, then the Go replay's digests; or declare the copy `frozen`
in `pinned-models.json` with the reason, if its schedules still replay on
the new model.

The concurrent protocol (P1) and service progress (P3) models are checked by
their runs, by simulation of `safety`, and by the bounded and exhaustive
checks [below](#bounded-and-exhaustive-checks):

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
  `concurrent_witness.qnt` and `restore_witness.qnt`: `checked` must fail at
  the schedule's last step, not before (Apalache); in `protocol_witness.qnt`
  the broken instances must fail within their schedule and the conforming one
  must not;
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

Each check reads only the modules it needs, copied alone into files of the
same names (`src/` in its directory). `quint verify` sends Apalache the typed
spec of every module it loaded as one string: the whole of
`restore_witness.qnt` with `restore_authority.qnt` makes 446 MB of it for one
witness, and Quint 0.33.1 then fails (`RangeError: Invalid string length`) or
exits 0 without a result. The script never counts an exit without Quint's
`[ok]` (and, for TLC, its completion line) as a pass.

**Last run, 2026-11-17 and 18** (12 cores and 15 GB shared with other work,
TLC with four workers; evidence kept locally under
`quint/results/check-models-full-*`):

| Result | Checks |
|---|---|
| As expected | 131 of 134: every correct configuration holds within its bounds, every witness schedule and broken configuration fails |
| Counterexample in a correct configuration | none |
| Bound not reached, no counterexample among the states explored (not a pass) | `restoreAuthorityTiny`: 245.7 million states to depth 20, 112 million queued, 2-hour limit. `concurrentProtocolLoadedDepth12`: 35.3 million states to depth 9 of 13, 31.9 million queued, 1-hour limit. `concurrentProtocolDepth8`: 56.8 million states, its last level reached with 39.6 million states still queued, stopped after 1 hour 56 minutes |

- No invariant or temporal property fails in a correct configuration, and
  every witness schedule and broken configuration fails as it must, each
  witness of `concurrent_witness.qnt` and `restore_witness.qnt` at its last
  step.
- **P1.** Every execution of up to 7 steps from the initial state keeps
  `checked` (28,878,324 states, 72 minutes). That graph is the one of
  November 7: within 7 steps no reply exists and no closure commits, so
  none of the actions ADR 007 and ADR 008 added is reached; nor from the
  loaded and closing prefixes (1,836,022 and 1,716,076 states, unchanged).
  Three more prefixes of `concurrent_focused.qnt`, each reachable by a run,
  start where those actions do, and every 6-step continuation keeps
  `checked`: a reply not yet sent (16,490,756 states: its deadline, its
  death unsent or behind its fence, the loss of the request's delivery), the
  reply delivered (6,990,594 states: its loss and redelivery), and a request
  expiring with its delivery under way and a bystander stopped (16,211,600
  states: the closure of its two parties only). The 12-step continuations
  of the four-request prefix do not fit this machine: after an hour, 35.3
  million states to depth 9 of 13, all keeping `safety`, 31.9 million
  queued; nor do the 8-step executions from the initial state, stopped
  after 1 hour 56 minutes with 56.8 million states explored and 39.6
  million queued (they would not reach those actions either).
- **P3.** `safety` holds in all 973,632 reachable states of
  `serviceProgressSmall`, and so do `progress`, `observed` and
  `deletionCompletes`; `successfulDelivery` holds on
  `serviceProgressReliable` (45,120 states). The negative property and the
  four broken or control configurations each yield a counterexample.
- **P2.** `restoreAuthorityTiny` did not finish within two hours: 245.7
  million distinct states to depth 20, all keeping `safety`, with 112
  million still queued. Since D-05 its state space is beyond this machine;
  the November 7 model, without the replica and the failover, completed.
  The restore witnesses and simulations remain its checks.
- **The other models.** The depth wrappers of `bounded.qnt` hold, among them
  `messagingDepth10` (34,486,031 states) and `deliveryLargeDepth12`
  (46,714,801 states), and so does every reachable state of `deliveryLarge`
  (45,176,641 states); the liveness, induction and protocol-induction
  checks pass, `protocolInductive.preserved` in 12 minutes.

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
| `composition.qnt`, `protocol_composition.qnt` | Deletion, requests and delivery composed over shared state; a deletion fences its agent's scope (`deletionScope`) |
| `concurrent_protocol.qnt` (+ `_bounded`, `_focused`, `_loaded`, `_witness`, `_test`) | Concurrent SQL coordination with delayed RPCs; bounded and witness variants for TLC. A request's closure fences its two parties only: no other store receives an event carrying its subject (`closureScope`, `closedSafe`, [ADR 007 §7](../docs/adr/007-delivery-closure-and-priority.md#71-a-requests-closure-fences-its-two-parties-only)). A deletion fences its agent's scope only, the stores that share a request with it (`deletionScope`, `deletionScopeCovers`, since the v0.1.0 audit). A reply or status no RPC carried dies at its deadline without a fence, anywhere in its queue (`retireUnsent`). An event a restore lost goes back to its queue under the same ID; a final request never reopens (`loseOutcome`, `redeliver`, [ADR 008](../docs/adr/008-redelivering-lost-agent-requests.md)) |
| `revocation.qnt` (+ `_test`) | Deletion barrier for one subject across several stores |
| `store_seal.qnt`, `store_enrollment.qnt` | Permanent store seal; restoration blocking new work before retiring a store |
| `restore_authority.qnt` (+ `_test`, `_witness`) | External restore authority, outcome records and declared losses within the RPO window (D-03 option B). Its synchronous replica on the standby, promotion under a new epoch, degraded mode, and PostgreSQL reconciled with the authority after a failover (D-05 option (a), [ADR 005](../docs/adr/005-keys-outside-restored-domain.md#model-revision-d-05-option-a)) |
| `credential_renewal.qnt` | Credential replacement of a live boot |
| `service_progress.qnt` (+ `_controls`, `_test`) | Progress of observation and notification slots. A restore may deliver a request or a notification again before the run stabilizes (ADR 008) |
| `invocation_completion.qnt` | Deferred results: an agent acknowledges "working" and posts one outcome; expiry, cancellation and deletion race to exactly one outcome. The output stream of [ADR 022](../docs/adr/022-native-streaming.md): its chunks stop at the outcome, belong to the current attempt (a restore's rerun deletes the old ones) and are never an outcome |
| `corpus_lifecycle.qnt` | Corpus builds, immutable releases, bindings applied at boot, the organization boundary and the host's image cache: eviction never removes a pinned image ([ADR 023](../docs/adr/023-corpora.md)) |
| `bounded.qnt`, `induction.qnt`, `protocol_induction.qnt`, `liveness.qnt` | Depth-bounded wrappers, inductive invariants and temporal checks over the original relations |
