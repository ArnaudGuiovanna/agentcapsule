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
`internal/controlplane/testdata/`. Section numbers (`§6.3`, …) in model headers
refer to the original design specification, which is not published.

## Running

Quint 0.33.1 is pinned in `package.json`:

```bash
cd spec
npm ci
npx quint typecheck delivery.qnt
npx quint run --main=invocationCompletion --init=init --step=step \
  --invariant=safety --max-steps=12 --max-samples=20000 invocation_completion.qnt
# Bounded model checking needs a Java runtime for Apalache:
npx quint verify --main=invocationCompletion --init=init --step=step \
  --invariant=safety --max-steps=10 invocation_completion.qnt
```

`npm run typecheck` checks every model; CI runs it on each change.

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
| `concurrent_protocol.qnt` (+ `_bounded`, `_focused`, `_loaded`, `_witness`, `_test`) | Concurrent SQL coordination with delayed RPCs; bounded and witness variants for TLC |
| `revocation.qnt` (+ `_test`) | Deletion barrier for one subject across several stores |
| `store_seal.qnt`, `store_enrollment.qnt` | Permanent store seal; restoration blocking new work before retiring a store |
| `restore_authority.qnt` (+ `_test`, `_witness`) | External restore authority, outcome records and declared losses within the RPO window (D-03 option B). Its synchronous replica on the standby, promotion under a new epoch, degraded mode, and PostgreSQL reconciled with the authority after a failover (D-05 option (a), [ADR 005](../docs/adr/005-keys-outside-restored-domain.md#model-revision-d-05-option-a)) |
| `credential_renewal.qnt` | Credential replacement of a live boot |
| `service_progress.qnt` (+ `_controls`, `_test`) | Progress of observation and notification slots |
| `invocation_completion.qnt` | Deferred results: an agent acknowledges "working" and posts one outcome; expiry, cancellation and deletion race to exactly one outcome |
| `bounded.qnt`, `induction.qnt`, `protocol_induction.qnt`, `liveness.qnt` | Depth-bounded wrappers, inductive invariants and temporal checks over the original relations |
