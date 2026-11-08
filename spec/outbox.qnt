/**
 * PostgreSQL request + outbox + idempotency response transaction. Two sessions
 * may stage different keys concurrently; same-key writers serialize (unique
 * constraint / row lock). The client-visible response follows the durable commit.
 * This refines the transaction boundary, not PostgreSQL's WAL implementation.
 * Body-hash mismatch handling remains checked in delivery.qnt and the Go store.
 */
module apiOutbox {
  const ATOMIC_OUTBOX: bool
  const SYNC_RESPONSE: bool
  pure val CLIENTS = Set("c1", "c2")
  pure val KEYS = Set("k1", "k2")
  type Phase = Idle | Read | RequestWritten | OutboxWritten | Committed
  type Row = { requests: int, events: int, saved: bool }
  pure val emptyRow = { requests: 0, events: 0, saved: false }
  pure def increment(n: int): int = if (n < 2) n + 1 else 2
  var up: bool
  var visible: str -> Row
  var stable: str -> Row
  var owners: str -> str
  var phase: str -> Phase
  var selected: str -> str
  var fresh: str -> bool
  var accepted: Set[str]

  action init = all {
    up' = true, visible' = KEYS.mapBy(_ => emptyRow), stable' = KEYS.mapBy(_ => emptyRow),
    owners' = KEYS.mapBy(_ => ""), phase' = CLIENTS.mapBy(_ => Idle),
    selected' = CLIENTS.mapBy(_ => "k1"), fresh' = CLIENTS.mapBy(_ => false), accepted' = Set(),
  }
  action keepStores = all { visible' = visible, stable' = stable }
  action keepClients = all { owners' = owners, phase' = phase, selected' = selected, fresh' = fresh }
  action begin(c: str, k: str): bool = all {
    up, phase.get(c) == Idle, owners.get(k) == "",
    owners' = owners.set(k, c), phase' = phase.set(c, Read), selected' = selected.set(c, k),
    fresh' = fresh.set(c, not(visible.get(k).saved)), up' = up, accepted' = accepted, keepStores,
  }
  action writeRequest(c: str): bool = {
    val k = selected.get(c)
    val row = visible.get(k)
    val partial = visible.set(k, { ...row, requests: increment(row.requests) })
    all {
      up, phase.get(c) == Read,
      visible' = if (not(ATOMIC_OUTBOX) and fresh.get(c)) partial else visible,
      stable' = if (not(ATOMIC_OUTBOX) and fresh.get(c)) partial else stable,
      phase' = phase.set(c, RequestWritten), selected' = selected, fresh' = fresh,
      owners' = owners, up' = up, accepted' = accepted,
    }
  }
  action writeOutbox(c: str): bool = all {
    up, phase.get(c) == RequestWritten,
    phase' = phase.set(c, OutboxWritten), selected' = selected, fresh' = fresh,
    owners' = owners, up' = up, accepted' = accepted, keepStores,
  }
  action commit(c: str): bool = {
    val k = selected.get(c)
    val row = visible.get(k)
    val committed = if (fresh.get(c)) {
      requests: if (ATOMIC_OUTBOX) increment(row.requests) else row.requests,
      events: increment(row.events), saved: true,
    } else row
    val committedStore = visible.set(k, committed)
    all {
      up, phase.get(c) == OutboxWritten,
      visible' = committedStore, stable' = if (SYNC_RESPONSE) committedStore else stable,
      owners' = owners.set(k, ""), phase' = phase.set(c, Committed),
      selected' = selected, fresh' = fresh, up' = up, accepted' = accepted,
    }
  }
  action respond(c: str): bool = all {
    up, phase.get(c) == Committed,
    accepted' = accepted.union(Set(selected.get(c))),
    phase' = phase.set(c, Idle), owners' = owners, selected' = selected, fresh' = fresh,
    up' = up, keepStores,
  }
  action flush = all {
    up, stable' = visible, visible' = visible, keepClients, up' = up, accepted' = accepted,
  }
  action processCrash = all {
    up, up' = false, keepStores,
    owners' = KEYS.mapBy(_ => ""), phase' = CLIENTS.mapBy(_ => Idle),
    selected' = CLIENTS.mapBy(_ => "k1"), fresh' = CLIENTS.mapBy(_ => false), accepted' = accepted,
  }
  action powerLoss = all {
    up' = false, visible' = stable, stable' = stable,
    owners' = KEYS.mapBy(_ => ""), phase' = CLIENTS.mapBy(_ => Idle),
    selected' = CLIENTS.mapBy(_ => "k1"), fresh' = CLIENTS.mapBy(_ => false), accepted' = accepted,
  }
  action recover = all { not(up), up' = true, keepStores, keepClients, accepted' = accepted }
  action step = any {
    { nondet c = CLIENTS.oneOf()
      nondet k = KEYS.oneOf()
      begin(c, k) },
    { nondet c = CLIENTS.oneOf()
      writeRequest(c) },
    { nondet c = CLIENTS.oneOf()
      writeOutbox(c) },
    { nondet c = CLIENTS.oneOf()
      commit(c) },
    { nondet c = CLIENTS.oneOf()
      respond(c) },
    flush, processCrash, powerLoss, recover,
  }
  val atomicVisibility = KEYS.forall(k => {
    val v = visible.get(k)
    val d = stable.get(k)
    v.requests == v.events and (v.saved == (v.events == 1)) and
    d.requests == d.events and (d.saved == (d.events == 1))
  })
  val oneRequestPerKey = KEYS.forall(k => visible.get(k).requests <= 1 and stable.get(k).requests <= 1)
  val acceptedSurvives = accepted.forall(k => {
    val r = visible.get(k)
    r.saved and r.requests == 1 and r.events == 1
  })
  val safety = atomicVisibility and oneRequestPerKey and acceptedSurvives
}
module outboxOk {
  import apiOutbox(ATOMIC_OUTBOX = true, SYNC_RESPONSE = true).*

  run concurrentKeysTest = init.then(begin("c1", "k1")).then(begin("c2", "k2"))
    .then(writeRequest("c1")).then(writeRequest("c2"))
    .then(writeOutbox("c2")).then(commit("c2")).then(respond("c2"))
    .then(processCrash).then(recover)
    .expect(safety and visible.get("k1").requests == 0 and visible.get("k2").events == 1)
}
module outboxSplitCommit {
  import apiOutbox(ATOMIC_OUTBOX = false, SYNC_RESPONSE = true).*
}
module outboxAsyncResponse {
  import apiOutbox(ATOMIC_OUTBOX = true, SYNC_RESPONSE = false).*
}
