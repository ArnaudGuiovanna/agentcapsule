/**
 * Local transactional effects: SQL statements, commit, flush, ACK and recovery
 * are separate transitions. This models SQLite's contract, not its pager/WAL.
 * `visible` survives a process crash; only `stable` survives a power loss.
 * A successful synchronous commit includes a stable WAL commit record; it does
 * not require the main database pages to have been checkpointed.
 * ACK history is observed by an independent client and survives server crashes.
 * Effects are local database mutations, never HTTP calls or arbitrary files.
 */
module durableStore {
  const CLIENTS: Set[str]
  const EVENTS: Set[int]
  const ATOMIC_PAIR: bool
  const MARKER_FIRST: bool
  const SYNC_COMMIT: bool
  const SERIALIZED_READ: bool

  type Phase = Idle | Read | Staged | Committed
  type Store = { seen: Set[int], effects: int -> int }
  var up: bool
  var visible: Store
  var stable: Store
  var owner: str
  var phase: str -> Phase
  var selected: str -> int
  var fresh: str -> bool
  var acknowledged: Set[int]
  // Count 2 represents two or more applications, already a safety violation.
  pure def increment(n: int): int = if (n < 2) n + 1 else 2
  pure val emptyStore = { seen: Set(), effects: EVENTS.mapBy(_ => 0) }
  action init = all {
    up' = true, visible' = emptyStore, stable' = emptyStore, owner' = "",
    phase' = CLIENTS.mapBy(_ => Idle), selected' = CLIENTS.mapBy(_ => 0),
    fresh' = CLIENTS.mapBy(_ => false), acknowledged' = Set(),
  }
  action keepClients = all { phase' = phase, selected' = selected, fresh' = fresh }
  action keepStores = all { visible' = visible, stable' = stable }

  action begin(c: str, e: int): bool = all {
    up, phase.get(c) == Idle,
    if (SERIALIZED_READ) owner == "" else true,
    owner' = if (SERIALIZED_READ) c else owner,
    phase' = phase.set(c, Read), selected' = selected.set(c, e),
    fresh' = fresh.set(c, not(visible.seen.contains(e))),
    keepStores, up' = up, acknowledged' = acknowledged,
  }
  // Correct: SQL changes are uncommitted and invisible outside this transaction.
  // Broken: commit the effect in its own transaction, then write its marker later.
  action stage(c: str): bool = {
    val e = selected.get(c)
    val effectOnly = { ...visible,
      effects: visible.effects.set(e, increment(visible.effects.get(e))) }
    val partial = if (MARKER_FIRST) { ...visible, seen: visible.seen.union(Set(e)) } else effectOnly
    all {
      up, phase.get(c) == Read,
      visible' = if (not(ATOMIC_PAIR) and fresh.get(c)) partial else visible,
      stable' = if (not(ATOMIC_PAIR) and fresh.get(c)) partial else stable,
      phase' = phase.set(c, Staged), selected' = selected, fresh' = fresh,
      owner' = owner, up' = up, acknowledged' = acknowledged,
    }
  }
  action commit(c: str): bool = {
    val e = selected.get(c)
    val applied = (ATOMIC_PAIR or MARKER_FIRST) and fresh.get(c)
    val nextStore = { seen: visible.seen.union(Set(e)),
      effects: if (applied) visible.effects.set(e, increment(visible.effects.get(e)))
               else visible.effects }
    all {
      up, phase.get(c) == Staged,
      visible' = nextStore, stable' = if (SYNC_COMMIT) nextStore else stable,
      phase' = phase.set(c, Committed), selected' = selected, fresh' = fresh,
      owner' = if (owner == c) "" else owner,
      up' = up, acknowledged' = acknowledged,
    }
  }
  action ack(c: str): bool = all {
    up, phase.get(c) == Committed,
    acknowledged' = acknowledged.union(Set(selected.get(c))),
    phase' = phase.set(c, Idle), selected' = selected, fresh' = fresh,
    keepStores, owner' = owner, up' = up,
  }
  action flush = all {
    up, stable' = visible, visible' = visible, keepClients,
    up' = up, owner' = owner, acknowledged' = acknowledged,
  }
  action processCrash = all {
    up, up' = false, owner' = "", keepStores,
    phase' = CLIENTS.mapBy(_ => Idle), selected' = CLIENTS.mapBy(_ => 0),
    fresh' = CLIENTS.mapBy(_ => false), acknowledged' = acknowledged,
  }
  action powerLoss = all {
    up' = false, owner' = "", visible' = stable, stable' = stable,
    phase' = CLIENTS.mapBy(_ => Idle), selected' = CLIENTS.mapBy(_ => 0),
    fresh' = CLIENTS.mapBy(_ => false), acknowledged' = acknowledged,
  }
  action recover = all {
    not(up), up' = true, owner' = owner, keepStores, keepClients,
    acknowledged' = acknowledged,
  }
  action step = any {
    { nondet c = CLIENTS.oneOf()
      nondet e = EVENTS.oneOf()
      begin(c, e) },
    { nondet c = CLIENTS.oneOf()
      stage(c) },
    { nondet c = CLIENTS.oneOf()
      commit(c) },
    { nondet c = CLIENTS.oneOf()
      ack(c) },
    flush, processCrash, powerLoss, recover,
  }
  val effectOnce = EVENTS.forall(e => visible.effects.get(e) <= 1 and stable.effects.get(e) <= 1)
  val pairAtomicity = EVENTS.forall(e =>
    (visible.seen.contains(e) == (visible.effects.get(e) == 1)) and
    (stable.seen.contains(e) == (stable.effects.get(e) == 1)))
  val ackSurvivesCrashes = acknowledged.forall(e =>
    visible.seen.contains(e) and visible.effects.get(e) == 1)
  val safety = effectOnce and pairAtomicity and ackSurvivesCrashes
}

module durabilityOk {
  import durableStore(CLIENTS = Set("c1", "c2"), EVENTS = Set(0, 1),
    ATOMIC_PAIR = true, MARKER_FIRST = false, SYNC_COMMIT = true, SERIALIZED_READ = true).*

  run rollbackBeforeCommitTest = init.then(begin("c1", 0)).then(stage("c1"))
    .then(processCrash).then(recover)
    .expect(safety and visible.effects.get(0) == 0)

  run lostAckRetryTest = init.then(begin("c1", 0)).then(stage("c1"))
    .then(commit("c1")).then(powerLoss).then(recover)
    .then(begin("c2", 0)).then(stage("c2")).then(commit("c2")).then(ack("c2"))
    .expect(safety and visible.effects.get(0) == 1 and acknowledged.contains(0))

  run ackThenPowerLossTest = init.then(begin("c1", 0)).then(stage("c1"))
    .then(commit("c1")).then(ack("c1")).then(powerLoss).then(recover)
    .expect(safety and visible.effects.get(0) == 1)
}
module durabilitySplitCommit {
  import durableStore(CLIENTS = Set("c1", "c2"), EVENTS = Set(0),
    ATOMIC_PAIR = false, MARKER_FIRST = false, SYNC_COMMIT = true, SERIALIZED_READ = true).*
}
module durabilityAsyncCommit {
  import durableStore(CLIENTS = Set("c1", "c2"), EVENTS = Set(0),
    ATOMIC_PAIR = true, MARKER_FIRST = false, SYNC_COMMIT = false, SERIALIZED_READ = true).*
}
module durabilityRacyRead {
  import durableStore(CLIENTS = Set("c1", "c2"), EVENTS = Set(0),
    ATOMIC_PAIR = true, MARKER_FIRST = false, SYNC_COMMIT = true, SERIALIZED_READ = false).*
}
module durabilityMarkerFirst {
  import durableStore(CLIENTS = Set("c1", "c2"), EVENTS = Set(0),
    ATOMIC_PAIR = false, MARKER_FIRST = true, SYNC_COMMIT = true, SERIALIZED_READ = true).*
}
