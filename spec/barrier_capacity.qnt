/**
 * Three store barriers, one VM slot, and an unbounded stream of ordinary
 * calls on the resident store a (start/finish can cycle forever). Since the
 * v0.1.0 audit (S-02) each store has its own admission turn: a barrier holds
 * its own store's turn, not the host's, so barriers of different stores run
 * at once. Capacity stays host-wide: a boot takes a free slot in one step
 * (host.lock, briefly). A barrier whose store needs the slot evicts the
 * resident store under that store's own turn: it queues on the victim's turn,
 * waits for the calls already admitted there, and new calls on the victim
 * cannot overtake it. Taking the victim's turn reserves the victim's slot for
 * the evicting barrier (RESERVE): no other boot takes it once the victim is
 * stopped, and the barrier's boot or its release ends the reservation. A
 * temporary VM releases its slot when its fence is acknowledged.
 *
 * Progress assumes available stores/SQL, workers eventually scheduled, finite
 * admitted callbacks, and replayable guest computation on forced eviction.
 * Worker crash/retry, unbounded barrier creation, wall-clock deadlines and the
 * complete request/notification service are not modeled by this component.
 * The choice of a victim among several is not modeled either: one slot.
 */
module barrierCapacity {
  const PRIORITY: bool
  const RECLAIM: bool
  const RESERVE: bool
  pure val STORES = Set("a", "b", "c")
  pure val SLOTS = 1
  // stage of each store's barrier: 0 queued, 1 holds its store's turn,
  // 2 its store's VM runs, 3 fence committed, 4 acknowledged.
  type State = { stage: str -> int, resident: Set[str], temporary: Set[str],
                 ordinary: bool, waits: str -> str, evicts: str -> str, reserved: str -> str,
                 fences: Set[str], acked: Set[str] }
  var s: State
  action init = s' = { stage: STORES.mapBy(x => 0), resident: Set("a"), temporary: Set(),
                       ordinary: true, waits: STORES.mapBy(x => ""), evicts: STORES.mapBy(x => ""),
                       reserved: STORES.mapBy(x => ""), fences: Set(), acked: Set() }
  // Who holds store v's turn exclusively: its own barrier, or an evictor.
  def ownTurn(v: str): bool = s.stage.get(v) >= 1 and s.stage.get(v) <= 3
  def evicted(v: str): bool = STORES.exists(x => s.evicts.get(x) == v)
  def exclusive(v: str): bool = ownTurn(v) or evicted(v)
  // An exclusive caller queued on v's turn, ahead of new ordinary calls.
  def queuedOn(v: str): bool = s.stage.get(v) == 0 or STORES.exists(x => s.waits.get(x) == v)
  // Ordinary calls of the resident store a share a's turn.
  def turnFree(v: str): bool = not(exclusive(v)) and (v != "a" or not(s.ordinary))
  // The slots reserved by evictions whose victim is stopped, but by x's own.
  def heldFor(x: str): int = STORES.filter(y => y != x and s.reserved.get(y) != "" and not(s.resident.contains(s.reserved.get(y)))).size()
  def freeFor(x: str): bool = s.resident.size() + heldFor(x) < SLOTS

  action ordinaryStart = all {
    not(s.ordinary), not(exclusive("a")), if (PRIORITY) not(queuedOn("a")) else true,
    s.resident.contains("a") or freeFor("a"),
    s' = { ...s, ordinary: true, resident: s.resident.union(Set("a")) },
  }
  action ordinaryFinish = all { s.ordinary, s' = { ...s, ordinary: false } }
  action acquire(x: str): bool = all {
    s.stage.get(x) == 0, turnFree(x),
    s' = { ...s, stage: s.stage.set(x, 1) },
  }
  action reuse(x: str): bool = all {
    s.stage.get(x) == 1, s.resident.contains(x),
    s' = { ...s, stage: s.stage.set(x, 2) },
  }
  action boot(x: str): bool = all {
    s.stage.get(x) == 1, not(s.resident.contains(x)), freeFor(x), s.waits.get(x) == "", s.evicts.get(x) == "",
    s' = { ...s, stage: s.stage.set(x, 2), resident: s.resident.union(Set(x)), temporary: s.temporary.union(Set(x)),
           reserved: s.reserved.set(x, "") },
  }
  // x's barrier queues on the resident v's turn to stop it for the slot.
  action queueEviction(x: str, v: str): bool = all {
    RECLAIM, s.stage.get(x) == 1, not(s.resident.contains(x)), not(freeFor(x)),
    s.resident.contains(v), v != x, s.waits.get(x) == "", s.evicts.get(x) == "", s.reserved.get(x) == "",
    s' = { ...s, waits: s.waits.set(x, v) },
  }
  // Holding v's turn, x reserves v's slot, unless v stopped meanwhile or
  // another eviction claimed it; then x gives up and looks again.
  action takeEviction(x: str): bool = all {
    s.waits.get(x) != "", turnFree(s.waits.get(x)),
    val v = s.waits.get(x)
    if (not(s.resident.contains(v)) or RESERVE and STORES.exists(y => y != x and s.reserved.get(y) == v))
      s' = { ...s, waits: s.waits.set(x, "") }
    else
      s' = { ...s, waits: s.waits.set(x, ""), evicts: s.evicts.set(x, v),
             reserved: if (RESERVE) s.reserved.set(x, v) else s.reserved },
  }
  // The victim's VM stops and its turn is released; a VM gone meanwhile
  // needs no stop.
  action evict(x: str): bool = all {
    s.evicts.get(x) != "",
    val v = s.evicts.get(x)
    s' = { ...s, evicts: s.evicts.set(x, ""), resident: s.resident.exclude(Set(v)), temporary: s.temporary.exclude(Set(v)) },
  }
  action fenceCommit(x: str): bool = all {
    s.stage.get(x) == 2, s.resident.contains(x),
    s' = { ...s, stage: s.stage.set(x, 3), fences: s.fences.union(Set(x)) },
  }
  action release(x: str): bool = all {
    s.stage.get(x) == 3,
    s' = { ...s, stage: s.stage.set(x, 4), acked: s.acked.union(Set(x)), reserved: s.reserved.set(x, ""),
           resident: if (s.temporary.contains(x)) s.resident.exclude(Set(x)) else s.resident,
           temporary: s.temporary.exclude(Set(x)) },
  }
  action step = any {
    ordinaryStart, ordinaryFinish,
    nondet x = STORES.oneOf()
    nondet v = STORES.oneOf()
    any { acquire(x), reuse(x), boot(x), queueEviction(x, v), takeEviction(x), evict(x), fenceCommit(x), release(x) },
    s' = s,
  }
  // A store's turn has one exclusive holder, never beside ordinary calls on
  // it; the slots, running or reserved, are never over-committed; no two
  // evictions claim one victim; a fence is acknowledged only once committed.
  val safety = s.acked.subseteq(s.fences) and s.resident.size() + heldFor("") <= SLOTS
    and STORES.forall(v => not(ownTurn(v) and evicted(v)))
    and STORES.forall(v => STORES.forall(x => STORES.forall(y => x != y and s.evicts.get(x) == v implies s.evicts.get(y) != v)))
    and STORES.forall(x => STORES.forall(y => x != y and s.reserved.get(x) != "" implies s.reserved.get(y) != s.reserved.get(x)))
    and (s.ordinary implies not(exclusive("a")))
    and s.temporary.subseteq(s.resident)
  temporal fair = ordinaryFinish.weakFair(s) and STORES.forall(x => acquire(x).weakFair(s) and reuse(x).weakFair(s)
    and boot(x).weakFair(s) and takeEviction(x).weakFair(s) and evict(x).weakFair(s) and fenceCommit(x).weakFair(s)
    and release(x).weakFair(s) and STORES.forall(v => queueEviction(x, v).weakFair(s)))
  temporal progress = fair implies eventually(s.acked == STORES)
}
module barrierCapacityOk {
  import barrierCapacity(PRIORITY = true, RECLAIM = true, RESERVE = true).*
  run priorityTest = init.then(ordinaryFinish).then(ordinaryStart.fail())
  run threeStoresOneSlotTest = init.then(ordinaryFinish).then(acquire("b")).then(queueEviction("b", "a")).then(takeEviction("b"))
    .then(evict("b")).then(boot("b")).then(fenceCommit("b")).then(release("b"))
    .then(acquire("c")).then(boot("c")).then(fenceCommit("c")).then(release("c"))
    .then(acquire("a")).then(boot("a")).then(fenceCommit("a")).then(release("a"))
    .expect(safety and s.acked == STORES and s.resident == Set())
  // Barriers of different stores hold their own turns at once (S-02).
  run concurrentBarriersTest = init.then(acquire("b")).then(acquire("c"))
    .expect(safety and ownTurn("b") and ownTurn("c") and s.ordinary)
  // An eviction waits for the calls admitted on its victim; new calls on the
  // victim wait behind it.
  run evictionWaitsForAdmittedCallsTest = init.then(acquire("b")).then(queueEviction("b", "a"))
    .expect(s.ordinary and not(turnFree("a")))
    .then(ordinaryFinish)
    .expect(turnFree("a") and queuedOn("a"))
    .then(takeEviction("b")).then(evict("b")).then(boot("b"))
    .expect(safety and s.resident == Set("b") and not(s.ordinary))
  // Once a's own barrier is done, ordinary calls on a may start again; the
  // slot b's eviction freed stays b's, so they cannot boot a into it.
  run evictedSlotStaysTheEvictorsTest = init.then(ordinaryFinish).then(acquire("a")).then(reuse("a"))
    .then(fenceCommit("a")).then(release("a")).then(ordinaryStart)
    .then(acquire("b")).then(queueEviction("b", "a")).then(ordinaryFinish).then(takeEviction("b")).then(evict("b"))
    .expect(safety and not(freeFor("a")) and freeFor("b") and not(queuedOn("a")))
    .then(ordinaryStart.fail())
}
module barrierCapacityNoPriority {
  import barrierCapacity(PRIORITY = false, RECLAIM = true, RESERVE = true).*
}
module barrierCapacityNoReclaim {
  import barrierCapacity(PRIORITY = true, RECLAIM = false, RESERVE = true).*
}
module barrierCapacityNoReservation {
  import barrierCapacity(PRIORITY = true, RECLAIM = true, RESERVE = false).*
}
