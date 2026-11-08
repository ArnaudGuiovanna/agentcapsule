/**
 * Three already-queued store barriers, one VM slot, and an unbounded stream of
 * ordinary calls (start/finish can cycle forever). The queue owns admission until
 * the fence commits and a temporary VM releases its slot. Ordinary callbacks
 * already admitted must finish; new callbacks cannot overtake a queued barrier.
 *
 * Progress assumes available stores/SQL, workers eventually scheduled, finite
 * admitted callbacks, and replayable guest computation on forced eviction.
 * Worker crash/retry, unbounded barrier creation, wall-clock deadlines and the
 * complete request/notification service are not modeled by this component.
 */
module barrierCapacity {
  const PRIORITY: bool
  const RECLAIM: bool
  type State = { queue: List[str], owner: str, resident: str, ordinary: bool,
                 stage: int, temporary: bool, fences: Set[str], acked: Set[str] }
  var s: State
  action init = s' = { queue: List("b","c","a"), owner: "", resident: "a",
                       ordinary: true, stage: 0, temporary: false,
                       fences: Set(), acked: Set() }
  val queueHead = if (s.queue.length() > 0) s.queue.head() else ""
  action ordinaryStart = all {
    s.owner == "", not(s.ordinary), if (PRIORITY) queueHead == "" else true,
    s' = { ...s, ordinary: true, resident: if (s.resident == "") "a" else s.resident },
  }
  action ordinaryFinish = all { s.ordinary, s' = { ...s, ordinary: false } }
  action acquire = all {
    queueHead != "", s.owner == "", not(s.ordinary),
    s' = { ...s, owner: queueHead, stage: 1, temporary: s.resident != queueHead },
  }
  action evict = all {
    RECLAIM, s.owner != "", s.stage == 1, s.resident != "", s.resident != s.owner,
    s' = { ...s, resident: "" },
  }
  action boot = all {
    s.owner != "", s.stage == 1, s.resident == "",
    s' = { ...s, resident: s.owner, stage: 2 },
  }
  action reuse = all {
    s.owner != "", s.stage == 1, s.resident == s.owner,
    s' = { ...s, stage: 2 },
  }
  action fenceCommit = all {
    s.owner != "", s.stage == 2, s.resident == s.owner,
    s' = { ...s, stage: 3, fences: s.fences.union(Set(s.owner)) },
  }
  action release = all {
    s.owner != "", s.stage == 3,
    s' = { ...s, queue: s.queue.tail(), owner: "", stage: 0, temporary: false,
           resident: if (s.temporary) "" else s.resident, acked: s.acked.union(Set(s.owner)) },
  }
  action step = any { ordinaryStart, ordinaryFinish, acquire, evict, boot, reuse, fenceCommit, release, s' = s }
  val safety = s.acked.subseteq(s.fences) and (s.ordinary implies s.owner == "")
    and (s.owner != "" implies s.owner == queueHead)
  temporal fair = ordinaryFinish.weakFair(s) and acquire.weakFair(s) and evict.weakFair(s)
    and boot.weakFair(s) and reuse.weakFair(s) and fenceCommit.weakFair(s) and release.weakFair(s)
  temporal progress = fair implies eventually(s.acked == Set("a","b","c"))
}
module barrierCapacityOk {
  import barrierCapacity(PRIORITY = true, RECLAIM = true).*
  run priorityTest = init.then(ordinaryFinish).then(ordinaryStart.fail())
  run threeStoresOneSlotTest = init.then(ordinaryFinish).then(acquire).then(evict).then(boot).then(fenceCommit).then(release)
    .then(acquire).then(boot).then(fenceCommit).then(release)
    .then(acquire).then(boot).then(fenceCommit).then(release)
    .expect(safety and s.acked == Set("a","b","c") and s.resident == "")
}
module barrierCapacityNoPriority {
  import barrierCapacity(PRIORITY = false, RECLAIM = true).*
}
module barrierCapacityNoReclaim {
  import barrierCapacity(PRIORITY = true, RECLAIM = false).*
}
