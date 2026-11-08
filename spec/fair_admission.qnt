/**
 * A tagged caller remains queued; two other clients may issue infinitely many
 * calls. Entries remain in the queue while active. Leading readers share the
 * kernel lock; an exclusive turn needs an empty active set. A dead owner's
 * released kernel lock is abstracted by alive=false, never by a timeout.
 * Finite three-client component, NOT a parametric proof or Go refinement.
 */
module fairAdmission {
  const WATCHED_SHARED: bool
  const POLICY: str
  const ALLOW_CRASH: bool
  pure val CLIENTS = Set(1,2,3)
  pure def shared(i: int): bool = if (i == 1) WATCHED_SHARED else i == 2
  type State = { queue: List[int], alive: Set[int], active: Set[int], done: bool }
  var s: State
  action init = {
    val predecessor = if (WATCHED_SHARED) 3 else 2
    s' = { queue: List(predecessor,1), alive: Set(predecessor,1), active: Set(), done: false }
  }
  def queued(i: int): bool = s.queue.indices().exists(n => s.queue[n] == i)
  def fifoEligible(i: int): bool = s.queue.indices().exists(n => s.queue[n] == i
    and 0.to(n-1).forall(k => shared(i) and shared(s.queue[k])))
  def eligible(i: int): bool = if (POLICY == "writers") {
    if (shared(i)) fifoEligible(i) and not(s.queue.indices().exists(n => not(shared(s.queue[n]))))
    else s.queue.indices().exists(n => s.queue[n] == i and 0.to(n-1).forall(k => shared(s.queue[k])))
  } else if (POLICY == "readers" and shared(i)) queued(i) else fifoEligible(i)
  action enqueue(i: int): bool = all {
    i != 1, not(queued(i)),
    s' = { ...s, queue: s.queue.append(i), alive: s.alive.union(Set(i)) },
  }
  action admit(i: int): bool = all {
    s.alive.contains(i), not(s.active.contains(i)), eligible(i),
    if (shared(i)) s.active.forall(j => shared(j)) else s.active == Set(),
    s' = { ...s, active: s.active.union(Set(i)) },
  }
  action finish(i: int): bool = all {
    s.active.contains(i),
    s' = { ...s, queue: s.queue.select(j => j != i), alive: s.alive.exclude(Set(i)),
      active: s.active.exclude(Set(i)), done: s.done or i == 1 },
  }
  action crash(i: int): bool = all {
    ALLOW_CRASH, i != 1, s.alive.contains(i),
    s' = { ...s, alive: s.alive.exclude(Set(i)), active: s.active.exclude(Set(i)) },
  }
  action prune = all {
    s.queue.indices().exists(n => not(s.alive.contains(s.queue[n]))),
    s' = { ...s, queue: s.queue.select(j => s.alive.contains(j)) },
  }
  action step = any {
    nondet i = CLIENTS.oneOf()
    any { enqueue(i), admit(i), finish(i), crash(i) },
    prune, s' = s,
  }
  val safety = s.active.subseteq(s.alive) and s.active.forall(i => queued(i))
    and (s.active.exists(i => not(shared(i))) implies s.active.size() == 1)
    and s.active.forall(i => fifoEligible(i))
  temporal fair = CLIENTS.forall(i => admit(i).weakFair(s) and finish(i).weakFair(s)) and prune.weakFair(s)
  // The watched request does not cancel. Every admitted callback terminates
  // and eligible actors/cleanup are weakly fair. No bound in real seconds.
  temporal progress = fair implies eventually(s.done)
}
module fairAdmissionShared {
  import fairAdmission(WATCHED_SHARED=true, POLICY="fifo", ALLOW_CRASH=true).*
  run noOvertakeTest = init.then(admit(3)).then(enqueue(2)).then(finish(3)).then(enqueue(3))
    .then(admit(1)).then(admit(2)).expect(safety and s.active == Set(1,2))
    .then(finish(1)).expect(s.done)
}
module fairAdmissionExclusive {
  import fairAdmission(WATCHED_SHARED=false, POLICY="fifo", ALLOW_CRASH=true).*
  run deadOwnerTest = init.then(admit(2)).then(crash(2)).then(prune)
    .then(enqueue(2)).then(admit(1)).expect(safety).then(admit(2).fail())
}
module fairAdmissionWriterPriority {
  import fairAdmission(WATCHED_SHARED=true, POLICY="writers", ALLOW_CRASH=false).*
}
module fairAdmissionReaderPriority {
  import fairAdmission(WATCHED_SHARED=false, POLICY="readers", ALLOW_CRASH=false).*
}
