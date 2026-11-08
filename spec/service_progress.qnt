/** P3: recurring arrivals through a finite set of reusable request slots.
 * A slot is recycled only after both observation and terminal notification;
 * real UUIDs and old RPCs must NOT be recycled this way. This is a progress
 * abstraction, not a proved refinement of P1/P2. Capacity is one execution VM;
 * barriers reserve that capacity ahead of new callbacks. Recovering a store
 * presupposes P2's available recovery data and current independent authority.
 */
module serviceProgress {
  const REQUESTS: Set[int]
  const STORES: Set[int]
  const PRIORITY: bool
  const SCHEDULED: bool
  const RECOVERY: bool
  const OUTBOX: bool
  const RELIABLE: bool
  const ALLOW_DELETE: bool
  pure val MAX_ATTEMPTS = 2
  type RequestId = int
  type Stage = Vacant | Accepted | Executing | Closing | Terminal | Observable
  type Delivery = Uncreated | Pending | RetiringDead | RetiringCancelled | Acked | Dead | Cancelled
  type Result = NoResult | Success | Aborted
  type Job = { stage: Stage, needsFence: bool, barriers: Set[int],
    notificationQueued: bool, effectCommitted: bool, inbox: bool,
    delivery: Delivery, attempts: int, result: Result, cooperative: bool }
  type State = { jobs: RequestId -> Job, admissionQueue: List[RequestId],
    workQueue: List[RequestId], notificationQueue: List[RequestId],
    running: Set[RequestId], available: Set[int], workerUp: bool,
    authorityUp: bool, stable: bool, taggedAccepted: bool, taggedObserved: bool,
    deletionPending: bool, deleted: bool, arrivalParity: bool }
  var s: State
  pure val emptyJob: Job = { stage: Vacant, needsFence: false, barriers: Set(),
    notificationQueued: false, effectCommitted: false, inbox: false,
    delivery: Uncreated, attempts: 0, result: NoResult, cooperative: false }
  pure val initialState: State = { jobs: REQUESTS.mapBy(_ => emptyJob),
    admissionQueue: List(), workQueue: List(), notificationQueue: List(),
    running: Set(), available: STORES, workerUp: true, authorityUp: true,
    stable: false, taggedAccepted: false, taggedObserved: false,
    deletionPending: false, deleted: false, arrivalParity: false }
  action init = s' = initialState
  pure def destination(i: int): int = if (i == 0) 0 else 1
  pure def queued(q: List[int], i: int): bool = q.indices().exists(k => q[k] == i)
  pure def unique(q: List[int]): bool = q.indices().forall(k => q.indices().forall(j => k == j or q[k] != q[j]))
  pure def atHead(q: List[int], i: int): bool = q.length() > 0 and q.head() == i
  def active(i: int): bool = Set(Accepted, Executing, Closing).contains(s.jobs.get(i).stage)
  def terminal(i: int): bool = Set(Terminal, Observable).contains(s.jobs.get(i).stage)
  def notified(i: int): bool = Set(Acked, Dead, Cancelled).contains(s.jobs.get(i).delivery)
  def eligible(i: int): bool = destination(i) != 0 or not(s.deletionPending or s.deleted)
  val online = s.workerUp and s.authorityUp
  def retiring(i: int): bool = Set(RetiringDead, RetiringCancelled).contains(s.jobs.get(i).delivery)
  val barriersPending = REQUESTS.exists(i => s.jobs.get(i).stage == Closing or retiring(i))
  action arrive(i: int, cooperative: bool): bool = all {
    online, s.jobs.get(i).stage == Vacant, eligible(i),
    s' = { ...s, jobs: s.jobs.set(i, { ...emptyJob, stage: Accepted, cooperative: cooperative }),
      admissionQueue: s.admissionQueue.append(i), taggedAccepted: s.taggedAccepted or i == 0,
      arrivalParity: not(s.arrivalParity) },
  }
  action admit(i: int): bool = all {
    online, atHead(s.admissionQueue, i), s.running == Set(),
    not(PRIORITY and barriersPending), eligible(i),
    s' = { ...s, jobs: s.jobs.set(i, { ...s.jobs.get(i), stage: Executing }),
      admissionQueue: s.admissionQueue.tail(), workQueue: s.workQueue.append(i), running: Set(i) },
  }
  pure def finished(st: State, i: int, result: Result): State = {
    ...st, jobs: st.jobs.set(i, { ...st.jobs.get(i), stage: Terminal, inbox: true,
      notificationQueued: OUTBOX, delivery: Pending, result: result,
      effectCommitted: result == Success }),
    running: st.running.exclude(Set(i)), workQueue: st.workQueue.select(j => j != i),
    notificationQueue: if (OUTBOX) st.notificationQueue.append(i) else st.notificationQueue,
  }
  // Abstracts successful local commit + final SQL transaction. P1 checks their
  // separate safety boundaries. A hung callback cannot take this action.
  action complete(i: int): bool = all {
    online, s.jobs.get(i).stage == Executing, s.jobs.get(i).cooperative,
    eligible(i), s.available.contains(destination(i)), s' = finished(s, i, Success),
  }
  pure def closing(st: State, i: int): State = { ...st,
    jobs: st.jobs.set(i, { ...st.jobs.get(i), stage: Closing, needsFence: true }),
    admissionQueue: st.admissionQueue.select(j => j != i), workQueue: st.workQueue.select(j => j != i) }
  // Fair deadline processing is an explicit obligation, not fair completion of
  // arbitrary user computation. A running callback is neutralized separately.
  action deadline(i: int): bool = all {
    online, Set(Accepted, Executing).contains(s.jobs.get(i).stage), s' = closing(s, i),
  }
  action closeDeleted(i: int): bool = all {
    online, s.deletionPending, destination(i) == 0,
    Set(Accepted, Executing).contains(s.jobs.get(i).stage), s' = closing(s, i),
  }
  action releaseExecution(i: int): bool = all {
    online, s.jobs.get(i).stage == Closing, s.running.contains(i),
    s' = { ...s, running: s.running.exclude(Set(i)) },
  }
  action fence(i: int, a: int): bool = all {
    online, s.jobs.get(i).stage == Closing, s.running == Set(),
    s.available.contains(a), not(s.jobs.get(i).barriers.contains(a)),
    s' = { ...s, jobs: s.jobs.set(i, { ...s.jobs.get(i), barriers: s.jobs.get(i).barriers.union(Set(a)) }) },
  }
  action commitClose(i: int): bool = all {
    online, s.jobs.get(i).stage == Closing, s.jobs.get(i).barriers == STORES,
    not(s.running.contains(i)), s' = finished(s, i, Aborted),
  }
  action requestDelete = all { ALLOW_DELETE, online, not(s.deletionPending or s.deleted),
    s' = { ...s, deletionPending: true } }
  action finishDelete = all { online, s.deletionPending,
    REQUESTS.forall(i => destination(i) != 0 or not(active(i))),
    s' = { ...s, deletionPending: false, deleted: true } }
  pure def delivered(st: State, i: int, outcome: Delivery, attempts: int): State = {
    ...st, jobs: st.jobs.set(i, { ...st.jobs.get(i), delivery: outcome,
      notificationQueued: Set(Pending, RetiringDead, RetiringCancelled).contains(outcome), attempts: attempts }),
    notificationQueue: if (Set(Pending, RetiringDead, RetiringCancelled).contains(outcome)) st.notificationQueue else st.notificationQueue.tail() }
  action notify(i: int, success: bool): bool = all {
    online, atHead(s.notificationQueue, i), s.jobs.get(i).delivery == Pending,
    eligible(i), s.available.contains(destination(i)),
    not(RELIABLE) or success,
    s' = delivered(s, i, if (success) Acked else if (s.jobs.get(i).attempts + 1 >= MAX_ATTEMPTS) RetiringDead else Pending,
      s.jobs.get(i).attempts + 1),
  }
  action cancelNotification(i: int): bool = all {
    online, atHead(s.notificationQueue, i), s.jobs.get(i).delivery == Pending, not(eligible(i)),
    s' = delivered(s, i, RetiringCancelled, s.jobs.get(i).attempts),
  }
  // Macrostep: reserve a maintenance slot, commit the event fence, record its
  // current ACK, retire the outbox head, release the slot. P1 separates commits.
  action retireNotification(i: int): bool = all {
    online, atHead(s.notificationQueue, i), retiring(i), s.running == Set(),
    s.available.contains(destination(i)),
    s' = delivered(s, i, if (s.jobs.get(i).delivery == RetiringDead) Dead else Cancelled, s.jobs.get(i).attempts),
  }
  // Authorised user polling is distinct from harness notification. This user
  // account survives deletion of its execution agent in the abstraction.
  action observe(i: int): bool = all {
    s.authorityUp, s.jobs.get(i).stage == Terminal, s.jobs.get(i).inbox,
    s' = { ...s, jobs: s.jobs.set(i, { ...s.jobs.get(i), stage: Observable }),
      taggedObserved: s.taggedObserved or i == 0 },
  }
  action recycle(i: int): bool = all {
    i != 0, s.jobs.get(i).stage == Observable, notified(i),
    s' = { ...s, jobs: s.jobs.set(i, emptyJob) },
  }
  action crashWorker = all { not(s.stable), s.workerUp, s' = { ...s, workerUp: false } }
  action recoverWorker = all { not(s.workerUp), s' = { ...s, workerUp: true } }
  action loseAuthority = all { not(s.stable), s.authorityUp, s' = { ...s, authorityUp: false } }
  action recoverAuthority = all { not(s.authorityUp), s' = { ...s, authorityUp: true } }
  action loseStore(a: int): bool = all { not(s.stable), s.available.contains(a), s' = { ...s, available: s.available.exclude(Set(a)) } }
  action recoverStore(a: int): bool = all { not(s.available.contains(a)), s.authorityUp,
    s' = { ...s, available: s.available.union(Set(a)) } }
  action stabilize = all { not(s.stable), s' = { ...s, stable: true } }
  action attempt(i: int): bool = { nondet success = Set(false, true).oneOf(); notify(i, success) }
  action step = any {
    nondet i = REQUESTS.oneOf()
    nondet a = STORES.oneOf()
    nondet cooperative = Set(false, true).oneOf()
    any { arrive(i, cooperative), admit(i), complete(i), deadline(i), closeDeleted(i),
      releaseExecution(i), fence(i, a), commitClose(i), attempt(i), cancelNotification(i), retireNotification(i), observe(i), recycle(i) },
    nondet a = STORES.oneOf()
    any { loseStore(a), recoverStore(a) },
    requestDelete, finishDelete, crashWorker, recoverWorker, loseAuthority, recoverAuthority, stabilize, s' = s,
  }
  val safety = all {
    unique(s.admissionQueue), unique(s.workQueue), unique(s.notificationQueue), s.running.size() <= 1,
    s.running.forall(i => Set(Executing, Closing).contains(s.jobs.get(i).stage)),
    REQUESTS.forall(i => all {
      queued(s.admissionQueue, i) == (s.jobs.get(i).stage == Accepted),
      queued(s.workQueue, i) == (s.jobs.get(i).stage == Executing),
      queued(s.notificationQueue, i) == s.jobs.get(i).notificationQueued,
      s.jobs.get(i).notificationQueued implies (terminal(i) and (s.jobs.get(i).delivery == Pending or retiring(i))),
      terminal(i) == s.jobs.get(i).inbox,
      s.jobs.get(i).result == Aborted implies s.jobs.get(i).barriers == STORES,
      s.jobs.get(i).result == Success implies s.jobs.get(i).effectCommitted,
      s.jobs.get(i).attempts <= MAX_ATTEMPTS,
      s.deleted implies (destination(i) != 0 or not(active(i))),
    }),
  }
  temporal scheduling = if (SCHEDULED) REQUESTS.forall(i =>
    admit(i).weakFair(s) and complete(i).weakFair(s) and deadline(i).weakFair(s)
    and closeDeleted(i).weakFair(s) and releaseExecution(i).weakFair(s)
    and STORES.forall(a => fence(i,a).weakFair(s)) and commitClose(i).weakFair(s)
    and attempt(i).weakFair(s) and cancelNotification(i).weakFair(s) and retireNotification(i).weakFair(s)) and finishDelete.weakFair(s) else true
  temporal recovery = if (RECOVERY) recoverWorker.weakFair(s) and recoverAuthority.weakFair(s)
    and STORES.forall(a => recoverStore(a).weakFair(s)) else true
  temporal assumptions = eventually(s.stable) and scheduling and recovery
  temporal terminates = REQUESTS.forall(i => always(active(i) implies eventually(terminal(i))))
  temporal outcomeAvailable = REQUESTS.forall(i => always(active(i) implies eventually(s.jobs.get(i).inbox)))
  temporal notificationTerminates = REQUESTS.forall(i => always(active(i) implies eventually(notified(i))))
  temporal progress = assumptions implies (terminates and outcomeAvailable and notificationTerminates)
  temporal observed = (assumptions and REQUESTS.forall(i => observe(i).weakFair(s))) implies
    always(s.taggedAccepted implies eventually(s.taggedObserved))
  temporal deletionCompletes = assumptions implies always(s.deletionPending implies eventually(s.deleted))
  // Only the reliable, nondeleting instance promises actual successful receipt.
  temporal successfulDelivery = assumptions implies REQUESTS.forall(i =>
    always(active(i) implies eventually(s.jobs.get(i).delivery == Acked)))
  // Negative property: there ARE fair executions with infinitely many arrivals.
  temporal arrivalsEventuallyStop = assumptions implies
    (eventually(always(s.arrivalParity)) or eventually(always(not(s.arrivalParity))))
}
module serviceProgressOk {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).*
}
module serviceProgressSmall {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).*
}
module serviceProgressReliable {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=true, ALLOW_DELETE=false).*
}
module serviceProgressNoPriority {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=false,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).*
}
module serviceProgressNoScheduling {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=false, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).*
}
module serviceProgressNoRecovery {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=false, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).*
}
module serviceProgressNoOutbox {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=false, RELIABLE=false, ALLOW_DELETE=true).*
}
