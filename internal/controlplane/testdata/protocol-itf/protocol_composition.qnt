/**
 * Shared-state protocol composition: one request a→b, reply, replacement status,
 * three registered stores and two delayed RPCs. SQL claim/authorization/ACK,
 * SQLite transaction begin/commit, revocation barriers and terminal notification
 * are separate. VM replacement invalidates cached callers and in-flight channels.
 *
 * Physical death, SQL authority retirement, startup claim/launch/confirmation/
 * publication and platform SQL admission/commit are separate. Physical volume
 * exclusivity and physical absence detection still rely on host contracts. Fixed store census, one auto-approved request,
 * one replacement per store. No public API, dynamic provisioning or full refinement.
 */
module protocolComposition {
  const WAIT_ALL: bool
  const SERIALIZE: bool
  const DURABLE: bool
  const CALLER_GUARD: bool
  const OWNER_GUARD: bool
  const DEDUP: bool
  const STATUS_FREE: bool
  const FRESH_STATUS: bool
  const MAX_GEN: int
  pure val STORES = Set("a", "b", "c")
  pure val WORKERS = Set("w1", "w2")
  pure val EVENTS = Set(0,1,2) // request, private reply, content-free status
  type Boot = { gen: int, alive: bool, fenceOnly: bool, phase: str, confirmed: bool, owner: bool, retired: bool }
  type Event = { state: str, attempts: int, owner: str, lease: bool, permitted: bool, closing: bool }
  type RPC = { event: int, token: int, gen: int, stage: str }
  type FenceReply = { store: str, subject: str }
  type State = { up: bool, phase: str, sealed: bool, request: str, final: str,
    closing: bool, notified: bool, boots: str -> Boot, callers: str -> int,
    placement: str -> str, bootLease: str -> bool, api: str, apiOwner: str,
    budgets: str -> int, events: int -> Event, rpc: str -> RPC,
    fences: str -> Set[str], replies: Set[FenceReply], deleteAcks: Set[str],
    closeAcks: Set[str], retireAcks: Set[int], seen: int -> int, effects: int -> int,
    staleEffect: bool, badCaller: bool, conflictingEnvelope: bool }
  pure val emptyEvent = { state: "ABSENT", attempts: 0, owner: "", lease: false, permitted: false, closing: false }
  pure val pendingEvent = { ...emptyEvent, state: "PENDING" }
  pure val idleRPC = { event: -1, token: 0, gen: 0, stage: "IDLE" }
  var s: State
  action init = s' = { up: true, phase: "LIVE", sealed: false, request: "ABSENT", final: "",
    closing: false, notified: false,
    boots: STORES.mapBy(_ => { gen: 1, alive: true, fenceOnly: false, phase: "PUBLISHED", confirmed: true, owner: false, retired: false }),
    placement: STORES.mapBy(_ => "RUNNING"), bootLease: STORES.mapBy(_ => false), api: "IDLE", apiOwner: "",
    callers: STORES.mapBy(_ => 0), budgets: STORES.mapBy(_ => 1),
    events: EVENTS.mapBy(_ => emptyEvent), rpc: WORKERS.mapBy(_ => idleRPC),
    fences: STORES.mapBy(_ => Set()), replies: Set(), deleteAcks: Set(), closeAcks: Set(),
    retireAcks: Set(), seen: EVENTS.mapBy(_ => -1), effects: EVENTS.mapBy(_ => 0),
    staleEffect: false, badCaller: false, conflictingEnvelope: false }
  pure def dest(e: int): str = if (e == 0) "b" else "a"
  pure def eventSubject(e: int): str = if (e == 0) "event/0" else if (e == 1) "event/1" else "event/2"
  pure def identity(e: int): int = if (e == 2 and not(FRESH_STATUS)) 1 else e
  pure def subjects(e: int): Set[str] = if (e == 2 and STATUS_FREE) Set("agent/a", "event/2")
    else Set("agent/a", "agent/b", "request/0", eventSubject(e))
  def ready(a: str): bool = s.boots.get(a).alive and s.boots.get(a).phase == "PUBLISHED" and not(s.boots.get(a).fenceOnly)
  // Admission is a SQL authority check, not a physical-liveness check.
  def currentCaller(a: str): bool = s.placement.get(a) == "RUNNING" and not(s.boots.get(a).fenceOnly)
    and s.callers.get(a) == s.boots.get(a).gen
  val sqlFree = not(Set("AUTH_A","AUTH_B").contains(s.api))
  def authorityFree(a: str): bool = sqlFree or a == "c"
  val activeRequest = Set("DELIVERING","PROCESSING").contains(s.request)
  def busy(a: str): bool = WORKERS.exists(w => s.rpc.get(w).stage == "EXECUTING" and dest(s.rpc.get(w).event) == a)
  def allowed(e: int): bool = subjects(e).intersect(s.fences.get(dest(e))) == Set()
  def isHead(e: int): bool = EVENTS.forall(i => (i < e and dest(i) == dest(e)) implies s.events.get(i).state != "PENDING")

  // Authenticated frame received while the physical published boot is alive.
  // The frame may wait in the host/SQL queue after that boot dies.
  action cacheCaller(a: str): bool = all {
    s.up, s.api == "IDLE", ready(a),
    s' = { ...s, callers: s.callers.set(a, s.boots.get(a).gen),
      api: if (a == "a") "RECEIVED_A" else "RECEIVED_B" },
  }
  // Admission acquires both participant agent rows and keeps them through the
  // business commit or rollback. A physical crash cannot release SQL row locks.
  action admitSubmit(mandateOwner: str): bool = all {
    s.up, s.api == "RECEIVED_A", s.phase == "LIVE", s.request == "ABSENT",
    s.budgets.get(mandateOwner) > 0,
    if (CALLER_GUARD) currentCaller("a") else true,
    if (OWNER_GUARD) mandateOwner == "a" else true,
    s' = { ...s, api: "AUTH_A", apiOwner: mandateOwner },
  }
  action submit(mandateOwner: str): bool = all {
    s.up, s.api == "AUTH_A", s.apiOwner == mandateOwner,
    s.phase == "LIVE", s.request == "ABSENT", s.budgets.get(mandateOwner) > 0,
    s' = { ...s, request: "DELIVERING", events: s.events.set(0,pendingEvent), api: "IDLE",
      budgets: s.budgets.set(mandateOwner, s.budgets.get(mandateOwner)-1),
      badCaller: s.badCaller or not(currentCaller("a")) or mandateOwner != "a" },
  }
  action admitReply = all {
    s.up, s.api == "RECEIVED_B", s.phase == "LIVE", s.request == "PROCESSING", not(s.closing),
    if (CALLER_GUARD) currentCaller("b") else true,
    s' = { ...s, api: "AUTH_B" },
  }
  action reply = all {
    s.up, s.api == "AUTH_B", s.phase == "LIVE", s.request == "PROCESSING", not(s.closing),
    s' = { ...s, request: "REPLIED", final: "REPLIED", events: s.events.set(1,pendingEvent), api: "IDLE",
      badCaller: s.badCaller or not(currentCaller("b")) },
  }
  action abortCall = all { s.api != "IDLE", s' = { ...s, api: "IDLE" } }
  action claim(w: str, e: int): bool = {
    val event = s.events.get(e)
    all {
      s.up, sqlFree, s.rpc.get(w).stage == "IDLE", event.state == "PENDING", isHead(e),
      not(event.lease), not(event.closing), event.attempts < 2, ready(dest(e)), s.placement.get(dest(e)) == "RUNNING",
      if (e == 2) true else s.phase == "LIVE" and not(s.closing),
      s' = { ...s, events: s.events.set(e,{ ...event, attempts: event.attempts+1, owner: w, lease: true, permitted: false }),
        rpc: s.rpc.set(w,{ event: e, token: event.attempts+1, gen: s.boots.get(dest(e)).gen, stage: "CLAIMED" }) },
    }
  }
  action authorize(w: str): bool = {
    val r = s.rpc.get(w)
    val event = if (EVENTS.contains(r.event)) s.events.get(r.event) else emptyEvent
    all {
      s.up, sqlFree, r.stage == "CLAIMED", event.state == "PENDING", event.owner == w,
      event.attempts == r.token, event.lease, not(event.closing),
      if (r.event == 2) true else s.phase == "LIVE" and not(s.closing),
      s' = { ...s, events: s.events.set(r.event,{ ...event, permitted: true }),
        rpc: s.rpc.set(w,{ ...r, stage: "SENT" }) },
    }
  }
  // SQLite writer transaction owns the store until commit or VMM death.
  action beginEffect(w: str): bool = {
    val r = s.rpc.get(w)
    all {
      r.stage == "SENT", ready(dest(r.event)), s.boots.get(dest(r.event)).gen == r.gen,
      not(busy(dest(r.event))), allowed(r.event),
      s' = { ...s, rpc: s.rpc.set(w,{ ...r, stage: "EXECUTING" }) },
    }
  }
  action commitEffect(w: str): bool = {
    val r = s.rpc.get(w)
    val old = if (EVENTS.contains(r.event)) s.seen.get(identity(r.event)) else -1
    val conflict = old != -1 and old != r.event
    val apply = not(conflict) and (old == -1 or not(DEDUP))
    all {
      r.stage == "EXECUTING",
      s' = { ...s, rpc: s.rpc.set(w,{ ...r, stage: if (conflict) "FAILED" else "ACK" }),
        seen: if (apply) s.seen.set(identity(r.event),r.event) else s.seen,
        effects: if (apply) s.effects.set(r.event, s.effects.get(r.event)+1) else s.effects,
        staleEffect: s.staleEffect or (apply and r.event != 2 and (s.phase == "DELETING" or s.request == "CANCELED")),
        conflictingEnvelope: s.conflictingEnvelope or conflict },
    }
  }
  action acknowledge(w: str): bool = {
    val r = s.rpc.get(w)
    val e = if (EVENTS.contains(r.event)) s.events.get(r.event) else emptyEvent
    all {
      s.up, sqlFree, r.stage == "ACK", e.state == "PENDING", e.lease, e.owner == w,
      e.attempts == r.token, e.permitted, not(e.closing),
      if (r.event == 0) s.request == "DELIVERING" and not(s.closing) else true,
      s' = { ...s, events: s.events.set(r.event,{ ...e, state: "DELIVERED", lease: false }),
        request: if (r.event == 0) "PROCESSING" else s.request,
        notified: s.notified or r.event != 0, rpc: s.rpc.set(w,idleRPC) },
    }
  }
  action expireLease(e: int): bool = all {
    s.events.get(e).lease, s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), lease: false }) },
  }
  action loseRPC(w: str): bool = all {
    s.rpc.get(w).stage != "IDLE", s.rpc.get(w).stage != "EXECUTING",
    s' = { ...s, rpc: s.rpc.set(w,idleRPC) },
  }
  action closeRequest = all { s.up, sqlFree, activeRequest, not(s.closing), s' = { ...s, closing: true } }
  action requestDelete = all { s.up, sqlFree, s.phase == "LIVE", s' = { ...s, phase: "QUIESCING" } }
  action beginRetire(e: int): bool = all {
    s.up, sqlFree, e != 0, s.events.get(e).state == "PENDING", not(s.events.get(e).lease),
    s.events.get(e).attempts == 2, not(s.events.get(e).closing),
    s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), closing: true }) },
  }
  def wanted(subject: str): bool =
    (subject == "agent/b" and s.phase == "QUIESCING") or
    (subject == "request/0" and s.closing) or
    EVENTS.exists(e => subject == eventSubject(e) and s.events.get(e).closing)
  action fenceStore(target: str, subject: str): bool = all {
    s.up, wanted(subject), s.boots.get(target).alive or (target == "b" and s.sealed),
    if (SERIALIZE) not(busy(target)) else true,
    s' = { ...s, fences: if (target == "b" and s.sealed) s.fences else s.fences.set(target,s.fences.get(target).union(Set(subject))),
      replies: s.replies.union(Set({ store: target, subject: subject })) },
  }
  action recordFence(target: str, subject: str): bool = all {
    s.up, s.replies.contains({ store: target, subject: subject }),
    s' = { ...s, replies: s.replies.exclude(Set({ store: target, subject: subject })),
      deleteAcks: if (subject == "agent/b") s.deleteAcks.union(Set(target)) else s.deleteAcks,
      closeAcks: if (subject == "request/0") s.closeAcks.union(Set(target)) else s.closeAcks,
      retireAcks: s.retireAcks.union(EVENTS.filter(e => subject == eventSubject(e) and target == dest(e))) },
  }
  action commitClose = all {
    s.up, sqlFree, s.closing, activeRequest, if (WAIT_ALL) s.closeAcks == STORES else true,
    s' = { ...s, request: "CANCELED", final: "CANCELED",
      events: s.events.set(0,{ ...s.events.get(0), state: if (s.events.get(0).state == "PENDING") "CANCELED" else s.events.get(0).state, lease: false })
        .set(2,pendingEvent) },
  }
  action commitDelete = {
    val fallback = (activeRequest or (s.request == "REPLIED" and not(s.notified))) and s.events.get(2).state == "ABSENT"
    all {
      s.up, sqlFree, s.phase == "QUIESCING", if (WAIT_ALL) s.deleteAcks == STORES else true,
      s' = { ...s, phase: "DELETING", request: if (activeRequest) "CANCELED" else s.request,
        final: if (activeRequest) "CANCELED" else s.final,
        events: EVENTS.mapBy(e => if (e == 2 and fallback) pendingEvent
          else if (e != 2 and s.events.get(e).state == "PENDING") { ...s.events.get(e), state: "CANCELED", lease: false }
          else s.events.get(e)) },
    }
  }
  action retire(e: int): bool = all {
    s.up, sqlFree, s.events.get(e).closing, s.events.get(e).state == "PENDING",
    if (WAIT_ALL) s.retireAcks.contains(e) else true,
    s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), state: "DEAD", lease: false }) },
  }
  // Unplanned physical death. SQL authority is unchanged until a separate
  // transaction retires it. Uncommitted local SQLite effects are aborted.
  action stopVM(a: str): bool = all {
    s.boots.get(a).alive,
    s' = { ...s, boots: s.boots.set(a,{ ...s.boots.get(a), alive: false }),
      fences: if (DURABLE) s.fences else s.fences.set(a,Set()),
      rpc: WORKERS.mapBy(w => if (s.rpc.get(w).stage == "EXECUTING" and dest(s.rpc.get(w).event) == a) idleRPC else s.rpc.get(w)),
      replies: s.replies.filter(r => r.store != a) },
  }
  action beginStop(a: str): bool = all {
    s.up, authorityFree(a), Set("RUNNING","STARTING").contains(s.placement.get(a)),
    s' = { ...s, placement: s.placement.set(a,"STOPPING"), bootLease: s.bootLease.set(a,false) },
  }
  // Host lock excludes retirement during a live start operation. After worker
  // death an unpublished boot is retired even when SQL confirmation committed.
  action retireBoot(a: str): bool = all {
    s.up, not(s.boots.get(a).owner),
    not(s.boots.get(a).alive) or s.placement.get(a) == "STOPPING" or s.boots.get(a).phase != "PUBLISHED",
    s' = { ...s, boots: s.boots.set(a,{ ...s.boots.get(a), alive: false, phase: "ABSENT", retired: true }),
      rpc: WORKERS.mapBy(w => if (s.rpc.get(w).stage == "EXECUTING" and dest(s.rpc.get(w).event) == a) idleRPC else s.rpc.get(w)),
      replies: s.replies.filter(r => r.store != a) },
  }
  action observeStopped(a: str): bool = all {
    s.up, authorityFree(a), not(s.boots.get(a).alive), s.boots.get(a).retired,
    s' = { ...s, placement: s.placement.set(a,"STOPPED"), bootLease: s.bootLease.set(a,false) },
  }
  // SQL claim, physical launch, SQL confirmation and host publication differ.
  // One boot record per store still assumes physical volume exclusivity.
  action bootVM(a: str, restricted: bool): bool = all {
    s.up, authorityFree(a), s.placement.get(a) == "STOPPED", not(s.boots.get(a).alive),
    s.boots.get(a).retired, s.boots.get(a).gen < MAX_GEN,
    if (a == "b") not(s.sealed) and (s.phase == "LIVE" or (s.phase == "QUIESCING" and restricted)) else true,
    s' = { ...s, placement: s.placement.set(a,"STARTING"), bootLease: s.bootLease.set(a,true),
      boots: s.boots.set(a,{ gen: s.boots.get(a).gen+1, alive: false, fenceOnly: restricted,
        phase: "ALLOCATED", confirmed: false, owner: false, retired: false }) },
  }
  action launchBoot(a: str): bool = all {
    s.up, s.boots.get(a).phase == "ALLOCATED", not(s.boots.get(a).retired),
    s' = { ...s, boots: s.boots.set(a,{ ...s.boots.get(a), alive: true, phase: "LAUNCHED", owner: true }) },
  }
  action expireBootLease(a: str): bool = all {
    s.bootLease.get(a), s' = { ...s, bootLease: s.bootLease.set(a,false) },
  }
  action confirmBoot(a: str): bool = all {
    s.up, authorityFree(a), s.boots.get(a).owner, s.boots.get(a).alive,
    s.boots.get(a).phase == "LAUNCHED", s.placement.get(a) == "STARTING", s.bootLease.get(a),
    if (a == "b") s.phase == "LIVE" or (s.phase == "QUIESCING" and s.boots.get(a).fenceOnly) else true,
    s' = { ...s, placement: s.placement.set(a,"RUNNING"), bootLease: s.bootLease.set(a,false),
      boots: s.boots.set(a,{ ...s.boots.get(a), confirmed: true }) },
  }
  action publishBoot(a: str): bool = all {
    s.up, s.boots.get(a).owner, s.boots.get(a).phase == "LAUNCHED", s.boots.get(a).confirmed,
    s' = { ...s, boots: s.boots.set(a,{ ...s.boots.get(a), phase: "PUBLISHED", owner: false }) },
  }
  // A failed synchronous start relinquishes its host lock for physical cleanup.
  action abandonBoot(a: str): bool = all {
    s.boots.get(a).owner, s' = { ...s, boots: s.boots.set(a,{ ...s.boots.get(a), owner: false }) },
  }
  action sealStore = all {
    s.up, authorityFree("b"), s.phase == "DELETING", not(s.boots.get("b").alive),
    s.placement.get("b") == "STOPPED", s.boots.get("b").retired,
    s' = { ...s, sealed: true },
  }
  action crashWorker = all { s.up, s' = { ...s, up: false, replies: Set(), api: "IDLE",
    boots: STORES.mapBy(a => { ...s.boots.get(a), owner: false }) } }
  action recoverWorker = all { not(s.up), s' = { ...s, up: true } }
  action step = any {
    { nondet a = Set("a","b").oneOf(); cacheCaller(a) },
    { nondet m = Set("a","c").oneOf(); admitSubmit(m) },
    { nondet m = Set("a","c").oneOf(); submit(m) }, admitReply, reply, abortCall,
    { nondet w = WORKERS.oneOf(); nondet e = EVENTS.oneOf(); claim(w,e) },
    { nondet w = WORKERS.oneOf(); authorize(w) },
    { nondet w = WORKERS.oneOf(); beginEffect(w) },
    { nondet w = WORKERS.oneOf(); commitEffect(w) },
    { nondet w = WORKERS.oneOf(); acknowledge(w) },
    { nondet w = WORKERS.oneOf(); loseRPC(w) },
    { nondet e = EVENTS.oneOf(); expireLease(e) },
    closeRequest, requestDelete,
    { nondet e = EVENTS.oneOf(); beginRetire(e) },
    { nondet a = STORES.oneOf(); nondet subject = Set("agent/b","request/0","event/1","event/2").oneOf(); fenceStore(a,subject) },
    { nondet a = STORES.oneOf(); nondet subject = Set("agent/b","request/0","event/1","event/2").oneOf(); recordFence(a,subject) },
    commitClose, commitDelete,
    { nondet e = EVENTS.oneOf(); retire(e) },
    { nondet a = STORES.oneOf(); stopVM(a) },
    { nondet a = STORES.oneOf(); beginStop(a) },
    { nondet a = STORES.oneOf(); retireBoot(a) },
    { nondet a = STORES.oneOf(); observeStopped(a) },
    { nondet a = STORES.oneOf(); launchBoot(a) },
    { nondet a = STORES.oneOf(); confirmBoot(a) },
    { nondet a = STORES.oneOf(); publishBoot(a) },
    { nondet a = STORES.oneOf(); abandonBoot(a) },
    { nondet a = STORES.oneOf(); expireBootLease(a) },
    { nondet a = STORES.oneOf(); nondet restricted = Set(true,false).oneOf(); bootVM(a,restricted) },
    sealStore, crashWorker, recoverWorker,
  }
  val noStaleEffect = not(s.staleEffect)
  val effectOnce = EVENTS.forall(e => s.effects.get(e) <= 1)
  val noConflictingEnvelope = not(s.conflictingEnvelope)
  val callerAuthorized = not(s.badCaller)
  def durableBarrier(a: str, subject: str): bool = s.fences.get(a).contains(subject) or (a == "b" and s.sealed)
  val acksSound = s.deleteAcks.forall(a => durableBarrier(a,"agent/b"))
    and s.closeAcks.forall(a => durableBarrier(a,"request/0"))
    and s.retireAcks.forall(e => durableBarrier(dest(e),eventSubject(e)))
  val tombstoneSafe = s.phase == "DELETING" implies STORES.forall(a => durableBarrier(a,"agent/b"))
  val terminalStable = s.final != "" implies s.request == s.final
  val terminalOutbox = s.final != "" implies s.events.get(1).state != "ABSENT" or s.events.get(2).state != "ABSENT"
  val statusIndependent = s.events.get(2).state != "ABSENT" implies subjects(2).intersect(Set("agent/b","request/0")) == Set()
  val noVMSealed = s.sealed implies not(s.boots.get("b").alive)
  val publicationConfirmed = STORES.forall(a => s.boots.get(a).phase == "PUBLISHED" implies s.boots.get(a).confirmed)
  val retirementBeforeStopped = STORES.forall(a => s.placement.get(a) == "STOPPED" implies
    (s.boots.get(a).retired and not(s.boots.get(a).alive)))
  val lockedAuthority = (s.api == "AUTH_A" implies currentCaller("a")) and
    (s.api == "AUTH_B" implies currentCaller("b"))
  val safety = noStaleEffect and effectOnce and noConflictingEnvelope and callerAuthorized and acksSound
    and tombstoneSafe and terminalStable and terminalOutbox and statusIndependent and noVMSealed
    and publicationConfirmed and retirementBeforeStopped and lockedAuthority
}
module protocolCompositionOk {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
  action submitted = init.then(cacheCaller("a")).then(admitSubmit("a")).then(submit("a"))
  action received = submitted.then(claim("w1",0)).then(authorize("w1"))
    .then(beginEffect("w1")).then(commitEffect("w1")).then(acknowledge("w1"))
  action replied = received.then(cacheCaller("b")).then(admitReply).then(reply)
  action deletionBarriers = fenceStore("a","agent/b").then(recordFence("a","agent/b"))
    .then(fenceStore("b","agent/b")).then(recordFence("b","agent/b"))
    .then(fenceStore("c","agent/b")).then(recordFence("c","agent/b"))
  run replyAppliedBeforeDeletionTest = replied.then(claim("w1",1)).then(authorize("w1"))
    .then(beginEffect("w1")).then(commitEffect("w1")).then(loseRPC("w1"))
    .then(requestDelete).then(deletionBarriers).then(commitDelete)
    .expect(safety and s.request == "REPLIED" and s.effects.get(1) == 1 and s.events.get(1).state == "CANCELED")
    .then(claim("w1",2)).then(authorize("w1")).then(beginEffect("w1"))
    .then(commitEffect("w1")).then(acknowledge("w1"))
    .expect(safety and s.notified and s.effects.get(1) == 1 and s.effects.get(2) == 1)
  run transactionDelaysFenceTest = submitted.then(claim("w1",0)).then(authorize("w1"))
    .then(beginEffect("w1")).then(requestDelete).expect(safety)
    .then(fenceStore("b","agent/b").fail())
  run authorizedEffectDuringQuiescingTest = submitted.then(claim("w1",0)).then(authorize("w1"))
    .then(beginEffect("w1")).then(requestDelete).then(commitEffect("w1"))
    .then(deletionBarriers).then(commitDelete).expect(safety and s.effects.get(0) == 1)
  run expiredLeaseRetryDeduplicatesTest = submitted.then(claim("w1",0)).then(authorize("w1"))
    .then(beginEffect("w1")).then(commitEffect("w1")).then(expireLease(0))
    .then(claim("w2",0)).then(authorize("w2")).then(beginEffect("w2"))
    .then(commitEffect("w2")).then(acknowledge("w2"))
    .expect(safety and s.effects.get(0) == 1 and s.request == "PROCESSING")
    .then(acknowledge("w1").fail())
  action retireStopped(a: str): bool = retireBoot(a).then(observeStopped(a))
  action restart(a: str, restricted: bool): bool = retireStopped(a).then(bootVM(a,restricted)).then(launchBoot(a)).then(confirmBoot(a)).then(publishBoot(a))
  run oldGenerationCannotSubmitTest = init.then(cacheCaller("a")).then(stopVM("a"))
    .then(restart("a",false)).expect(safety).then(admitSubmit("a").fail())
  run oldChannelCannotDeliverTest = submitted.then(claim("w1",0)).then(authorize("w1"))
    .then(stopVM("b")).then(restart("b",false)).expect(safety).then(beginEffect("w1").fail())
  run fenceOnlyCannotDeliverTest = submitted.then(stopVM("b")).then(restart("b",true))
    .expect(safety).then(claim("w1",0).fail())
  run sealBlocksRestartTest = init.then(requestDelete).then(deletionBarriers)
    .then(commitDelete).then(stopVM("b")).then(retireStopped("b")).then(sealStore).expect(safety)
    .then(bootVM("b",true).fail())
  run admittedCallSurvivesPhysicalCrashTest = init.then(cacheCaller("a")).then(admitSubmit("a"))
    .then(stopVM("a")).then(retireBoot("a")).then(submit("a")).then(observeStopped("a"))
    .expect(safety and s.request == "DELIVERING" and not(s.boots.get("a").alive))
  run receivedCallCanEnterSQLAfterPhysicalCrashTest = init.then(cacheCaller("a")).then(stopVM("a"))
    .then(admitSubmit("a")).then(submit("a")).expect(safety and s.request == "DELIVERING")
  run admittedCallBlocksSQLRetirementTest = init.then(cacheCaller("a")).then(admitSubmit("a"))
    .then(stopVM("a")).then(retireBoot("a")).expect(safety).then(observeStopped("a").fail())
  run sqlRetirementRejectsReceivedCallTest = init.then(cacheCaller("a")).then(beginStop("a"))
    .expect(safety and s.boots.get("a").alive).then(admitSubmit("a").fail())
  run confirmationWithoutPublicationIsRetiredTest = init.then(stopVM("a")).then(retireStopped("a"))
    .then(bootVM("a",false)).then(launchBoot("a")).then(confirmBoot("a"))
    .then(crashWorker).then(recoverWorker).then(retireBoot("a")).then(observeStopped("a"))
    .expect(safety and s.placement.get("a") == "STOPPED" and not(s.boots.get("a").alive))
  run publicationAfterStopIntentHasNoAuthorityTest = init.then(stopVM("a")).then(retireStopped("a"))
    .then(bootVM("a",false)).then(launchBoot("a")).then(confirmBoot("a"))
    .then(beginStop("a")).then(publishBoot("a")).then(cacheCaller("a"))
    .expect(safety).then(admitSubmit("a").fail())
}
module protocolCompositionEarlyTombstone {
  import protocolComposition(WAIT_ALL=false, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionRacyFence {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=false, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionVolatileFence {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=false, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionStaleCaller {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=false,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionForeignMandate {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=false, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionNoDedup {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=false, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionDependentStatus {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=false, FRESH_STATUS=true, MAX_GEN=2).*
}
module protocolCompositionReusedEnvelope {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=false, MAX_GEN=2).*
}
