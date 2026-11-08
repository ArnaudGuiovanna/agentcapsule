/** P1. Shared-state structure approved on 2026-11-06.
 * SQL is shared coordination state. Explicit RPC records represent delayed
 * messages; the model extends protocol_composition's transaction granularity.
 */
module concurrentProtocol {
  type AgentId = int
  type RequestId = int
  type EventId = (RequestId, int)
  type AgentPhase = Active | Quiescing | Deleting
  type Placement = Stopped | Starting | Running | Stopping
  type BootPhase = AbsentBoot | Allocated | Launched | Published
  type RequestPhase = AbsentRequest | PendingApproval | Delivering | Processing
    | Replied | Declined | Canceled | Expired | Failed
  type Closure = NoClosure | CancelRequest | ExpireRequest | FailRequest
  type EventPhase = AbsentEvent | PendingEvent | DeliveredEvent | CanceledEvent | DeadEvent
  type CallPhase = EmptyCall | ReceivedCall | AdmittedCall
  type CallKind = SubmitCall | ReplyCall | AcceptCall | DeclineCall
  type RPCPhase = IdleRPC | ClaimedRPC | SentRPC | ExecutingRPC | AckRPC | FailedRPC
  type Subject = AgentSubject(AgentId) | RequestSubject(RequestId) | EventSubject(EventId)
  type Agent = { phase: AgentPhase, placement: Placement, generation: int,
    alive: bool, bootPhase: BootPhase, confirmed: bool, startOwner: bool,
    retired: bool, fenceOnly: bool, bootLease: bool, sealed: bool }
  type Request = { phase: RequestPhase, final: RequestPhase, closure: Closure,
    notified: bool, accepted: bool }
  type Mandate = { remaining: int, valid: bool }
  type Event = { phase: EventPhase, attempts: int, owner: int, leased: bool,
    permitted: bool, closing: bool }
  type Call = { phase: CallPhase, kind: CallKind, request: RequestId,
    caller: AgentId, generation: int, mandate: AgentId, locks: Set[AgentId] }
  type RPC = { phase: RPCPhase, event: EventId, generation: int, token: int }
  type Receipt = { store: AgentId, subject: Subject }
  type State = { up: bool, agents: AgentId -> Agent, requests: RequestId -> Request,
    mandates: AgentId -> Mandate, events: EventId -> Event, order: List[EventId],
    calls: int -> Call, rpc: int -> RPC, fences: AgentId -> Set[Subject],
    receipts: Set[Receipt], acks: Set[Receipt], seen: Set[EventId],
    effects: EventId -> int, staleEffect: bool, badCaller: bool, badOrder: bool }
  var s: State

  const AGENTS: Set[AgentId]
  const ROUTES: RequestId -> (AgentId, AgentId)
  const MANUAL: Set[AgentId]
  const LOCKS: bool
  const WAIT_ALL: bool
  const SERIALIZE: bool
  const DEDUP: bool
  const CALLER_GUARD: bool
  const SCOPED_FENCES: bool
  const FIFO: bool
  const MAX_GEN: int
  pure val REQUESTS = ROUTES.keys()
  pure val EVENTS = REQUESTS.map(r => Set((r,0),(r,1),(r,2))).flatten()
  pure val SLOTS = Set(0,1)
  pure val WORKERS = Set(0,1)
  pure val BUDGET = 2
  pure val ATTEMPTS = 2
  pure val emptyEvent = { phase: AbsentEvent, attempts: 0, owner: 0,
    leased: false, permitted: false, closing: false }
  pure val emptyCall = { phase: EmptyCall, kind: SubmitCall, request: 0,
    caller: 0, generation: 0, mandate: 0, locks: Set() }
  pure val idleRPC = { phase: IdleRPC, event: (0,0), generation: 0, token: 0 }
  pure def sender(r: RequestId): AgentId = ROUTES.get(r)._1
  pure def recipient(r: RequestId): AgentId = ROUTES.get(r)._2
  pure def peers(r: RequestId): Set[AgentId] = Set(sender(r),recipient(r))
  pure def dest(e: EventId): AgentId = if (e._2 == 0) recipient(e._1) else sender(e._1)
  pure def terminal(p: RequestPhase): bool = Set(Replied,Declined,Canceled,Expired,Failed).contains(p)
  pure def active(p: RequestPhase): bool = Set(PendingApproval,Delivering,Processing).contains(p)
  pure def vmCall(k: CallKind): bool = k == SubmitCall or k == ReplyCall
  pure def closureState(c: Closure): RequestPhase = match c {
    | CancelRequest => Canceled | ExpireRequest => Expired | FailRequest => Failed | _ => AbsentRequest
  }
  pure def ready(x: State, a: AgentId): bool = {
    val b = x.agents.get(a)
    b.alive and b.bootPhase == Published and not(b.fenceOnly)
  }
  pure def freeAgents(x: State, ids: Set[AgentId]): bool =
    not(LOCKS) or SLOTS.forall(i => x.calls.get(i).locks.intersect(ids) == Set())
  pure def currentCaller(x: State, c: Call): bool = {
    val a = x.agents.get(c.caller)
    a.placement == Running and not(a.fenceOnly) and a.generation == c.generation
  }
  pure def livePeers(x: State, r: RequestId): bool = peers(r).forall(a => x.agents.get(a).phase == Active)
  pure def enqueue(x: State, e: EventId): State = if (x.events.get(e).phase == AbsentEvent)
    { ...x, events: x.events.set(e,{ ...emptyEvent, phase: PendingEvent }), order: x.order.append(e) }
    else x
  pure def withTerminal(x: State, r: RequestId, final: RequestPhase, kind: int): State = {
    val y = { ...x, requests: x.requests.set(r,{ ...x.requests.get(r), phase: final, final: final }) }
    if (x.agents.get(sender(r)).phase == Active) enqueue(y,(r,kind)) else y
  }
  pure val initialState: State = {
    up: true,
    agents: AGENTS.mapBy(_ => { phase: Active, placement: Running, generation: 1,
      alive: true, bootPhase: Published, confirmed: true, startOwner: false,
      retired: false, fenceOnly: false, bootLease: false, sealed: false }),
    requests: REQUESTS.mapBy(_ => { phase: AbsentRequest, final: AbsentRequest,
      closure: NoClosure, notified: false, accepted: false }),
    mandates: AGENTS.mapBy(_ => { remaining: BUDGET, valid: true }),
    events: EVENTS.mapBy(_ => emptyEvent), order: List(),
    calls: SLOTS.mapBy(_ => emptyCall), rpc: WORKERS.mapBy(_ => idleRPC),
    fences: AGENTS.mapBy(_ => Set()), receipts: Set(), acks: Set(), seen: Set(),
    effects: EVENTS.mapBy(_ => 0), staleEffect: false, badCaller: false, badOrder: false,
  }
  action init = s' = initialState

  pure def canReceive(x: State, slot: int, r: RequestId, kind: CallKind): bool = {
    val caller = if (kind == SubmitCall) sender(r) else recipient(r)
    // Manual consent is authenticated as an owner API call, not by a live VM.
    x.up and x.calls.get(slot).phase == EmptyCall and (not(vmCall(kind)) or ready(x,caller))
  }
  pure def received(x: State, slot: int, r: RequestId, kind: CallKind, mandate: AgentId): State = {
    val caller = if (kind == SubmitCall) sender(r) else recipient(r)
    { ...x, calls: x.calls.set(slot,{ ...emptyCall, phase: ReceivedCall, request: r,
      kind: kind, caller: caller, generation: x.agents.get(caller).generation, mandate: mandate }) }
  }
  action receive(slot: int, r: RequestId, kind: CallKind, mandate: AgentId): bool = all {
    canReceive(s,slot,r,kind), s' = received(s,slot,r,kind,mandate),
  }
  pure def businessAllowed(x: State, c: Call): bool = {
    val q = x.requests.get(c.request)
    livePeers(x,c.request) and q.closure == NoClosure and
      (if (c.kind == SubmitCall) q.phase == AbsentRequest and c.mandate == c.caller
        and x.mandates.get(c.mandate).valid and x.mandates.get(c.mandate).remaining > 0
      else if (c.kind == ReplyCall) q.phase == Processing
      else q.phase == PendingApproval)
  }
  pure def canAdmit(x: State, slot: int): bool = {
    val c = x.calls.get(slot)
    x.up and c.phase == ReceivedCall and freeAgents(x,peers(c.request)) and businessAllowed(x,c)
      and (not(vmCall(c.kind)) or not(CALLER_GUARD) or currentCaller(x,c))
  }
  pure def admitted(x: State, slot: int): State = { ...x, calls: x.calls.set(slot,
    { ...x.calls.get(slot), phase: AdmittedCall, locks: peers(x.calls.get(slot).request) }) }
  action admit(slot: int): bool = all { canAdmit(s,slot), s' = admitted(s,slot) }
  pure def canCommitCall(x: State, slot: int): bool =
    x.up and x.calls.get(slot).phase == AdmittedCall and businessAllowed(x,x.calls.get(slot))
  pure def callCommitted(x: State, slot: int): State = {
    val c = x.calls.get(slot)
    val r = c.request
    val q = x.requests.get(r)
    val y = { ...x, calls: x.calls.set(slot,emptyCall), badCaller: x.badCaller or (vmCall(c.kind) and not(currentCaller(x,c))) }
    if (c.kind == SubmitCall) {
      val phase = if (MANUAL.contains(recipient(r))) PendingApproval else Delivering
      val z = { ...y, requests: y.requests.set(r,{ ...q, phase: phase, accepted: true }),
        mandates: y.mandates.set(c.mandate,{ ...y.mandates.get(c.mandate), remaining: y.mandates.get(c.mandate).remaining-1 }) }
      if (phase == Delivering) enqueue(z,(r,0)) else z
    } else if (c.kind == AcceptCall)
      enqueue({ ...y, requests: y.requests.set(r,{ ...q, phase: Delivering }) },(r,0))
    else withTerminal(y,r,if (c.kind == ReplyCall) Replied else Declined,if (c.kind == ReplyCall) 1 else 2)
  }
  action commitCall(slot: int): bool = all { canCommitCall(s,slot), s' = callCommitted(s,slot) }
  action abortCall(slot: int): bool = all {
    s.calls.get(slot).phase != EmptyCall, s' = { ...s, calls: s.calls.set(slot,emptyCall) },
  }
  action expireMandate(a: AgentId): bool = all {
    s.mandates.get(a).valid, s' = { ...s, mandates: s.mandates.set(a,{ ...s.mandates.get(a), valid: false }) },
  }
  pure def requestSubject(r: RequestId): Subject = RequestSubject(if (SCOPED_FENCES) r else 0)
  pure def subjects(e: EventId): Set[Subject] = if (e._2 == 2)
    Set(AgentSubject(dest(e)),EventSubject(e))
    else Set(AgentSubject(sender(e._1)),AgentSubject(recipient(e._1)),requestSubject(e._1),EventSubject(e))
  pure def isHead(x: State, e: EventId): bool = x.order.indices().exists(i => x.order[i] == e and
    x.order.indices().forall(j => j < i implies (dest(x.order[j]) != dest(e) or x.events.get(x.order[j]).phase != PendingEvent)))
  pure def busy(x: State, a: AgentId): bool = WORKERS.exists(w =>
    x.rpc.get(w).phase == ExecutingRPC and dest(x.rpc.get(w).event) == a)
  pure def allowed(x: State, e: EventId): bool = subjects(e).intersect(x.fences.get(dest(e))) == Set()
  pure def dispatchable(x: State, e: EventId): bool =
    x.agents.get(dest(e)).phase == Active and
    (e._2 == 2 or (livePeers(x,e._1) and x.requests.get(e._1).closure == NoClosure))
  pure def canClaim(x: State, w: int, e: EventId): bool = {
    val v = x.events.get(e)
    x.up and freeAgents(x,peers(e._1)) and x.rpc.get(w).phase == IdleRPC and
      v.phase == PendingEvent and (not(FIFO) or isHead(x,e)) and not(v.leased) and not(v.closing) and
      v.attempts < ATTEMPTS and ready(x,dest(e)) and x.agents.get(dest(e)).placement == Running and dispatchable(x,e)
  }
  pure def claimed(x: State, w: int, e: EventId): State = {
    val v = x.events.get(e)
    { ...x, events: x.events.set(e,{ ...v, attempts: v.attempts+1, owner: w, leased: true, permitted: false }),
      rpc: x.rpc.set(w,{ event: e, token: v.attempts+1, generation: x.agents.get(dest(e)).generation, phase: ClaimedRPC }),
      badOrder: x.badOrder or not(isHead(x,e)) }
  }
  action claim(w: int, e: EventId): bool = all { canClaim(s,w,e), s' = claimed(s,w,e) }
  pure def ownedLease(x: State, w: int): bool = {
    val r = x.rpc.get(w)
    val e = x.events.get(r.event)
    e.phase == PendingEvent and e.owner == w and e.attempts == r.token and e.leased and not(e.closing)
  }
  pure def canAuthorize(x: State, w: int): bool = {
    val r = x.rpc.get(w)
    x.up and freeAgents(x,peers(r.event._1)) and r.phase == ClaimedRPC and
      ownedLease(x,w) and dispatchable(x,r.event)
  }
  pure def authorized(x: State, w: int): State = {
    val r = x.rpc.get(w)
    { ...x, events: x.events.set(r.event,{ ...x.events.get(r.event), permitted: true }),
      rpc: x.rpc.set(w,{ ...r, phase: SentRPC }) }
  }
  action authorize(w: int): bool = all { canAuthorize(s,w), s' = authorized(s,w) }
  pure def canBeginEffect(x: State, w: int): bool = {
    val r = x.rpc.get(w)
    r.phase == SentRPC and ready(x,dest(r.event)) and
      x.agents.get(dest(r.event)).generation == r.generation and not(busy(x,dest(r.event))) and allowed(x,r.event)
  }
  action beginEffect(w: int): bool = all {
    canBeginEffect(s,w), s' = { ...s, rpc: s.rpc.set(w,{ ...s.rpc.get(w), phase: ExecutingRPC }) },
  }
  pure def forbiddenEffect(x: State, e: EventId): bool =
    x.agents.get(dest(e)).phase == Deleting or (e._2 != 2 and
      (peers(e._1).exists(a => x.agents.get(a).phase == Deleting) or
       Set(Canceled,Expired,Failed).contains(x.requests.get(e._1).phase)))
  pure def effectCommitted(x: State, w: int): State = {
    val r = x.rpc.get(w)
    val apply = not(DEDUP) or not(x.seen.contains(r.event))
    { ...x, rpc: x.rpc.set(w,{ ...r, phase: AckRPC }), seen: x.seen.union(Set(r.event)),
      effects: if (apply) x.effects.set(r.event,x.effects.get(r.event)+1) else x.effects,
      staleEffect: x.staleEffect or (apply and forbiddenEffect(x,r.event)) }
  }
  action commitEffect(w: int): bool = all { s.rpc.get(w).phase == ExecutingRPC, s' = effectCommitted(s,w) }
  pure def canAcknowledge(x: State, w: int): bool = {
    val r = x.rpc.get(w)
    val q = x.requests.get(r.event._1)
    x.up and freeAgents(x,peers(r.event._1)) and r.phase == AckRPC and ownedLease(x,w) and
      x.events.get(r.event).permitted and (r.event._2 != 0 or (q.phase == Delivering and q.closure == NoClosure))
  }
  pure def acknowledged(x: State, w: int): State = {
    val r = x.rpc.get(w)
    val q = x.requests.get(r.event._1)
    { ...x, events: x.events.set(r.event,{ ...x.events.get(r.event), phase: DeliveredEvent, leased: false }),
      requests: x.requests.set(r.event._1,{ ...q, phase: if (r.event._2 == 0) Processing else q.phase,
        notified: q.notified or r.event._2 != 0 }), rpc: x.rpc.set(w,idleRPC) }
  }
  action acknowledge(w: int): bool = all { canAcknowledge(s,w), s' = acknowledged(s,w) }
  action expireLease(e: EventId): bool = all {
    s.events.get(e).leased, s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), leased: false }) },
  }
  action loseRPC(w: int): bool = all {
    s.rpc.get(w).phase != IdleRPC, s.rpc.get(w).phase != ExecutingRPC,
    s' = { ...s, rpc: s.rpc.set(w,idleRPC) },
  }
  pure def canClose(x: State, r: RequestId): bool = x.up and freeAgents(x,peers(r)) and
    active(x.requests.get(r).phase) and x.requests.get(r).closure == NoClosure
  action closeRequest(r: RequestId, why: Closure): bool = all {
    why != NoClosure, canClose(s,r),
    s' = { ...s, requests: s.requests.set(r,{ ...s.requests.get(r), closure: why }) },
  }
  action requestDelete(a: AgentId): bool = all {
    s.up, freeAgents(s,Set(a)), s.agents.get(a).phase == Active,
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), phase: Quiescing }) },
  }
  action beginRetire(e: EventId): bool = all {
    s.up, freeAgents(s,peers(e._1)), e._2 != 0, s.events.get(e).phase == PendingEvent,
    not(s.events.get(e).leased), s.events.get(e).attempts == ATTEMPTS, not(s.events.get(e).closing),
    s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), closing: true }) },
  }
  pure def wanted(x: State, subject: Subject): bool = match subject {
    | AgentSubject(a) => x.agents.get(a).phase == Quiescing
    | RequestSubject(r) => x.requests.get(r).closure != NoClosure
    | EventSubject(e) => x.events.get(e).closing
  }
  pure val SUBJECTS = AGENTS.map(a => AgentSubject(a)).union(REQUESTS.map(r => RequestSubject(r)))
    .union(EVENTS.map(e => EventSubject(e)))
  pure def barrier(x: State, a: AgentId, subject: Subject): bool = x.fences.get(a).contains(subject) or x.agents.get(a).sealed
  pure def canFence(x: State, a: AgentId, subject: Subject): bool = x.up and wanted(x,subject) and
    (x.agents.get(a).alive or x.agents.get(a).sealed) and (not(SERIALIZE) or not(busy(x,a)))
  pure def fenced(x: State, a: AgentId, subject: Subject): State = { ...x,
    fences: if (x.agents.get(a).sealed) x.fences else x.fences.set(a,x.fences.get(a).union(Set(subject))),
    receipts: x.receipts.union(Set({ store: a, subject: subject })) }
  action fenceStore(a: AgentId, subject: Subject): bool = all { canFence(s,a,subject), s' = fenced(s,a,subject) }
  action recordFence(a: AgentId, subject: Subject): bool = {
    val receipt = { store: a, subject: subject }
    all { s.up, s.receipts.contains(receipt),
      s' = { ...s, acks: s.acks.union(Set(receipt)), receipts: s.receipts.exclude(Set(receipt)) } }
  }
  pure def allAcks(x: State, subject: Subject): bool = AGENTS.forall(a => x.acks.contains({ store: a, subject: subject }))
  pure def canCommitClose(x: State, r: RequestId): bool = x.up and freeAgents(x,peers(r)) and
    x.requests.get(r).closure != NoClosure and active(x.requests.get(r).phase) and
    (not(WAIT_ALL) or allAcks(x,RequestSubject(r)))
  pure def closeCommitted(x: State, r: RequestId): State = {
    val y = { ...x, events: EVENTS.mapBy(e => if (e._1 == r and e._2 != 2 and x.events.get(e).phase == PendingEvent)
      { ...x.events.get(e), phase: CanceledEvent, leased: false } else x.events.get(e)) }
    withTerminal(y,r,closureState(x.requests.get(r).closure),2)
  }
  action commitClose(r: RequestId): bool = all { canCommitClose(s,r), s' = closeCommitted(s,r) }
  pure def canCommitDelete(x: State, a: AgentId): bool = x.up and freeAgents(x,AGENTS) and
    x.agents.get(a).phase == Quiescing and (not(WAIT_ALL) or allAcks(x,AgentSubject(a)))
  pure def deleteCommitted(x: State, a: AgentId): State = {
    val y = { ...x, agents: x.agents.set(a,{ ...x.agents.get(a), phase: Deleting }),
      events: EVENTS.mapBy(e => if (subjects(e).contains(AgentSubject(a)) and x.events.get(e).phase == PendingEvent)
        { ...x.events.get(e), phase: CanceledEvent, leased: false } else x.events.get(e)) }
    REQUESTS.fold(y,(z,r) => if (peers(r).contains(a) and active(z.requests.get(r).phase))
      withTerminal(z,r,Canceled,2)
      else if (peers(r).contains(a) and z.requests.get(r).phase == Replied and not(z.requests.get(r).notified)
        and z.agents.get(sender(r)).phase == Active) enqueue(z,(r,2)) else z)
  }
  action commitDelete(a: AgentId): bool = all { canCommitDelete(s,a), s' = deleteCommitted(s,a) }
  action retire(e: EventId): bool = all {
    s.up, freeAgents(s,peers(e._1)), s.events.get(e).closing, s.events.get(e).phase == PendingEvent,
    not(WAIT_ALL) or s.acks.contains({ store: dest(e), subject: EventSubject(e) }),
    s' = { ...s, events: s.events.set(e,{ ...s.events.get(e), phase: DeadEvent, leased: false }) },
  }
  pure def abortLocal(x: State, a: AgentId): State = { ...x,
    rpc: WORKERS.mapBy(w => if (x.rpc.get(w).phase == ExecutingRPC and dest(x.rpc.get(w).event) == a) idleRPC else x.rpc.get(w)),
    receipts: x.receipts.filter(r => r.store != a) }
  pure def physicallyStopped(x: State, a: AgentId): State = abortLocal(
    { ...x, agents: x.agents.set(a,{ ...x.agents.get(a), alive: false }) },a)
  action stopVM(a: AgentId): bool = all { s.agents.get(a).alive, s' = physicallyStopped(s,a) }
  action beginStop(a: AgentId): bool = all {
    s.up, freeAgents(s,Set(a)), Set(Running,Starting).contains(s.agents.get(a).placement),
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), placement: Stopping, bootLease: false }) },
  }
  pure def canRetireBoot(x: State, a: AgentId): bool = {
    val b = x.agents.get(a)
    x.up and not(b.startOwner) and (not(b.alive) or b.placement == Stopping or b.bootPhase != Published)
  }
  pure def bootRetired(x: State, a: AgentId): State = abortLocal(
    { ...x, agents: x.agents.set(a,{ ...x.agents.get(a), alive: false, bootPhase: AbsentBoot, retired: true }) },a)
  action retireBoot(a: AgentId): bool = all { canRetireBoot(s,a), s' = bootRetired(s,a) }
  action observeStopped(a: AgentId): bool = all {
    s.up, freeAgents(s,Set(a)), not(s.agents.get(a).alive), s.agents.get(a).retired,
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), placement: Stopped, bootLease: false }) },
  }
  pure def canBoot(x: State, a: AgentId, restricted: bool): bool = {
    val b = x.agents.get(a)
    x.up and freeAgents(x,Set(a)) and b.placement == Stopped and not(b.alive) and b.retired and
      b.generation < MAX_GEN and not(b.sealed) and (b.phase == Active or (b.phase == Quiescing and restricted))
  }
  pure def bootClaimed(x: State, a: AgentId, restricted: bool): State = { ...x,
    agents: x.agents.set(a,{ ...x.agents.get(a), placement: Starting, bootLease: true,
      generation: x.agents.get(a).generation+1, alive: false, fenceOnly: restricted,
      bootPhase: Allocated, confirmed: false, startOwner: false, retired: false }) }
  action bootVM(a: AgentId, restricted: bool): bool = all { canBoot(s,a,restricted), s' = bootClaimed(s,a,restricted) }
  action launchBoot(a: AgentId): bool = all {
    s.up, s.agents.get(a).bootPhase == Allocated, not(s.agents.get(a).retired),
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), alive: true, bootPhase: Launched, startOwner: true }) },
  }
  action expireBootLease(a: AgentId): bool = all {
    s.agents.get(a).bootLease, s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), bootLease: false }) },
  }
  pure def canConfirm(x: State, a: AgentId): bool = {
    val b = x.agents.get(a)
    x.up and freeAgents(x,Set(a)) and b.startOwner and b.alive and b.bootPhase == Launched and
      b.placement == Starting and b.bootLease and (b.phase == Active or (b.phase == Quiescing and b.fenceOnly))
  }
  action confirmBoot(a: AgentId): bool = all {
    canConfirm(s,a), s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), placement: Running, bootLease: false, confirmed: true }) },
  }
  action publishBoot(a: AgentId): bool = all {
    s.up, s.agents.get(a).startOwner, s.agents.get(a).bootPhase == Launched, s.agents.get(a).confirmed,
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), bootPhase: Published, startOwner: false }) },
  }
  action abandonBoot(a: AgentId): bool = all {
    s.agents.get(a).startOwner, s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), startOwner: false }) },
  }
  action sealStore(a: AgentId): bool = all {
    s.up, freeAgents(s,Set(a)), s.agents.get(a).phase == Deleting, not(s.agents.get(a).alive),
    s.agents.get(a).placement == Stopped, s.agents.get(a).retired, not(s.agents.get(a).sealed),
    s' = { ...s, agents: s.agents.set(a,{ ...s.agents.get(a), sealed: true }) },
  }
  action crashWorker = all {
    s.up, s' = { ...s, up: false, receipts: Set(), calls: SLOTS.mapBy(_ => emptyCall),
      agents: AGENTS.mapBy(a => { ...s.agents.get(a), startOwner: false }) },
  }
  action recoverWorker = all { not(s.up), s' = { ...s, up: true } }
  val quotaConserved = AGENTS.forall(a => s.mandates.get(a).remaining >= 0 and
    s.mandates.get(a).remaining + REQUESTS.filter(r => sender(r) == a and s.requests.get(r).accepted).size() == BUDGET)
  val terminalStable = REQUESTS.forall(r => terminal(s.requests.get(r).final) implies s.requests.get(r).phase == s.requests.get(r).final)
  val lockedAuthority = SLOTS.forall(i => s.calls.get(i).phase == AdmittedCall and vmCall(s.calls.get(i).kind)
    implies currentCaller(s,s.calls.get(i)))
  val effectOnce = EVENTS.forall(e => s.effects.get(e) <= 1)
  val acksSound = s.acks.forall(r => barrier(s,r.store,r.subject))
  val tombstoneSafe = AGENTS.forall(a => s.agents.get(a).phase == Deleting implies AGENTS.forall(b => barrier(s,b,AgentSubject(a))))
  val closedSafe = REQUESTS.forall(r => Set(Expired,Failed).contains(s.requests.get(r).phase) implies
    AGENTS.forall(a => barrier(s,a,RequestSubject(r))))
  val noLiveRequestForDeleted = REQUESTS.forall(r => active(s.requests.get(r).phase) implies
    peers(r).forall(a => s.agents.get(a).phase != Deleting))
  val terminalOutbox = REQUESTS.forall(r => terminal(s.requests.get(r).phase) and s.agents.get(sender(r)).phase == Active implies
    s.events.get((r,1)).phase != AbsentEvent or s.events.get((r,2)).phase != AbsentEvent)
  val noVMSealed = AGENTS.forall(a => s.agents.get(a).sealed implies not(s.agents.get(a).alive))
  val publicationConfirmed = AGENTS.forall(a => s.agents.get(a).bootPhase == Published implies s.agents.get(a).confirmed)
  val retirementBeforeStopped = AGENTS.forall(a => s.agents.get(a).placement == Stopped implies
    s.agents.get(a).retired and not(s.agents.get(a).alive))
  val noStaleEffect = not(s.staleEffect)
  val fifo = not(s.badOrder)
  val safety = quotaConserved and terminalStable and lockedAuthority and effectOnce and not(s.badCaller)
    and not(s.staleEffect) and not(s.badOrder) and acksSound and tombstoneSafe and closedSafe
    and noLiveRequestForDeleted and terminalOutbox and noVMSealed and publicationConfirmed and retirementBeforeStopped
  action step = any {
    { nondet slot = SLOTS.oneOf(); nondet r = REQUESTS.oneOf(); nondet kind = Set(SubmitCall,ReplyCall,AcceptCall,DeclineCall).oneOf();
      nondet m = AGENTS.oneOf(); receive(slot,r,kind,m) },
    { nondet slot = SLOTS.oneOf(); any { admit(slot), commitCall(slot), abortCall(slot) } },
    { nondet a = AGENTS.oneOf(); expireMandate(a) },
    { nondet w = WORKERS.oneOf(); nondet e = EVENTS.oneOf(); claim(w,e) },
    { nondet w = WORKERS.oneOf(); any { authorize(w), beginEffect(w), commitEffect(w), acknowledge(w), loseRPC(w) } },
    { nondet e = EVENTS.oneOf(); expireLease(e) },
    { nondet r = REQUESTS.oneOf(); nondet why = Set(CancelRequest,ExpireRequest,FailRequest).oneOf(); closeRequest(r,why) },
    { nondet r = REQUESTS.oneOf(); commitClose(r) },
    { nondet a = AGENTS.oneOf(); any { requestDelete(a), commitDelete(a) } },
    { nondet a = AGENTS.oneOf(); nondet p = SUBJECTS.oneOf(); any { fenceStore(a,p), recordFence(a,p) } },
    { nondet e = EVENTS.oneOf(); any { beginRetire(e), retire(e) } },
    { nondet a = AGENTS.oneOf(); any { stopVM(a), beginStop(a), retireBoot(a), observeStopped(a),
      launchBoot(a), confirmBoot(a), publishBoot(a), expireBootLease(a), abandonBoot(a), sealStore(a) } },
    { nondet a = AGENTS.oneOf(); nondet restricted = Set(true,false).oneOf(); bootVM(a,restricted) },
    crashWorker, recoverWorker,
  }
}
module concurrentProtocolFour {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolNoLock {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=false, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolEarlyDelete {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=false, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolRacyFence {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=false, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolNoDedup {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=false,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolStaleCaller {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=false, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolWrongRequestFence {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=false, FIFO=true, MAX_GEN=2).*
}
module concurrentProtocolNoFifo {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=false, MAX_GEN=2).*
}
