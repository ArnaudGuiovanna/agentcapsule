/** Finite-domain induction over the original protocol transition relation.
 * No execution-depth bound if all three obligations pass. Cardinalities,
 * allocation limits and host contracts remain those of protocolCompositionOk.
 */
module protocolInductive {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).* from "./protocol_composition"
  pure val SUBJECTS = Set("agent/b","request/0","event/0","event/1","event/2")
  pure val BOOT_PHASES = Set("ABSENT","ALLOCATED","LAUNCHED","PUBLISHED")
  pure val PLACEMENTS = Set("STOPPED","STARTING","RUNNING","STOPPING")
  pure val API_PHASES = Set("IDLE","RECEIVED_A","RECEIVED_B","AUTH_A","AUTH_B")
  pure val eventDomain = Set("ABSENT","PENDING","DELIVERED","CANCELED","DEAD").map(st =>
    0.to(2).map(n => WORKERS.union(Set("")).map(w => Set(false,true).map(l => Set(false,true).map(p =>
      Set(false,true).map(c => {state:st,attempts:n,owner:w,lease:l,permitted:p,closing:c}))
      .flatten()).flatten()).flatten()).flatten()).flatten()
  pure val rpcDomain = (-1).to(2).map(e => 0.to(2).map(t => 0.to(MAX_GEN).map(g =>
    Set("IDLE","CLAIMED","SENT","EXECUTING","ACK","FAILED").map(st =>
      {event:e,token:t,gen:g,stage:st})).flatten()).flatten()).flatten()
  pure val replyDomain = STORES.map(a => SUBJECTS.map(p => {store:a,subject:p})).flatten()
  pure val BOOL = Set(false,true)
  val typeOK = all {
    BOOL.contains(s.up),
    Set("LIVE","QUIESCING","DELETING").contains(s.phase),
    BOOL.contains(s.sealed),
    Set("ABSENT","DELIVERING","PROCESSING","REPLIED","CANCELED").contains(s.request),
    Set("","REPLIED","CANCELED").contains(s.final),
    BOOL.contains(s.closing),
    BOOL.contains(s.notified),
    s.boots.keys() == STORES,
    STORES.forall(a => 1.to(MAX_GEN).contains(s.boots.get(a).gen) and BOOT_PHASES.contains(s.boots.get(a).phase)),
    STORES.setOfMaps(PLACEMENTS).contains(s.placement), STORES.setOfMaps(BOOL).contains(s.bootLease),
    API_PHASES.contains(s.api), STORES.union(Set("")).contains(s.apiOwner),
    STORES.setOfMaps(0.to(MAX_GEN)).contains(s.callers),
    STORES.setOfMaps(0.to(1)).contains(s.budgets),
    EVENTS.setOfMaps(eventDomain).contains(s.events),
    WORKERS.setOfMaps(rpcDomain).contains(s.rpc),
    STORES.setOfMaps(SUBJECTS.powerset()).contains(s.fences),
    replyDomain.powerset().contains(s.replies),
    STORES.powerset().contains(s.deleteAcks),
    STORES.powerset().contains(s.closeAcks),
    EVENTS.powerset().contains(s.retireAcks),
    EVENTS.setOfMaps((-1).to(2)).contains(s.seen),
    EVENTS.setOfMaps(0.to(1)).contains(s.effects),
    BOOL.contains(s.staleEffect),
    BOOL.contains(s.badCaller),
    BOOL.contains(s.conflictingEnvelope),
  }
  var probe: bool
  action baseInit = all { init, probe' = false }
  // Independent symbolic choices cover every state in the finite type domain.
  action arbitraryInit = {
    nondet v0 = BOOL.oneOf()
    nondet v1 = Set("LIVE","QUIESCING","DELETING").oneOf()
    nondet v2 = BOOL.oneOf()
    nondet v3 = Set("ABSENT","DELIVERING","PROCESSING","REPLIED","CANCELED").oneOf()
    nondet v4 = Set("","REPLIED","CANCELED").oneOf()
    nondet v5 = BOOL.oneOf()
    nondet v6 = BOOL.oneOf()
    // Factored choices cover the Cartesian record domains without enumerating
    // all combinations of Boolean boot fields in the SMT encoding.
    nondet bootG = STORES.setOfMaps(1.to(MAX_GEN)).oneOf()
    nondet bootA = STORES.setOfMaps(BOOL).oneOf()
    nondet bootF = STORES.setOfMaps(BOOL).oneOf()
    nondet bootP = STORES.setOfMaps(BOOT_PHASES).oneOf()
    nondet bootC = STORES.setOfMaps(BOOL).oneOf()
    nondet bootO = STORES.setOfMaps(BOOL).oneOf()
    nondet bootR = STORES.setOfMaps(BOOL).oneOf()
    val v7 = STORES.mapBy(a => { gen: bootG.get(a), alive: bootA.get(a), fenceOnly: bootF.get(a),
      phase: bootP.get(a), confirmed: bootC.get(a), owner: bootO.get(a), retired: bootR.get(a) })
    nondet placements = STORES.setOfMaps(PLACEMENTS).oneOf()
    nondet bootLeases = STORES.setOfMaps(BOOL).oneOf()
    nondet apiPhase = API_PHASES.oneOf()
    nondet apiOwner = STORES.union(Set("")).oneOf()
    nondet v8 = STORES.setOfMaps(0.to(MAX_GEN)).oneOf()
    nondet v9 = STORES.setOfMaps(0.to(1)).oneOf()
    nondet v10 = EVENTS.setOfMaps(eventDomain).oneOf()
    nondet v11 = WORKERS.setOfMaps(rpcDomain).oneOf()
    nondet v12 = STORES.setOfMaps(SUBJECTS.powerset()).oneOf()
    nondet v13 = replyDomain.powerset().oneOf()
    nondet v14 = STORES.powerset().oneOf()
    nondet v15 = STORES.powerset().oneOf()
    nondet v16 = EVENTS.powerset().oneOf()
    nondet v17 = EVENTS.setOfMaps((-1).to(2)).oneOf()
    nondet v18 = EVENTS.setOfMaps(0.to(1)).oneOf()
    nondet v19 = BOOL.oneOf()
    nondet v20 = BOOL.oneOf()
    nondet v21 = BOOL.oneOf()
    all { probe' = false, s' = {
      up: v0,
      phase: v1,
      sealed: v2,
      request: v3,
      final: v4,
      closing: v5,
      notified: v6,
      boots: v7, placement: placements, bootLease: bootLeases, api: apiPhase, apiOwner: apiOwner,
      callers: v8,
      budgets: v9,
      events: v10,
      rpc: v11,
      fences: v12,
      replies: v13,
      deleteAcks: v14,
      closeAcks: v15,
      retireAcks: v16,
      seen: v17,
      effects: v18,
      staleEffect: v19,
      badCaller: v20,
      conflictingEnvelope: v21
    } }
  }
  val protocolInvariant = all {
    typeOK, safety,
    // Fence responses can be lost, but an ACK never precedes durable fencing.
    s.replies.forall(r => durableBarrier(r.store,r.subject)),
    s.sealed implies s.phase == "DELETING" and s.placement.get("b") == "STOPPED",
    STORES.forall(a => s.boots.get(a).retired implies
      (not(s.boots.get(a).alive) and s.boots.get(a).phase == "ABSENT" and not(s.boots.get(a).owner))),
    STORES.forall(a => s.boots.get(a).owner implies s.boots.get(a).phase == "LAUNCHED" and not(s.boots.get(a).retired)),
    STORES.forall(a => s.boots.get(a).phase == "ALLOCATED" implies
      (not(s.boots.get(a).alive) and not(s.boots.get(a).confirmed) and not(s.boots.get(a).owner) and not(s.boots.get(a).retired))),
    STORES.forall(a => s.placement.get(a) == "RUNNING" implies s.boots.get(a).confirmed),
    STORES.forall(a => s.placement.get(a) == "STARTING" implies not(s.boots.get(a).confirmed)),
    STORES.forall(a => s.bootLease.get(a) implies s.placement.get(a) == "STARTING"),
    s.api == "AUTH_A" implies s.up and s.phase == "LIVE" and s.request == "ABSENT"
      and s.apiOwner == "a" and s.budgets.get("a") > 0,
    s.api == "AUTH_B" implies s.up and s.phase == "LIVE" and s.request == "PROCESSING" and not(s.closing),
    // The local writer transaction excludes a barrier until commit or VM death.
    WORKERS.forall(w => s.rpc.get(w).stage != "IDLE" implies EVENTS.contains(s.rpc.get(w).event)),
    WORKERS.forall(w => s.rpc.get(w).stage == "EXECUTING" implies
      (ready(dest(s.rpc.get(w).event)) and s.rpc.get(w).gen == s.boots.get(dest(s.rpc.get(w).event)).gen
      and allowed(s.rpc.get(w).event)
      and (s.rpc.get(w).event == 2 or (s.phase != "DELETING" and s.request != "CANCELED")))),
    EVENTS.forall(e => s.seen.get(e) == (if (s.effects.get(e) == 0) -1 else e)),
    s.final == (if (Set("REPLIED","CANCELED").contains(s.request)) s.request else ""),
    s.request == "CANCELED" implies s.phase == "DELETING" or s.closeAcks == STORES,
    s.request == "REPLIED" implies s.events.get(1).state != "ABSENT",
    s.request == "CANCELED" implies s.events.get(2).state != "ABSENT",
  }
  // Only the INPUT state is restricted to the candidate invariant.
  action inductionStep = all { protocolInvariant, step, probe' = true }
  // Distribute the proof flag over the SAME clauses; the AST audit checks
  // this exact correspondence so splitting cannot silently weaken the target.
  val preserved = all {
    probe implies (BOOL.contains(s.up)),
    probe implies (Set("LIVE","QUIESCING","DELETING").contains(s.phase)),
    probe implies (BOOL.contains(s.sealed)),
    probe implies (Set("ABSENT","DELIVERING","PROCESSING","REPLIED","CANCELED").contains(s.request)),
    probe implies (Set("","REPLIED","CANCELED").contains(s.final)),
    probe implies (BOOL.contains(s.closing)),
    probe implies (BOOL.contains(s.notified)),
    probe implies (s.boots.keys() == STORES),
    probe implies (STORES.forall(a => 1.to(MAX_GEN).contains(s.boots.get(a).gen) and BOOT_PHASES.contains(s.boots.get(a).phase))),
    probe implies (STORES.setOfMaps(PLACEMENTS).contains(s.placement)),
    probe implies (STORES.setOfMaps(BOOL).contains(s.bootLease)),
    probe implies (API_PHASES.contains(s.api)),
    probe implies (STORES.union(Set("")).contains(s.apiOwner)),
    probe implies (STORES.setOfMaps(0.to(MAX_GEN)).contains(s.callers)),
    probe implies (STORES.setOfMaps(0.to(1)).contains(s.budgets)),
    probe implies (EVENTS.setOfMaps(eventDomain).contains(s.events)),
    probe implies (WORKERS.setOfMaps(rpcDomain).contains(s.rpc)),
    probe implies (STORES.setOfMaps(SUBJECTS.powerset()).contains(s.fences)),
    probe implies (replyDomain.powerset().contains(s.replies)),
    probe implies (STORES.powerset().contains(s.deleteAcks)),
    probe implies (STORES.powerset().contains(s.closeAcks)),
    probe implies (EVENTS.powerset().contains(s.retireAcks)),
    probe implies (EVENTS.setOfMaps((-1).to(2)).contains(s.seen)),
    probe implies (EVENTS.setOfMaps(0.to(1)).contains(s.effects)),
    probe implies (BOOL.contains(s.staleEffect)),
    probe implies (BOOL.contains(s.badCaller)),
    probe implies (BOOL.contains(s.conflictingEnvelope)),
    probe implies (noStaleEffect),
    probe implies (effectOnce),
    probe implies (noConflictingEnvelope),
    probe implies (callerAuthorized),
    probe implies (acksSound),
    probe implies (tombstoneSafe),
    probe implies (terminalStable),
    probe implies (terminalOutbox),
    probe implies (statusIndependent),
    probe implies (noVMSealed),
    probe implies (publicationConfirmed),
    probe implies (retirementBeforeStopped),
    probe implies (lockedAuthority),
    probe implies (s.replies.forall(r => durableBarrier(r.store,r.subject))),
    probe implies (s.sealed implies s.phase == "DELETING" and s.placement.get("b") == "STOPPED"),
    probe implies (STORES.forall(a => s.boots.get(a).retired implies
      (not(s.boots.get(a).alive) and s.boots.get(a).phase == "ABSENT" and not(s.boots.get(a).owner)))),
    probe implies (STORES.forall(a => s.boots.get(a).owner implies s.boots.get(a).phase == "LAUNCHED" and not(s.boots.get(a).retired))),
    probe implies (STORES.forall(a => s.boots.get(a).phase == "ALLOCATED" implies
      (not(s.boots.get(a).alive) and not(s.boots.get(a).confirmed) and not(s.boots.get(a).owner) and not(s.boots.get(a).retired)))),
    probe implies (STORES.forall(a => s.placement.get(a) == "RUNNING" implies s.boots.get(a).confirmed)),
    probe implies (STORES.forall(a => s.placement.get(a) == "STARTING" implies not(s.boots.get(a).confirmed))),
    probe implies (STORES.forall(a => s.bootLease.get(a) implies s.placement.get(a) == "STARTING")),
    probe implies (s.api == "AUTH_A" implies s.up and s.phase == "LIVE" and s.request == "ABSENT"
      and s.apiOwner == "a" and s.budgets.get("a") > 0),
    probe implies (s.api == "AUTH_B" implies s.up and s.phase == "LIVE" and s.request == "PROCESSING" and not(s.closing)),
    probe implies (WORKERS.forall(w => s.rpc.get(w).stage != "IDLE" implies EVENTS.contains(s.rpc.get(w).event))),
    probe implies (WORKERS.forall(w => s.rpc.get(w).stage == "EXECUTING" implies
      (ready(dest(s.rpc.get(w).event)) and s.rpc.get(w).gen == s.boots.get(dest(s.rpc.get(w).event)).gen
      and allowed(s.rpc.get(w).event)
      and (s.rpc.get(w).event == 2 or (s.phase != "DELETING" and s.request != "CANCELED"))))),
    probe implies (EVENTS.forall(e => s.seen.get(e) == (if (s.effects.get(e) == 0) -1 else e))),
    probe implies (s.final == (if (Set("REPLIED","CANCELED").contains(s.request)) s.request else "")),
    probe implies (s.request == "CANCELED" implies s.phase == "DELETING" or s.closeAcks == STORES),
    probe implies (s.request == "REPLIED" implies s.events.get(1).state != "ABSENT"),
    probe implies (s.request == "CANCELED" implies s.events.get(2).state != "ABSENT"),
  }
  val implied = protocolInvariant implies safety

}
