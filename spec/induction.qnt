/**
 * Induction on the ORIGINAL transition relations, at fixed finite constants.
 * Type domains generate arbitrary states; init is NOT used for the induction step.
 * These checks remove the execution-depth bound, NOT the cardinality bounds.
 * Size-independent proof sketch (not a machine-checked parameterized theorem):
 * - launch adds one VM only to a free lock, hence an empty volume; confirm,
 *   stop, vmCrash and reconcile only remove VMs. Other actions preserve vms.
 * - deliver either preserves an existing effect protected by seen, or inserts
 *   the first effect with count one and atomically adds its id to seen.
 *   All other delivery-model actions preserve the harness state.
 */
module lifecycleInductive {
  import lifecycle(AGENTS = Set("a", "b"), JOBS = Set("j1", "j2"), MAX_ACTIVE = 1, MAX_GEN = 3,
                   HOST_LOCK = true, RECONCILE_SCAN = true).* from "./lifecycle"

  pure val vmDomain = AGENTS.map(a =>
    1.to(MAX_GEN).map(g => { agent: a, gen: g })).flatten()
  pure val jobDomain = Set(Idle, Acquired, Fenced, Launched).map(p =>
    AGENTS.union(Set("")).map(a =>
      0.to(MAX_GEN).map(g => { phase: p, agent: a, gen: g })).flatten()).flatten()
  pure val leaseDomain = JOBS.union(Set("")).map(j =>
    0.to(MAX_GEN).map(g =>
      Set(false, true).map(b => { holder: j, gen: g, valid: b })).flatten()).flatten()

  val typeOK = all {
    Set(false, true).contains(workerUp),
    Set(false, true).contains(reconciled),
    JOBS.setOfMaps(jobDomain).contains(jobs),
    vmDomain.powerset().contains(vms),
    vmDomain.powerset().contains(known),
    AGENTS.setOfMaps(leaseDomain).contains(lease),
    AGENTS.setOfMaps(0.to(MAX_GEN)).contains(gen),
    AGENTS.setOfMaps(Set(Stopped, Starting, Running, Deleting, Deleted)).contains(st),
    AGENTS.setOfMaps(Set("", "vm", "deleter")).contains(hostLock),
    AGENTS.setOfMaps(Set(false, true)).contains(deleteRequested),
    AGENTS.setOfMaps(Set(false, true)).contains(dekDestroyed),
  }

  // Critical strengthening: an occupied volume has exactly its kernel lock.
  // exclusiveVolume alone permits an arbitrary state with one VM and a free lock.
  val volumeInductive = all {
    typeOK,
    JOBS.forall(j => jobs.get(j).phase != Idle implies
      (AGENTS.contains(jobs.get(j).agent) and 1.to(MAX_GEN).contains(jobs.get(j).gen))),
    exclusiveVolume,
    AGENTS.forall(a => (hostLock.get(a) == "vm") == (vmsOf(vms, a).size() == 1)),
  }
}

module deliveryInductive {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).* from "./delivery"

  pure val idemDomain = Set(Absent, InProgress, Done).map(s =>
    BODIES.union(Set("")).map(b =>
      (-1).to(MAX_EVENTS).map(n => { state: s, body: b, seq: n })).flatten()).flatten()
  pure val eventDomain = KEYS.map(k => BODIES.map(b =>
    Set(Pending, Delivered, Dead).map(s =>
      0.to(MAX_ATTEMPTS).map(n => { key: k, body: b, state: s, attempts: n }))
      .flatten()).flatten()).flatten()

  // allListsUpTo is not implemented by the pinned Apalache translator.
  pure def boundedLists(ids: Set[int], n: int): Set[List[int]] =
    1.to(n).fold(Set(List()), (lists, _) =>
      lists.union(lists.map(xs => ids.map(i => xs.append(i))).flatten()))
  val allocated = 0.to(MAX_EVENTS - 1).filter(i => i < nextSeq)

  val typeOK = all {
    0.to(MAX_EVENTS).contains(nextSeq),
    KEYS.setOfMaps(idemDomain).contains(idem),
    allocated.setOfMaps(eventDomain).contains(events),
    KEYS.setOfMaps((-1).to(MAX_EVENTS).powerset()).contains(responses),
    KEYS.setOfMaps(Set(-1)).contains(pendingWrite),
    allocated.powerset().contains(seen),
    seen.setOfMaps(0.to(2)).contains(effects),
    boundedLists(0.to(MAX_EVENTS - 1), MAX_EVENTS).contains(log),
  }

  // Durable deduplication and effects must agree. The log bounds are closed
  // because only a first processing appends, and ids are never reused.
  val effectsInductive = all {
    typeOK,
    effects.keys().forall(s => effects.get(s) == 1),
    log.indices().map(i => log[i]) == seen,
    log.length() == seen.size(),
  }
}
