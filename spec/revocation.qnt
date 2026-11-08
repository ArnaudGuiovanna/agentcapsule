/**
 * Distributed deletion barrier for one subject across three registered stores.
 * Intent/QUIESCING blocks admission; it is not the abstract deletion tombstone.
 * Old authorized work may finish until all durable local fences acknowledge.
 * Only then may PostgreSQL atomically tombstone and cancel active requests.
 *
 * The census is fixed. Creating/restoring stores, authenticated envelope subjects,
 * VM sealing/key destruction and refinement to composition.qnt remain obligations.
 * SQL transactions and local fence serialization are refined in fencing.qnt.
 */
module distributedRevocation {
  const WAIT_FOR_ALL: bool
  const SERIALIZE_EFFECT: bool
  const DURABLE_FENCE: bool
  pure val STORES = Set("a", "b", "c")
  type Local = { online: bool, issued: bool, active: bool, executing: bool,
                 effected: bool, fence: bool, stableFence: bool, reply: bool, ack: bool }
  type State = { phase: str, coordinator: bool, stores: str -> Local, staleEffect: bool }
  pure val emptyLocal = { online: true, issued: false, active: false, executing: false,
                         effected: false, fence: false, stableFence: false, reply: false, ack: false }
  var s: State

  action init = s' = { phase: "LIVE", coordinator: true,
                      stores: STORES.mapBy(_ => emptyLocal), staleEffect: false }
  action admit(target: str): bool = {
    val l = s.stores.get(target)
    all {
      s.coordinator, s.phase == "LIVE", not(l.issued),
      s' = { ...s, stores: s.stores.set(target, { ...l, issued: true, active: true }) },
    }
  }
  action beginEffect(target: str): bool = {
    val l = s.stores.get(target)
    all {
      l.online, l.issued, not(l.effected), not(l.executing), not(l.fence),
      s' = { ...s, stores: s.stores.set(target, { ...l, executing: true }) },
    }
  }
  action commitEffect(target: str): bool = {
    val l = s.stores.get(target)
    all {
      l.online, l.executing,
      s' = { ...s, stores: s.stores.set(target, { ...l, executing: false, effected: true }),
             staleEffect: s.staleEffect or s.phase == "DELETING" },
    }
  }
  action requestDeletion = all {
    s.coordinator, s.phase == "LIVE",
    s' = { ...s, phase: "QUIESCING" },
  }
  action localFence(target: str): bool = {
    val l = s.stores.get(target)
    all {
      s.coordinator, s.phase == "QUIESCING", l.online,
      if (SERIALIZE_EFFECT) not(l.executing) else true,
      s' = { ...s, stores: s.stores.set(target, { ...l, fence: true,
             stableFence: if (DURABLE_FENCE) true else l.stableFence, reply: true }) },
    }
  }
  action recordAck(target: str): bool = {
    val l = s.stores.get(target)
    all {
      s.coordinator, s.phase == "QUIESCING", l.reply,
      s' = { ...s, stores: s.stores.set(target, { ...l, ack: true, reply: false }) },
    }
  }
  action loseAck(target: str): bool = {
    val l = s.stores.get(target)
    all { l.reply, s' = { ...s, stores: s.stores.set(target, { ...l, reply: false }) } }
  }
  action commitTombstone = all {
    s.coordinator, s.phase == "QUIESCING",
    if (WAIT_FOR_ALL) STORES.forall(t => s.stores.get(t).ack) else true,
    s' = { ...s, phase: "DELETING",
           stores: STORES.mapBy(t => { ...s.stores.get(t), active: false }) },
  }
  // Crashes of the coordinator cannot undo committed intent, target ACKs or
  // tombstone/cancellation. Unreceived local ACKs may be lost and retried.
  action coordinatorCrash = all {
    s.coordinator,
    s' = { ...s, coordinator: false,
           stores: STORES.mapBy(t => { ...s.stores.get(t), reply: false }) },
  }
  action coordinatorRecover = all { not(s.coordinator), s' = { ...s, coordinator: true } }
  action storePowerLoss(target: str): bool = {
    val l = s.stores.get(target)
    all {
      l.online,
      s' = { ...s, stores: s.stores.set(target, { ...l, online: false,
             executing: false, fence: l.stableFence, reply: false }) },
    }
  }
  action storeRecover(target: str): bool = {
    val l = s.stores.get(target)
    all { not(l.online), s' = { ...s, stores: s.stores.set(target, { ...l, online: true }) } }
  }
  action step = any {
    { nondet t = STORES.oneOf(); admit(t) },
    { nondet t = STORES.oneOf(); beginEffect(t) },
    { nondet t = STORES.oneOf(); commitEffect(t) },
    requestDeletion,
    { nondet t = STORES.oneOf(); localFence(t) },
    { nondet t = STORES.oneOf(); recordAck(t) },
    { nondet t = STORES.oneOf(); loseAck(t) },
    commitTombstone, coordinatorCrash, coordinatorRecover,
    { nondet t = STORES.oneOf(); storePowerLoss(t) },
    { nondet t = STORES.oneOf(); storeRecover(t) },
  }
  val noStaleEffect = not(s.staleEffect)
  val acknowledgedSurvives = STORES.forall(t => s.stores.get(t).ack implies s.stores.get(t).fence)
  val tombstoneBarrier = s.phase == "DELETING" implies STORES.forall(t => s.stores.get(t).fence)
  val tombstoneCancels = s.phase == "DELETING" implies STORES.forall(t => not(s.stores.get(t).active))
  val safety = noStaleEffect and acknowledgedSurvives and tombstoneBarrier and tombstoneCancels
}
module revocationOk {
  import distributedRevocation(WAIT_FOR_ALL = true, SERIALIZE_EFFECT = true, DURABLE_FENCE = true).*

  run waitsForEffectTest = init.then(admit("b")).then(beginEffect("b")).then(requestDeletion)
    .then(localFence("a")).then(recordAck("a")).then(localFence("b").fail())

  run lostAckRetryTest = init.then(admit("b")).then(beginEffect("b")).then(requestDeletion)
    .then(commitEffect("b")).then(localFence("a")).then(recordAck("a"))
    .then(localFence("b")).then(loseAck("b")).then(coordinatorCrash).then(coordinatorRecover)
    .then(localFence("b")).then(recordAck("b")).then(localFence("c")).then(recordAck("c"))
    .then(commitTombstone).then(storePowerLoss("b")).then(storeRecover("b"))
    .expect(safety and s.phase == "DELETING" and s.stores.get("b").effected)

  run cannotFinishEarlyTest = init.then(requestDeletion).then(localFence("a"))
    .then(recordAck("a")).then(commitTombstone.fail())
}
module revocationEarlyTombstone {
  import distributedRevocation(WAIT_FOR_ALL = false, SERIALIZE_EFFECT = true, DURABLE_FENCE = true).*
}
module revocationRacyFence {
  import distributedRevocation(WAIT_FOR_ALL = true, SERIALIZE_EFFECT = false, DURABLE_FENCE = true).*
}
module revocationVolatileFence {
  import distributedRevocation(WAIT_FOR_ALL = true, SERIALIZE_EFFECT = true, DURABLE_FENCE = false).*
}
