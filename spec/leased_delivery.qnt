/** Two workers may retain delayed RPCs after their leases expire. PostgreSQL
 * claims, SQLite effects, ACKs and retirement barriers are separate transitions.
 * The two events start queued; API admission/idempotency is checked separately.
 * A local effect/fence is one serial SQLite transaction, refined in fencing.qnt.
 */
module leasedDelivery {
  const WAIT_FOR_FENCE: bool
  const DEDUP: bool
  pure val EVENTS = Set(0, 1)
  pure val WORKERS = Set("w1", "w2")
  type Event = { state: str, attempts: int, fenced: bool, effects: int }
  type RPC = { event: int, token: int }
  type State = { events: int -> Event, rpc: str -> RPC, owner: str,
                 lease: bool, closing: bool, log: List[int], lateEffect: bool }
  pure val idle = { event: -1, token: 0 }
  var s: State
  action init = s' = {
    events: EVENTS.mapBy(_ => { state: "PENDING", attempts: 0, fenced: false, effects: 0 }),
    rpc: WORKERS.mapBy(_ => idle), owner: "", lease: false,
    closing: false, log: List(), lateEffect: false,
  }
  val pending = EVENTS.filter(e => s.events.get(e).state == "PENDING")
  val headSeq = pending.fold(2, (a, b) => if (a < b) a else b)
  action claim(w: str): bool = all {
    headSeq < 2, not(s.lease), not(s.closing), s.rpc.get(w).event == -1,
    s.events.get(headSeq).attempts < 2,
    s' = { ...s, owner: w, lease: true,
      events: s.events.set(headSeq, { ...s.events.get(headSeq), attempts: s.events.get(headSeq).attempts + 1 }),
      rpc: s.rpc.set(w, { event: headSeq, token: s.events.get(headSeq).attempts + 1 }) },
  }
  action applyRPC(w: str): bool = {
    val e = s.rpc.get(w).event
    all {
      e != -1, not(s.events.get(e).fenced),
      s' = if (s.events.get(e).effects > 0 and DEDUP) s else {
        ...s, events: s.events.set(e, { ...s.events.get(e), effects: if (s.events.get(e).effects < 2) s.events.get(e).effects + 1 else 2 }),
        log: if (s.events.get(e).effects == 0) s.log.append(e) else s.log,
        lateEffect: s.lateEffect or s.events.get(e).state == "DEAD",
      },
    }
  }
  action acknowledge(w: str): bool = {
    val e = s.rpc.get(w).event
    all {
      e != -1, s.events.get(e).effects > 0, s.events.get(e).state == "PENDING",
      s.lease, s.owner == w, not(s.closing), s.rpc.get(w).token == s.events.get(e).attempts,
      s' = { ...s, events: s.events.set(e, { ...s.events.get(e), state: "DELIVERED" }),
             rpc: s.rpc.set(w, idle), lease: false, owner: "" },
    }
  }
  action leaseExpires = all { s.lease, s' = { ...s, lease: false } }
  // A worker crash may discard its RPC while the database lease remains active.
  // Alternatively the RPC survives a timeout and applyRPC may run much later.
  action dropRPC(w: str): bool = all {
    s.rpc.get(w).event != -1, s' = { ...s, rpc: s.rpc.set(w, idle) },
  }
  action beginRetirement = all {
    headSeq < 2, not(s.lease), not(s.closing), s.events.get(headSeq).attempts == 2,
    s' = { ...s, closing: true },
  }
  action fence = all {
    s.closing, s' = { ...s, events: s.events.set(headSeq, { ...s.events.get(headSeq), fenced: true }) },
  }
  action finishRetirement = all {
    s.closing,
    if (WAIT_FOR_FENCE) s.events.get(headSeq).fenced else true,
    s' = { ...s, events: s.events.set(headSeq, { ...s.events.get(headSeq), state: "DEAD" }),
           closing: false, owner: "" },
  }
  action step = any {
    { nondet w = WORKERS.oneOf(); claim(w) },
    { nondet w = WORKERS.oneOf(); applyRPC(w) },
    { nondet w = WORKERS.oneOf(); acknowledge(w) },
    { nondet w = WORKERS.oneOf(); dropRPC(w) },
    leaseExpires, beginRetirement, fence, finishRetirement,
    // Terminal queues are allowed to stutter without creating a deadlock error.
    all { pending == Set(), s' = s },
  }
  val fifo = 0.to(s.log.length() - 2).forall(i => s.log[i] < s.log[i + 1])
  val effectOnce = EVENTS.forall(e => s.events.get(e).effects <= 1)
  val noLateEffect = not(s.lateEffect)
  val safety = fifo and effectOnce and noLateEffect
}
module leasedDeliveryOk {
  import leasedDelivery(WAIT_FOR_FENCE = true, DEDUP = true).*

  run delayedWorkerTest = init.then(claim("w1")).then(leaseExpires)
    .then(claim("w2")).then(leaseExpires).then(beginRetirement)
    .then(fence).then(finishRetirement).expect(safety).then(applyRPC("w1").fail())
}
module leasedDeliveryNoFence {
  import leasedDelivery(WAIT_FOR_FENCE = false, DEDUP = true).*
}
module leasedDeliveryNoDedup {
  import leasedDelivery(WAIT_FOR_FENCE = true, DEDUP = false).*
}
