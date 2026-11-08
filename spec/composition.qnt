/**
 * Minimal shared-state composition of deletion, requests and event delivery.
 * It abstracts leases, consent and API idempotency (checked in the other models).
 * A submit represents an already authorized request and its transactional outbox.
 * Deletion first installs a tombstone and cancels work, then stops the VM and
 * destroys its key. Launches and deliveries may have read their state beforehand.
 * This is an interaction model, not a proved refinement of the three full models.
 */
module composition {
  const AGENTS: Set[str]
  const MAX_REQS: int
  const MAX_ATTEMPTS: int
  const CANCEL_ON_DELETE: bool
  const DELIVERY_FENCE: bool
  const LAUNCH_FENCE: bool

  type Phase = Live | Deleting | Deleted
  type RequestState = Working | Terminal
  type EventState = Queued | Done | Dead | Canceled
  type Request = { sender: str, recipient: str, state: RequestState,
                   event: EventState, attempts: int, effects: int }

  var phase: str -> Phase
  var running: Set[str]
  var startIntent: Set[str]
  var requests: int -> Request
  var nextReq: int
  var inFlight: Set[int]
  var staleEffect: bool // history observer: an effect after a participant's tombstone

  action init = all {
    phase' = AGENTS.mapBy(_ => Live), running' = Set(), startIntent' = Set(),
    requests' = Map(), nextReq' = 0, inFlight' = Set(), staleEffect' = false,
  }
  val vars = (phase, running, startIntent, requests, nextReq, inFlight, staleEffect)
  action keepAgents = all { phase' = phase, running' = running, startIntent' = startIntent }
  action keepWork = all {
    requests' = requests, nextReq' = nextReq, inFlight' = inFlight, staleEffect' = staleEffect,
  }
  def live(a: str): bool = phase.get(a) == Live
  def touches(q: Request, a: str): bool = q.sender == a or q.recipient == a
  def pendingFor(a: str): Set[int] = requests.keys().filter(i =>
    requests.get(i).recipient == a and requests.get(i).event == Queued)
  def queueHead(a: str): int = pendingFor(a).fold(MAX_REQS, (n, i) => if (i < n) i else n)

  action submit(a: str, b: str): bool = all {
    a != b, live(a), live(b), nextReq < MAX_REQS,
    requests' = requests.put(nextReq, { sender: a, recipient: b, state: Working,
      event: Queued, attempts: 0, effects: 0 }),
    nextReq' = nextReq + 1, inFlight' = inFlight, staleEffect' = staleEffect, keepAgents,
  }
  action readStart(a: str): bool = all {
    live(a), not(running.contains(a)), not(startIntent.contains(a)),
    startIntent' = startIntent.union(Set(a)), phase' = phase, running' = running, keepWork,
  }
  action launch(a: str): bool = all {
    startIntent.contains(a),
    if (LAUNCH_FENCE) live(a) else true,
    running' = running.union(Set(a)), startIntent' = startIntent.exclude(Set(a)),
    phase' = phase, keepWork,
  }
  action beginDelivery(i: int): bool = {
    val q = requests.get(i)
    all {
      requests.keys().contains(i), q.state == Working, q.event == Queued,
      q.attempts < MAX_ATTEMPTS, live(q.sender), live(q.recipient),
      running.contains(q.recipient), i == queueHead(q.recipient), not(inFlight.contains(i)),
      inFlight' = inFlight.union(Set(i)), requests' = requests, nextReq' = nextReq,
      staleEffect' = staleEffect, keepAgents,
    }
  }
  // success=false: failed delivery; processed=true, success=false: lost ACK.
  // DELIVERY_FENCE is a contract at the effect's linearization point, serialized
  // with deletion/expiration. A check before an unsynchronized external effect
  // does NOT implement this contract. Effects already applied are not undone.
  action finishDelivery(i: int, processed: bool, success: bool): bool = {
    val q = requests.get(i)
    val allowed = live(q.sender) and live(q.recipient) and q.state == Working and q.event == Queued
    val attempts = q.attempts + 1
    // The durable effect counter also abstracts the deduplication marker here.
    val applyEffect = processed and q.effects == 0
    all {
      inFlight.contains(i), (not(success) or processed),
      if (DELIVERY_FENCE) allowed else true,
      requests' = requests.set(i, { ...q, attempts: attempts,
        effects: if (applyEffect) q.effects + 1 else q.effects,
        event: if (success) Done else if (attempts >= MAX_ATTEMPTS) Dead else Queued }),
      inFlight' = inFlight.exclude(Set(i)),
      staleEffect' = (staleEffect or (applyEffect and not(allowed))),
      nextReq' = nextReq, keepAgents,
    }
  }
  // Discard a completion whose deletion/expiration fence is no longer valid.
  action discardDelivery(i: int): bool = all {
    inFlight.contains(i),
    requests.get(i).state == Terminal,
    inFlight' = inFlight.exclude(Set(i)), requests' = requests,
    nextReq' = nextReq, staleEffect' = staleEffect, keepAgents,
  }
  action finishRequest(i: int): bool = all {
    requests.keys().contains(i), requests.get(i).state == Working,
    requests.get(i).event == Done or requests.get(i).event == Dead,
    requests' = requests.set(i, { ...requests.get(i), state: Terminal }),
    nextReq' = nextReq, inFlight' = inFlight, staleEffect' = staleEffect, keepAgents,
  }
  action expire(i: int): bool = all {
    requests.keys().contains(i), requests.get(i).state == Working,
    requests' = requests.set(i, { ...requests.get(i), state: Terminal,
      event: if (requests.get(i).event == Queued) Canceled else requests.get(i).event }),
    nextReq' = nextReq, inFlight' = inFlight, staleEffect' = staleEffect, keepAgents,
  }
  action requestDelete(a: str): bool = all {
    live(a), phase' = phase.set(a, Deleting),
    requests' = if (CANCEL_ON_DELETE) requests.keys().mapBy(i => {
      val q = requests.get(i)
      if (touches(q, a)) { ...q, state: Terminal,
        event: if (q.event == Queued) Canceled else q.event } else q
    }) else requests,
    running' = running, startIntent' = startIntent,
    // In-flight work survives this transaction, exposing delayed completions.
    inFlight' = inFlight, nextReq' = nextReq, staleEffect' = staleEffect,
  }
  action finishDelete(a: str): bool = all {
    phase.get(a) == Deleting, phase' = phase.set(a, Deleted),
    running' = running.exclude(Set(a)), startIntent' = startIntent, keepWork,
  }
  action idle = all { keepAgents, keepWork }
  action step = {
    nondet a = AGENTS.oneOf()
    nondet b = AGENTS.oneOf()
    nondet i = 0.to(MAX_REQS - 1).oneOf()
    nondet processed = Set(false, true).oneOf()
    nondet success = Set(false, true).oneOf()
    any {
      submit(a, b), readStart(a), launch(a), beginDelivery(i),
      finishDelivery(i, processed, success), discardDelivery(i), finishRequest(i), expire(i),
      requestDelete(a), finishDelete(a), idle,
    }
  }
  val noVmAfterDelete = AGENTS.forall(a => phase.get(a) == Deleted implies not(running.contains(a)))
  val noLiveRequestForDeleted = requests.keys().forall(i => {
    val q = requests.get(i)
    not(live(q.sender) and live(q.recipient)) implies q.state == Terminal
  })
  val noQueuedEventForDeleted = requests.keys().forall(i => {
    val q = requests.get(i)
    not(live(q.sender) and live(q.recipient)) implies q.event != Queued
  })
  val noStaleEffect = not(staleEffect)
  val effectOnce = requests.keys().forall(i => requests.get(i).effects <= 1)
  val safety = noVmAfterDelete and noLiveRequestForDeleted and noQueuedEventForDeleted
               and noStaleEffect and effectOnce

  // Witness queries ensure deletion actually intersects queued and in-flight work.
  val noDeleteInFlight = not(AGENTS.exists(a => not(live(a)) and
    inFlight.exists(i => touches(requests.get(i), a))))
  val noThreeActors = not(requests.keys().size() >= 2 and AGENTS.forall(a =>
    requests.keys().exists(i => touches(requests.get(i), a))))

  def terminal(i: int): bool = if (requests.keys().contains(i)) requests.get(i).state == Terminal else false
  temporal fair = (AGENTS.forall(a => finishDelete(a).weakFair(vars))) and
    0.to(MAX_REQS - 1).forall(i => expire(i).weakFair(vars) and discardDelivery(i).weakFair(vars))
  temporal requestsTerminate = 0.to(MAX_REQS - 1).forall(i =>
    always(requests.keys().contains(i) implies eventually(terminal(i))))
  temporal deletionsFinish = AGENTS.forall(a =>
    always(phase.get(a) == Deleting implies eventually(phase.get(a) == Deleted)))
  temporal workDrains = eventually(always(inFlight.size() == 0 and
    AGENTS.forall(a => pendingFor(a).size() == 0)))
  temporal progress = fair implies (requestsTerminate and deletionsFinish and workDrains)
}

module compositionOk {
  import composition(AGENTS = Set("a", "b"), MAX_REQS = 2, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = true, DELIVERY_FENCE = true, LAUNCH_FENCE = true).*

  run deletionDuringDeliveryTest = init.then(submit("a", "b"))
    .then(readStart("b")).then(launch("b")).then(beginDelivery(0))
    .then(requestDelete("b")).expect(safety)
    .then(finishDelivery(0, true, true).fail())

  run deletionDuringStartTest = init.then(readStart("b"))
    .then(requestDelete("b")).then(finishDelete("b")).expect(safety)
    .then(launch("b").fail())

  run deletingSenderCancelsQueueTest = init.then(submit("a", "b"))
    .then(requestDelete("a")).expect(noLiveRequestForDeleted and noQueuedEventForDeleted)
    .then(submit("a", "b").fail())
}
module compositionLarge {
  import composition(AGENTS = Set("a", "b", "c"), MAX_REQS = 4, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = true, DELIVERY_FENCE = true, LAUNCH_FENCE = true).*
}
module compositionNoCancel {
  import composition(AGENTS = Set("a", "b"), MAX_REQS = 2, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = false, DELIVERY_FENCE = true, LAUNCH_FENCE = true).*
}
module compositionNoDeliveryFence {
  import composition(AGENTS = Set("a", "b"), MAX_REQS = 2, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = true, DELIVERY_FENCE = false, LAUNCH_FENCE = true).*

  // The observer must not mistake a deduplicated replay for a new effect.
  run duplicateAfterDeleteIsNotANewEffectTest = init.then(submit("a", "b"))
    .then(readStart("b")).then(launch("b")).then(beginDelivery(0))
    .then(finishDelivery(0, true, false)).then(beginDelivery(0))
    .then(requestDelete("b")).then(finishDelivery(0, true, false))
    .expect(noStaleEffect and requests.get(0).effects == 1)
}
module compositionNoLaunchFence {
  import composition(AGENTS = Set("a", "b"), MAX_REQS = 2, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = true, DELIVERY_FENCE = true, LAUNCH_FENCE = false).*
}
module compositionTiny {
  import composition(AGENTS = Set("a", "b"), MAX_REQS = 1, MAX_ATTEMPTS = 2,
    CANCEL_ON_DELETE = true, DELIVERY_FENCE = true, LAUNCH_FENCE = true).*
}
