// -*- mode: Bluespec; -*-
/**
 * Model 3 — An agent's event queue and API idempotency keys.
 *
 * Covers (section numbers refer to the original, unpublished design specification):
 *   - point 3: at-least-once delivery, per-agent FIFO, dead-letter queue (§5.5, §8.2);
 *   - point 7: `Idempotency-Key` (§7.1).
 *
 * Abstractions:
 *   - a single agent (the queue is per agent);
 *   - the client may replay a request at will and lose responses;
 *   - a delivery has three outcomes: success, lost ACK (worker crash after processing
 *     by the harness), failure before processing.
 */
module delivery {
  const KEYS: Set[str]
  const BODIES: Set[str]
  const MAX_EVENTS: int
  const MAX_ATTEMPTS: int
  // The worker always delivers the pending event with the smallest `seq`.
  const FIFO_HEAD: bool
  // The harness deduplicates by `event_id` in its volume.
  const HARNESS_DEDUP: bool
  // An event that exhausts its budget moves to DEAD (otherwise it stays at the head).
  const DEAD_LETTER: bool
  // The idempotency key and the event are written in the same transaction.
  const ATOMIC_IDEM: bool

  type IdemState = Absent | InProgress | Done
  type EState = Pending | Delivered | Dead
  type Outcome = Ok | LostAck | Fail
  type Idem = { state: IdemState, body: str, seq: int }
  type Event = { key: str, body: str, state: EState, attempts: int }

  var idem: str -> Idem
  var events: int -> Event
  var nextSeq: int
  var responses: str -> Set[int]   // seq values returned to the client for each key (202 responses)
  var pendingWrite: str -> int     // non-atomic variant: event created, key not written yet (-1 = none)
  var seen: Set[int]               // harness deduplication store (volume)
  var effects: int -> int          // number of times each event's effect was applied
  var log: List[int]               // order of first processing by the harness

  action init = all {
    idem' = KEYS.mapBy(k => { state: Absent, body: "", seq: -1 }),
    events' = Map(),
    nextSeq' = 0,
    responses' = KEYS.mapBy(k => Set()),
    pendingWrite' = KEYS.mapBy(k => -1),
    seen' = Set(),
    effects' = Map(),
    log' = List(),
  }

  action keepHarness = all { seen' = seen, effects' = effects, log' = log }

  // --- API: POST with Idempotency-Key ---

  // Unknown key, atomic version: key + event in a single transaction.
  // `lost`: the response does not reach the client (it will replay).
  action apiNewAtomic(k: str, b: str, lost: bool): bool = all {
    ATOMIC_IDEM,
    idem.get(k).state == Absent,
    nextSeq < MAX_EVENTS,
    idem' = idem.set(k, { state: Done, body: b, seq: nextSeq }),
    events' = events.put(nextSeq, { key: k, body: b, state: Pending, attempts: 0 }),
    nextSeq' = nextSeq + 1,
    responses' = if (lost) responses else responses.setBy(k, s => s.union(Set(nextSeq))),
    pendingWrite' = pendingWrite, keepHarness,
  }

  // Non-atomic version: transaction 1 = event, transaction 2 = key.
  action apiNewStep1(k: str, b: str): bool = all {
    not(ATOMIC_IDEM),
    idem.get(k).state == Absent,
    pendingWrite.get(k) == -1,
    nextSeq < MAX_EVENTS,
    events' = events.put(nextSeq, { key: k, body: b, state: Pending, attempts: 0 }),
    nextSeq' = nextSeq + 1,
    pendingWrite' = pendingWrite.set(k, nextSeq),
    idem' = idem, responses' = responses, keepHarness,
  }

  action apiNewStep2(k: str): bool = {
    val s = pendingWrite.get(k)
    all {
      s != -1,
      idem' = idem.set(k, { state: Done, body: events.get(s).body, seq: s }),
      pendingWrite' = pendingWrite.set(k, -1),
      responses' = responses.setBy(k, r => r.union(Set(s))),
      events' = events, nextSeq' = nextSeq, keepHarness,
    }
  }

  // API crash between the two transactions: the key is never written.
  action apiCrash(k: str): bool = all {
    pendingWrite.get(k) != -1,
    pendingWrite' = pendingWrite.set(k, -1),
    idem' = idem, events' = events, nextSeq' = nextSeq, responses' = responses, keepHarness,
  }

  // Replay with the same body: the initial response is returned (no new event).
  action apiReplay(k: str, b: str): bool = all {
    idem.get(k).state == Done,
    idem.get(k).body == b,
    responses' = responses.setBy(k, s => s.union(Set(idem.get(k).seq))),
    idem' = idem, events' = events, nextSeq' = nextSeq, pendingWrite' = pendingWrite, keepHarness,
  }
  // Replay with another body: 422, nothing changes. Key in progress: 409, nothing changes.
  // These two cases have no state effect, so they are implicit.

  // --- worker: queue delivery ---

  def pendingSeqs: Set[int] = events.keys().filter(s => events.get(s).state == Pending)
  def headSeq: int = pendingSeqs.fold(MAX_EVENTS, (acc, s) => if (s < acc) s else acc)

  action deliver(s: int, o: Outcome): bool = {
    val e = events.get(s)
    val processed = o == Ok or o == LostAck
    val firstTime = not(seen.contains(s))
    val apply = processed and (firstTime or not(HARNESS_DEDUP))
    val att = e.attempts + 1
    // An attempt without ACK (failure OR lost ACK, observed when the lease expires) consumes
    // budget. Consequence: a DEAD event MAY have been processed by the harness.
    val nextState = if (o == Ok) Delivered
                    else if (att >= MAX_ATTEMPTS and DEAD_LETTER) Dead
                    else Pending
    all {
      events.keys().contains(s),
      e.state == Pending,
      e.attempts < MAX_ATTEMPTS,
      if (FIFO_HEAD) s == headSeq else true,
      events' = events.set(s, { ...e, state: nextState, attempts: att }),
      seen' = if (processed) seen.union(Set(s)) else seen,
      effects' = if (apply) effects.put(s, (if (effects.keys().contains(s)) effects.get(s) else 0) + 1) else effects,
      log' = if (processed and firstTime) log.append(s) else log,
      idem' = idem, nextSeq' = nextSeq, responses' = responses, pendingWrite' = pendingWrite,
    }
  }

  action step = {
    nondet k = KEYS.oneOf()
    nondet b = BODIES.oneOf()
    nondet lost = Set(true, false).oneOf()
    nondet s = 0.to(MAX_EVENTS - 1).oneOf()
    nondet o = Set(Ok, LostAck, Fail).oneOf()
    any {
      apiNewAtomic(k, b, lost), apiNewStep1(k, b), apiNewStep2(k), apiCrash(k),
      apiReplay(k, b), deliver(s, o),
    }
  }

  // Exact same transition relation as step for nonempty choice domains (all instances here).
  // Distribute existential choices over disjunction and drop unused choices in each branch.
  // TLC otherwise enumerates their Cartesian product even for unrelated actions.
  // Keep step unchanged for comparison and historical random-simulation seeds.
  action stepCompact = any {
    {
      nondet k = KEYS.oneOf()
      nondet b = BODIES.oneOf()
      nondet lost = Set(true, false).oneOf()
      apiNewAtomic(k, b, lost)
    },
    {
      nondet k = KEYS.oneOf()
      nondet b = BODIES.oneOf()
      apiNewStep1(k, b)
    },
    {
      nondet k = KEYS.oneOf()
      apiNewStep2(k)
    },
    {
      nondet k = KEYS.oneOf()
      apiCrash(k)
    },
    {
      nondet k = KEYS.oneOf()
      nondet b = BODIES.oneOf()
      apiReplay(k, b)
    },
    {
      nondet s = 0.to(MAX_EVENTS - 1).oneOf()
      nondet o = Set(Ok, LostAck, Fail).oneOf()
      deliver(s, o)
    },
  }

  // --- properties ---

  // Point 3 — an event's effect is applied only once despite redeliveries.
  val effectOnce: bool = effects.keys().forall(s => effects.get(s) <= 1)

  // Point 3 — FIFO: the harness processes events in `seq` order.
  val fifo: bool = 0.to(log.length() - 2).forall(i => log[i] < log[i + 1])

  // Point 3 — no head-of-line blocking: a pending event always has an
  // attempt available (otherwise it would have moved to DEAD).
  val noHeadOfLineBlocking: bool = pendingSeqs.forall(s => events.get(s).attempts < MAX_ATTEMPTS)

  // Point 7 — at most one event per idempotency key.
  val oneEventPerKey: bool = KEYS.forall(k =>
    events.keys().filter(s => events.get(s).key == k).size() <= 1)

  // Point 7 — all responses returned for a key designate the same event.
  val replayConsistent: bool = KEYS.forall(k => responses.get(k).size() <= 1)

  // Point 7 — a different body never creates an event.
  val bodyMatches: bool = events.keys().forall(s => {
    val e = events.get(s)
    idem.get(e.key).state == Done implies idem.get(e.key).body == e.body
  })

  val safety: bool = effectOnce and fifo and noHeadOfLineBlocking
                     and oneEventPerKey and replayConsistent and bodyMatches
}

// --- instances ---

module deliveryOk {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).*
}

module deliveryNoFifo {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = false, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).*
}

module deliveryNoDedup {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = false, DEAD_LETTER = true, ATOMIC_IDEM = true).*
}

module deliveryNoDeadLetter {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = false, ATOMIC_IDEM = true).*
}

module deliveryNonAtomicIdem {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1", "b2"), MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = false).*
}

module deliveryLarge {
  import delivery(KEYS = Set("k1", "k2", "k3", "k4"), BODIES = Set("b1", "b2", "b3"),
                  MAX_EVENTS = 4, MAX_ATTEMPTS = 3,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).*
}

module deliveryThreeKeys {
  import delivery(KEYS = Set("k1", "k2", "k3"), BODIES = Set("b1", "b2", "b3"),
                  MAX_EVENTS = 3, MAX_ATTEMPTS = 2,
                  FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).*
}
