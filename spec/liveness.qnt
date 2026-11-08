/**
 * Temporal checks on the ORIGINAL transition relations, using small finite
 * instances for TLC. Fairness is assumed separately for each request/event.
 * These do not assume that the environment chooses to submit requests.
 */
module messagingLiveness {
  import messaging(USERS = Set("a", "b"), MAX_MANDATES = 1, MAX_REQS = 1,
    MAX_PER_MANDATE = 1, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
    CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).* from "./messaging"

  val vars = (discoverable, ads, mode, deleted, mandates, nextMandate,
              requests, nextReq, acceptIntent, lastSearch)
  def finished(i: int): bool = if (reqIds.contains(i)) isTerminal(requests.get(i).state) else false
  temporal fair = 0.to(MAX_REQS - 1).forall(i =>
    expire(i).weakFair(vars) and deliverFail(i).weakFair(vars))
  temporal terminates = 0.to(MAX_REQS - 1).forall(i =>
    always(reqIds.contains(i) implies eventually(finished(i))))
  temporal requestsTerminate = fair implies terminates
  // Negative control: the scheduler can otherwise postpone expiration forever.
  temporal requestsTerminateWithoutFairness = terminates
}

module deliveryLiveness {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1"), MAX_EVENTS = 2, MAX_ATTEMPTS = 2,
    FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true).* from "./delivery"

  val vars = (idem, events, nextSeq, responses, pendingWrite, seen, effects, log)
  action attempt(i: int): bool = {
    nondet o = Set(Ok, LostAck, Fail).oneOf()
    deliver(i, o)
  }
  temporal fair = 0.to(MAX_EVENTS - 1).forall(i => attempt(i).weakFair(vars))
  def final(i: int): bool = if (events.keys().contains(i)) events.get(i).state != Pending else false
  temporal eventsTerminate = fair implies 0.to(MAX_EVENTS - 1).forall(i =>
    always(events.keys().contains(i) implies eventually(final(i))))
  // Finite lifetime creation bound, no key/id reuse: production eventually stops.
  temporal queueDrains = fair implies eventually(always(pendingSeqs.size() == 0))
  temporal progress = eventsTerminate and queueDrains
}

module deliveryLivenessNoDeadLetter {
  import delivery(KEYS = Set("k1", "k2"), BODIES = Set("b1"), MAX_EVENTS = 2, MAX_ATTEMPTS = 2,
    FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = false, ATOMIC_IDEM = true).* from "./delivery"

  val vars = (idem, events, nextSeq, responses, pendingWrite, seen, effects, log)
  action attempt(i: int): bool = {
    nondet o = Set(Ok, LostAck, Fail).oneOf()
    deliver(i, o)
  }
  temporal fair = 0.to(MAX_EVENTS - 1).forall(i => attempt(i).weakFair(vars))
  def final(i: int): bool = if (events.keys().contains(i)) events.get(i).state != Pending else false
  temporal eventsTerminate = fair implies 0.to(MAX_EVENTS - 1).forall(i =>
    always(events.keys().contains(i) implies eventually(final(i))))
  // Finite lifetime creation bound, no key/id reuse: production eventually stops.
  temporal queueDrains = fair implies eventually(always(pendingSeqs.size() == 0))
  temporal progress = eventsTerminate and queueDrains
}
