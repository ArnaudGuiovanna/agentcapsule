/**
 * Depth wrappers for exhaustive TLC safety checks. Each original step, including
 * a stuttering one, increments depth once. There is no transition filtering.
 * The artificial frontier is a deadlock, intentionally ignored by TLC's -deadlock
 * flag. These wrappers are NOT suitable for liveness checking.
 */
module messagingDepth8 {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
    MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
    CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true) as M from "./messaging"
  var depth: int
  action init = all { M::init, depth' = 0 }
  action step = all { depth < 8, M::stepCompact, depth' = depth + 1 }
  val safety = M::safety
}

module messagingDepth10 {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
    MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
    CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true) as M from "./messaging"
  var depth: int
  action init = all { M::init, depth' = 0 }
  action step = all { depth < 10, M::stepCompact, depth' = depth + 1 }
  val safety = M::safety
}

module messagingLargeDepth8 {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 3, MAX_REQS = 4,
    MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
    CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true) as M from "./messaging"
  var depth: int
  action init = all { M::init, depth' = 0 }
  action step = all { depth < 8, M::stepCompact, depth' = depth + 1 }
  val safety = M::safety
}

module lifecycleLargeDepth10 {
  import lifecycle(AGENTS = Set("a", "b", "c"), JOBS = Set("j1", "j2", "j3"),
    MAX_ACTIVE = 2, MAX_GEN = 3, HOST_LOCK = true, RECONCILE_SCAN = true) as M from "./lifecycle"
  var depth: int
  action init = all { M::init, depth' = 0 }
  action step = all { depth < 10, M::stepCompact, depth' = depth + 1 }
  val safety = M::safety
}

module deliveryLargeDepth12 {
  import delivery(KEYS = Set("k1", "k2", "k3", "k4"), BODIES = Set("b1", "b2", "b3"),
    MAX_EVENTS = 4, MAX_ATTEMPTS = 3,
    FIFO_HEAD = true, HARNESS_DEDUP = true, DEAD_LETTER = true, ATOMIC_IDEM = true) as M from "./delivery"
  var depth: int
  action init = all { M::init, depth' = 0 }
  action step = all { depth < 12, M::stepCompact, depth' = depth + 1 }
  val safety = M::safety
}
