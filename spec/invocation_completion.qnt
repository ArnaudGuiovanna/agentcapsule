// -*- mode: Bluespec; -*-
/**
 * Deferred invocation result.
 *
 * Delivering an instruction holds an exclusive host admission turn;
 * the guest's platform calls wait for that turn. An agent that must read a
 * file or call its model therefore answers "working": the delivery is closed
 * (FIFO advanced, delivery.qnt semantics unchanged), the operation stays
 * RUNNING, and the result arrives later through the platform channel.
 *
 * This model covers only the cycle after delivery, for one invocation:
 * completion by the agent (idempotency key, content, boot generation),
 * deadline, cancellation by the requester, agent deletion, restart.
 * Each transition is one PostgreSQL transaction under the lock of
 * the agent, then of the instruction/operation rows; they are therefore atomic.
 */
module invocationCompletion {
  pure val KEYS = Set("k1", "k2")
  pure val BODIES = Set("a", "b")
  pure val MAX_BOOT = 2

  type Status = Queued | Working | Completed | AgentFailed | TimedOut | Canceled
  var status: Status
  var syncResult: bool        // answer given within the delivery (original path)
  var due: bool               // result_due_at passed (abstract clock)
  var boot: int               // current generation of the agent
  var key: str                // completion_key ("" = aucune)
  var body: str               // content recorded with the key
  var resultVisible: bool     // a result readable by the requester exists
  var terminalWrites: int     // number of transitions to a terminal state
  var lateOrStale: bool       // witness: completion after the deadline or by an old boot

  action init = all {
    status' = Queued, syncResult' = false, due' = false, boot' = 1, key' = "", body' = "",
    resultVisible' = false, terminalWrites' = 0, lateOrStale' = false,
  }

  // Delivery with an immediate answer (unchanged) or a "working" acknowledgment.
  action deliverSync = all {
    status == Queued,
    status' = Completed, syncResult' = true, resultVisible' = true, terminalWrites' = terminalWrites + 1,
    due' = due, boot' = boot, key' = key, body' = body, lateOrStale' = lateOrStale,
  }
  action deliverWorking = all {
    status == Queued,
    status' = Working,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }
  action tick = all {
    status == Working, not(due), due' = true,
    status' = status, syncResult' = syncResult, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }
  // The agent restarts: the new generation may complete, the old one may not.
  action reboot = all {
    boot < MAX_BOOT, boot' = boot + 1,
    status' = status, syncResult' = syncResult, due' = due, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }

  // CompleteInvocationFromVM: authorizeVM refuses any boot other than the current one;
  // a key already set can only replay (same key and content) or refuse.
  action complete(gen: int, k: str, b: str, ok: bool): bool = all {
    gen == boot, key == "", status == Working, not(due),
    status' = if (ok) Completed else AgentFailed,
    key' = k, body' = b, resultVisible' = ok, terminalWrites' = terminalWrites + 1,
    lateOrStale' = (lateOrStale or due or gen != boot),
    syncResult' = syncResult, due' = due, boot' = boot,
  }
  // Replay (same key and content) or conflict: the response differs, the state does not.
  action completeAgain(gen: int, k: str, b: str): bool = all {
    gen == boot, key != "",
    status' = status, syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }
  action expire = all {
    status == Working, due, key == "",
    status' = TimedOut, terminalWrites' = terminalWrites + 1,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, lateOrStale' = lateOrStale,
  }
  // Cancellation by the requester, or agent deletion: same guard.
  action cancel = all {
    status == Working, key == "",
    status' = Canceled, terminalWrites' = terminalWrites + 1,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, lateOrStale' = lateOrStale,
  }
  action stutter = all {
    status' = status, syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }

  action step = any {
    deliverSync, deliverWorking, tick, reboot, expire, cancel, stutter,
    nondet gen = 1.to(MAX_BOOT).oneOf()
    nondet k = KEYS.oneOf()
    nondet b = BODIES.oneOf()
    nondet ok = Bool.oneOf()
    any { complete(gen, k, b, ok), completeAgain(gen, k, b) },
  }

  // A single outcome, never rewritten.
  val atMostOneOutcome = terminalWrites <= 1
  // A readable result exists exactly when the invocation completed successfully.
  val resultIffCompleted = resultVisible == (status == Completed)
  // A key exists only for an agent's completion, and freezes it.
  val keyOnlyForAgentOutcome = (key != "") == (status == Completed and not(syncResult) or status == AgentFailed)
  // Never a completion after the deadline, nor by an old boot.
  val noLateOrStaleCompletion = not(lateOrStale)
  val safety = atMostOneOutcome and resultIffCompleted and keyOnlyForAgentOutcome and noLateOrStaleCompletion
}
