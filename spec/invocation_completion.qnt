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
 *
 * The output stream (ADR 022). While the invocation is working, its agent's
 * current boot may open an output stream over the platform channel; the
 * opening binds it to the invocation's current attempt. The worker coalesces
 * the stream's deltas into chunks; each chunk is committed by one transaction
 * under the same locks, which checks again what the opening checked: the
 * stream's boot is current, the invocation is working and before its
 * deadline, and the stream's attempt is the current one. The stream itself
 * lives in the worker's memory, on the duplex connection: an outcome's
 * transaction cannot close it, so the stream closes later, at any time
 * (closeStream). A restore's rerun gives the invocation a new attempt and
 * deletes the previous attempt's chunks in the same transaction
 * (resetAttempt); an old stream may still be open then.
 *
 * Deltas are never an outcome: no stream action writes the status, the key,
 * the body or the result. A rerun of an invocation whose outcome a restore
 * declared lost, and the replay of a dead letter, also start a new attempt,
 * but from an outcome, which this model's single outcome per invocation does
 * not cover (restore_authority.qnt and concurrent_protocol.qnt do). Their
 * stream rule is the same: a new attempt, the old chunks deleted.
 */
module invocationCompletionModel {
  // Each chunk's transaction checks again that the stream's boot is current
  // and that the invocation is working and before its deadline (false: it
  // trusts the open stream).
  const RECHECK_STATE: bool
  // Each chunk's transaction checks that the stream's attempt is the
  // invocation's current one (false: it does not).
  const RECHECK_ATTEMPT: bool
  // The stream's close frame files the streamed text as the result (true: the
  // shortcut ADR 022 forbids).
  const CLOSE_IS_OUTCOME: bool

  pure val KEYS = Set("k1", "k2")
  pure val BODIES = Set("a", "b")
  pure val MAX_BOOT = 2
  pure val MAX_ATTEMPT = 2

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
  var attempt: int            // the invocation's current attempt (owner_instructions.attempt)
  var streamOpen: bool        // the worker holds an open output stream for the invocation
  var streamBoot: int         // the boot generation that opened it
  var streamAttempt: int      // the attempt the opening bound it to
  var chunks: Set[int]        // stored chunks, by the attempt of the stream that produced them
  var deltaAfterOutcome: bool // witness: a chunk committed while the invocation had its outcome
  var outcomeByStream: bool   // witness: a stream action wrote the outcome

  val terminal = Set(Completed, AgentFailed, TimedOut, Canceled).contains(status)

  action init = all {
    status' = Queued, syncResult' = false, due' = false, boot' = 1, key' = "", body' = "",
    resultVisible' = false, terminalWrites' = 0, lateOrStale' = false,
    attempt' = 1, streamOpen' = false, streamBoot' = 0, streamAttempt' = 0, chunks' = Set(),
    deltaAfterOutcome' = false, outcomeByStream' = false,
  }

  // The stream's state, unchanged by the invocation's own transitions.
  action streamUnchanged = all {
    attempt' = attempt, streamOpen' = streamOpen, streamBoot' = streamBoot, streamAttempt' = streamAttempt,
    chunks' = chunks, deltaAfterOutcome' = deltaAfterOutcome, outcomeByStream' = outcomeByStream,
  }
  // The invocation's state, unchanged by the stream's actions.
  action outcomeUnchanged = all {
    status' = status, syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
  }

  // Delivery with an immediate answer (unchanged) or a "working" acknowledgment.
  action deliverSync = all {
    status == Queued,
    status' = Completed, syncResult' = true, resultVisible' = true, terminalWrites' = terminalWrites + 1,
    due' = due, boot' = boot, key' = key, body' = body, lateOrStale' = lateOrStale,
    streamUnchanged,
  }
  action deliverWorking = all {
    status == Queued,
    status' = Working,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamUnchanged,
  }
  action tick = all {
    status == Working, not(due), due' = true,
    status' = status, syncResult' = syncResult, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamUnchanged,
  }
  // The agent restarts: the new generation may complete, the old one may not.
  action reboot = all {
    boot < MAX_BOOT, boot' = boot + 1,
    status' = status, syncResult' = syncResult, due' = due, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamUnchanged,
  }

  // CompleteInvocationFromVM: authorizeVM refuses any boot other than the current one;
  // a key already set can only replay (same key and content) or refuse.
  action complete(gen: int, k: str, b: str, ok: bool): bool = all {
    gen == boot, key == "", status == Working, not(due),
    status' = if (ok) Completed else AgentFailed,
    key' = k, body' = b, resultVisible' = ok, terminalWrites' = terminalWrites + 1,
    lateOrStale' = (lateOrStale or due or gen != boot),
    syncResult' = syncResult, due' = due, boot' = boot,
    streamUnchanged,
  }
  // Replay (same key and content) or conflict: the response differs, the state does not.
  action completeAgain(gen: int, k: str, b: str): bool = all {
    gen == boot, key != "",
    status' = status, syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamUnchanged,
  }
  action expire = all {
    status == Working, due, key == "",
    status' = TimedOut, terminalWrites' = terminalWrites + 1,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, lateOrStale' = lateOrStale,
    streamUnchanged,
  }
  // Cancellation by the requester, or agent deletion: same guard.
  action cancel = all {
    status == Working, key == "",
    status' = Canceled, terminalWrites' = terminalWrites + 1,
    syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, lateOrStale' = lateOrStale,
    streamUnchanged,
  }

  // A restore's rerun (scheduleReruns): the invocation runs again under the
  // same identifier, with a new attempt and a new deadline. The same
  // transaction deletes the previous attempt's chunks. An old stream may still
  // be open in the worker.
  action resetAttempt = all {
    status == Working, key == "", attempt < MAX_ATTEMPT,
    status' = Queued, attempt' = attempt + 1, due' = false, chunks' = Set(),
    syncResult' = syncResult, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamOpen' = streamOpen, streamBoot' = streamBoot, streamAttempt' = streamAttempt,
    deltaAfterOutcome' = deltaAfterOutcome, outcomeByStream' = outcomeByStream,
  }

  // POST /v1/invocations/stream, its opening transaction: the caller is the
  // current boot (authorizeVM), the invocation is working and before its
  // deadline. The stream is bound to the current attempt. A harness that opens
  // it again names the attempt the first opening gave it (att > 0), which must
  // still be current; a first opening names none (att == 0).
  def mayOpen(gen: int, att: int): bool =
    not(streamOpen) and gen == boot and status == Working and not(due) and (att == 0 or att == attempt)
  action openStream(gen: int, att: int): bool = all {
    mayOpen(gen, att),
    streamOpen' = true, streamBoot' = gen, streamAttempt' = attempt,
    attempt' = attempt, chunks' = chunks, deltaAfterOutcome' = deltaAfterOutcome, outcomeByStream' = outcomeByStream,
    outcomeUnchanged,
  }

  // The worker commits a chunk of the open stream's deltas.
  val mayAppend = streamOpen
    and (not(RECHECK_STATE) or (streamBoot == boot and status == Working and not(due)))
    and (not(RECHECK_ATTEMPT) or streamAttempt == attempt)
  action appendDelta = all {
    mayAppend,
    chunks' = chunks.union(Set(streamAttempt)),
    deltaAfterOutcome' = (deltaAfterOutcome or terminal),
    attempt' = attempt, streamOpen' = streamOpen, streamBoot' = streamBoot, streamAttempt' = streamAttempt,
    outcomeByStream' = outcomeByStream,
    outcomeUnchanged,
  }

  // The stream closes: the harness's close frame, a broken connection, or the
  // platform after it refused a chunk (an outcome, the deadline, a newer
  // attempt or boot). Under CLOSE_IS_OUTCOME, the close frame of a working
  // invocation files the streamed text as its result.
  action closeStream = {
    val files = CLOSE_IS_OUTCOME and status == Working and not(due) and key == ""
      and streamBoot == boot and streamAttempt == attempt
    all {
      streamOpen,
      streamOpen' = false,
      attempt' = attempt, streamBoot' = streamBoot, streamAttempt' = streamAttempt,
      chunks' = chunks, deltaAfterOutcome' = deltaAfterOutcome,
      if (files) all {
        status' = Completed, resultVisible' = true, terminalWrites' = terminalWrites + 1,
        outcomeByStream' = true,
        syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body, lateOrStale' = lateOrStale,
      } else all {
        outcomeByStream' = outcomeByStream,
        outcomeUnchanged,
      },
    }
  }

  action stutter = all {
    status' = status, syncResult' = syncResult, due' = due, boot' = boot, key' = key, body' = body,
    resultVisible' = resultVisible, terminalWrites' = terminalWrites, lateOrStale' = lateOrStale,
    streamUnchanged,
  }

  action step = any {
    deliverSync, deliverWorking, tick, reboot, expire, cancel, stutter,
    resetAttempt, appendDelta, closeStream,
    nondet gen = 1.to(MAX_BOOT).oneOf()
    nondet k = KEYS.oneOf()
    nondet b = BODIES.oneOf()
    nondet ok = Bool.oneOf()
    nondet att = 0.to(MAX_ATTEMPT).oneOf()
    any { complete(gen, k, b, ok), completeAgain(gen, k, b), openStream(gen, att) },
  }

  // A single outcome, never rewritten.
  val atMostOneOutcome = terminalWrites <= 1
  // A readable result exists exactly when the invocation completed successfully.
  val resultIffCompleted = resultVisible == (status == Completed)
  // A key exists only for an agent's completion, and freezes it.
  val keyOnlyForAgentOutcome = (key != "") == (status == Completed and not(syncResult) or status == AgentFailed)
  // Never a completion after the deadline, nor by an old boot.
  val noLateOrStaleCompletion = not(lateOrStale)
  // No chunk is committed once the invocation has its outcome.
  val noDeltaAfterOutcome = not(deltaAfterOutcome)
  // Every stored chunk comes from a stream of the invocation's current attempt.
  val deltaMatchesCurrentAttempt = chunks.forall(a => a == attempt)
  // A stream never writes the outcome: a result comes only from the delivery's
  // answer or from a completion.
  val deltasNeverAnOutcome = not(outcomeByStream) and (resultVisible implies (syncResult or key != ""))
  val streamSafety = noDeltaAfterOutcome and deltaMatchesCurrentAttempt and deltasNeverAnOutcome
  val safety = atMostOneOutcome and resultIffCompleted and keyOnlyForAgentOutcome and noLateOrStaleCompletion
    and streamSafety

  // Reachability targets of the simulation (--witnesses): the races that the
  // chunks' checks decide.
  val staleStreamWitness = streamOpen and streamAttempt != attempt and status == Working
  val streamOpenAtOutcomeWitness = streamOpen and terminal
}

module invocationCompletion {
  import invocationCompletionModel(RECHECK_STATE = true, RECHECK_ATTEMPT = true, CLOSE_IS_OUTCOME = false).*

  // A stream opens only for a working invocation, from its agent's current
  // boot, before its deadline.
  run openStreamOnlyWhileWorkingTest = init
    .expect(not(mayOpen(1, 0)))
    .then(deliverWorking)
    .then(reboot)
    .expect(not(mayOpen(1, 0)))
    .expect(not(mayOpen(2, 2)))
    .then(openStream(2, 0))
    .expect(streamOpen and streamAttempt == 1 and streamBoot == 2)
    .then(closeStream)
    .then(tick)
    .expect(not(mayOpen(2, 1)))
    .then(expire)
    .expect(not(mayOpen(2, 1)))
    .expect(safety)

  // An outcome stops the chunks, although the stream is still open.
  run noChunkAfterTheOutcomeTest = init
    .then(deliverWorking)
    .then(openStream(1, 0))
    .then(appendDelta)
    .then(complete(1, "k1", "a", true))
    .expect(streamOpen and streamOpenAtOutcomeWitness)
    .expect(not(mayAppend))
    .then(closeStream)
    .expect(status == Completed and chunks == Set(1) and safety)

  // A cancellation stops the chunks too; the stream then closes.
  run cancelStopsTheChunksTest = init
    .then(deliverWorking)
    .then(openStream(1, 0))
    .then(appendDelta)
    .then(cancel)
    .expect(not(mayAppend))
    .then(closeStream)
    .expect(status == Canceled and not(resultVisible) and safety)

  // A rerun deletes the old attempt's chunks; the old stream, still open,
  // stores nothing for the new attempt, and cannot be opened again under its
  // attempt.
  run rerunDropsTheOldAttemptTest = init
    .then(deliverWorking)
    .then(openStream(1, 0))
    .then(appendDelta)
    .then(resetAttempt)
    .expect(chunks == Set() and attempt == 2)
    .then(deliverWorking)
    .expect(staleStreamWitness)
    .expect(not(mayAppend))
    .then(closeStream)
    .expect(not(mayOpen(1, 1)))
    .then(openStream(1, 0))
    .then(appendDelta)
    .expect(chunks == Set(2) and streamAttempt == 2 and safety)

  // Closing the stream is not an outcome: the invocation keeps working, and
  // its deadline still ends it without a result.
  run closingTheStreamIsNotAnOutcomeTest = init
    .then(deliverWorking)
    .then(openStream(1, 0))
    .then(appendDelta)
    .then(closeStream)
    .expect(status == Working and not(resultVisible))
    .then(tick)
    .then(expire)
    .expect(status == TimedOut and not(resultVisible) and chunks == Set(1) and safety)
}

// Broken configurations: each must yield a counterexample (scripts/check-models.py).
module invocationCompletionTrustsTheStream {
  import invocationCompletionModel(RECHECK_STATE = false, RECHECK_ATTEMPT = true, CLOSE_IS_OUTCOME = false).*
}
module invocationCompletionAnyAttempt {
  import invocationCompletionModel(RECHECK_STATE = true, RECHECK_ATTEMPT = false, CLOSE_IS_OUTCOME = false).*
}
module invocationCompletionCloseFiles {
  import invocationCompletionModel(RECHECK_STATE = true, RECHECK_ATTEMPT = true, CLOSE_IS_OUTCOME = true).*
}
