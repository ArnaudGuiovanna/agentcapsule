/**
 * A single harness database serializes local effects and revocation. The writer
 * lock is acquired BEFORE reading the fence, held through effect + inbox commit.
 * Fence ACK is sent only after its own durable transaction commits.
 * This is a per-store contract. A control-plane tombstone is not a local fence:
 * end-to-end deletion additionally requires a protocol fencing every participant.
 */
module localFence {
  const TRANSACTION_LOCK: bool
  const DURABLE_FENCE: bool
  type Phase = Idle | Read | Staged
  var up: bool
  var phase: Phase
  var owner: str
  var allowed: bool
  var fenceVisible: bool
  var fenceStable: bool
  var fencePending: bool
  var fenceAck: bool // observer at the revocation caller; survives server crashes
  var applied: bool // local effect + inbox, committed synchronously
  var staleEffect: bool // observer of actual commits after the barrier

  action init = all {
    up' = true, phase' = Idle, owner' = "", allowed' = false,
    fenceVisible' = false, fenceStable' = false, fencePending' = false,
    fenceAck' = false, applied' = false, staleEffect' = false,
  }
  action keepFence = all {
    fenceVisible' = fenceVisible, fenceStable' = fenceStable,
    fencePending' = fencePending, fenceAck' = fenceAck,
  }
  action keepEffect = all { applied' = applied, staleEffect' = staleEffect }
  action begin = all {
    up, phase == Idle, not(fenceVisible),
    if (TRANSACTION_LOCK) owner == "" else true,
    owner' = if (TRANSACTION_LOCK) "effect" else owner,
    phase' = Read, allowed' = not(fenceVisible), up' = up, keepFence, keepEffect,
  }
  action stage = all {
    up, phase == Read, phase' = Staged, owner' = owner, allowed' = allowed,
    up' = up, keepFence, keepEffect,
  }
  action commit = all {
    up, phase == Staged, allowed,
    applied' = true,
    staleEffect' = (staleEffect or (not(applied) and (fenceVisible or fenceAck))),
    phase' = Idle, owner' = if (owner == "effect") "" else owner,
    allowed' = false, up' = up, keepFence,
  }
  action revokeBegin = all {
    up, owner == "", not(fenceVisible),
    owner' = "revoke", phase' = phase, allowed' = allowed, up' = up,
    keepFence, keepEffect,
  }
  action revokeCommit = all {
    up, owner == "revoke", owner' = "",
    fenceVisible' = true, fenceStable' = if (DURABLE_FENCE) true else fenceStable,
    fencePending' = true, fenceAck' = fenceAck,
    up' = up, phase' = phase, allowed' = allowed, keepEffect,
  }
  action revokeAck = all {
    up, fencePending,
    fenceAck' = true, fencePending' = false,
    fenceVisible' = fenceVisible, fenceStable' = fenceStable,
    up' = up, phase' = phase, owner' = owner, allowed' = allowed, keepEffect,
  }
  action processCrash = all {
    up, up' = false, phase' = Idle, owner' = "", allowed' = false,
    fenceVisible' = fenceVisible, fenceStable' = fenceStable,
    fencePending' = false, fenceAck' = fenceAck, keepEffect,
  }
  action powerLoss = all {
    up' = false, phase' = Idle, owner' = "", allowed' = false,
    fenceVisible' = fenceStable, fenceStable' = fenceStable,
    fencePending' = false, fenceAck' = fenceAck, keepEffect,
  }
  action recover = all {
    not(up), up' = true, phase' = phase, owner' = owner, allowed' = allowed,
    keepFence, keepEffect,
  }
  action step = any {
    begin, stage, commit, revokeBegin, revokeCommit, revokeAck,
    processCrash, powerLoss, recover,
  }
  val noStaleEffect = not(staleEffect)
  val ackFenceSurvives = fenceAck implies fenceVisible
  val safety = noStaleEffect and ackFenceSurvives
}
module fencingOk {
  import localFence(TRANSACTION_LOCK = true, DURABLE_FENCE = true).*

  run fenceWaitsForEffectTest = init.then(begin).then(stage).then(revokeBegin.fail())

  run effectBeforeFenceTest = init.then(begin).then(stage).then(commit)
    .then(revokeBegin).then(revokeCommit).then(revokeAck).then(powerLoss).then(recover)
    .expect(safety and applied and fenceAck).then(begin.fail())

  run fenceBeforeEffectTest = init.then(revokeBegin).then(revokeCommit).then(revokeAck)
    .expect(safety and not(applied)).then(begin.fail())
}
module fencingRacyCheck {
  import localFence(TRANSACTION_LOCK = false, DURABLE_FENCE = true).*
}
module fencingVolatileFence {
  import localFence(TRANSACTION_LOCK = true, DURABLE_FENCE = false).*
}
