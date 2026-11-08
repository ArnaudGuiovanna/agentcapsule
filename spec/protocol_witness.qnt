/** Fixed schedules through original protocol actions. Minimality is relative
 * to the schedule only. Platform SQL admission precedes its separate commit.
 */
module protocolEnvelopeSchedule {
  const FRESH: bool
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true, OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=FRESH, MAX_GEN=2).* from "./protocol_composition"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheCaller("a"), pc' = pc+1 },
    all { pc == 1, admitSubmit("a"), pc' = pc+1 },
    all { pc == 2, submit("a"), pc' = pc+1 },
    all { pc == 3, claim("w1",0), pc' = pc+1 },
    all { pc == 4, authorize("w1"), pc' = pc+1 },
    all { pc == 5, beginEffect("w1"), pc' = pc+1 },
    all { pc == 6, commitEffect("w1"), pc' = pc+1 },
    all { pc == 7, acknowledge("w1"), pc' = pc+1 },
    all { pc == 8, cacheCaller("b"), pc' = pc+1 },
    all { pc == 9, admitReply, pc' = pc+1 },
    all { pc == 10, reply, pc' = pc+1 },
    all { pc == 11, claim("w1",1), pc' = pc+1 },
    all { pc == 12, authorize("w1"), pc' = pc+1 },
    all { pc == 13, beginEffect("w1"), pc' = pc+1 },
    all { pc == 14, commitEffect("w1"), pc' = pc+1 },
    all { pc == 15, loseRPC("w1"), pc' = pc+1 },
    all { pc == 16, requestDelete, pc' = pc+1 },
    all { pc == 17, fenceStore("a","agent/b"), pc' = pc+1 },
    all { pc == 18, recordFence("a","agent/b"), pc' = pc+1 },
    all { pc == 19, fenceStore("b","agent/b"), pc' = pc+1 },
    all { pc == 20, recordFence("b","agent/b"), pc' = pc+1 },
    all { pc == 21, fenceStore("c","agent/b"), pc' = pc+1 },
    all { pc == 22, recordFence("c","agent/b"), pc' = pc+1 },
    all { pc == 23, commitDelete, pc' = pc+1 },
    all { pc == 24, claim("w1",2), pc' = pc+1 },
    all { pc == 25, authorize("w1"), pc' = pc+1 },
    all { pc == 26, beginEffect("w1"), pc' = pc+1 },
    all { pc == 27, commitEffect("w1"), pc' = pc+1 },
    all { pc == 28, acknowledge("w1"), pc' = pc+1 }
  }
  val envelopeSafe = noConflictingEnvelope
  val effectsSafe = noStaleEffect
  val checked = safety
}
module protocolFenceSchedule {
  const SERIAL: bool
  import protocolComposition(WAIT_ALL=true, SERIALIZE=SERIAL, DURABLE=true, CALLER_GUARD=true, OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).* from "./protocol_composition"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheCaller("a"), pc' = pc+1 },
    all { pc == 1, admitSubmit("a"), pc' = pc+1 },
    all { pc == 2, submit("a"), pc' = pc+1 },
    all { pc == 3, claim("w1",0), pc' = pc+1 },
    all { pc == 4, authorize("w1"), pc' = pc+1 },
    all { pc == 5, beginEffect("w1"), pc' = pc+1 },
    all { pc == 6, requestDelete, pc' = pc+1 },
    all { pc == 7, fenceStore("a","agent/b"), pc' = pc+1 },
    all { pc == 8, recordFence("a","agent/b"), pc' = pc+1 },
    all { pc == 9, fenceStore("b","agent/b"), pc' = pc+1 },
    all { pc == 10, recordFence("b","agent/b"), pc' = pc+1 },
    all { pc == 11, fenceStore("c","agent/b"), pc' = pc+1 },
    all { pc == 12, recordFence("c","agent/b"), pc' = pc+1 },
    all { pc == 13, commitDelete, pc' = pc+1 },
    all { pc == 14, commitEffect("w1"), pc' = pc+1 }
  }
  val envelopeSafe = noConflictingEnvelope
  val effectsSafe = noStaleEffect
  val checked = safety
}
module protocolEnvelopeConforming { import protocolEnvelopeSchedule(FRESH=true).* }
module protocolEnvelopeReused { import protocolEnvelopeSchedule(FRESH=false).* }
module protocolFenceRacy { import protocolFenceSchedule(SERIAL=false).* }

// General negative control: retire SQL authority without waiting for the
// admitted platform transaction's participant row locks.
module protocolAuthorityNoLock {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true,
    OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).* from "./protocol_composition"
  action retireWithoutLock = all {
    s.up, s.placement.get("a") == "RUNNING",
    s' = { ...s, placement: s.placement.set("a","STOPPING"), bootLease: s.bootLease.set("a",false) },
  }
  action stepWithoutLock = any { step, retireWithoutLock }
}
