module protocolTrace {
  import protocolComposition(WAIT_ALL=true, SERIALIZE=true, DURABLE=true, CALLER_GUARD=true, OWNER_GUARD=true, DEDUP=true, STATUS_FREE=true, FRESH_STATUS=true, MAX_GEN=2).* from "./protocol_composition"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheCaller("a"), pc' = pc + 1 },
    all { pc == 1, admitSubmit("a"), pc' = pc + 1 },
    all { pc == 2, submit("a"), pc' = pc + 1 },
    all { pc == 3, claim("w1",0), pc' = pc + 1 },
    all { pc == 4, authorize("w1"), pc' = pc + 1 },
    all { pc == 5, beginEffect("w1"), pc' = pc + 1 },
    all { pc == 6, requestDelete, pc' = pc + 1 },
    all { pc == 7, commitEffect("w1"), pc' = pc + 1 },
    all { pc == 8, loseRPC("w1"), pc' = pc + 1 },
    all { pc == 9, fenceStore("a","agent/b"), pc' = pc + 1 },
    all { pc == 10, recordFence("a","agent/b"), pc' = pc + 1 },
    all { pc == 11, fenceStore("b","agent/b"), pc' = pc + 1 },
    all { pc == 12, recordFence("b","agent/b"), pc' = pc + 1 },
    all { pc == 13, fenceStore("c","agent/b"), pc' = pc + 1 },
    all { pc == 14, recordFence("c","agent/b"), pc' = pc + 1 },
    all { pc == 15, commitDelete, pc' = pc + 1 },
    all { pc == 16, claim("w1",2), pc' = pc + 1 },
    all { pc == 17, authorize("w1"), pc' = pc + 1 },
    all { pc == 18, beginEffect("w1"), pc' = pc + 1 },
    all { pc == 19, commitEffect("w1"), pc' = pc + 1 },
    all { pc == 20, acknowledge("w1"), pc' = pc + 1 }
  }
}
