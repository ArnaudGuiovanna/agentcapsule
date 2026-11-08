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
    all { pc == 6, commitEffect("w1"), pc' = pc + 1 },
    all { pc == 7, expireLease(0), pc' = pc + 1 },
    all { pc == 8, loseRPC("w1"), pc' = pc + 1 },
    all { pc == 9, claim("w1",0), pc' = pc + 1 },
    all { pc == 10, authorize("w1"), pc' = pc + 1 },
    all { pc == 11, beginEffect("w1"), pc' = pc + 1 },
    all { pc == 12, commitEffect("w1"), pc' = pc + 1 },
    all { pc == 13, acknowledge("w1"), pc' = pc + 1 }
  }
}
