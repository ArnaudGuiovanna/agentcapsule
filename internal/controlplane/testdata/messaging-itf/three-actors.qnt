module messagingTrace {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3, MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true, CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).* from "./messaging"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, setVisibility("marc", true), pc' = pc + 1 },
    all { pc == 1, setVisibility("zoe", true), pc' = pc + 1 },
    all { pc == 2, instruct("arnaud"), pc' = pc + 1 },
    all { pc == 3, submit("arnaud", "marc", 0), pc' = pc + 1 },
    all { pc == 4, submit("arnaud", "zoe", 0), pc' = pc + 1 },
    all { pc == 5, instruct("marc"), pc' = pc + 1 },
    all { pc == 6, submit("marc", "zoe", 1), pc' = pc + 1 },
    all { pc == 7, accept(0), pc' = pc + 1 },
    all { pc == 8, deliver(0), pc' = pc + 1 },
    all { pc == 9, reply(0), pc' = pc + 1 },
    all { pc == 10, notifySender(0), pc' = pc + 1 },
    all { pc == 11, accept(1), pc' = pc + 1 },
    all { pc == 12, deliver(1), pc' = pc + 1 },
    all { pc == 13, reply(1), pc' = pc + 1 },
    all { pc == 14, notifySender(1), pc' = pc + 1 },
    all { pc == 15, accept(2), pc' = pc + 1 },
    all { pc == 16, deliver(2), pc' = pc + 1 },
    all { pc == 17, reply(2), pc' = pc + 1 },
    all { pc == 18, notifySender(2), pc' = pc + 1 }
  }
}
