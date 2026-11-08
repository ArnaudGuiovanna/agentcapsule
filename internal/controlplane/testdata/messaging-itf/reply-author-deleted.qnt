module messagingTrace {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3, MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true, CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).* from "./messaging"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, setVisibility("marc", true), pc' = pc + 1 },
    all { pc == 1, setMode("marc", Auto), pc' = pc + 1 },
    all { pc == 2, instruct("arnaud"), pc' = pc + 1 },
    all { pc == 3, submit("arnaud", "marc", 0), pc' = pc + 1 },
    all { pc == 4, deliver(0), pc' = pc + 1 },
    all { pc == 5, reply(0), pc' = pc + 1 },
    all { pc == 6, deleteUser("marc"), pc' = pc + 1 },
    all { pc == 7, notifySender(0), pc' = pc + 1 }
  }
}
