module messagingTrace {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3, MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true, CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).* from "./messaging"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, setVisibility("marc", true), pc' = pc + 1 },
    all { pc == 1, syncAds("marc"), pc' = pc + 1 },
    all { pc == 2, search("arnaud"), pc' = pc + 1 },
    all { pc == 3, setVisibility("marc", false), pc' = pc + 1 },
    all { pc == 4, search("arnaud"), pc' = pc + 1 },
    all { pc == 5, deleteUser("marc"), pc' = pc + 1 },
    all { pc == 6, syncAds("marc"), pc' = pc + 1 }
  }
}
