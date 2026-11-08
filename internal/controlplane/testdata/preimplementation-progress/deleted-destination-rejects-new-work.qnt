module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, requestDelete, pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 1, finishDelete, pc' = pc+1, covered' = covered.union(Set("finishDelete")) }
  }
  val checked = safety and (pc == 2 implies (s.deleted))
  val reached = pc == 2 and (s.deleted)
  action blockedAttempt0 = all { arrive(0,true), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(blockedAttempt0.fail())
}
