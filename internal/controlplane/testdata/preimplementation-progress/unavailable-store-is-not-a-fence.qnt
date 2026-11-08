module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(0,false), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, deadline(0), pc' = pc+1, covered' = covered.union(Set("deadline")) },
    all { pc == 2, loseStore(0), pc' = pc+1, covered' = covered.union(Set("loseStore")) },
    all { pc == 3, fence(0,1), pc' = pc+1, covered' = covered.union(Set("fence")) }
  }
  val checked = safety and (pc == 4 implies (s.jobs.get(0).barriers == Set(1)))
  val reached = pc == 4 and (s.jobs.get(0).barriers == Set(1))
  action blockedAttempt0 = all { commitClose(0), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt0.fail())
  action blockedAttempt1 = all { fence(0,0), pc' = pc, covered' = covered }
  run blocked1Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt1.fail())
}
