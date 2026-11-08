module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, arrive(0,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 2, arrive(2,true), pc' = pc+1, covered' = covered.union(Set("arrive")) }
  }
  val checked = safety and (pc == 3 implies (s.admissionQueue == List(1,0,2)))
  val reached = pc == 3 and (s.admissionQueue == List(1,0,2))
  action blockedAttempt0 = all { admit(0), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt0.fail())
}
