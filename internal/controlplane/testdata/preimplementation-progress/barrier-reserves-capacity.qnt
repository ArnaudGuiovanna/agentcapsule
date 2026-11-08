module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, admit(1), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, arrive(0,false), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 3, deadline(0), pc' = pc+1, covered' = covered.union(Set("deadline")) },
    all { pc == 4, arrive(2,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 5, complete(1), pc' = pc+1, covered' = covered.union(Set("complete")) }
  }
  val checked = safety and (pc == 6 implies (s.running == Set() and barriersPending))
  val reached = pc == 6 and (s.running == Set() and barriersPending)
  action blockedAttempt0 = all { admit(2), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt0.fail())
}
