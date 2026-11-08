module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(0,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, crashWorker, pc' = pc+1, covered' = covered.union(Set("crashWorker")) },
    all { pc == 2, stabilize, pc' = pc+1, covered' = covered.union(Set("stabilize")) },
    all { pc == 3, recoverWorker, pc' = pc+1, covered' = covered.union(Set("recoverWorker")) },
    all { pc == 4, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 5, complete(0), pc' = pc+1, covered' = covered.union(Set("complete")) }
  }
  val checked = safety and (pc == 6 implies (s.jobs.get(0).inbox and s.workerUp))
  val reached = pc == 6 and (s.jobs.get(0).inbox and s.workerUp)
}
