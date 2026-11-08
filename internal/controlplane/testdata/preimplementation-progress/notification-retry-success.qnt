module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(0,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, complete(0), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 3, notify(0,false), pc' = pc+1, covered' = covered.union(Set("notify")) },
    all { pc == 4, notify(0,true), pc' = pc+1, covered' = covered.union(Set("notify")) }
  }
  val checked = safety and (pc == 5 implies (s.jobs.get(0).delivery == Acked and s.jobs.get(0).attempts == 2))
  val reached = pc == 5 and (s.jobs.get(0).delivery == Acked and s.jobs.get(0).attempts == 2)
}
