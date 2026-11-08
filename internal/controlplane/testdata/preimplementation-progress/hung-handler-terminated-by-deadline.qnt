module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(0,false), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, deadline(0), pc' = pc+1, covered' = covered.union(Set("deadline")) },
    all { pc == 3, releaseExecution(0), pc' = pc+1, covered' = covered.union(Set("releaseExecution")) },
    all { pc == 4, fence(0,0), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 5, fence(0,1), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 6, commitClose(0), pc' = pc+1, covered' = covered.union(Set("commitClose")) },
    all { pc == 7, notify(0,true), pc' = pc+1, covered' = covered.union(Set("notify")) },
    all { pc == 8, observe(0), pc' = pc+1, covered' = covered.union(Set("observe")) }
  }
  val checked = safety and (pc == 9 implies (s.taggedObserved and s.jobs.get(0).result == Aborted))
  val reached = pc == 9 and (s.taggedObserved and s.jobs.get(0).result == Aborted)
}
