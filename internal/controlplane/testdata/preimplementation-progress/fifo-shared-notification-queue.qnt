module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(2,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, admit(2), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, complete(2), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 3, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 4, admit(1), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 5, complete(1), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 6, notify(2,true), pc' = pc+1, covered' = covered.union(Set("notify")) },
    all { pc == 7, notify(1,true), pc' = pc+1, covered' = covered.union(Set("notify")) }
  }
  val checked = safety and (pc == 8 implies (s.notificationQueue == List() and s.jobs.get(1).delivery == Acked and s.jobs.get(2).delivery == Acked))
  val reached = pc == 8 and (s.notificationQueue == List() and s.jobs.get(1).delivery == Acked and s.jobs.get(2).delivery == Acked)
}
