module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, arrive(0,false), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 3, requestDelete, pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 4, closeDeleted(0), pc' = pc+1, covered' = covered.union(Set("closeDeleted")) },
    all { pc == 5, releaseExecution(0), pc' = pc+1, covered' = covered.union(Set("releaseExecution")) },
    all { pc == 6, fence(0,0), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 7, fence(0,1), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 8, commitClose(0), pc' = pc+1, covered' = covered.union(Set("commitClose")) },
    all { pc == 9, finishDelete, pc' = pc+1, covered' = covered.union(Set("finishDelete")) },
    all { pc == 10, cancelNotification(0), pc' = pc+1, covered' = covered.union(Set("cancelNotification")) },
    all { pc == 11, retireNotification(0), pc' = pc+1, covered' = covered.union(Set("retireNotification")) },
    all { pc == 12, observe(0), pc' = pc+1, covered' = covered.union(Set("observe")) },
    all { pc == 13, admit(1), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 14, complete(1), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 15, notify(1,true), pc' = pc+1, covered' = covered.union(Set("notify")) }
  }
  val checked = safety and (pc == 16 implies (s.deleted and s.taggedObserved and s.jobs.get(0).delivery == Cancelled and s.jobs.get(1).delivery == Acked))
  val reached = pc == 16 and (s.deleted and s.taggedObserved and s.jobs.get(0).delivery == Cancelled and s.jobs.get(1).delivery == Acked)
}
