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
    all { pc == 3, fence(0,1), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 4, stabilize, pc' = pc+1, covered' = covered.union(Set("stabilize")) },
    all { pc == 5, recoverStore(0), pc' = pc+1, covered' = covered.union(Set("recoverStore")) },
    all { pc == 6, fence(0,0), pc' = pc+1, covered' = covered.union(Set("fence")) },
    all { pc == 7, commitClose(0), pc' = pc+1, covered' = covered.union(Set("commitClose")) }
  }
  val checked = safety and (pc == 8 implies (s.jobs.get(0).inbox and s.stable))
  val reached = pc == 8 and (s.jobs.get(0).inbox and s.stable)
}
