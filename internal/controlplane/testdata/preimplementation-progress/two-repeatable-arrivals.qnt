module preparedTrace {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./sources/service_progress"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, stabilize, pc' = pc+1, covered' = covered.union(Set("stabilize")) },
    all { pc == 1, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 2, admit(1), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 3, complete(1), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 4, notify(1,true), pc' = pc+1, covered' = covered.union(Set("notify")) },
    all { pc == 5, observe(1), pc' = pc+1, covered' = covered.union(Set("observe")) },
    all { pc == 6, recycle(1), pc' = pc+1, covered' = covered.union(Set("recycle")) },
    all { pc == 7, arrive(1,true), pc' = pc+1, covered' = covered.union(Set("arrive")) },
    all { pc == 8, admit(1), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 9, complete(1), pc' = pc+1, covered' = covered.union(Set("complete")) },
    all { pc == 10, notify(1,true), pc' = pc+1, covered' = covered.union(Set("notify")) },
    all { pc == 11, observe(1), pc' = pc+1, covered' = covered.union(Set("observe")) },
    all { pc == 12, recycle(1), pc' = pc+1, covered' = covered.union(Set("recycle")) }
  }
  val checked = safety and (pc == 13 implies (s == { ...initialState, stable: true }))
  val reached = pc == 13 and (s == { ...initialState, stable: true })
}
