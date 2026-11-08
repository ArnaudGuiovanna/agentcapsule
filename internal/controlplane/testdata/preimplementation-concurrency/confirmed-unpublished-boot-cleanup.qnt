module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, stopVM(0), pc' = pc+1, covered' = covered.union(Set("stopVM")) },
    all { pc == 1, retireBoot(0), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 2, observeStopped(0), pc' = pc+1, covered' = covered.union(Set("observeStopped")) },
    all { pc == 3, bootVM(0,false), pc' = pc+1, covered' = covered.union(Set("bootVM")) },
    all { pc == 4, launchBoot(0), pc' = pc+1, covered' = covered.union(Set("launchBoot")) },
    all { pc == 5, confirmBoot(0), pc' = pc+1, covered' = covered.union(Set("confirmBoot")) },
    all { pc == 6, crashWorker, pc' = pc+1, covered' = covered.union(Set("crashWorker")) },
    all { pc == 7, recoverWorker, pc' = pc+1, covered' = covered.union(Set("recoverWorker")) },
    all { pc == 8, retireBoot(0), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 9, observeStopped(0), pc' = pc+1, covered' = covered.union(Set("observeStopped")) }
  }
  val checked = safety and (pc == 10 implies (s.agents.get(0).placement == Stopped and not(s.agents.get(0).alive)))
  val reached = pc == 10 and (s.agents.get(0).placement == Stopped and not(s.agents.get(0).alive))
}
