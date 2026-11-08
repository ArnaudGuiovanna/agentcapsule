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
    all { pc == 6, beginStop(0), pc' = pc+1, covered' = covered.union(Set("beginStop")) },
    all { pc == 7, publishBoot(0), pc' = pc+1, covered' = covered.union(Set("publishBoot")) },
    all { pc == 8, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) }
  }
  val checked = safety and (pc == 9 implies (s.agents.get(0).alive and s.agents.get(0).placement == Stopping and not(currentCaller(s,s.calls.get(0)))))
  val reached = pc == 9 and (s.agents.get(0).alive and s.agents.get(0).placement == Stopping and not(currentCaller(s,s.calls.get(0))))
}
