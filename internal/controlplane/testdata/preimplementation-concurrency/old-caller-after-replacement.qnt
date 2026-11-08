module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 1, stopVM(0), pc' = pc+1, covered' = covered.union(Set("stopVM")) },
    all { pc == 2, retireBoot(0), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 3, observeStopped(0), pc' = pc+1, covered' = covered.union(Set("observeStopped")) },
    all { pc == 4, bootVM(0,false), pc' = pc+1, covered' = covered.union(Set("bootVM")) },
    all { pc == 5, launchBoot(0), pc' = pc+1, covered' = covered.union(Set("launchBoot")) },
    all { pc == 6, confirmBoot(0), pc' = pc+1, covered' = covered.union(Set("confirmBoot")) },
    all { pc == 7, publishBoot(0), pc' = pc+1, covered' = covered.union(Set("publishBoot")) }
  }
  val checked = safety and (pc == 8 implies (s.calls.get(0).generation == 1 and s.agents.get(0).generation == 2))
  val reached = pc == 8 and (s.calls.get(0).generation == 1 and s.agents.get(0).generation == 2)
  action blockedAttempt0 = all { admit(0), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt0.fail())
}
