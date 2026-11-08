module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 3, claim(0,(0,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 4, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 5, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 6, requestDelete(1), pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 7, stopVM(1), pc' = pc+1, covered' = covered.union(Set("stopVM")) },
    all { pc == 8, retireBoot(1), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 9, observeStopped(1), pc' = pc+1, covered' = covered.union(Set("observeStopped")) },
    all { pc == 10, bootVM(1,true), pc' = pc+1, covered' = covered.union(Set("bootVM")) },
    all { pc == 11, launchBoot(1), pc' = pc+1, covered' = covered.union(Set("launchBoot")) },
    all { pc == 12, confirmBoot(1), pc' = pc+1, covered' = covered.union(Set("confirmBoot")) },
    all { pc == 13, publishBoot(1), pc' = pc+1, covered' = covered.union(Set("publishBoot")) },
    all { pc == 14, fenceStore(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 15, recordFence(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 16, fenceStore(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 17, recordFence(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 18, fenceStore(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 19, recordFence(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 20, commitDelete(1), pc' = pc+1, covered' = covered.union(Set("commitDelete")) }
  }
  val checked = safety and (pc == 21 implies (s.requests.get(0).phase == Canceled and s.effects.get((0,0)) == 0 and s.agents.get(1).fenceOnly))
  val reached = pc == 21 and (s.requests.get(0).phase == Canceled and s.effects.get((0,0)) == 0 and s.agents.get(1).fenceOnly)
}
