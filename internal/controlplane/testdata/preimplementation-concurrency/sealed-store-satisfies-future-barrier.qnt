module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, requestDelete(1), pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 1, fenceStore(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 2, recordFence(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 3, fenceStore(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 4, recordFence(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 5, fenceStore(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 6, recordFence(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 7, commitDelete(1), pc' = pc+1, covered' = covered.union(Set("commitDelete")) },
    all { pc == 8, stopVM(1), pc' = pc+1, covered' = covered.union(Set("stopVM")) },
    all { pc == 9, retireBoot(1), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 10, observeStopped(1), pc' = pc+1, covered' = covered.union(Set("observeStopped")) },
    all { pc == 11, sealStore(1), pc' = pc+1, covered' = covered.union(Set("sealStore")) },
    all { pc == 12, receive(0,2,SubmitCall,2), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 13, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 14, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 15, closeRequest(2,CancelRequest), pc' = pc+1, covered' = covered.union(Set("closeRequest")) },
    all { pc == 16, fenceStore(0,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 17, recordFence(0,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 18, fenceStore(1,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 19, recordFence(1,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 20, fenceStore(2,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 21, recordFence(2,RequestSubject(2)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 22, commitClose(2), pc' = pc+1, covered' = covered.union(Set("commitClose")) }
  }
  val checked = safety and (pc == 23 implies (s.agents.get(1).sealed and s.requests.get(2).phase == Canceled))
  val reached = pc == 23 and (s.agents.get(1).sealed and s.requests.get(2).phase == Canceled)
}
