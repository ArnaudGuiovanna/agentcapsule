module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(1), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 3, stopVM(1), pc' = pc+1, covered' = covered.union(Set("stopVM")) },
    all { pc == 4, retireBoot(1), pc' = pc+1, covered' = covered.union(Set("retireBoot")) },
    all { pc == 5, observeStopped(1), pc' = pc+1, covered' = covered.union(Set("observeStopped")) },
    all { pc == 6, receive(0,0,AcceptCall,1), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 7, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 8, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) }
  }
  val checked = safety and (pc == 9 implies (s.requests.get(0).phase == Delivering and not(s.agents.get(1).alive)))
  val reached = pc == 9 and (s.requests.get(0).phase == Delivering and not(s.agents.get(1).alive))
}
