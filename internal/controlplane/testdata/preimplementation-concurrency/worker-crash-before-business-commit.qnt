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
    all { pc == 2, crashWorker, pc' = pc+1, covered' = covered.union(Set("crashWorker")) },
    all { pc == 3, recoverWorker, pc' = pc+1, covered' = covered.union(Set("recoverWorker")) },
    all { pc == 4, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 5, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 6, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) }
  }
  val checked = safety and (pc == 7 implies (s.requests.get(0).accepted and s.mandates.get(0).remaining == 1))
  val reached = pc == 7 and (s.requests.get(0).accepted and s.mandates.get(0).remaining == 1)
}
