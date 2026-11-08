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
    all { pc == 3, receive(0,1,SubmitCall,2), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 4, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 5, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 6, closeRequest(0,ExpireRequest), pc' = pc+1, covered' = covered.union(Set("closeRequest")) },
    all { pc == 7, fenceStore(0,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 8, recordFence(0,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 9, fenceStore(1,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 10, recordFence(1,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 11, fenceStore(2,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 12, recordFence(2,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 13, commitClose(0), pc' = pc+1, covered' = covered.union(Set("commitClose")) },
    all { pc == 14, claim(0,(1,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 15, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 16, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 17, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 18, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 19, claim(0,(0,2)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 20, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 21, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 22, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 23, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) }
  }
  val checked = safety and (pc == 24 implies (s.requests.get(0).phase == Expired and s.requests.get(1).phase == Processing and s.requests.get(0).notified))
  val reached = pc == 24 and (s.requests.get(0).phase == Expired and s.requests.get(1).phase == Processing and s.requests.get(0).notified)
}
