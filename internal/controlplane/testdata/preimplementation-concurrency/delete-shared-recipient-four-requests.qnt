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
    all { pc == 6, receive(0,2,SubmitCall,2), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 7, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 8, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 9, receive(0,3,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 10, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 11, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 12, claim(0,(0,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 13, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 14, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 15, claim(1,(2,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 16, authorize(1), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 17, beginEffect(1), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 18, requestDelete(1), pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 19, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 20, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 21, commitEffect(1), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 22, acknowledge(1), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 23, fenceStore(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 24, recordFence(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 25, fenceStore(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 26, recordFence(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 27, fenceStore(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 28, recordFence(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 29, commitDelete(1), pc' = pc+1, covered' = covered.union(Set("commitDelete")) },
    all { pc == 30, claim(0,(0,2)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 31, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 32, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 33, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 34, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 35, receive(0,2,ReplyCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 36, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 37, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) }
  }
  val checked = safety and (pc == 38 implies (s.requests.get(0).phase == Canceled and s.requests.get(1).phase == Canceled and s.requests.get(2).phase == Replied and s.requests.get(3).phase == Delivering and s.requests.get(0).notified))
  val reached = pc == 38 and (s.requests.get(0).phase == Canceled and s.requests.get(1).phase == Canceled and s.requests.get(2).phase == Replied and s.requests.get(3).phase == Delivering and s.requests.get(0).notified)
}
