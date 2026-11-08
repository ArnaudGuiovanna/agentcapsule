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
    all { pc == 6, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 7, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 8, receive(0,0,ReplyCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 9, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 10, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 11, claim(0,(0,1)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 12, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 13, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 14, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 15, loseRPC(0), pc' = pc+1, covered' = covered.union(Set("loseRPC")) },
    all { pc == 16, requestDelete(1), pc' = pc+1, covered' = covered.union(Set("requestDelete")) },
    all { pc == 17, fenceStore(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 18, recordFence(0,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 19, fenceStore(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 20, recordFence(1,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 21, fenceStore(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 22, recordFence(2,AgentSubject(1)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 23, commitDelete(1), pc' = pc+1, covered' = covered.union(Set("commitDelete")) },
    all { pc == 24, claim(0,(0,2)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 25, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 26, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 27, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 28, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) }
  }
  val checked = safety and (pc == 29 implies (s.requests.get(0).phase == Replied and s.requests.get(0).notified and s.effects.get((0,1)) == 1 and s.effects.get((0,2)) == 1))
  val reached = pc == 29 and (s.requests.get(0).phase == Replied and s.requests.get(0).notified and s.effects.get((0,1)) == 1 and s.effects.get((0,2)) == 1)
}
