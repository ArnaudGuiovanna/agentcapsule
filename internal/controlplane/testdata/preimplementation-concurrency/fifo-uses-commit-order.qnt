module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, receive(0,1,SubmitCall,2), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 1, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 2, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 3, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 4, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) },
    all { pc == 5, commitCall(0), pc' = pc+1, covered' = covered.union(Set("commitCall")) },
    all { pc == 6, claim(0,(1,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 7, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 8, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 9, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 10, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) },
    all { pc == 11, claim(0,(0,0)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 12, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 13, beginEffect(0), pc' = pc+1, covered' = covered.union(Set("beginEffect")) },
    all { pc == 14, commitEffect(0), pc' = pc+1, covered' = covered.union(Set("commitEffect")) },
    all { pc == 15, acknowledge(0), pc' = pc+1, covered' = covered.union(Set("acknowledge")) }
  }
  val checked = safety and (pc == 16 implies (s.effects.get((0,0)) == 1 and s.effects.get((1,0)) == 1))
  val reached = pc == 16 and (s.effects.get((0,0)) == 1 and s.effects.get((1,0)) == 1)
}
