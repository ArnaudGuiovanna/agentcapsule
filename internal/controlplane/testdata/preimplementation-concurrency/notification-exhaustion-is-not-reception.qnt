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
    all { pc == 3, closeRequest(0,FailRequest), pc' = pc+1, covered' = covered.union(Set("closeRequest")) },
    all { pc == 4, fenceStore(0,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 5, recordFence(0,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 6, fenceStore(1,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 7, recordFence(1,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 8, fenceStore(2,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 9, recordFence(2,RequestSubject(0)), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 10, commitClose(0), pc' = pc+1, covered' = covered.union(Set("commitClose")) },
    all { pc == 11, claim(0,(0,2)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 12, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 13, loseRPC(0), pc' = pc+1, covered' = covered.union(Set("loseRPC")) },
    all { pc == 14, expireLease((0,2)), pc' = pc+1, covered' = covered.union(Set("expireLease")) },
    all { pc == 15, claim(0,(0,2)), pc' = pc+1, covered' = covered.union(Set("claim")) },
    all { pc == 16, authorize(0), pc' = pc+1, covered' = covered.union(Set("authorize")) },
    all { pc == 17, loseRPC(0), pc' = pc+1, covered' = covered.union(Set("loseRPC")) },
    all { pc == 18, expireLease((0,2)), pc' = pc+1, covered' = covered.union(Set("expireLease")) },
    all { pc == 19, beginRetire((0,2)), pc' = pc+1, covered' = covered.union(Set("beginRetire")) },
    all { pc == 20, fenceStore(0,EventSubject((0,2))), pc' = pc+1, covered' = covered.union(Set("fenceStore")) },
    all { pc == 21, recordFence(0,EventSubject((0,2))), pc' = pc+1, covered' = covered.union(Set("recordFence")) },
    all { pc == 22, retire((0,2)), pc' = pc+1, covered' = covered.union(Set("retire")) }
  }
  val checked = safety and (pc == 23 implies (s.events.get((0,2)).phase == DeadEvent and not(s.requests.get(0).notified)))
  val reached = pc == 23 and (s.events.get((0,2)).phase == DeadEvent and not(s.requests.get(0).notified))
}
