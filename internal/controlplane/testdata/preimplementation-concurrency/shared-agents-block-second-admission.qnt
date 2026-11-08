module preparedTrace {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./sources/concurrent_protocol"
  var pc: int
  var covered: Set[str]
  action traceInit = all { init, pc' = 0, covered' = Set() }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 1, receive(1,3,SubmitCall,0), pc' = pc+1, covered' = covered.union(Set("receive")) },
    all { pc == 2, admit(0), pc' = pc+1, covered' = covered.union(Set("admit")) }
  }
  val checked = safety and (pc == 3 implies (s.calls.get(0).phase == AdmittedCall and s.calls.get(1).phase == ReceivedCall))
  val reached = pc == 3 and (s.calls.get(0).phase == AdmittedCall and s.calls.get(1).phase == ReceivedCall)
  action blockedAttempt0 = all { admit(1), pc' = pc, covered' = covered }
  run blocked0Test = traceInit.then(traceStep).then(traceStep).then(traceStep).then(blockedAttempt0.fail())
}
