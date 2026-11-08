/** Fixed original-action schedules. Counterexamples are valid executions,
 * but shortest depth here is only within this schedule, never global. */
module concurrentWitnessStaleCallerGuard {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  run guardTest = init.then(receive(0,0,SubmitCall,0)).expect(safety).then(beginStop(0)).expect(safety).then(admit(0).fail())
}
module concurrentWitnessStaleCallerBroken {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=false, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1 },
    all { pc == 1, beginStop(0), pc' = pc+1 },
    all { pc == 2, admit(0), pc' = pc+1 }
  }
  val checked = lockedAuthority
}
module concurrentWitnessNoFifoGuard {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  run guardTest = init.then(receive(0,0,SubmitCall,0)).expect(safety).then(admit(0)).expect(safety).then(commitCall(0)).expect(safety).then(receive(0,1,SubmitCall,2)).expect(safety).then(admit(0)).expect(safety).then(commitCall(0)).expect(safety).then(claim(0,(1,0)).fail())
}
module concurrentWitnessNoFifoBroken {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=false).* from "./concurrent_protocol"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1 },
    all { pc == 1, admit(0), pc' = pc+1 },
    all { pc == 2, commitCall(0), pc' = pc+1 },
    all { pc == 3, receive(0,1,SubmitCall,2), pc' = pc+1 },
    all { pc == 4, admit(0), pc' = pc+1 },
    all { pc == 5, commitCall(0), pc' = pc+1 },
    all { pc == 6, claim(0,(1,0)), pc' = pc+1 }
  }
  val checked = fifo
}
module concurrentWitnessNoDedupGuard {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  run guardTest = init.then(receive(0,0,SubmitCall,0)).expect(safety).then(admit(0)).expect(safety).then(commitCall(0)).expect(safety).then(claim(0,(0,0))).expect(safety).then(authorize(0)).expect(safety).then(beginEffect(0)).expect(safety).then(commitEffect(0)).expect(safety).then(expireLease((0,0))).expect(safety).then(claim(1,(0,0))).expect(safety).then(authorize(1)).expect(safety).then(beginEffect(1)).expect(safety).then(commitEffect(1)).expect(safety).expect(effectOnce)
}
module concurrentWitnessNoDedupBroken {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=false, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1 },
    all { pc == 1, admit(0), pc' = pc+1 },
    all { pc == 2, commitCall(0), pc' = pc+1 },
    all { pc == 3, claim(0,(0,0)), pc' = pc+1 },
    all { pc == 4, authorize(0), pc' = pc+1 },
    all { pc == 5, beginEffect(0), pc' = pc+1 },
    all { pc == 6, commitEffect(0), pc' = pc+1 },
    all { pc == 7, expireLease((0,0)), pc' = pc+1 },
    all { pc == 8, claim(1,(0,0)), pc' = pc+1 },
    all { pc == 9, authorize(1), pc' = pc+1 },
    all { pc == 10, beginEffect(1), pc' = pc+1 },
    all { pc == 11, commitEffect(1), pc' = pc+1 }
  }
  val checked = effectOnce
}
module concurrentWitnessRacyFenceGuard {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  run guardTest = init.then(receive(0,0,SubmitCall,0)).expect(safety).then(admit(0)).expect(safety).then(commitCall(0)).expect(safety).then(claim(0,(0,0))).expect(safety).then(authorize(0)).expect(safety).then(beginEffect(0)).expect(safety).then(closeRequest(0,ExpireRequest)).expect(safety).then(fenceStore(0,RequestSubject(0))).expect(safety).then(recordFence(0,RequestSubject(0))).expect(safety).then(fenceStore(1,RequestSubject(0)).fail())
}
module concurrentWitnessRacyFenceBroken {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=false, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, receive(0,0,SubmitCall,0), pc' = pc+1 },
    all { pc == 1, admit(0), pc' = pc+1 },
    all { pc == 2, commitCall(0), pc' = pc+1 },
    all { pc == 3, claim(0,(0,0)), pc' = pc+1 },
    all { pc == 4, authorize(0), pc' = pc+1 },
    all { pc == 5, beginEffect(0), pc' = pc+1 },
    all { pc == 6, closeRequest(0,ExpireRequest), pc' = pc+1 },
    all { pc == 7, fenceStore(0,RequestSubject(0)), pc' = pc+1 },
    all { pc == 8, recordFence(0,RequestSubject(0)), pc' = pc+1 },
    all { pc == 9, fenceStore(1,RequestSubject(0)), pc' = pc+1 },
    all { pc == 10, recordFence(1,RequestSubject(0)), pc' = pc+1 },
    all { pc == 11, fenceStore(2,RequestSubject(0)), pc' = pc+1 },
    all { pc == 12, recordFence(2,RequestSubject(0)), pc' = pc+1 },
    all { pc == 13, commitClose(0), pc' = pc+1 },
    all { pc == 14, commitEffect(0), pc' = pc+1 }
  }
  val checked = noStaleEffect
}
module concurrentWitnessWrongRequestFenceGuard {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true).* from "./concurrent_protocol"
  run guardTest = init.then(receive(0,1,SubmitCall,2)).expect(safety).then(admit(0)).expect(safety).then(commitCall(0)).expect(safety).then(claim(0,(1,0))).expect(safety).then(authorize(0)).expect(safety).then(closeRequest(1,ExpireRequest)).expect(safety).then(fenceStore(0,RequestSubject(1))).expect(safety).then(recordFence(0,RequestSubject(1))).expect(safety).then(fenceStore(1,RequestSubject(1))).expect(safety).then(recordFence(1,RequestSubject(1))).expect(safety).then(fenceStore(2,RequestSubject(1))).expect(safety).then(recordFence(2,RequestSubject(1))).expect(safety).then(commitClose(1)).expect(safety).then(beginEffect(0).fail())
}
module concurrentWitnessWrongRequestFenceBroken {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), MAX_GEN=2, LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true, CALLER_GUARD=true, SCOPED_FENCES=false, FIFO=true).* from "./concurrent_protocol"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, receive(0,1,SubmitCall,2), pc' = pc+1 },
    all { pc == 1, admit(0), pc' = pc+1 },
    all { pc == 2, commitCall(0), pc' = pc+1 },
    all { pc == 3, claim(0,(1,0)), pc' = pc+1 },
    all { pc == 4, authorize(0), pc' = pc+1 },
    all { pc == 5, closeRequest(1,ExpireRequest), pc' = pc+1 },
    all { pc == 6, fenceStore(0,RequestSubject(1)), pc' = pc+1 },
    all { pc == 7, recordFence(0,RequestSubject(1)), pc' = pc+1 },
    all { pc == 8, fenceStore(1,RequestSubject(1)), pc' = pc+1 },
    all { pc == 9, recordFence(1,RequestSubject(1)), pc' = pc+1 },
    all { pc == 10, fenceStore(2,RequestSubject(1)), pc' = pc+1 },
    all { pc == 11, recordFence(2,RequestSubject(1)), pc' = pc+1 },
    all { pc == 12, commitClose(1), pc' = pc+1 },
    all { pc == 13, beginEffect(0), pc' = pc+1 },
    all { pc == 14, commitEffect(0), pc' = pc+1 }
  }
  val checked = noStaleEffect
}
