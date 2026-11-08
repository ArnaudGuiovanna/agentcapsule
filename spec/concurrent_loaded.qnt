/** Additional exploration from a reachable four-request state.
 * The 12-action prefix is checked below. Subsequent step is the UNRESTRICTED
 * original transition relation. This does not cover every possible prefix and
 * does not replace checking from the ordinary init state.
 */
module concurrentProtocolLoaded {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./concurrent_protocol"
  pure val loadedState = List(0,1,2,3).foldl(initialState,(x,r) =>
    callCommitted(admitted(received(x,0,r,SubmitCall,sender(r)),0),0))
  action loadedInit = s' = loadedState
  run prefixReachabilityTest = init
    .then(receive(0,0,SubmitCall,0)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,1,SubmitCall,2)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,2,SubmitCall,2)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,3,SubmitCall,0)).then(admit(0)).then(commitCall(0))
    .expect(safety and s == loadedState)
}
