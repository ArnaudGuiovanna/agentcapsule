/** Exact depth frontiers for TLC safety exploration. No original transition is
 * removed before the frontier; the depth variable counts EVERY original step.
 * Artificial frontier deadlocks are ignored by TLC's -deadlock option.
 * These wrappers are not liveness specifications.
 */
module concurrentProtocolDepth8 {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2) as P from "./concurrent_protocol"
  var depth: int
  action init = all { P::init, depth' = 0 }
  action step = all { depth < 8, P::step, depth' = depth+1 }
  val safety = P::safety
}
module concurrentProtocolLoadedDepth12 {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2) as P from "./concurrent_protocol"
  pure val loadedState = List(0,1,2,3).foldl(P::initialState,(x,r) =>
    P::callCommitted(P::admitted(P::received(x,0,r,P::SubmitCall,P::sender(r)),0),0))
  var depth: int
  action init = all { P::s' = loadedState, depth' = 0 }
  action step = all { depth < 12, P::step, depth' = depth+1 }
  val safety = P::safety
}
