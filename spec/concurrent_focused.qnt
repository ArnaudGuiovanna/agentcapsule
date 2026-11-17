/** Checked reachable prefixes plus unrestricted bounded continuations.
 * These do not cover all prefixes; the original transition relation is kept.
 * The configured bounds are honest scopes, not replacements for a depth-8 pass.
 */
module concurrentPrefixes {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./concurrent_protocol"
  pure val loadedState = List(0,1,2,3).foldl(initialState,(x,r) =>
    callCommitted(admitted(received(x,0,r,SubmitCall,sender(r)),0),0))
  pure val closingState = {
    val x = authorized(claimed(loadedState,0,(0,0)),0)
    val y = { ...x, rpc:x.rpc.set(0,{ ...x.rpc.get(0), phase:ExecutingRPC }) }
    val z = authorized(claimed(y,1,(2,0)),1)
    val d = { ...z, agents:z.agents.set(1,{ ...z.agents.get(1), phase:Quiescing }) }
    List(0,2).foldl(d,(st,a) => {
      val f = fenced(st,a,AgentSubject(1))
      val r = { store:a, subject:AgentSubject(1) }
      { ...f, acks:f.acks.union(Set(r)), receipts:f.receipts.exclude(Set(r)) }
    })
  }
  run loadedPrefixTest = init
    .then(receive(0,0,SubmitCall,0)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,1,SubmitCall,2)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,2,SubmitCall,2)).then(admit(0)).then(commitCall(0)).expect(safety)
    .then(receive(0,3,SubmitCall,0)).then(admit(0)).then(commitCall(0))
    .expect(safety and s == loadedState)
  run closingPrefixTest = init
    .then(receive(0,0,SubmitCall,0)).then(admit(0)).then(commitCall(0))
    .then(receive(0,1,SubmitCall,2)).then(admit(0)).then(commitCall(0))
    .then(receive(0,2,SubmitCall,2)).then(admit(0)).then(commitCall(0))
    .then(receive(0,3,SubmitCall,0)).then(admit(0)).then(commitCall(0))
    .then(claim(0,(0,0))).then(authorize(0)).then(beginEffect(0))
    .then(claim(1,(2,0))).then(authorize(1)).then(requestDelete(1))
    .then(fenceStore(0,AgentSubject(1))).then(recordFence(0,AgentSubject(1)))
    .then(fenceStore(2,AgentSubject(1))).then(recordFence(2,AgentSubject(1)))
    .expect(safety and s == closingState)
    .then(commitEffect(0)).then(fenceStore(1,AgentSubject(1)))
    .then(recordFence(1,AgentSubject(1))).then(commitDelete(1))
    .expect(safety and s.requests.get(0).phase == Canceled and s.requests.get(2).phase == Delivering)
  // ADR 007 and ADR 008 need more steps than the explorations from init
  // take: a reply exists after 11 steps, a closure commits after 9. These
  // prefixes start where those behaviours begin.
  pure def delivered(x: State, w: int, e: EventId): State = {
    val y = authorized(claimed(x,w,e),w)
    acknowledged(effectCommitted({ ...y, rpc:y.rpc.set(w,{ ...y.rpc.get(w), phase:ExecutingRPC }) },w),w)
  }
  pure def submitted(x: State, r: RequestId): State =
    callCommitted(admitted(received(x,0,r,SubmitCall,sender(r)),0),0)
  // Request 0 delivered and replied; its reply waits, never sent: it can
  // expire and die unsent, be sent, or its request's delivery be lost.
  pure val repliedState = callCommitted(admitted(received(delivered(submitted(initialState,0),0,(0,0)),
    0,0,ReplyCall,1),0),0)
  // The reply delivered too: a restore of its sender can lose it.
  pure val replyDeliveredState = delivered(repliedState,0,(0,1))
  // Request 0 expires while its delivery is under way and agent 2, not a
  // party, is stopped: its closure fences its two parties only.
  pure val expiringState = {
    val x = authorized(claimed(submitted(initialState,0),0,(0,0)),0)
    val y = bootRetired(physicallyStopped(x,2),2)
    val z = { ...y, agents:y.agents.set(2,{ ...y.agents.get(2), placement:Stopped, bootLease:false }) }
    { ...z, requests:z.requests.set(0,{ ...z.requests.get(0), closure:ExpireRequest }) }
  }
  action submitCall(r: RequestId): bool = receive(0,r,SubmitCall,sender(r)).then(admit(0)).then(commitCall(0))
  action deliverEvent(w: int, e: EventId): bool =
    claim(w,e).then(authorize(w)).then(beginEffect(w)).then(commitEffect(w)).then(acknowledge(w))
  run repliedPrefixTest = init.then(submitCall(0)).then(deliverEvent(0,(0,0)))
    .then(receive(0,0,ReplyCall,1)).then(admit(0)).then(commitCall(0))
    .expect(safety and s == repliedState and s.events.get((0,1)).phase == PendingEvent)
  run replyDeliveredPrefixTest = init.then(submitCall(0)).then(deliverEvent(0,(0,0)))
    .then(receive(0,0,ReplyCall,1)).then(admit(0)).then(commitCall(0)).then(deliverEvent(0,(0,1)))
    .expect(safety and s == replyDeliveredState and s.requests.get(0).notified)
  run expiringPrefixTest = init.then(submitCall(0)).then(claim(0,(0,0))).then(authorize(0))
    .then(stopVM(2)).then(retireBoot(2)).then(observeStopped(2)).then(closeRequest(0,ExpireRequest))
    .expect(safety and s == expiringState)
}
module concurrentExploration {
  import concurrentProtocol(AGENTS=Set(0,1,2), ROUTES=Map(0->(0,1),1->(2,1),2->(2,0),3->(0,2)),
    MANUAL=Set(), LOCKS=true, WAIT_ALL=true, SERIALIZE=true, DEDUP=true,
    CALLER_GUARD=true, SCOPED_FENCES=true, FIFO=true, MAX_GEN=2).* from "./concurrent_protocol"
  // Prefix constants are pure: no extra mutable protocol state is imported.
  import concurrentPrefixes.loadedState from "./concurrent_focused"
  import concurrentPrefixes.closingState from "./concurrent_focused"
  import concurrentPrefixes.repliedState from "./concurrent_focused"
  import concurrentPrefixes.replyDeliveredState from "./concurrent_focused"
  import concurrentPrefixes.expiringState from "./concurrent_focused"
  const LIMIT: int
  const PREFIX: int
  var depth: int
  action boundedInit = all {
    s' = if (PREFIX == 0) initialState else if (PREFIX == 1) loadedState else if (PREFIX == 2) closingState
      else if (PREFIX == 3) repliedState else if (PREFIX == 4) replyDeliveredState else expiringState,
    depth' = 0,
  }
  action boundedStep = all { depth < LIMIT, step, depth' = depth+1 }
  val checked = safety
}
module concurrentProtocolDepth7 {
  import concurrentExploration(LIMIT=7,PREFIX=0).*
}
module concurrentProtocolLoadedDepth4 {
  import concurrentExploration(LIMIT=4,PREFIX=1).*
}
module concurrentProtocolClosingDepth4 {
  import concurrentExploration(LIMIT=4,PREFIX=2).*
}
// ADR 007 and ADR 008 from their prefixes: the reply's deadline, its death
// unsent or behind its fence, the loss of an outcome and its redelivery, and
// a closure that fences its two parties only.
module concurrentProtocolRepliedDepth6 {
  import concurrentExploration(LIMIT=6,PREFIX=3).*
}
module concurrentProtocolReplyDeliveredDepth6 {
  import concurrentExploration(LIMIT=6,PREFIX=4).*
}
module concurrentProtocolExpiringDepth6 {
  import concurrentExploration(LIMIT=6,PREFIX=5).*
}
