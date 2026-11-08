// Deterministic reproductions of existing broken configurations. These use
// original actions and invariants, without changing the protocol or claiming
// an exhaustive search. In particular, the racy-fence schedule is rare in
// random simulation because all three fences must precede the late commit.
module revocationEarlyTombstoneTests {
  import distributedRevocation(WAIT_FOR_ALL = false, SERIALIZE_EFFECT = true, DURABLE_FENCE = true).* from "./revocation"
  run earlyTombstoneTest = init.then(requestDeletion).then(commitTombstone)
    .expect(not(tombstoneBarrier) and not(safety))
}

module revocationRacyFenceTests {
  import distributedRevocation(WAIT_FOR_ALL = true, SERIALIZE_EFFECT = false, DURABLE_FENCE = true).* from "./revocation"
  run lateEffectTest = init.then(admit("b")).then(beginEffect("b"))
    .then(requestDeletion)
    .then(localFence("a")).then(recordAck("a"))
    .then(localFence("b")).then(recordAck("b"))
    .then(localFence("c")).then(recordAck("c"))
    .then(commitTombstone).then(commitEffect("b"))
    .expect(not(noStaleEffect) and not(safety))
}

module revocationVolatileFenceTests {
  import distributedRevocation(WAIT_FOR_ALL = true, SERIALIZE_EFFECT = true, DURABLE_FENCE = false).* from "./revocation"
  run forgottenFenceTest = init.then(requestDeletion)
    .then(localFence("a")).then(recordAck("a"))
    .then(storePowerLoss("a"))
    .expect(not(acknowledgedSurvives) and not(safety))
}
