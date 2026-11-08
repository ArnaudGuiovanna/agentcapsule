/**
 * Permanent managed-execution seal of one store, used by later revocations.
 * Deletion eligibility abstracts an ALREADY completed distributed data barrier.
 * A durable host ban must precede cgroup drain; the local receipt follows both.
 * PostgreSQL publication precedes the ACK in a future revocation manifest.
 * Crashed workers lose observations, not durable host/SQL records; a delayed
 * launch still consults the host ban. This finite component is not a refinement
 * of all Go transitions, a crypto-erasure proof or a restore/migration protocol.
 */
module storeSeal {
  const WAIT_FOR_DRAIN: bool
  const DURABLE_BAN: bool
  type State = { worker: bool, deleting: bool, running: bool, ticket: bool,
                 banned: bool, stableBan: bool, localReceipt: bool,
                 observed: bool, sqlReceipt: bool, ack: bool }
  var s: State
  action init = s' = { worker: true, deleting: false, running: true, ticket: true,
                       banned: false, stableBan: false, localReceipt: false,
                       observed: false, sqlReceipt: false, ack: false }
  action completeDeletionBarrier = all {
    s.worker, not(s.deleting), s' = { ...s, deleting: true },
  }
  action sealIntent = all {
    s.worker, s.deleting,
    s' = { ...s, banned: true, stableBan: if (DURABLE_BAN) true else s.stableBan },
  }
  action drain = all {
    s.worker, s.banned, s' = { ...s, running: false },
  }
  action makeReceipt = all {
    s.worker, s.deleting, s.banned,
    if (WAIT_FOR_DRAIN) not(s.running) else true,
    s' = { ...s, localReceipt: true, observed: true },
  }
  action readReceipt = all {
    s.worker, s.localReceipt, s.banned, not(s.running),
    s' = { ...s, observed: true },
  }
  action publishReceipt = all {
    s.worker, s.deleting, s.observed,
    s' = { ...s, sqlReceipt: true },
  }
  action ackFutureFence = all {
    s.worker, s.sqlReceipt, s.observed, s' = { ...s, ack: true },
  }
  action workerCrash = all {
    s.worker, s' = { ...s, worker: false, observed: false },
  }
  action workerRecover = all {
    not(s.worker), s' = { ...s, worker: true },
  }
  action vmCrash = all { s.running, s' = { ...s, running: false } }
  action hostPowerLoss = s' = { ...s, worker: false, running: false,
                              banned: s.stableBan, observed: false }
  // This ticket was allocated before deletion; lease expiry/SQL phase alone
  // cannot physically prevent a delayed launcher from entering the host.
  action delayedLaunch = all {
    s.worker, s.ticket, not(s.running), not(s.banned),
    s' = { ...s, running: true, ticket: false },
  }
  action step = any {
    completeDeletionBarrier, sealIntent, drain, makeReceipt, readReceipt,
    publishReceipt, ackFutureFence, workerCrash, workerRecover, vmCrash,
    hostPowerLoss, delayedLaunch,
  }
  val physicalSeal = s.localReceipt implies (s.banned and not(s.running))
  val receiptChain = (s.sqlReceipt implies s.localReceipt) and (s.ack implies s.sqlReceipt)
  val noExecutionAfterAck = s.ack implies not(s.running)
  val safety = physicalSeal and receiptChain and noExecutionAfterAck
}
module storeSealOk {
  import storeSeal(WAIT_FOR_DRAIN = true, DURABLE_BAN = true).*
  run refusesReceiptBeforeDrainTest = init.then(completeDeletionBarrier)
    .then(sealIntent).then(makeReceipt.fail())
  run refusesPublicationWithoutObservationTest = init.then(completeDeletionBarrier)
    .then(sealIntent).then(drain).then(makeReceipt).then(workerCrash)
    .then(workerRecover).then(publishReceipt.fail())
  run interruptedPublicationTest = init.then(completeDeletionBarrier).then(sealIntent)
    .then(drain).then(makeReceipt).then(workerCrash)
    .then(workerRecover).then(readReceipt)
    .then(publishReceipt).then(ackFutureFence).then(hostPowerLoss)
    .then(workerRecover).expect(safety and s.ack).then(delayedLaunch.fail())
}
module storeSealEarlyReceipt {
  import storeSeal(WAIT_FOR_DRAIN = false, DURABLE_BAN = true).*
}
module storeSealVolatileBan {
  import storeSeal(WAIT_FOR_DRAIN = true, DURABLE_BAN = false).*
}
