module serviceProgressTests {
  import serviceProgress(REQUESTS=Set(0,1,2), STORES=Set(0,1), PRIORITY=true, SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./service_progress"
  // retiring-notice-waits-for-capacity
  run scenario0Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,false)).expect(safety).expect(s.jobs.get(0).delivery == RetiringDead and s.running == Set(1))
  run refusal0x0Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,false)).expect(safety).then(retireNotification(0).fail())
  // retiring-notice-reserves-capacity
  run scenario1Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,false)).expect(safety).then(arrive(1,true)).expect(safety).expect(s.jobs.get(0).delivery == RetiringDead and s.running == Set())
  run refusal1x0Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,false)).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1).fail())
  // successful-request-observed-and-notified
  run scenario2Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(observe(0)).expect(safety).then(notify(0,true)).expect(safety).expect(s.taggedObserved and s.jobs.get(0).delivery == Acked)
  // hung-handler-terminated-by-deadline
  run scenario3Test = init.then(arrive(0,false)).expect(safety).then(admit(0)).expect(safety).then(deadline(0)).expect(safety).then(releaseExecution(0)).expect(safety).then(fence(0,0)).expect(safety).then(fence(0,1)).expect(safety).then(commitClose(0)).expect(safety).then(notify(0,true)).expect(safety).then(observe(0)).expect(safety).expect(s.taggedObserved and s.jobs.get(0).result == Aborted)
  // queued-request-deadline
  run scenario4Test = init.then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(fence(0,0)).expect(safety).then(fence(0,1)).expect(safety).then(commitClose(0)).expect(safety).then(observe(0)).expect(safety).expect(s.jobs.get(0).stage == Observable and s.jobs.get(0).delivery == Pending)
  // terminal-notification-failure-keeps-inbox
  run scenario5Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,false)).expect(safety).then(retireNotification(0)).expect(safety).then(observe(0)).expect(safety).expect(s.jobs.get(0).delivery == Dead and s.jobs.get(0).inbox and s.taggedObserved)
  // notification-retry-success
  run scenario6Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(notify(0,false)).expect(safety).then(notify(0,true)).expect(safety).expect(s.jobs.get(0).delivery == Acked and s.jobs.get(0).attempts == 2)
  // delete-running-agent-preserves-other-work
  run scenario7Test = init.then(arrive(0,false)).expect(safety).then(admit(0)).expect(safety).then(arrive(1,true)).expect(safety).then(requestDelete).expect(safety).then(closeDeleted(0)).expect(safety).then(releaseExecution(0)).expect(safety).then(fence(0,0)).expect(safety).then(fence(0,1)).expect(safety).then(commitClose(0)).expect(safety).then(finishDelete).expect(safety).then(cancelNotification(0)).expect(safety).then(retireNotification(0)).expect(safety).then(observe(0)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(notify(1,true)).expect(safety).expect(s.deleted and s.taggedObserved and s.jobs.get(0).delivery == Cancelled and s.jobs.get(1).delivery == Acked)
  // barrier-reserves-capacity
  run scenario8Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(arrive(2,true)).expect(safety).then(complete(1)).expect(safety).expect(s.running == Set() and barriersPending)
  run refusal8x0Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(arrive(2,true)).expect(safety).then(complete(1)).expect(safety).then(admit(2).fail())
  // fence-waits-for-current-execution
  run scenario9Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).expect(s.running == Set(1))
  run refusal9x0Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(fence(0,0).fail())
  // restore-recovery-before-closing
  run scenario10Test = init.then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(loseStore(0)).expect(safety).then(fence(0,1)).expect(safety).then(stabilize).expect(safety).then(recoverStore(0)).expect(safety).then(fence(0,0)).expect(safety).then(commitClose(0)).expect(safety).expect(s.jobs.get(0).inbox and s.stable)
  // unavailable-store-is-not-a-fence
  run scenario11Test = init.then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(loseStore(0)).expect(safety).then(fence(0,1)).expect(safety).expect(s.jobs.get(0).barriers == Set(1))
  run refusal11x0Test = init.then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(loseStore(0)).expect(safety).then(fence(0,1)).expect(safety).then(commitClose(0).fail())
  run refusal11x1Test = init.then(arrive(0,false)).expect(safety).then(deadline(0)).expect(safety).then(loseStore(0)).expect(safety).then(fence(0,1)).expect(safety).then(fence(0,0).fail())
  // worker-crash-recovery
  run scenario12Test = init.then(arrive(0,true)).expect(safety).then(crashWorker).expect(safety).then(stabilize).expect(safety).then(recoverWorker).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).expect(s.jobs.get(0).inbox and s.workerUp)
  // authority-recovery-enables-observation
  run scenario13Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(loseAuthority).expect(safety).then(stabilize).expect(safety).then(recoverAuthority).expect(safety).then(observe(0)).expect(safety).expect(s.taggedObserved and s.authorityUp)
  // observe-requires-current-authority
  run scenario14Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(loseAuthority).expect(safety).expect(s.jobs.get(0).inbox and not(s.authorityUp))
  run refusal14x0Test = init.then(arrive(0,true)).expect(safety).then(admit(0)).expect(safety).then(complete(0)).expect(safety).then(loseAuthority).expect(safety).then(observe(0).fail())
  // fifo-shared-notification-queue
  run scenario15Test = init.then(arrive(2,true)).expect(safety).then(admit(2)).expect(safety).then(complete(2)).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(notify(2,true)).expect(safety).then(notify(1,true)).expect(safety).expect(s.notificationQueue == List() and s.jobs.get(1).delivery == Acked and s.jobs.get(2).delivery == Acked)
  // cannot-recycle-with-outstanding-notice
  run scenario16Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(observe(1)).expect(safety).expect(s.jobs.get(1).stage == Observable and s.jobs.get(1).delivery == Pending)
  run refusal16x0Test = init.then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(observe(1)).expect(safety).then(recycle(1).fail())
  // two-repeatable-arrivals
  run scenario17Test = init.then(stabilize).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(notify(1,true)).expect(safety).then(observe(1)).expect(safety).then(recycle(1)).expect(safety).then(arrive(1,true)).expect(safety).then(admit(1)).expect(safety).then(complete(1)).expect(safety).then(notify(1,true)).expect(safety).then(observe(1)).expect(safety).then(recycle(1)).expect(safety).expect(s == { ...initialState, stable: true })
  // fifo-admission-cannot-overtake
  run scenario18Test = init.then(arrive(1,true)).expect(safety).then(arrive(0,true)).expect(safety).then(arrive(2,true)).expect(safety).expect(s.admissionQueue == List(1,0,2))
  run refusal18x0Test = init.then(arrive(1,true)).expect(safety).then(arrive(0,true)).expect(safety).then(arrive(2,true)).expect(safety).then(admit(0).fail())
  // deleted-destination-rejects-new-work
  run scenario19Test = init.then(requestDelete).expect(safety).then(finishDelete).expect(safety).expect(s.deleted)
  run refusal19x0Test = init.then(requestDelete).expect(safety).then(finishDelete).expect(safety).then(arrive(0,true).fail())
}
