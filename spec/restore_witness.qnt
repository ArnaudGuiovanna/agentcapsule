/** Fixed original-action witnesses, not exhaustive interleaving exploration. */
module restoreWitnessStaleActivationGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1})).expect(safety).then(beginRevocation(0)).expect(safety).then(crashStore(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(activate(1).fail())
}
module restoreWitnessStaleActivationBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=false, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginRestore(1), pc' = pc+1 },
    all { pc == 1, retire(1), pc' = pc+1 },
    all { pc == 2, install(1), pc' = pc+1 },
    all { pc == 3, launchRestore(1), pc' = pc+1 },
    all { pc == 4, scan(1), pc' = pc+1 },
    all { pc == 5, synchronize(1), pc' = pc+1 },
    all { pc == 6, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1}), pc' = pc+1 },
    all { pc == 7, beginRevocation(0), pc' = pc+1 },
    all { pc == 8, crashStore(0), pc' = pc+1 },
    all { pc == 9, finishRevocation(0), pc' = pc+1 },
    all { pc == 10, activate(1), pc' = pc+1 }
  }
  val checked = noRestoredRevocation
}
module restoreWitnessMissingHistoryGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginEffect(1,0)).expect(safety).then(commitEffect(1)).expect(safety).then(recordOutcome(0)).expect(safety).then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1})).expect(safety).then(activate(1).fail())
}
module restoreWitnessMissingHistoryBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=false, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheKey(1,0), pc' = pc+1 },
    all { pc == 1, beginEffect(1,0), pc' = pc+1 },
    all { pc == 2, commitEffect(1), pc' = pc+1 },
    all { pc == 3, recordOutcome(0), pc' = pc+1 },
    all { pc == 4, beginRestore(1), pc' = pc+1 },
    all { pc == 5, retire(1), pc' = pc+1 },
    all { pc == 6, install(1), pc' = pc+1 },
    all { pc == 7, launchRestore(1), pc' = pc+1 },
    all { pc == 8, scan(1), pc' = pc+1 },
    all { pc == 9, synchronize(1), pc' = pc+1 },
    all { pc == 10, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1}), pc' = pc+1 },
    all { pc == 11, activate(1), pc' = pc+1 }
  }
  val checked = noUndeclaredLoss
}
/** D-03 option B. The same image, older than the ACK, activates once the loss is
 * declared. Safety holds at every step; the former guarantee does not. */
module restoreWitnessDeclaredLossGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginEffect(1,0)).expect(safety).then(commitEffect(1)).expect(safety).then(recordOutcome(0)).expect(safety).then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1})).expect(safety).then(declareLoss(1)).expect(safety).then(activate(1)).expect(safety and not(noLostAcknowledgedOutcome))
}
module restoreWitnessDeclaredLossFormerInvariant {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheKey(1,0), pc' = pc+1 },
    all { pc == 1, beginEffect(1,0), pc' = pc+1 },
    all { pc == 2, commitEffect(1), pc' = pc+1 },
    all { pc == 3, recordOutcome(0), pc' = pc+1 },
    all { pc == 4, beginRestore(1), pc' = pc+1 },
    all { pc == 5, retire(1), pc' = pc+1 },
    all { pc == 6, install(1), pc' = pc+1 },
    all { pc == 7, launchRestore(1), pc' = pc+1 },
    all { pc == 8, scan(1), pc' = pc+1 },
    all { pc == 9, synchronize(1), pc' = pc+1 },
    all { pc == 10, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1}), pc' = pc+1 },
    all { pc == 11, declareLoss(1), pc' = pc+1 },
    all { pc == 12, activate(1), pc' = pc+1 }
  }
  // Violated on this schedule: the reason option B changes the model.
  val checked = noLostAcknowledgedOutcome
  // Holds on this schedule: the option B guarantee and the rest of safety.
  val kept = safety
}
/** A declared loss lives in the authority. If a control-plane backup could roll
 * the authority back, an announced loss would be forgotten. */
module restoreWitnessForgottenLossGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginEffect(1,0)).expect(safety).then(commitEffect(1)).expect(safety).then(recordOutcome(0)).expect(safety).then(beginRestore(1)).expect(safety).then(takeControlBackup).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1})).expect(safety).then(declareLoss(1)).expect(safety).then(activate(1)).expect(safety).then(beginRestore(0)).expect(safety).then(retire(0)).expect(safety).then(install(0)).expect(safety and root.lost == Set(lossAt(0,2)))
}
module restoreWitnessForgottenLossBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=true, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheKey(1,0), pc' = pc+1 },
    all { pc == 1, beginEffect(1,0), pc' = pc+1 },
    all { pc == 2, commitEffect(1), pc' = pc+1 },
    all { pc == 3, recordOutcome(0), pc' = pc+1 },
    all { pc == 4, beginRestore(1), pc' = pc+1 },
    all { pc == 5, takeControlBackup, pc' = pc+1 },
    all { pc == 6, retire(1), pc' = pc+1 },
    all { pc == 7, install(1), pc' = pc+1 },
    all { pc == 8, launchRestore(1), pc' = pc+1 },
    all { pc == 9, scan(1), pc' = pc+1 },
    all { pc == 10, synchronize(1), pc' = pc+1 },
    all { pc == 11, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:1}), pc' = pc+1 },
    all { pc == 12, declareLoss(1), pc' = pc+1 },
    all { pc == 13, activate(1), pc' = pc+1 },
    all { pc == 14, beginRestore(0), pc' = pc+1 },
    all { pc == 15, retire(0), pc' = pc+1 },
    all { pc == 16, install(0), pc' = pc+1 }
  }
  val checked = declaredLossesSurvive
}
module restoreWitnessSurvivingKEKGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(crashStore(1)).expect(safety).then(beginRevocation(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(destroyKey(0)).expect(safety).then(decryptBackup(0,0).fail())
}
module restoreWitnessSurvivingKEKBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=true, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginSeal(0), pc' = pc+1 },
    all { pc == 1, retire(0), pc' = pc+1 },
    all { pc == 2, seal(0), pc' = pc+1 },
    all { pc == 3, crashStore(1), pc' = pc+1 },
    all { pc == 4, beginRevocation(0), pc' = pc+1 },
    all { pc == 5, finishRevocation(0), pc' = pc+1 },
    all { pc == 6, destroyKey(0), pc' = pc+1 },
    all { pc == 7, decryptBackup(0,0), pc' = pc+1 }
  }
  val checked = erasedKeysUnavailable
}
module restoreWitnessCachedDEKGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(beginRevocation(0)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:1,revision:1,subjects:Set(0),epoch:1})).expect(safety).then(finishRevocation(0)).expect(safety).then(destroyKey(0).fail())
}
module restoreWitnessCachedDEKBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=false,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, cacheKey(1,0), pc' = pc+1 },
    all { pc == 1, beginSeal(0), pc' = pc+1 },
    all { pc == 2, retire(0), pc' = pc+1 },
    all { pc == 3, seal(0), pc' = pc+1 },
    all { pc == 4, beginRevocation(0), pc' = pc+1 },
    all { pc == 5, scan(1), pc' = pc+1 },
    all { pc == 6, synchronize(1), pc' = pc+1 },
    all { pc == 7, recordReceipt({store:1,incarnation:1,revision:1,subjects:Set(0),epoch:1}), pc' = pc+1 },
    all { pc == 8, finishRevocation(0), pc' = pc+1 },
    all { pc == 9, destroyKey(0), pc' = pc+1 },
    all { pc == 10, decryptBackup(1,0), pc' = pc+1 }
  }
  val checked = erasedKeysUnavailable
}
module restoreWitnessNoRetirementGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginRestore(0)).expect(safety).then(skipRetirement(0).fail())
}
module restoreWitnessNoRetirementBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=false, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginRestore(0), pc' = pc+1 },
    all { pc == 1, skipRetirement(0), pc' = pc+1 }
  }
  val checked = retiredBeforeInstall
}
module restoreWitnessRevivedSealGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(beginRestore(0).fail())
}
module restoreWitnessRevivedSealBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=false, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginSeal(0), pc' = pc+1 },
    all { pc == 1, retire(0), pc' = pc+1 },
    all { pc == 2, seal(0), pc' = pc+1 },
    all { pc == 3, beginRestore(0), pc' = pc+1 }
  }
  val checked = permanentSeals
}
/** D-05 option (a). Each guard below runs on the safe configuration and ends
 * with the step its guard refuses. Each broken schedule disables that one guard
 * and violates the named invariant at its last step. */
/** The replica acknowledges a seal it has only received; the standby restarts,
 * then the primary is lost. The promoted root forgets the seal. */
module restoreWitnessEarlyAckGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety and s.replica.sealed.contains(0)).then(crashStandby.fail())
}
module restoreWitnessEarlyAckBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=false, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginSeal(0), pc' = pc+1 },
    all { pc == 1, retire(0), pc' = pc+1 },
    all { pc == 2, seal(0), pc' = pc+1 },
    all { pc == 3, crashStandby, pc' = pc+1 },
    all { pc == 4, losePrimary, pc' = pc+1 },
    all { pc == 5, promote, pc' = pc+1 }
  }
  val checked = permanentSeals
}
/** The old primary comes back after the promotion and resends its log. The
 * promoted authority has destroyed a key since; accepting the resend revives it. */
module restoreWitnessUnfencedGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(crashStore(1)).expect(safety).then(beginRevocation(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(losePrimary).expect(safety).then(promote).expect(safety).then(destroyKey(0)).expect(safety).then(oldPrimaryReturns).expect(safety).then(oldPrimaryResends.fail())
}
module restoreWitnessUnfencedBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=false, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginSeal(0), pc' = pc+1 },
    all { pc == 1, retire(0), pc' = pc+1 },
    all { pc == 2, seal(0), pc' = pc+1 },
    all { pc == 3, crashStore(1), pc' = pc+1 },
    all { pc == 4, beginRevocation(0), pc' = pc+1 },
    all { pc == 5, finishRevocation(0), pc' = pc+1 },
    all { pc == 6, losePrimary, pc' = pc+1 },
    all { pc == 7, promote, pc' = pc+1 },
    all { pc == 8, destroyKey(0), pc' = pc+1 },
    all { pc == 9, oldPrimaryReturns, pc' = pc+1 },
    all { pc == 10, oldPrimaryResends, pc' = pc+1 }
  }
  val checked = keyDestructionSurvives
}
/** A promotion keeps the old epoch. In degraded mode the old primary gave out
 * revision 1 for subject 0, and a restoring image fenced it and kept the signed
 * receipt. The promoted root gives revision 1 again, to subject 1; the old
 * receipt binds, and the image activates without fencing subject 1. */
module restoreWitnessSameEpochGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(loseLink).expect(safety).then(enterDegraded).expect(safety).then(beginRevocation(0)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(losePrimary).expect(safety).then(promote).expect(safety).then(launchRestore(1)).expect(safety).then(beginRevocation(1)).expect(safety and root.revision == 1).then(recordReceipt({store:1,incarnation:2,revision:1,subjects:Set(0),epoch:1}).fail())
}
module restoreWitnessSameEpochBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=false, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginRestore(1), pc' = pc+1 },
    all { pc == 1, retire(1), pc' = pc+1 },
    all { pc == 2, install(1), pc' = pc+1 },
    all { pc == 3, launchRestore(1), pc' = pc+1 },
    all { pc == 4, loseLink, pc' = pc+1 },
    all { pc == 5, enterDegraded, pc' = pc+1 },
    all { pc == 6, beginRevocation(0), pc' = pc+1 },
    all { pc == 7, scan(1), pc' = pc+1 },
    all { pc == 8, synchronize(1), pc' = pc+1 },
    all { pc == 9, losePrimary, pc' = pc+1 },
    all { pc == 10, promote, pc' = pc+1 },
    all { pc == 11, launchRestore(1), pc' = pc+1 },
    all { pc == 12, beginRevocation(1), pc' = pc+1 },
    all { pc == 13, recordReceipt({store:1,incarnation:2,revision:1,subjects:Set(0),epoch:1}), pc' = pc+1 },
    all { pc == 14, activate(1), pc' = pc+1 }
  }
  val checked = activationCurrent
}
/** Key destruction continues in degraded mode. The replica still holds the
 * key; a disaster and a promotion bring it back. */
module restoreWitnessDegradedDestructionGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(crashStore(1)).expect(safety).then(beginRevocation(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(loseLink).expect(safety).then(enterDegraded).expect(safety).then(destroyKey(0).fail())
}
module restoreWitnessDegradedDestructionBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=true).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginSeal(0), pc' = pc+1 },
    all { pc == 1, retire(0), pc' = pc+1 },
    all { pc == 2, seal(0), pc' = pc+1 },
    all { pc == 3, crashStore(1), pc' = pc+1 },
    all { pc == 4, beginRevocation(0), pc' = pc+1 },
    all { pc == 5, finishRevocation(0), pc' = pc+1 },
    all { pc == 6, loseLink, pc' = pc+1 },
    all { pc == 7, enterDegraded, pc' = pc+1 },
    all { pc == 8, destroyKey(0), pc' = pc+1 },
    all { pc == 9, losePrimary, pc' = pc+1 },
    all { pc == 10, promote, pc' = pc+1 }
  }
  val checked = keyDestructionSurvives
}
/** The API opens on the promoted PostgreSQL before the root's records are
 * replayed. A membership revoked after the last WAL shipment works again. */
module restoreWitnessEarlyOpenGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(revokeAccess(1)).expect(safety).then(losePrimary).expect(safety).then(promote).expect(safety and not(s.pg.accessRevoked.contains(1))).then(openApi.fail())
}
module restoreWitnessEarlyOpenBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=false, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, revokeAccess(1), pc' = pc+1 },
    all { pc == 1, losePrimary, pc' = pc+1 },
    all { pc == 2, promote, pc' = pc+1 },
    all { pc == 3, openApi, pc' = pc+1 }
  }
  val checked = noRevivedAccess
}
/** Degraded mode as decided: a standing grant (here a membership) is revoked
 * while the standby is unreachable, then the primary is lost before the WAL
 * ships. The blanket token revocation does not cover it: the member's issuer
 * signs a new token after the failover. The safe rule makes it wait. */
module restoreWitnessDecidedGrantGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(loseLink).expect(safety).then(enterDegraded).expect(safety).then(revokeAccess(1).fail())
}
module restoreWitnessDecidedGrant {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=true, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, loseLink, pc' = pc+1 },
    all { pc == 1, enterDegraded, pc' = pc+1 },
    all { pc == 2, revokeAccess(1), pc' = pc+1 },
    all { pc == 3, losePrimary, pc' = pc+1 },
    all { pc == 4, promote, pc' = pc+1 },
    all { pc == 5, reconcileDatabase, pc' = pc+1 },
    all { pc == 6, openApi, pc' = pc+1 }
  }
  val checked = noRevivedAccess
}
/** Degraded mode as decided: a revocation subject (a request, say) is revoked
 * to completion while the standby is unreachable, then the primary is lost. No
 * token is involved. After the failover a restored image runs its job. */
module restoreWitnessDecidedSubjectGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).* from "./restore_authority"
  run guardTest = init.then(crashStore(0)).expect(safety).then(crashStore(1)).expect(safety).then(loseLink).expect(safety).then(enterDegraded).expect(safety).then(beginRevocation(0)).expect(safety).then(finishRevocation(0).fail())
}
module restoreWitnessDecidedSubject {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=true, DESTROY_DEGRADED=false).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, crashStore(0), pc' = pc+1 },
    all { pc == 1, crashStore(1), pc' = pc+1 },
    all { pc == 2, loseLink, pc' = pc+1 },
    all { pc == 3, enterDegraded, pc' = pc+1 },
    all { pc == 4, beginRevocation(0), pc' = pc+1 },
    all { pc == 5, finishRevocation(0), pc' = pc+1 },
    all { pc == 6, losePrimary, pc' = pc+1 },
    all { pc == 7, promote, pc' = pc+1 },
    all { pc == 8, beginRestore(1), pc' = pc+1 },
    all { pc == 9, retire(1), pc' = pc+1 },
    all { pc == 10, install(1), pc' = pc+1 },
    all { pc == 11, launchRestore(1), pc' = pc+1 },
    all { pc == 12, scan(1), pc' = pc+1 },
    all { pc == 13, synchronize(1), pc' = pc+1 },
    all { pc == 14, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set(),epoch:2}), pc' = pc+1 },
    all { pc == 15, activate(1), pc' = pc+1 },
    all { pc == 16, cacheKey(1,0), pc' = pc+1 },
    all { pc == 17, beginEffect(1,0), pc' = pc+1 },
    all { pc == 18, commitEffect(1), pc' = pc+1 }
  }
  val checked = noStaleEffect
}
