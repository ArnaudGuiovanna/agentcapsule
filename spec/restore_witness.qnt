/** Fixed original-action witnesses, not exhaustive interleaving exploration. */
module restoreWitnessStaleActivationGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set()})).expect(safety).then(beginRevocation(0)).expect(safety).then(crashStore(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(activate(1).fail())
}
module restoreWitnessStaleActivationBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=false, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, beginRestore(1), pc' = pc+1 },
    all { pc == 1, retire(1), pc' = pc+1 },
    all { pc == 2, install(1), pc' = pc+1 },
    all { pc == 3, launchRestore(1), pc' = pc+1 },
    all { pc == 4, scan(1), pc' = pc+1 },
    all { pc == 5, synchronize(1), pc' = pc+1 },
    all { pc == 6, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set()}), pc' = pc+1 },
    all { pc == 7, beginRevocation(0), pc' = pc+1 },
    all { pc == 8, crashStore(0), pc' = pc+1 },
    all { pc == 9, finishRevocation(0), pc' = pc+1 },
    all { pc == 10, activate(1), pc' = pc+1 }
  }
  val checked = noRestoredRevocation
}
module restoreWitnessMissingHistoryGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginEffect(1,0)).expect(safety).then(commitEffect(1)).expect(safety).then(recordOutcome(0)).expect(safety).then(beginRestore(1)).expect(safety).then(retire(1)).expect(safety).then(install(1)).expect(safety).then(launchRestore(1)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:2,revision:0,subjects:Set()})).expect(safety).then(activate(1).fail())
}
module restoreWitnessMissingHistoryBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=false, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
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
    all { pc == 10, recordReceipt({store:1,incarnation:2,revision:0,subjects:Set()}), pc' = pc+1 },
    all { pc == 11, activate(1), pc' = pc+1 }
  }
  val checked = noLostAcknowledgedOutcome
}
module restoreWitnessSurvivingKEKGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(crashStore(1)).expect(safety).then(beginRevocation(0)).expect(safety).then(finishRevocation(0)).expect(safety).then(destroyKey(0)).expect(safety).then(decryptBackup(0,0).fail())
}
module restoreWitnessSurvivingKEKBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=true, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
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
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(cacheKey(1,0)).expect(safety).then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(beginRevocation(0)).expect(safety).then(scan(1)).expect(safety).then(synchronize(1)).expect(safety).then(recordReceipt({store:1,incarnation:1,revision:1,subjects:Set(0)})).expect(safety).then(finishRevocation(0)).expect(safety).then(destroyKey(0).fail())
}
module restoreWitnessCachedDEKBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=false).* from "./restore_authority"
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
    all { pc == 7, recordReceipt({store:1,incarnation:1,revision:1,subjects:Set(0)}), pc' = pc+1 },
    all { pc == 8, finishRevocation(0), pc' = pc+1 },
    all { pc == 9, destroyKey(0), pc' = pc+1 },
    all { pc == 10, decryptBackup(1,0), pc' = pc+1 }
  }
  val checked = erasedKeysUnavailable
}
module restoreWitnessNoRetirementGuard {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(beginRestore(0)).expect(safety).then(skipRetirement(0).fail())
}
module restoreWitnessNoRetirementBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=false, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
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
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  run guardTest = init.then(beginSeal(0)).expect(safety).then(retire(0)).expect(safety).then(seal(0)).expect(safety).then(beginRestore(0).fail())
}
module restoreWitnessRevivedSealBroken {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true, RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=false, CACHE_GUARD=true).* from "./restore_authority"
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
