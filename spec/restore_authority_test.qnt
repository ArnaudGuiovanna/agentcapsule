module restoreAuthorityTests {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  action reconcile(a: int): bool = scan(a).then(synchronize(a)).then(recordReceipt(s.scans.get(a)))
  action revoke(p: int): bool = beginRevocation(p).then(reconcile(0)).then(reconcile(1)).then(finishRevocation(p))
  action restoreImage(a: int): bool = beginRestore(a).then(retire(a)).then(install(a)).then(launchRestore(a))
  action permanentlySeal(a: int): bool = beginSeal(a).then(retire(a)).then(seal(a))
  action applied = init.then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1))
  action acknowledged = applied.then(recordOutcome(0))
  // A disaster restore: the image predates the ACK and no archive holds the outcome.
  action restoredWithoutOutcome = acknowledged.then(restoreImage(1)).then(reconcile(1))
  action activatedWithDeclaredLoss = restoredWithoutOutcome.then(declareLoss(1)).then(activate(1))
  action rerun = cacheKey(1,0).then(beginEffect(1,0)).then(commitEffect(1))

  run oldImageReconcilesRevocationsAndOutcomesTest = acknowledged.then(captureArchive(1))
    .then(revoke(0)).then(restoreImage(1)).then(repairHistory(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and s.stores.get(1).phase == Ready and s.stores.get(1).incarnation == 2
      and s.stores.get(1).disk.effects.contains(0) and s.stores.get(1).fences.contains(0) and root.lost == Set())
  run markerCannotInventRecoveryDataTest = acknowledged.then(restoreImage(1))
    .expect(root.committed.contains(0)).then(repairHistory(1).fail())
  run freshBackupKeepsAcknowledgedOutcomeTest = acknowledged.then(takeBackup(1)).then(takeControlBackup)
    .then(restoreImage(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and noLostAcknowledgedOutcome and s.stores.get(1).disk.effects.contains(0)
      and root.lost == Set() and outcomeStatus(root,s,0) == Confirmed)
  run unacknowledgedOutcomeCanBeRecomputedTest = applied.then(restoreImage(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and not(s.stores.get(1).disk.effects.contains(0)) and root.committed == Set()
      and root.lost == Set() and outcomeStatus(root,s,0) == Unrecorded)
    .then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordOutcome(0))
    .expect(safety and root.committed.contains(0))
  run unavailableArchivePreventsRepairTest = acknowledged.then(captureArchive(1)).then(restoreImage(1))
    .then(loseArchive(1)).expect(safety).then(repairHistory(1).fail())

  // D-03 option B: a loss within the window is allowed only once declared.
  run undeclaredLossPreventsActivationTest = restoredWithoutOutcome
    .expect(safety and not(s.stores.get(1).disk.effects.contains(0)) and outcomeStatus(root,s,0) == Confirmed)
    .then(activate(1).fail())
  run declaredLossAllowsActivationTest = restoredWithoutOutcome.then(declareLoss(1))
    .expect(safety and root.lost == Set(lossAt(0,2)) and outcomeStatus(root,s,0) == LostRescheduled and due(root,s,0))
    .then(activate(1))
    .expect(safety and s.stores.get(1).phase == Ready and not(s.stores.get(1).disk.effects.contains(0)))
  // Negative witness: the pre-B guarantee fails on this run, while safety holds.
  run declaredLossBreaksFormerGuaranteeTest = activatedWithDeclaredLoss
    .expect(safety and noUndeclaredLoss and not(noLostAcknowledgedOutcome))
  run declaredLossIsRerunOnceTest = activatedWithDeclaredLoss.then(rerun)
    .expect(safety and s.stores.get(1).disk.effects.contains(0) and not(due(root,s,0)))
    .then(recordRerun(0))
    .expect(safety and outcomeStatus(root,s,0) == RerunConfirmed and root.lost == Set(lossAt(0,2)))
    .then(beginEffect(1,0)).then(commitEffect(1)).expect(safety and s.stores.get(1).disk.effects == Set(0))
    .then(recordRerun(0).fail())
  run rerunNeedsDeclaredLossTest = acknowledged.expect(safety and outcomeStatus(root,s,0) == Confirmed)
    .then(recordRerun(0).fail())
  run noDeclarationWithoutLossTest = acknowledged.then(takeBackup(1)).then(restoreImage(1)).then(reconcile(1))
    .expect(safety and canActivate(root,s,1)).then(declareLoss(1).fail())
  run repairComesBeforeDeclarationTest = acknowledged.then(captureArchive(1)).then(restoreImage(1))
    .then(reconcile(1)).expect(safety and archiveRepairs(root,s,1)).then(declareLoss(1).fail())
  run lostArchiveLeadsToDeclaredLossTest = acknowledged.then(captureArchive(1)).then(restoreImage(1))
    .then(loseArchive(1)).then(reconcile(1)).then(declareLoss(1)).then(activate(1))
    .expect(safety and outcomeStatus(root,s,0) == LostRescheduled and due(root,s,0))
  run declaredLossSurvivesControlBackupRestoreTest = acknowledged.then(takeControlBackup)
    .then(restoreImage(1)).then(reconcile(1)).then(declareLoss(1)).then(activate(1))
    .then(restoreImage(0)).then(reconcile(0)).then(activate(0))
    .expect(safety and root.lost == Set(lossAt(0,2)) and outcomeStatus(root,s,0) == LostRescheduled)
  // D-05: an image older than an offboarding declares the loss but revives
  // neither the revocation, nor the seal, nor the key, nor the job.
  action offboardedAfterBackup = init.then(takeBackup(1)).then(takeControlBackup)
    .then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordOutcome(0))
    .then(revoke(0)).then(permanentlySeal(0)).then(restoreImage(1)).then(destroyKey(0))
    .then(reconcile(1)).then(declareLoss(1)).then(activate(1))
  run oldImageDoesNotReviveOffboardedJobTest = offboardedAfterBackup
    .expect(safety and root.revoked.contains(0) and root.sealed.contains(0) and root.destroyedKeys.contains(0)
      and s.stores.get(1).fences.contains(0) and outcomeStatus(root,s,0) == LostRescheduled and not(due(root,s,0)))
    .then(cacheKey(1,0).fail())
  run oldImageDoesNotReviveDestroyedKeyTest = offboardedAfterBackup.expect(safety).then(decryptBackup(1,0).fail())

  run activationRechecksNewRevocationTest = init.then(restoreImage(1)).then(reconcile(1))
    .then(beginRevocation(0)).then(reconcile(0)).then(finishRevocation(0))
    .expect(safety and root.revoked.contains(0)).then(activate(1).fail())
  run rescanAfterConcurrentRevocationTest = init.then(restoreImage(1)).then(reconcile(1))
    .then(beginRevocation(0)).then(reconcile(0)).then(finishRevocation(0))
    .then(reconcile(1)).then(activate(1)).expect(safety and s.stores.get(1).fences.contains(0))
  run oldReceiptCannotBindToNewImageTest = init.then(beginRevocation(0)).then(reconcile(1))
    .then(restoreImage(1)).then(scan(1)).expect(safety)
    .then(recordReceipt({store:1,incarnation:1,revision:1,subjects:Set(0)}).fail())
  run lostReceiptIsRetriedFromDurableFenceTest = init.then(beginRevocation(0)).then(scan(1)).then(synchronize(1))
    .then(loseReceipts).then(synchronize(1)).then(recordReceipt(s.scans.get(1)))
    .then(reconcile(0)).then(finishRevocation(0)).expect(safety and root.revoked.contains(0))
  run authorityOutageBlocksOtherwiseReadyActivationTest = init.then(restoreImage(1)).then(reconcile(1))
    .expect(canActivate(root,s,1)).then(rootUnavailable).then(activate(1).fail())
  run authorityRecoveryAllowsActivationTest = init.then(restoreImage(1)).then(reconcile(1))
    .then(rootUnavailable).then(rootAvailable).then(activate(1)).expect(safety and s.stores.get(1).phase == Ready)

  run writerBlocksFenceTest = init.then(cacheKey(1,0)).then(beginEffect(1,0))
    .then(beginRevocation(0)).then(reconcile(0)).then(scan(1)).expect(safety).then(synchronize(1).fail())
  run admittedWriterFinishesBeforeRevocationTest = init.then(cacheKey(1,0)).then(beginEffect(1,0))
    .then(beginRevocation(0)).then(reconcile(0)).then(scan(1)).then(commitEffect(1))
    .then(synchronize(1)).then(recordReceipt(s.scans.get(1))).then(finishRevocation(0))
    .then(recordOutcome(0)).expect(safety and s.stores.get(1).disk.effects.contains(0))
  run physicalRetirementAbortsOldWriterTest = init.then(cacheKey(1,0)).then(beginEffect(1,0))
    .then(beginRestore(1)).then(beginRevocation(0)).then(reconcile(0)).then(retire(1)).then(finishRevocation(0))
    .then(install(1)).then(launchRestore(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and s.stores.get(1).writer == -1 and s.stores.get(1).disk.effects == Set())
  run revokedSubjectCannotAcquireNewKeyTest = init.then(revoke(0)).expect(safety).then(cacheKey(1,0).fail())

  run destructionWaitsForAllCachedCopiesTest = init.then(cacheKey(1,0)).then(revoke(0)).then(permanentlySeal(0))
    .expect(safety and s.stores.get(1).cachedKeys.contains(0)).then(destroyKey(0).fail())
  run destructionRequiresPermanentSealTest = init.then(revoke(0)).expect(safety).then(destroyKey(0).fail())
  run destroyedKeyCannotDecryptOldBackupTest = init.then(cacheKey(1,0)).then(revoke(0)).then(permanentlySeal(0))
    .then(crashStore(1)).then(destroyKey(0)).expect(safety and root.destroyedKeys.contains(0))
    .then(decryptBackup(1,0).fail())
  run liveKeyDecryptsBackupTest = init.then(decryptBackup(1,0)).expect(safety)
  run sealedStoreCannotBeRestoredTest = init.then(permanentlySeal(0)).expect(safety).then(beginRestore(0).fail())
  run sealRetirementCannotInstallUnreservedImageTest = init.then(revoke(0)).then(beginSeal(1)).then(retire(1))
    .expect(safety and root.incarnations.get(1) == 1).then(install(1).fail())
  run sealedStoreCannotBlockFutureRevocationTest = init.then(permanentlySeal(0))
    .then(beginRevocation(1)).then(reconcile(1)).then(finishRevocation(1))
    .expect(safety and root.revoked.contains(1) and s.stores.get(0).phase == Sealed)
  run authorityStateSurvivesControlBackupRestoreTest = init.then(takeControlBackup).then(revoke(0))
    .then(restoreImage(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and root.revoked.contains(0) and root.incarnations.get(1) == 2)
}

// Two restores of the same store: a loss is declared per image, never inherited.
module restoreAuthorityRepeatedRestoreTests {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=3, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  action reconcile(a: int): bool = scan(a).then(synchronize(a)).then(recordReceipt(s.scans.get(a)))
  action restoreImage(a: int): bool = beginRestore(a).then(retire(a)).then(install(a)).then(launchRestore(a))
  action lostAndRerun = init.then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordOutcome(0))
    .then(restoreImage(1)).then(reconcile(1)).then(declareLoss(1)).then(activate(1))
    .then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordRerun(0))

  run earlierDeclarationDoesNotCoverLaterLossTest = lostAndRerun.then(restoreImage(1)).then(reconcile(1))
    .expect(safety and s.stores.get(1).incarnation == 3 and root.lost == Set(lossAt(0,2)))
    .then(activate(1).fail())
  run eachRestoreDeclaresItsOwnLossTest = lostAndRerun.then(restoreImage(1)).then(reconcile(1))
    .then(declareLoss(1)).then(activate(1))
    .expect(safety and root.lost == Set(lossAt(0,2),lossAt(0,3)) and root.rerun == Set(lossAt(0,2))
      and outcomeStatus(root,s,0) == LostRescheduled and due(root,s,0))
  run backupAfterRerunNeedsNoDeclarationTest = lostAndRerun.then(takeBackup(1))
    .then(restoreImage(1)).then(reconcile(1)).then(activate(1))
    .expect(safety and root.lost == Set(lossAt(0,2)) and outcomeStatus(root,s,0) == Confirmed)
}

// Deterministic reproductions of the broken configurations for option B.
module restoreAuthorityMissingHistoryTests {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=false,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  action reconcile(a: int): bool = scan(a).then(synchronize(a)).then(recordReceipt(s.scans.get(a)))
  action restoreImage(a: int): bool = beginRestore(a).then(retire(a)).then(install(a)).then(launchRestore(a))
  action activatedSilently = init.then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordOutcome(0))
    .then(restoreImage(1)).then(reconcile(1)).then(activate(1))
  run undeclaredLossTest = activatedSilently.expect(not(noUndeclaredLoss) and not(safety))
  run silentRerunTest = activatedSilently.then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1))
    .expect(not(noSilentRerun) and not(safety))
}

module restoreAuthorityRollbackTests {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=true, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).* from "./restore_authority"
  action reconcile(a: int): bool = scan(a).then(synchronize(a)).then(recordReceipt(s.scans.get(a)))
  action restoreImage(a: int): bool = beginRestore(a).then(retire(a)).then(install(a)).then(launchRestore(a))
  // A rolled-back authority forgets a loss it already announced.
  run forgottenLossTest = init.then(cacheKey(1,0)).then(beginEffect(1,0)).then(commitEffect(1)).then(recordOutcome(0))
    .then(beginRestore(1)).then(takeControlBackup).then(retire(1)).then(install(1)).then(launchRestore(1))
    .then(reconcile(1)).then(declareLoss(1)).then(activate(1)).expect(safety)
    .then(restoreImage(0)).expect(not(declaredLossesSurvive) and not(safety))
}
