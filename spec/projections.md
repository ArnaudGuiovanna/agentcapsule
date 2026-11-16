# Go projections of the model runs

A Go projection of a run drives the real code (PostgreSQL, the harness store,
the host's admission queue or the authorities) through the run's steps and
checks the run's expectation. This table lists every `run` of the models,
every fixed witness schedule (a module with `traceInit`, whose `checked`
invariant must fail) and every simulation witness (a `val` ending in
`Witness`), with the Go tests that project it.

A Go test named after its run (`TestFooBar` for `fooBarTest`) projects it
directly. A case of an ITF replay (`TestPreimplementationP1ITF/<case>`,
`TestPreimplementationP3ITF/<case>`, `TestProtocolITFMicrosteps/<case>`)
replays a fixed schedule of a pinned copy of the model, under
`internal/controlplane/testdata/`; the table names the run it matches. Other
tests were written for the same behaviour before the run existed.

Status:

- **full**: the Go tests drive the run's steps, or a finer schedule of them,
  and check its expectation;
- **partial**: they check part of it; the notes say which part is missing;
- **model-only**: deliberately not projected: a broken configuration, a
  reachability target, a state the simulation starts from, or an abstraction
  that a finer model replaces;
- **pending**: not projected yet; the code it needs is planned (the notes say
  where);
- **gap**: not projected, and nothing planned.

`python3 scripts/check-model-projections.py` recomputes the runs and witnesses
from `spec/*.qnt` and the Go test names from the tracked `*_test.go` files. It
fails when a run or witness is missing from this table or listed twice, when a
row names a run, a witness or a Go test that does not exist, or when a Go test
named after a run exists and its row does not name it.
`scripts/check-repo-hygiene.py` runs it, and so does CI. A new run needs a row
here: `full` or `partial` with its Go tests, or another status with a reason.

Several tests need more than PostgreSQL: the KVM build tags
(`TestBarrierCapacityOneSlotThreeStoresAndReplay`,
`TestLostGuestFenceACKDoesNotBecomeIndependentReceipt`,
`TestMaintenanceServiceRecoversRenewalCrashesWithoutIncomingWork`,
`TestPreimplementationP1HostSealITF`, `TestStoreSealWorkerCrashBeforeDatabaseReceipt`).
The others run in the PostgreSQL campaign (`scripts/verify-postgres.py`) or
in the ordinary unit tests.


### `barrier_capacity.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `barrierCapacityOk.priorityTest` | full | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure` | New ordinary work waits behind queued barriers; the barriers run in queue order. |
| `barrierCapacityOk.threeStoresOneSlotTest` | partial | `TestBarrierCapacityOneSlotThreeStoresAndReplay` | KVM campaign: one VM slot, barriers on the stopped agents boot temporary fence-only guests and give the slot back. |

### `composition.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `compositionOk.deletionDuringDeliveryTest` | model-only | — | Abstract composition: its `requestDelete` is the tombstone. The Go deletion first quiesces and waits for the open writer, as `protocol_composition.qnt` says (`authorizedEffectDuringQuiescingTest`). |
| `compositionOk.deletionDuringStartTest` | full | `TestPlacementDeletionAndDurabilityGuards` | A boot read before the deletion request cannot be confirmed after it. |
| `compositionOk.deletingSenderCancelsQueueTest` | partial | `TestRevocationWaitsForEveryStoreAndCancelsAtomically`, `TestPreimplementationP3ITF/deleted-destination-rejects-new-work` | Go cancels the deleted agent's requests at the tombstone, not at the deletion request (as `protocol_composition.qnt`); then the agent's next request is refused. |
| `compositionNoDeliveryFence.duplicateAfterDeleteIsNotANewEffectTest` | model-only | — | Runs on a broken configuration to check the model's observer. |

### `concurrent_focused.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `concurrentPrefixes.loadedPrefixTest` | model-only | — | Checks that a start state of the bounded simulation is reachable; no behaviour of its own. |
| `concurrentPrefixes.closingPrefixTest` | model-only | — | Checks that a start state of the bounded simulation is reachable; no behaviour of its own. |

### `concurrent_loaded.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `concurrentProtocolLoaded.prefixReachabilityTest` | model-only | — | Checks that a start state of the bounded simulation is reachable; no behaviour of its own. |

### `concurrent_protocol_test.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `concurrentProtocolTests.deletionAcrossFourRequestsTest` | full | `TestPreimplementationP1ITF/delete-shared-recipient-four-requests` |  |
| `concurrentProtocolTests.requestLocalExpirationTest` | full | `TestPreimplementationP1ITF/expiration-preserves-neighbor-request` |  |
| `concurrentProtocolTests.terminalStateSurvivesLateReplyTest` | full | `TestTerminalStateSurvivesLateReply` |  |
| `concurrentProtocolTests.sharedMandateLockTest` | full | `TestPreimplementationP1ITF/shared-agents-block-second-admission` |  |
| `concurrentProtocolTests.sharedMandateConservationTest` | full | `TestPreimplementationP1ITF/shared-mandate-two-admissions` |  |
| `concurrentProtocolTests.expirationDuringAdmissionTest` | full | `TestPreimplementationP1ITF/mandate-expires-before-commit` |  |
| `concurrentProtocolTests.foreignMandateTest` | full | `TestForeignMandate` |  |
| `concurrentProtocolTests.fifoAcrossRequestsTest` | full | `TestFifoAcrossRequests` |  |
| `concurrentProtocolTests.fifoAfterFirstAckTest` | full | `TestPreimplementationP1ITF/fifo-uses-commit-order` |  |
| `concurrentProtocolTests.duplicateAfterLostAckTest` | partial | `TestPreimplementationP1ITF/lost-ack-competing-lease`, `TestDeliveryConcurrentClaimsFIFOAndLostAck` | The fixture does not replay the refused late ACK (`acknowledge(0).fail()`). |
| `concurrentProtocolTests.duplicateAcrossGenerationTest` | full | `TestPreimplementationP1ITF/dedup-survives-generation-change` |  |
| `concurrentProtocolTests.oldChannelTest` | full | `TestPreimplementationP1ITF/old-channel-after-replacement` |  |
| `concurrentProtocolTests.oldCallerTest` | full | `TestPreimplementationP1ITF/old-caller-after-replacement` |  |
| `concurrentProtocolTests.admittedPhysicalDeathTest` | full | `TestPreimplementationP1ITF/sql-commit-after-physical-death` |  |
| `concurrentProtocolTests.authorityLockTest` | full | `TestAuthorityLock` |  |
| `concurrentProtocolTests.writerBlocksFenceTest` | full | `TestPreimplementationP1ITF/writer-blocks-revocation`, `TestAbortedWriterThenFence` | `TestAbortedWriterThenFence` checks it with the writer in another process. |
| `concurrentProtocolTests.abortedWriterThenFenceTest` | full | `TestAbortedWriterThenFence`, `TestPreimplementationP1ITF/writer-crash-then-restricted-fencing` | Guest writer crash: the writer process is killed (SIGKILL) inside its open transaction. The fixture cancels the writer instead. |
| `concurrentProtocolTests.fencedDuplicateRefusedTest` | full | `TestFencedDuplicateRefused` |  |
| `concurrentProtocolTests.statusAfterReplyRevocationTest` | partial | `TestPreimplementationP1ITF/revoked-reply-gets-fresh-status` | The fixture also delivers the reply, with a lost ACK, before the deletion. |
| `concurrentProtocolTests.expiredUnsentReplyTest` | partial | `TestExpiredDeliveryDiesWithoutItsRecipient` | Written from ADR 007, not step by step; the P1 fixture pins the model before ADR 007. |
| `concurrentProtocolTests.expiredSentReplyWaitsForFenceTest` | partial | `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence` | As above. |
| `concurrentProtocolTests.unfencedRetireAllowsLateEffectTest` | model-only | — | Defines a broken action to show why `retireUnsent` needs `not(sent)`; Go has no such path. |
| `concurrentProtocolTests.expiredSentReplyRetiredAfterFenceTest` | partial | `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence` | As above. |
| `concurrentProtocolTests.unsentReplyDiesBehindHeadTest` | partial | `TestExpiredDeliveryBehindAStuckHeadDies` | Written from ADR 007 §7, not step by step. |
| `concurrentProtocolTests.retirementLeavesDeletionTest` | partial | `TestRetirementLeavesADeletionToCancel` | As above. |
| `concurrentProtocolTests.deletionCancelsExpiredReplyTest` | partial | `TestRetirementLeavesADeletionToCancel` | As above. |
| `concurrentProtocolTests.closureFencesOnlyItsPartiesTest` | full | `TestClosureFencesOnlyItsParties`, `TestRequestClosureFencesOnlyItsParties` |  |
| `concurrentProtocolTests.closureCommitsWithoutOtherStoresTest` | full | `TestClosureCommitsWithoutOtherStores`, `TestRequestClosureFencesOnlyItsParties` |  |
| `concurrentProtocolTests.closureScopeTest` | model-only | — | Checks the model's own closure scope (`closureScope`) in its initial state. |
| `concurrentProtocolTests.closureWithoutRecipientAllowsStaleEffectTest` | model-only | — | Defines a broken action (`commitCloseWithout`) to show why the recipient's fence is needed; Go has no such path. |
| `concurrentProtocolTests.retiredNotificationTest` | partial | `TestExhaustedDeliveryFencesLateWorkerAndNotifiesSender` | The fixture `notification-exhaustion-is-not-reception` is not replayed: CANCELED/DEAD projection discrepancy (fixture README). |
| `concurrentProtocolTests.restoredRecipientGetsRequestAgainTest` | full | `TestRestoreRedeliversALostRequest` |  |
| `concurrentProtocolTests.restoreNeedsRetiredStoreTest` | partial | `TestVolumeRestoreOperationAndLossMapping`, `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` | Losses enter PostgreSQL only with the activation, after an image is installed; the install is refused while the old VMM holds the volume. |
| `concurrentProtocolTests.finalRequestDoesNotReopenTest` | full | `TestRestoreDoesNotReopenAFinalRequest`, `TestBothPartiesRestored` |  |
| `concurrentProtocolTests.closingRequestIsNotRedeliveredTest` | full | `TestClosingRequestIsNotRedelivered` |  |
| `concurrentProtocolTests.restoredSenderGetsReplyAgainTest` | full | `TestRestoreRedeliversALostReplyAndStatus`, `TestBothPartiesRestored` |  |
| `concurrentProtocolTests.restoredSenderGetsStatusAgainTest` | full | `TestRestoreRedeliversALostReplyAndStatus` | The status of a declined request, not of a canceled one. |
| `concurrentProtocolTests.deletionBlocksRedeliveryTest` | full | `TestRedeliveryIsSkippedWithAReason` | Its case "other agent being deleted". |
| `concurrentProtocolTests.closureCancelsRedeliveryTest` | full | `TestARedeliveredRequestCanBeCanceled` |  |
| `concurrentProtocolTests.reopenedRequestBreaksTerminalStableTest` | model-only | — | Defines a broken action (`reopen`) to show why a final request is not delivered again; Go has no such path. |
| `concurrentProtocolTests.sealAndFutureBarrierTest` | partial | `TestPreimplementationP1HostSealITF` | Privileged host test (KVM build tags); not in the PostgreSQL campaign. |
| `concurrentProtocolTests.workerCrashRollsBackAdmissionTest` | full | `TestPreimplementationP1ITF/worker-crash-before-business-commit` |  |
| `concurrentProtocolTests.orphanedConfirmedBootTest` | full | `TestPreimplementationP1ITF/confirmed-unpublished-boot-cleanup` |  |
| `concurrentProtocolTests.expiredStartLeaseCleanupTest` | full | `TestPreimplementationP1ITF/expired-start-lease-cleanup` |  |
| `concurrentProtocolTests.publicationAfterStopIntentTest` | full | `TestPreimplementationP1ITF/publication-after-stop-intent` |  |
| `concurrentProtocolManualTests.manualAcceptTest` | full | `TestPreimplementationP1ITF/manual-consent` |  |
| `concurrentProtocolManualTests.manualAcceptWhileSleepingTest` | full | `TestPreimplementationP1ITF/manual-consent-while-vm-sleeps` |  |
| `concurrentProtocolManualTests.manualDeclineTest` | full | `TestPreimplementationP1ITF/manual-decline` |  |
| `concurrentProtocolManualTests.closeBlocksConsentTest` | partial | `TestCancellationIntentBlocksConsentAndSurvivesDeletion` | A cancellation, not an expiry, blocks the consent. |
| `concurrentProtocolManualTests.abortedAdmissionReleasesLocksTest` | partial | `TestPreimplementationP1ITF/aborted-admission-releases-locks` | The fixture aborts a submission, then requests a deletion; the run aborts an acceptance, then cancels. |

### `concurrent_witness.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `concurrentWitnessStaleCallerGuard.guardTest` | full | `TestSqlRetirementRejectsReceivedCall` |  |
| `concurrentWitnessStaleCallerBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `concurrentWitnessNoFifoGuard.guardTest` | partial | `TestFifoAcrossRequests` | The same guard with the two requests in the other order. |
| `concurrentWitnessNoFifoBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `concurrentWitnessNoDedupGuard.guardTest` | full | `TestPreimplementationP1ITF/lost-ack-competing-lease` |  |
| `concurrentWitnessNoDedupBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `concurrentWitnessRacyFenceGuard.guardTest` | full | `TestConcurrentWitnessRacyFenceGuard` |  |
| `concurrentWitnessRacyFenceBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `concurrentWitnessWrongRequestFenceGuard.guardTest` | full | `TestConcurrentWitnessWrongRequestFenceGuard` |  |
| `concurrentWitnessWrongRequestFenceBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |

### `credential_renewal.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `credentialRenewalOk.confirmationCrashRetainsWakeTest` | full | `TestConfirmationCrashRetainsWake`, `TestMaintenanceServiceRecoversRenewalCrashesWithoutIncomingWork/confirmed` | The second test is the KVM campaign's, with the real worker process killed. |
| `credentialRenewalOk.canceledSnapshotTest` | full | `TestRenewalCancellationAndDurability` |  |

### `durability.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `durabilityOk.rollbackBeforeCommitTest` | full | `TestProcessCrashRecovery/before-commit` |  |
| `durabilityOk.lostAckRetryTest` | partial | `TestProcessCrashRecovery/after-commit` | A process crash, not a power loss. |
| `durabilityOk.ackThenPowerLossTest` | partial | `TestProcessCrashRecovery/after-commit` | A process crash, not a power loss; the store sets `synchronous=FULL`. |

### `fair_admission.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `fairAdmissionShared.noOvertakeTest` | full | `TestNoOvertake`, `TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork` |  |
| `fairAdmissionExclusive.deadOwnerTest` | full | `TestDeadOwner`, `TestBarrierAdmissionWorkerSIGKILL` |  |

### `fencing.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `fencingOk.fenceWaitsForEffectTest` | full | `TestFenceWaitsForEffectTransaction` |  |
| `fencingOk.effectBeforeFenceTest` | partial | `TestFenceWaitsForEffectTransaction`, `TestProcessCrashRecovery/fence-committed` | A process crash, not a power loss. |
| `fencingOk.fenceBeforeEffectTest` | full | `TestFenceSurvivesReopenAndRejectsEitherParticipant` |  |

### `leased_delivery.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `leasedDeliveryOk.delayedWorkerTest` | full | `TestExhaustedDeliveryFencesLateWorkerAndNotifiesSender` |  |

### `outbox.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `outboxOk.concurrentKeysTest` | partial | `TestAPIProcessCrash`, `TestConcurrentIdempotencyAndMandateBudget` | Crash before and after the commit, and concurrent keys, in separate tests. |

### `protocol_composition.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `protocolCompositionOk.replyAppliedBeforeDeletionTest` | full | `TestProtocolITFMicrosteps/reply-committed-ack-lost-delete` |  |
| `protocolCompositionOk.transactionDelaysFenceTest` | full | `TestPreimplementationP1ITF/writer-blocks-revocation` |  |
| `protocolCompositionOk.authorizedEffectDuringQuiescingTest` | full | `TestProtocolITFMicrosteps/transaction-crosses-quiescing` |  |
| `protocolCompositionOk.expiredLeaseRetryDeduplicatesTest` | partial | `TestProtocolITFMicrosteps/expired-lease-retry`, `TestPreimplementationP1ITF/lost-ack-competing-lease` | Neither replays the refused ACK of the first worker. |
| `protocolCompositionOk.oldGenerationCannotSubmitTest` | full | `TestPreimplementationP1ITF/old-caller-after-replacement` |  |
| `protocolCompositionOk.oldChannelCannotDeliverTest` | full | `TestPreimplementationP1ITF/old-channel-after-replacement` |  |
| `protocolCompositionOk.fenceOnlyCannotDeliverTest` | partial | `TestPlacementFenceOnlyAdmission`, `TestCapabilitiesRequireAuthenticationAndRespectFenceOnly` | A fence-only boot is confirmed only as such and refuses application work; no claim is tried. |
| `protocolCompositionOk.sealBlocksRestartTest` | partial | `TestPreimplementationP1HostSealITF`, `TestSealedVolumeRemovalRetryAndFutureFence` | Privileged host test (KVM build tags) and the host's sealed volume. |
| `protocolCompositionOk.admittedCallSurvivesPhysicalCrashTest` | full | `TestPreimplementationP1ITF/sql-commit-after-physical-death` |  |
| `protocolCompositionOk.receivedCallCanEnterSQLAfterPhysicalCrashTest` | full | `TestReceivedCallCanEnterSQLAfterPhysicalCrash` |  |
| `protocolCompositionOk.admittedCallBlocksSQLRetirementTest` | full | `TestAuthorityLock` |  |
| `protocolCompositionOk.sqlRetirementRejectsReceivedCallTest` | full | `TestSqlRetirementRejectsReceivedCall` |  |
| `protocolCompositionOk.confirmationWithoutPublicationIsRetiredTest` | full | `TestPreimplementationP1ITF/confirmed-unpublished-boot-cleanup` |  |
| `protocolCompositionOk.publicationAfterStopIntentHasNoAuthorityTest` | full | `TestPreimplementationP1ITF/publication-after-stop-intent` |  |

### `protocol_witness.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `protocolEnvelopeSchedule` | partial | `TestProtocolITFMicrosteps/reply-committed-ack-lost-delete` | The fixture replays this schedule on the conforming instance (`protocolEnvelopeConforming`); `protocolEnvelopeReused` is a broken configuration. |
| `protocolFenceSchedule` | model-only | — | Counterexample schedule for `protocolFenceRacy`, a broken configuration. Its guard is `transactionDelaysFenceTest`. |

### `restore_authority.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `restoreAuthority.degradedWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.promotedWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.windowWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.blanketWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.tokenCoveredWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.reconciledWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.reopenedWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.restoredAfterFailoverWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.windowRestoredWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.declaredAfterFailoverWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.seededWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |
| `restoreAuthority.secondFailoverWitness` | model-only | — | Reachability target of the simulation (`--witnesses`), not a behaviour. |

### `restore_authority_test.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `restoreAuthorityTests.oldImageReconcilesRevocationsAndOutcomesTest` | full | `TestOldImageReconcilesRevocationsAndOutcomes` |  |
| `restoreAuthorityTests.markerCannotInventRecoveryDataTest` | full | `TestActivationRequiresActualRecoveredData` |  |
| `restoreAuthorityTests.freshBackupKeepsAcknowledgedOutcomeTest` | full | `TestFreshBackupKeepsAcknowledgedOutcome` |  |
| `restoreAuthorityTests.unacknowledgedOutcomeCanBeRecomputedTest` | full | `TestUnacknowledgedOutcomeCanBeRecomputed` |  |
| `restoreAuthorityTests.unavailableArchivePreventsRepairTest` | full | `TestLostArchiveLeadsToDeclaredLoss` |  |
| `restoreAuthorityTests.undeclaredLossPreventsActivationTest` | full | `TestUndeclaredLossPreventsActivation`, `TestActivationRequiresActualRecoveredData` |  |
| `restoreAuthorityTests.declaredLossAllowsActivationTest` | full | `TestDeclaredLossAllowsActivation` |  |
| `restoreAuthorityTests.declaredLossBreaksFormerGuaranteeTest` | full | `TestDeclaredLossBreaksFormerGuarantee` |  |
| `restoreAuthorityTests.declaredLossIsRerunOnceTest` | full | `TestDeclaredLossIsRerunOnce` |  |
| `restoreAuthorityTests.rerunNeedsDeclaredLossTest` | full | `TestRerunNeedsDeclaredLoss` |  |
| `restoreAuthorityTests.noDeclarationWithoutLossTest` | full | `TestNoDeclarationWithoutLoss` |  |
| `restoreAuthorityTests.repairComesBeforeDeclarationTest` | full | `TestRepairComesBeforeDeclaration`, `TestActivationRequiresActualRecoveredData` |  |
| `restoreAuthorityTests.lostArchiveLeadsToDeclaredLossTest` | full | `TestLostArchiveLeadsToDeclaredLoss` |  |
| `restoreAuthorityTests.declaredLossSurvivesControlBackupRestoreTest` | full | `TestDeclaredLossSurvivesControlBackupRestore` |  |
| `restoreAuthorityTests.oldImageDoesNotReviveOffboardedJobTest` | full | `TestOldImageDoesNotReviveOffboardedJob` |  |
| `restoreAuthorityTests.oldImageDoesNotReviveDestroyedKeyTest` | full | `TestOldImageDoesNotReviveDestroyedKey` |  |
| `restoreAuthorityTests.activationRechecksNewRevocationTest` | full | `TestReceiptRevisionAndForgeryCannotPublish`, `TestPublicationSerializesConcurrentRevocation` |  |
| `restoreAuthorityTests.rescanAfterConcurrentRevocationTest` | full | `TestReceiptRevisionAndForgeryCannotPublish`, `TestPublicationSerializesConcurrentRevocation` |  |
| `restoreAuthorityTests.oldReceiptCannotBindToNewImageTest` | full | `TestConcurrentReservationAndOldReceiptCannotRebind` |  |
| `restoreAuthorityTests.lostReceiptIsRetriedFromDurableFenceTest` | full | `TestLostGuestFenceACKDoesNotBecomeIndependentReceipt` | KVM build tags, with PostgreSQL. |
| `restoreAuthorityTests.authorityOutageBlocksOtherwiseReadyActivationTest` | partial | `TestInitializationIdentityAndMissingAuthorityFailClosed` | An outage and a recovery on a key grant, not on an activation (ADR 003). |
| `restoreAuthorityTests.authorityRecoveryAllowsActivationTest` | partial | `TestInitializationIdentityAndMissingAuthorityFailClosed` | As above. |
| `restoreAuthorityTests.writerBlocksFenceTest` | partial | `TestFenceWaitsForEffectTransaction`, `TestAbortedWriterThenFence` | The store's writer blocks the fence; no guest is writing while the authority's revocation arrives (ADR 003). |
| `restoreAuthorityTests.admittedWriterFinishesBeforeRevocationTest` | partial | `TestRevocationWaitsForEveryStoreAndCancelsAtomically` | Old authorized work finishes before the fence, in the harness store; no guest (ADR 003). |
| `restoreAuthorityTests.physicalRetirementAbortsOldWriterTest` | partial | `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` | Install is refused while a VMM is registered or holds the volume (ADR 003). |
| `restoreAuthorityTests.revokedSubjectCannotAcquireNewKeyTest` | full | `TestSubjectKeyGateUsesIndependentIntent` |  |
| `restoreAuthorityTests.destructionWaitsForAllCachedCopiesTest` | partial | `TestDestructionWaitsForAllCachedCopies`, `TestKeyHoldDelaysDestructionAndClearsTheKey` | A guest's copy after the callback is the worker's obligation (ADR 005). |
| `restoreAuthorityTests.destructionRequiresPermanentSealTest` | full | `TestDestructionRequiresPermanentSeal`, `TestServiceRefusesADestructionWithoutASealedBinding` | The authorities refuse it (ADR 006 wave 3): in process, standalone and armed (`internal/restoreauthority`; armed, the catalogue refuses the key authority's own `Revoke` in the transaction that would record it), and through the authority service (`internal/authorityclient`). |
| `restoreAuthorityTests.destroyedKeyCannotDecryptOldBackupTest` | full | `TestDestroyedKeyCannotDecryptOldBackup`, `TestAcknowledgedWritesSurviveTheFailover` |  |
| `restoreAuthorityTests.liveKeyDecryptsBackupTest` | full | `TestLiveKeyDecryptsBackup` |  |
| `restoreAuthorityTests.sealedStoreCannotBeRestoredTest` | full | `TestReceiptRevisionAndForgeryCannotPublish` |  |
| `restoreAuthorityTests.sealRetirementCannotInstallUnreservedImageTest` | partial | `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` | A restore needs a LIVE agent and its reservation before it installs (ADR 003). |
| `restoreAuthorityTests.sealedStoreCannotBlockFutureRevocationTest` | full | `TestCurrentFenceAndRevocationPublicationRequireIndependentACKs` |  |
| `restoreAuthorityTests.authorityStateSurvivesControlBackupRestoreTest` | partial | `TestDeclaredLossSurvivesControlBackupRestore`, `TestPrivateDirectoriesAndRestoreSeparation` | The authorities keep their state outside the restored domain; no activation after a control-plane restore (ADR 003). |
| `restoreAuthorityRepeatedRestoreTests.earlierDeclarationDoesNotCoverLaterLossTest` | full | `TestEarlierDeclarationDoesNotCoverLaterLoss` |  |
| `restoreAuthorityRepeatedRestoreTests.eachRestoreDeclaresItsOwnLossTest` | full | `TestEachRestoreDeclaresItsOwnLoss` |  |
| `restoreAuthorityRepeatedRestoreTests.backupAfterRerunNeedsNoDeclarationTest` | full | `TestBackupAfterRerunNeedsNoDeclaration` |  |
| `restoreAuthorityMissingHistoryTests.undeclaredLossTest` | model-only | — | Broken configuration (ADR 003): no Go switch; `TestUndeclaredLossPreventsActivation` checks the guard it removes. |
| `restoreAuthorityMissingHistoryTests.silentRerunTest` | model-only | — | As above. |
| `restoreAuthorityRollbackTests.forgottenLossTest` | partial | `TestDeclaredLossIsNeverWithdrawn` | The catalogue refuses to delete or change a loss; it cannot detect its own rollback (ADR 003). |
| `restoreAuthorityReplicaTests.acknowledgedWriteIsOnReplicaTest` | full | `TestAcknowledgedWritesSurviveTheFailover` |  |
| `restoreAuthorityReplicaTests.destroyedKeyNeverReturnsAfterFailoverTest` | full | `TestAcknowledgedWritesSurviveTheFailover` |  |
| `restoreAuthorityReplicaTests.destructionResumesAfterResyncTest` | full | `TestDestructionResumesAfterResync` |  |
| `restoreAuthorityReplicaTests.oldPrimaryCannotResendAfterPromotionTest` | full | `TestOldPrimaryCannotResendAfterPromotion` |  |
| `restoreAuthorityReplicaTests.restoredImageRescansUnderNewEpochTest` | partial | `TestReceiptOfTheOldEpochCannotBindAfterPromotion` | The rescan without its degraded period (ADR 005). |
| `restoreAuthorityReplicaTests.tokenRevocationCoveredByBlanketTest` | pending | — | ADR 006 wave 7 (the announcement and the reconciliation). |
| `restoreAuthorityReplicaTests.grantRevocationWaitsForReplicaTest` | full | `TestGrantRevocationWaitsForReplica`, `TestAccessRecordContinuesInDegradedMode` | The authority service with its replica, degraded mode and the API on PostgreSQL (ADR 006 wave 5): the model's acknowledged access revocation is the API's confirmed one. In degraded mode a member's revocation takes effect at once and stays `pending`; its record is not on the replica, and no later question confirms it. |
| `restoreAuthorityReplicaTests.grantRevocationResumesAfterResyncTest` | full | `TestGrantRevocationResumesAfterResync` | After the resync the replica holds the record and the API confirms the revocation; the one left pending in degraded mode is confirmed too. |
| `restoreAuthorityReplicaTests.subjectRevocationCompletesAfterResyncTest` | full | `TestSubjectRevocationCompletesAfterResync` |  |
| `restoreAuthorityReplicaTests.degradedOutcomeIsAnnouncedAsWindowTest` | partial | `TestDegradedOutcomeIsLostWithThePrimary` | The loss is shown; its announcement comes with ADR 006 wave 7. |
| `restoreAuthorityReplicaTests.syncOutcomeIsDeclaredOneByOneTest` | full | `TestSyncOutcomeIsDeclaredOneByOne` |  |
| `restoreAuthorityReplicaTests.resyncEndsDegradedModeTest` | full | `TestResyncEndsDegradedMode` |  |
| `restoreAuthorityReplicaTests.reconciliationReplaysRootTest` | pending | — | ADR 006 wave 7. |
| `restoreAuthorityReplicaTests.shippedDatabaseNeedsNoReportTest` | pending | — | ADR 006 wave 7. |
| `restoreAuthorityReplicaTests.promotedAuthorityRunsAloneUntilSeededTest` | full | `TestPromotedAuthorityRunsAloneUntilSeeded` |  |
| `restoreAuthorityDecidedDegradedTests.blanketCoversTokensOnlyTest` | model-only | — | Degraded mode as first decided, replaced by finding 1 option (a) (ADR 005); documents the finding. |
| `restoreAuthorityDecidedDegradedTests.shippedGrantRevocationSurvivesTest` | pending | — | ADR 006 wave 7. |
| `restoreAuthorityDecidedDegradedTests.completedSubjectRevocationIsLostTest` | model-only | — | Degraded mode as first decided; documents finding 1 (ADR 005). |

### `restore_witness.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `restoreWitnessStaleActivationGuard.guardTest` | partial | `TestReceiptRevisionAndForgeryCannotPublish`, `TestPublicationSerializesConcurrentRevocation` | Activation rechecks a revocation that began after its scan. |
| `restoreWitnessStaleActivationBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessMissingHistoryGuard.guardTest` | full | `TestUndeclaredLossPreventsActivation` |  |
| `restoreWitnessMissingHistoryBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessDeclaredLossGuard.guardTest` | full | `TestDeclaredLossAllowsActivation` |  |
| `restoreWitnessDeclaredLossFormerInvariant` | full | `TestDeclaredLossBreaksFormerGuarantee` |  |
| `restoreWitnessForgottenLossGuard.guardTest` | partial | `TestDeclaredLossIsNeverWithdrawn` | As `forgottenLossTest`. |
| `restoreWitnessForgottenLossBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessSurvivingKEKGuard.guardTest` | partial | `TestRevocationSurvivesRestoredKeyAndPrecedesCreation`, `TestDestroyedKeyCannotDecryptOldBackup` | The key directory restored from a backup keeps the revocation; the destroyed key decrypts nothing. |
| `restoreWitnessSurvivingKEKBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessCachedDEKGuard.guardTest` | partial | `TestDestructionWaitsForAllCachedCopies` | As `destructionWaitsForAllCachedCopiesTest`. |
| `restoreWitnessCachedDEKBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessNoRetirementGuard.guardTest` | partial | `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` | As `physicalRetirementAbortsOldWriterTest`. |
| `restoreWitnessNoRetirementBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessRevivedSealGuard.guardTest` | full | `TestReceiptRevisionAndForgeryCannotPublish` |  |
| `restoreWitnessRevivedSealBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessEarlyAckGuard.guardTest` | full | `TestEveryWriteReachesTheReplicaBeforeItReturns` |  |
| `restoreWitnessEarlyAckBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessUnfencedGuard.guardTest` | full | `TestOldPrimaryCannotResendAfterPromotion` |  |
| `restoreWitnessUnfencedBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessSameEpochGuard.guardTest` | full | `TestReceiptOfTheOldEpochCannotBindAfterPromotion` |  |
| `restoreWitnessSameEpochBroken` | full | `TestReceiptOfTheSameEpochWouldActivateUnfenced` | Without the epoch in the MAC, the old receipt would activate (ADR 005). |
| `restoreWitnessDegradedDestructionGuard.guardTest` | full | `TestDegradedModeHoldsKeyDestruction` |  |
| `restoreWitnessDegradedDestructionBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessEarlyOpenGuard.guardTest` | pending | — | ADR 006 wave 7. |
| `restoreWitnessEarlyOpenBroken` | model-only | — | Broken configuration: Go has no switch that removes the guard. |
| `restoreWitnessDecidedGrantGuard.guardTest` | pending | — | ADR 006 wave 5: a grant's revocation waits for the replica in degraded mode. |
| `restoreWitnessDecidedGrant` | model-only | — | Finding 1 of ADR 005: degraded mode as first decided. |
| `restoreWitnessDecidedSubjectGuard.guardTest` | full | `TestSubjectRevocationCompletesAfterResync` |  |
| `restoreWitnessDecidedSubject` | model-only | — | As above. |

### `revocation.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `revocationOk.waitsForEffectTest` | full | `TestRevocationWaitsForEveryStoreAndCancelsAtomically` |  |
| `revocationOk.lostAckRetryTest` | partial | `TestRevocationLostAckSurvivesReopenAndConcurrentRetry` | The store's power loss after the tombstone is not emulated. |
| `revocationOk.cannotFinishEarlyTest` | full | `TestRevocationWaitsForEveryStoreAndCancelsAtomically`, `TestRevocationUnavailableStoreAndNotificationRollback` |  |

### `revocation_test.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `revocationEarlyTombstoneTests.earlyTombstoneTest` | model-only | — | Reproduces a broken configuration (file header). |
| `revocationRacyFenceTests.lateEffectTest` | model-only | — | Reproduces a broken configuration (file header). |
| `revocationVolatileFenceTests.forgottenFenceTest` | model-only | — | Reproduces a broken configuration (file header). |

### `service_progress_test.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `serviceProgressTests.scenario0Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure` | `retiring-notice-waits-for-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.refusal0x0Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure` | `retiring-notice-waits-for-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.scenario1Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure`, `TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork` | `retiring-notice-reserves-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.refusal1x0Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure`, `TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork` | `retiring-notice-reserves-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.scenario2Test` | full | `TestPreimplementationP3ITF/successful-request-observed-and-notified` |  |
| `serviceProgressTests.scenario3Test` | full | `TestPreimplementationP3ITF/hung-handler-terminated-by-deadline` |  |
| `serviceProgressTests.scenario4Test` | full | `TestPreimplementationP3ITF/queued-request-deadline` |  |
| `serviceProgressTests.scenario5Test` | full | `TestPreimplementationP3ITF/terminal-notification-failure-keeps-inbox` |  |
| `serviceProgressTests.scenario6Test` | full | `TestPreimplementationP3ITF/notification-retry-success` |  |
| `serviceProgressTests.scenario7Test` | gap | — | `delete-running-agent-preserves-other-work`. Deletion race: needs a binding in which the deleted agent does not execute the other request. |
| `serviceProgressTests.scenario8Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure`, `TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork` | `barrier-reserves-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.refusal8x0Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure`, `TestCommonAdmissionQueueDoesNotLetLaterBarriersOvertakeWork` | `barrier-reserves-capacity`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.scenario9Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure` | `fence-waits-for-current-execution`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.refusal9x0Test` | partial | `TestBarrierAdmissionFIFOAndOrdinaryBackpressure` | `fence-waits-for-current-execution`. Capacity half only, on the host's admission queue: the worker's fences take `WithBarrier`, its callbacks `WithApplication` (`internal/worker/control_linux.go`). The SQL replay of the case waits for the capacity adapter (`scope.json`). |
| `serviceProgressTests.scenario10Test` | full | `TestPreimplementationP3ITF/restore-recovery-before-closing` |  |
| `serviceProgressTests.scenario11Test` | full | `TestPreimplementationP3ITF/unavailable-store-is-not-a-fence` |  |
| `serviceProgressTests.refusal11x0Test` | full | `TestPreimplementationP3ITF/unavailable-store-is-not-a-fence` |  |
| `serviceProgressTests.refusal11x1Test` | full | `TestPreimplementationP3ITF/unavailable-store-is-not-a-fence` |  |
| `serviceProgressTests.scenario12Test` | full | `TestPreimplementationP3ITF/worker-crash-recovery` |  |
| `serviceProgressTests.scenario13Test` | full | `TestPreimplementationP3ITF/authority-recovery-enables-observation` |  |
| `serviceProgressTests.scenario14Test` | full | `TestPreimplementationP3ITF/observe-requires-current-authority` |  |
| `serviceProgressTests.refusal14x0Test` | full | `TestPreimplementationP3ITF/observe-requires-current-authority` |  |
| `serviceProgressTests.scenario15Test` | full | `TestPreimplementationP3ITF/fifo-shared-notification-queue` |  |
| `serviceProgressTests.scenario16Test` | gap | — | `cannot-recycle-with-outstanding-notice`. Needs the identity retention contract; there is no recycle method. |
| `serviceProgressTests.refusal16x0Test` | gap | — | `cannot-recycle-with-outstanding-notice`. Needs the identity retention contract; there is no recycle method. |
| `serviceProgressTests.scenario17Test` | full | `TestPreimplementationP3ITF/two-repeatable-arrivals` |  |
| `serviceProgressTests.scenario18Test` | gap | — | `fifo-admission-cannot-overtake`. Needs the global admission queue, not one agent's mailbox. |
| `serviceProgressTests.refusal18x0Test` | gap | — | `fifo-admission-cannot-overtake`. Needs the global admission queue, not one agent's mailbox. |
| `serviceProgressTests.scenario20Test` | partial | `TestExpiredDeliveryDiesWithoutItsRecipient` | ADR 007; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.refusal20x0Test` | partial | `TestExpiredDeliveryDiesWithoutItsRecipient` | ADR 007; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.scenario21Test` | partial | `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence` | ADR 007; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.refusal21x0Test` | partial | `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence` | ADR 007; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.scenario21x1Test` | partial | `TestExpiredDeliveryThatMayHaveReachedWaitsForItsFence` | ADR 007; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.scenario22Test` | partial | `TestExpiredDeliveryBehindAStuckHeadDies` | ADR 007 §7; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.refusal22x0Test` | partial | `TestRetirementLeavesADeletionToCancel` | ADR 007 §7; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.scenario22x1Test` | partial | `TestRetirementLeavesADeletionToCancel` | ADR 007 §7; the P3 fixture pins the model before ADR 007. |
| `serviceProgressTests.scenario23Test` | partial | `TestRestoreRedeliversALostRequest` | ADR 008, not step by step; the P3 fixture pins the model before ADR 008. |
| `serviceProgressTests.scenario23x1Test` | full | `TestRedeliveredRequestEndsAtItsDeadline` |  |
| `serviceProgressTests.scenario24Test` | partial | `TestRestoreRedeliversALostReplyAndStatus` | ADR 008, not step by step; the P3 fixture pins the model before ADR 008. |
| `serviceProgressTests.refusal24x0Test` | model-only | — | `stabilize` is the progress proof's assumption that faults stop; it has no Go counterpart. |
| `serviceProgressTests.scenario19Test` | full | `TestPreimplementationP3ITF/deleted-destination-rejects-new-work` |  |
| `serviceProgressTests.refusal19x0Test` | full | `TestPreimplementationP3ITF/deleted-destination-rejects-new-work` |  |

### `store_enrollment.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `storeEnrollmentOk.newlyCreatedStoreCatchesCompletedRevocationTest` | partial | `TestEnrollmentHistoricalAndConcurrentRevocations` | A new store must fence revocations completed before it. |
| `storeEnrollmentOk.activationRechecksConcurrentRevocationTest` | partial | `TestEnrollmentActivationWaitsForConcurrentIntentCommit` |  |
| `storeEnrollmentOk.oldReceiptCannotAuthorizeRestoredImageTest` | full | `TestConcurrentReservationAndOldReceiptCannotRebind` |  |
| `storeEnrollmentOk.restorationCatchesCompletedAndConcurrentRevocationsTest` | partial | `TestReceiptRevisionAndForgeryCannotPublish`, `TestPublicationSerializesConcurrentRevocation` |  |
| `storeEnrollmentOk.retirementWaitsForPhysicalStopTest` | partial | `TestInstallVolumeRequiresRetiredRegisteredInodeAndExactImage` |  |
| `storeEnrollmentOk.permanentSealCannotBeRestoredTest` | full | `TestReceiptRevisionAndForgeryCannotPublish` |  |

### `store_seal.qnt`

| Run or witness | Status | Go projection | Notes |
|---|---|---|---|
| `storeSealOk.refusesReceiptBeforeDrainTest` | partial | `TestStoreSealRequiresCompletedBarrierAndImmutableReceipt`, `TestSealedVolumeRemovalRetryAndFutureFence` | SQL and host halves in separate tests. |
| `storeSealOk.refusesPublicationWithoutObservationTest` | partial | `TestStoreSealWorkerCrashBeforeDatabaseReceipt` | KVM campaign. |
| `storeSealOk.interruptedPublicationTest` | partial | `TestStoreSealWorkerCrashBeforeDatabaseReceipt`, `TestStoreSealDatabaseRecovery` | KVM campaign and PostgreSQL recovery; no host power loss. |
