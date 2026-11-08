/** Dynamic store enrollment and restoration against a durable revocation census.
 *
 * A restoration first blocks new application work, then physically retires the
 * previous image. Installing an older image may lose every local fence. Only a
 * restricted boot may run until catch-up and activation have completed.
 *
 * Revocation intent and its READY/DRAINING census are one SQL transaction.
 * Activation rechecks the durable catalogue in the same serialization domain.
 * Fence receipts identify the store incarnation; old receipts survive restore.
 * Atomic durable SQL/local commits and authentic incarnation identities remain
 * contracts. This component does not prove filesystem copy, encryption, key
 * erasure, rollback of the authoritative SQL catalogue, or effect-ledger restore.
 */
module storeEnrollment {
  const STORES: Set[str]
  const SUBJECTS: Set[str]
  const INITIAL: str
  const MAX_EPOCH: int
  const RECHECK: bool
  const EPOCH_GUARD: bool
  const RETIRE_GUARD: bool
  const SEAL_GUARD: bool

  type Receipt = { store: str, subject: str, epoch: int }
  type State = {
    phase: str -> str, epoch: str -> int, physical: str -> bool,
    busy: str -> str, fences: str -> Set[str], receipts: Set[Receipt],
    acks: str -> (str -> int), catalogue: str -> str,
    targets: str -> Set[str], read: str -> Set[str], scanned: Set[str],
    seals: Set[str], staleEffect: bool,
  }
  var s: State

  pure val EMPTY = SUBJECTS.mapBy(_ => 0)
  def executes(a: str): bool = s.physical.get(a) and Set("READY","DRAINING").contains(s.phase.get(a))
  val revoked = SUBJECTS.filter(p => s.catalogue.get(p) != "LIVE")
  def caughtUp(a: str, subjects: Set[str]): bool = subjects.forall(p => s.acks.get(a).get(p) == s.epoch.get(a))

  action init = s' = {
    phase: STORES.mapBy(a => if (a == INITIAL) "READY" else "ABSENT"),
    epoch: STORES.mapBy(a => if (a == INITIAL) 1 else 0),
    physical: STORES.mapBy(a => a == INITIAL), busy: STORES.mapBy(_ => ""),
    fences: STORES.mapBy(_ => Set()), receipts: Set(), acks: STORES.mapBy(_ => EMPTY),
    catalogue: SUBJECTS.mapBy(_ => "LIVE"), targets: SUBJECTS.mapBy(_ => Set()),
    read: STORES.mapBy(_ => Set()), scanned: Set(), seals: Set(), staleEffect: false,
  }

  action reserve(a: str): bool = all {
    s.phase.get(a) == "ABSENT",
    s' = { ...s, phase: s.phase.set(a,"INSTALLING"), epoch: s.epoch.set(a,1) },
  }
  // Durable reservation invalidates old receipts before any physical mutation.
  action restore(a: str): bool = all {
    s.phase.get(a) == "READY" or (not(SEAL_GUARD) and s.phase.get(a) == "SEALED"),
    s.epoch.get(a) < MAX_EPOCH,
    s' = { ...s, phase: s.phase.set(a,"DRAINING"), epoch: s.epoch.set(a,s.epoch.get(a)+1),
      scanned: s.scanned.exclude(Set(a)) },
  }
  action retire(a: str): bool = all {
    s.phase.get(a) == "DRAINING",
    s' = { ...s, phase: s.phase.set(a,"INSTALLING"), physical: s.physical.set(a,false), busy: s.busy.set(a,"") },
  }
  // A safe installation is possible only after observed physical retirement.
  // The broken alternative publishes INSTALLING while old application work lives.
  action skipRetirement(a: str): bool = all {
    not(RETIRE_GUARD), s.phase.get(a) == "DRAINING",
    s' = { ...s, phase: s.phase.set(a,"INSTALLING") },
  }
  action install(a: str): bool = all {
    s.phase.get(a) == "INSTALLING", not(s.physical.get(a)),
    s' = { ...s, phase: s.phase.set(a,"FENCING"), physical: s.physical.set(a,true),
      fences: s.fences.set(a,Set()), read: s.read.set(a,Set()), scanned: s.scanned.exclude(Set(a)) },
  }
  action scan(a: str): bool = all {
    s.phase.get(a) == "FENCING",
    s' = { ...s, read: s.read.set(a,revoked), scanned: s.scanned.union(Set(a)) },
  }
  action activate(a: str): bool = all {
    s.phase.get(a) == "FENCING", s.scanned.contains(a),
    caughtUp(a, if (RECHECK) revoked else s.read.get(a)),
    s' = { ...s, phase: s.phase.set(a,"READY") },
  }
  action seal(a: str): bool = all {
    s.phase.get(a) == "INSTALLING", not(s.physical.get(a)),
    s' = { ...s, phase: s.phase.set(a,"SEALED"), seals: s.seals.union(Set(a)) },
  }
  action beginRevocation(p: str): bool = all {
    s.catalogue.get(p) == "LIVE",
    s' = { ...s, catalogue: s.catalogue.set(p,"FENCING"),
      targets: s.targets.set(p,STORES.filter(a => executes(a))) },
  }
  action fence(a: str, p: str): bool = all {
    s.physical.get(a), Set("READY","FENCING").contains(s.phase.get(a)),
    s.busy.get(a) == "", revoked.contains(p),
    s' = { ...s, fences: s.fences.set(a,s.fences.get(a).union(Set(p))),
      receipts: s.receipts.union(Set({ store:a, subject:p, epoch:s.epoch.get(a) })) },
  }
  action acknowledge(r: Receipt): bool = all {
    s.receipts.contains(r),
    if (EPOCH_GUARD) r.epoch == s.epoch.get(r.store) else true,
    s' = { ...s, acks: s.acks.set(r.store,s.acks.get(r.store).set(r.subject,s.epoch.get(r.store))) },
  }
  action finishRevocation(p: str): bool = all {
    s.catalogue.get(p) == "FENCING",
    s.targets.get(p).forall(a => not(executes(a)) or caughtUp(a,Set(p))),
    s' = { ...s, catalogue: s.catalogue.set(p,"DONE") },
  }
  action beginEffect(a: str, p: str): bool = all {
    s.phase.get(a) == "READY", s.physical.get(a), s.busy.get(a) == "",
    not(s.fences.get(a).contains(p)),
    s' = { ...s, busy: s.busy.set(a,p) },
  }
  action commitEffect(a: str): bool = all {
    s.physical.get(a), s.busy.get(a) != "",
    s' = { ...s, busy: s.busy.set(a,""),
      staleEffect: s.staleEffect or s.catalogue.get(s.busy.get(a)) == "DONE" },
  }
  // Lost responses are harmless: retries consult the durable local fence.
  action loseResponses = s' = { ...s, receipts: Set() }
  action step = any {
    nondet a = STORES.oneOf()
    nondet p = SUBJECTS.oneOf()
    any { reserve(a), restore(a), retire(a), skipRetirement(a), install(a), scan(a), activate(a),
      seal(a), beginRevocation(p), fence(a,p), finishRevocation(p), beginEffect(a,p), commitEffect(a) },
    nondet r = s.receipts.oneOf()
    acknowledge(r),
    loseResponses,
  }

  val currentAcks = STORES.forall(a => SUBJECTS.forall(p =>
    (s.epoch.get(a) > 0 and s.acks.get(a).get(p) == s.epoch.get(a)) implies s.fences.get(a).contains(p)))
  val noRestoredRevocation = SUBJECTS.forall(p => s.catalogue.get(p) == "DONE" implies
    STORES.forall(a => executes(a) implies s.fences.get(a).contains(p)))
  val retiredBeforeInstall = STORES.forall(a => Set("ABSENT","INSTALLING","SEALED").contains(s.phase.get(a)) implies
    (not(s.physical.get(a)) and s.busy.get(a) == ""))
  val permanentSeals = s.seals.forall(a => s.phase.get(a) == "SEALED")
  val safety = all { currentAcks, noRestoredRevocation, retiredBeforeInstall, permanentSeals, not(s.staleEffect) }
}

module storeEnrollmentOk {
  import storeEnrollment(STORES=Set("a","b","c"), SUBJECTS=Set("agent/x","request/y"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=true, EPOCH_GUARD=true, RETIRE_GUARD=true, SEAL_GUARD=true).*

  run newlyCreatedStoreCatchesCompletedRevocationTest = init
    .then(beginRevocation("agent/x")).then(fence("a","agent/x"))
    .then(acknowledge({store:"a",subject:"agent/x",epoch:1})).then(finishRevocation("agent/x"))
    .then(reserve("b")).then(install("b")).then(scan("b"))
    .then(activate("b")).fail()
  run activationRechecksConcurrentRevocationTest = init
    .then(reserve("b")).then(install("b")).then(scan("b"))
    .then(beginRevocation("agent/x")).then(activate("b")).fail()
  run oldReceiptCannotAuthorizeRestoredImageTest = init
    .then(beginRevocation("agent/x")).then(fence("a","agent/x"))
    .then(restore("a")).then(retire("a")).then(install("a"))
    .then(acknowledge({store:"a",subject:"agent/x",epoch:1})).fail()
  run restorationCatchesCompletedAndConcurrentRevocationsTest = init
    .then(beginRevocation("agent/x")).then(fence("a","agent/x"))
    .then(acknowledge({store:"a",subject:"agent/x",epoch:1})).then(finishRevocation("agent/x"))
    .then(restore("a")).then(retire("a")).then(install("a")).then(scan("a"))
    .then(fence("a","agent/x")).then(acknowledge({store:"a",subject:"agent/x",epoch:2}))
    .then(beginRevocation("request/y")).then(finishRevocation("request/y"))
    .then(fence("a","request/y")).then(acknowledge({store:"a",subject:"request/y",epoch:2}))
    .then(activate("a")).expect(safety and s.phase.get("a") == "READY")
  run retirementWaitsForPhysicalStopTest = init
    .then(beginEffect("a","agent/x")).then(restore("a"))
    .then(beginRevocation("agent/x")).then(retire("a")).then(finishRevocation("agent/x"))
    .expect(safety and s.busy.get("a") == "")
  run permanentSealCannotBeRestoredTest = init
    .then(reserve("b")).then(seal("b")).then(restore("b")).fail()
}
module storeEnrollmentTiny {
  import storeEnrollment(STORES=Set("a","b"), SUBJECTS=Set("agent/x"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=true, EPOCH_GUARD=true, RETIRE_GUARD=true, SEAL_GUARD=true).*
}
module storeEnrollmentStaleScan {
  import storeEnrollment(STORES=Set("a","b"), SUBJECTS=Set("agent/x"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=false, EPOCH_GUARD=true, RETIRE_GUARD=true, SEAL_GUARD=true).*
}
module storeEnrollmentOldReceipt {
  import storeEnrollment(STORES=Set("a","b"), SUBJECTS=Set("agent/x"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=true, EPOCH_GUARD=false, RETIRE_GUARD=true, SEAL_GUARD=true).*
}
module storeEnrollmentNoRetirement {
  import storeEnrollment(STORES=Set("a","b"), SUBJECTS=Set("agent/x"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=true, EPOCH_GUARD=true, RETIRE_GUARD=false, SEAL_GUARD=true).*
}
module storeEnrollmentRevivedSeal {
  import storeEnrollment(STORES=Set("a","b"), SUBJECTS=Set("agent/x"), INITIAL="a",
    MAX_EPOCH=2, RECHECK=true, EPOCH_GUARD=true, RETIRE_GUARD=true, SEAL_GUARD=false).*
}
