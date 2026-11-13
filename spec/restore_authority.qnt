/** P2: restore against an authority outside the restored failure domain.
 * A consistent external archive contains actual opaque outcome records; repair
 * copies those records, never invents business data from a deduplication ID.
 * The authority records an outcome before it can be acknowledged externally.
 * D-03 option B (docs/adr/003-restore-rpo.md): when no archive can repair a
 * restored image, each acknowledged outcome it lacks is declared lost in the
 * authority, per event and per incarnation, before activation. A declared loss
 * is never withdrawn. The job is due again under the same event ID, so a rerun
 * is idempotent, unless its subject was revoked since. The former guarantee
 * noLostAcknowledgedOutcome is kept only as a negative witness.
 * Archive availability, durable authority writes, authenticated receipts, physical
 * retirement and key/copy erasure remain implementation/environment contracts.
 * Logical subjects and store identities use separate roles even when numerically
 * equal. Crypto is symbolic: a surviving raw KEK is an explicit negative case.
 */
module restoreAuthority {
  type AgentId = int
  type EventId = int
  type StorePhase = Ready | Draining | Installing | Reconciling | Sealed
  // What a caller can learn about one event, for the current image of its store.
  type OutcomeStatus = Unrecorded | Confirmed | LostRescheduled | RerunConfirmed
  // A declared loss names the event and the restored image (incarnation) that lacks it.
  type Loss = { event: EventId, incarnation: int }
  type Receipt = { store: AgentId, incarnation: int, revision: int, subjects: Set[AgentId] }
  type Root = { revision: int, pending: Set[AgentId], revoked: Set[AgentId], destroyedKeys: Set[AgentId],
    incarnations: AgentId -> int, committed: Set[EventId], acks: AgentId -> Receipt, sealed: Set[AgentId],
    lost: Set[Loss], rerun: Set[Loss] }
  type Disk = { catalogue: Set[AgentId], wrappedKeys: Set[AgentId],
    seen: Set[EventId], effects: Set[EventId] }
  type Store = { phase: StorePhase, incarnation: int, alive: bool,
    writer: EventId, cachedKeys: Set[AgentId], fences: Set[AgentId], disk: Disk }
  type State = { rootAvailable: bool, stores: AgentId -> Store,
    backups: AgentId -> Disk, controlBackup: Root, archives: AgentId -> Disk,
    archiveAvailable: Set[AgentId], scans: AgentId -> Receipt, scanned: Set[AgentId], receipts: Set[Receipt],
    everRevoked: Set[AgentId], everDestroyed: Set[AgentId], everSealed: Set[AgentId], everAcked: Set[EventId],
    everDeclared: Set[Loss], highIncarnation: AgentId -> int, leakedRevokedData: bool, staleEffect: bool,
    badActivation: bool, lostAcknowledgedEffect: bool, undeclaredLoss: bool, silentRerun: bool }
  const STORES: Set[AgentId]
  const SUBJECTS: Set[AgentId]
  const EVENT_DEST: EventId -> AgentId
  const EVENT_SUBJECT: EventId -> AgentId
  const MAX_INC: int
  const ROOT_ROLLBACK: bool
  const ACK_EPOCH: bool
  const RECHECK: bool
  const HISTORY_GUARD: bool
  const RAW_KEK: bool
  const RETIRE_GUARD: bool
  const SEAL_GUARD: bool
  const CACHE_GUARD: bool
  pure val EVENTS = EVENT_DEST.keys()
  pure def blankReceipt(a: AgentId): Receipt = {store:a,incarnation:0,revision:-1,subjects:Set()}
  pure val emptyDisk: Disk = { catalogue:Set(), wrappedKeys:SUBJECTS, seen:Set(), effects:Set() }
  pure val initialRoot: Root = { revision:0, pending:Set(), revoked:Set(), destroyedKeys:Set(),
    incarnations:STORES.mapBy(_ => 1), committed:Set(), acks:STORES.mapBy(a => blankReceipt(a)), sealed:Set(),
    lost:Set(), rerun:Set() }
  pure val initialState: State = { rootAvailable:true,
    stores:STORES.mapBy(_ => { phase:Ready, incarnation:1, alive:true, writer:-1,
      cachedKeys:Set(), fences:Set(), disk:emptyDisk }),
    backups:STORES.mapBy(_ => emptyDisk), controlBackup:initialRoot,
    archives:STORES.mapBy(_ => emptyDisk), archiveAvailable:Set(),
    scans:STORES.mapBy(a => blankReceipt(a)), scanned:Set(), receipts:Set(),
    everRevoked:Set(), everDestroyed:Set(), everSealed:Set(), everAcked:Set(),
    everDeclared:Set(), highIncarnation:STORES.mapBy(_ => 1), leakedRevokedData:false, staleEffect:false,
    badActivation:false, lostAcknowledgedEffect:false, undeclaredLoss:false, silentRerun:false }
  var root: Root
  var s: State
  action init = all { root' = initialRoot, s' = initialState }
  pure def executes(x: State, a: AgentId): bool = x.stores.get(a).alive and
    Set(Ready,Draining).contains(x.stores.get(a).phase)
  pure def hasOutcomes(d: Disk, es: Set[EventId]): bool = es.subseteq(d.seen) and es.subseteq(d.effects)
  pure def required(r: Root, a: AgentId): Set[EventId] = r.committed.filter(e => EVENT_DEST.get(e) == a)
  pure def ackedFor(x: State, a: AgentId): Set[EventId] = x.everAcked.filter(e => EVENT_DEST.get(e) == a)
  pure def lossAt(e: EventId, i: int): Loss = { event:e, incarnation:i }
  pure def missingOutcomes(d: Disk, es: Set[EventId]): Set[EventId] = es.filter(e => not(hasOutcomes(d,Set(e))))
  // Each outcome is in the restored data or declared lost for this very image.
  // A loss declared for an earlier image never covers a later restore.
  pure def accounted(d: Disk, es: Set[EventId], losses: Set[Loss], i: int): bool =
    missingOutcomes(d,es).forall(e => losses.contains(lossAt(e,i)))
  pure def archiveRepairs(r: Root, x: State, a: AgentId): bool =
    x.archiveAvailable.contains(a) and hasOutcomes(x.archives.get(a),required(r,a))

  action takeBackup(a: AgentId): bool = all {
    s.stores.get(a).phase == Ready, s.stores.get(a).writer == -1,
    root' = root, s' = { ...s, backups:s.backups.set(a,s.stores.get(a).disk) },
  }
  action takeControlBackup = all { s.rootAvailable, root' = root, s' = { ...s, controlBackup:root } }
  action captureArchive(a: AgentId): bool = all {
    s.stores.get(a).phase == Ready, s.stores.get(a).writer == -1,
    root' = root, s' = { ...s, archives:s.archives.set(a,s.stores.get(a).disk), archiveAvailable:s.archiveAvailable.union(Set(a)) },
  }
  pure def canRestore(r: Root, x: State, a: AgentId): bool = x.rootAvailable and
    (x.stores.get(a).phase == Ready or (not(SEAL_GUARD) and x.stores.get(a).phase == Sealed)) and
    r.incarnations.get(a) < MAX_INC
  action beginRestore(a: AgentId): bool = all {
    canRestore(root,s,a),
    root' = { ...root, incarnations:root.incarnations.set(a,root.incarnations.get(a)+1), acks:root.acks.set(a,blankReceipt(a)) },
    s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Draining }),
      scanned:s.scanned.exclude(Set(a)), highIncarnation:s.highIncarnation.set(a,root.incarnations.get(a)+1) },
  }
  // Permanent retirement does not allocate a replacement incarnation.
  action beginSeal(a: AgentId): bool = all {
    s.rootAvailable, s.stores.get(a).phase == Ready, root' = root,
    s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Draining }) },
  }
  pure def physicallyRetired(x: State, a: AgentId): State = { ...x,
    stores:x.stores.set(a,{ ...x.stores.get(a), phase:Installing, alive:false, writer:-1, cachedKeys:Set() }) }
  action retire(a: AgentId): bool = all {
    s.stores.get(a).phase == Draining, root' = root, s' = physicallyRetired(s,a),
  }
  action skipRetirement(a: AgentId): bool = all {
    not(RETIRE_GUARD), s.stores.get(a).phase == Draining,
    root' = root, s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Installing }) },
  }
  pure def installed(r: Root, x: State, a: AgentId): State = { ...x,
    stores:x.stores.set(a,{ ...x.stores.get(a), phase:Reconciling, incarnation:r.incarnations.get(a),
      disk:x.backups.get(a), fences:x.backups.get(a).catalogue }), scanned:x.scanned.exclude(Set(a)) }
  action install(a: AgentId): bool = all {
    s.stores.get(a).phase == Installing, not(s.stores.get(a).alive),
    // A seal-only retirement does not reserve a new image. Reusing its old
    // incarnation would make old durable ACKs certify a rolled-back disk.
    s.stores.get(a).incarnation < root.incarnations.get(a),
    root' = if (ROOT_ROLLBACK) s.controlBackup else root, s' = installed(root,s,a),
  }
  action launchRestore(a: AgentId): bool = all {
    s.stores.get(a).phase == Reconciling, not(s.stores.get(a).alive),
    root' = root, s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), alive:true }) },
  }
  action repairHistory(a: AgentId): bool = all {
    s.rootAvailable, s.stores.get(a).phase == Reconciling, archiveRepairs(root,s,a),
    root' = root, s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), disk:{ ...s.stores.get(a).disk,
      effects:s.archives.get(a).effects, seen:s.archives.get(a).seen } }) },
  }
  // Option B: the restore inspects the restricted image and writes in the
  // authority every recorded outcome that the image lacks. It never replaces an
  // available repair, and it never names an outcome that the image holds.
  action declareLoss(a: AgentId): bool = {
    val b = s.stores.get(a)
    val losses = missingOutcomes(b.disk,required(root,a)).map(e => lossAt(e,b.incarnation))
    all {
      s.rootAvailable, b.phase == Reconciling, b.alive, b.incarnation == root.incarnations.get(a),
      not(archiveRepairs(root,s,a)), not(losses.subseteq(root.lost)),
      root' = { ...root, lost:root.lost.union(losses) }, s' = { ...s, everDeclared:s.everDeclared.union(losses) },
    }
  }
  action seal(a: AgentId): bool = all {
    s.rootAvailable, s.stores.get(a).phase == Installing, not(s.stores.get(a).alive),
    root' = { ...root, sealed:root.sealed.union(Set(a)) },
    s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Sealed }), everSealed:s.everSealed.union(Set(a)) },
  }
  action beginRevocation(p: AgentId): bool = all {
    s.rootAvailable, not(root.pending.contains(p)),
    root' = { ...root, pending:root.pending.union(Set(p)), revision:root.revision+1 }, s' = s,
  }
  pure def canScan(x: State, a: AgentId): bool = x.rootAvailable and x.stores.get(a).alive and
    Set(Ready,Reconciling).contains(x.stores.get(a).phase)
  pure def scanned(r: Root, x: State, a: AgentId): State = { ...x, scanned:x.scanned.union(Set(a)),
    scans:x.scans.set(a,{ store:a, incarnation:x.stores.get(a).incarnation, revision:r.revision, subjects:r.pending }) }
  action scan(a: AgentId): bool = all { canScan(s,a), root' = root, s' = scanned(root,s,a) }
  pure def canSynchronize(x: State, a: AgentId): bool = x.stores.get(a).alive and
    Set(Ready,Reconciling).contains(x.stores.get(a).phase) and x.stores.get(a).writer == -1 and
    x.scanned.contains(a) and x.scans.get(a).incarnation == x.stores.get(a).incarnation
  pure def synchronized(x: State, a: AgentId): State = {
    val subjects = x.stores.get(a).fences.union(x.scans.get(a).subjects)
    { ...x, stores:x.stores.set(a,{ ...x.stores.get(a), fences:subjects,
      disk:{ ...x.stores.get(a).disk, catalogue:subjects } }), receipts:x.receipts.union(Set(x.scans.get(a))) }
  }
  action synchronize(a: AgentId): bool = all { canSynchronize(s,a), root' = root, s' = synchronized(s,a) }
  pure def canRecord(r: Root, x: State, receipt: Receipt): bool = x.rootAvailable and x.receipts.contains(receipt) and
    Set(Ready,Reconciling).contains(x.stores.get(receipt.store).phase) and
    x.stores.get(receipt.store).incarnation == r.incarnations.get(receipt.store) and
    (not(ACK_EPOCH) or receipt.incarnation == r.incarnations.get(receipt.store)) and
    receipt.revision >= r.acks.get(receipt.store).revision
  // A SQL ACK attaches to the current manifest. Checking the signed incarnation
  // BEFORE attaching it is essential; the broken variant rebinds an old receipt.
  action recordReceipt(receipt: Receipt): bool = all {
    canRecord(root,s,receipt), s' = s,
    root' = { ...root, acks:root.acks.set(receipt.store,{ ...receipt, incarnation:root.incarnations.get(receipt.store) }) },
  }
  pure def subjectAcknowledged(r: Root, a: AgentId, p: AgentId): bool =
    r.acks.get(a).incarnation == r.incarnations.get(a) and r.acks.get(a).subjects.contains(p)
  pure def canFinishRevocation(r: Root, x: State, p: AgentId): bool = x.rootAvailable and r.pending.contains(p) and
    not(r.revoked.contains(p)) and STORES.forall(a => not(executes(x,a)) or subjectAcknowledged(r,a,p))
  // A physically stopped or restricted restoration image cannot execute old
  // work. It must catch up before any subsequent ordinary activation.
  action finishRevocation(p: AgentId): bool = all {
    canFinishRevocation(root,s,p), root' = { ...root, revoked:root.revoked.union(Set(p)) },
    s' = { ...s, everRevoked:s.everRevoked.union(Set(p)) },
  }
  pure def canActivate(r: Root, x: State, a: AgentId): bool = {
    val b = x.stores.get(a)
    x.rootAvailable and b.phase == Reconciling and b.alive and x.scanned.contains(a) and
      b.incarnation == r.incarnations.get(a) and (not(SEAL_GUARD) or not(r.sealed.contains(a))) and
      r.acks.get(a).incarnation == r.incarnations.get(a) and
      (not(RECHECK) or r.acks.get(a).revision == r.revision) and
      (not(HISTORY_GUARD) or accounted(b.disk,required(r,a),r.lost,b.incarnation))
  }
  pure def activated(r: Root, x: State, a: AgentId): State = {
    val b = x.stores.get(a)
    { ...x, stores:x.stores.set(a,{ ...b, phase:Ready }),
      badActivation:x.badActivation or not(r.pending.subseteq(b.fences)),
      lostAcknowledgedEffect:x.lostAcknowledgedEffect or not(hasOutcomes(b.disk,ackedFor(x,a))),
      undeclaredLoss:x.undeclaredLoss or not(accounted(b.disk,ackedFor(x,a),x.everDeclared,b.incarnation)) }
  }
  action activate(a: AgentId): bool = all { canActivate(root,s,a), root' = root, s' = activated(root,s,a) }
  action loseReceipts = all { s.receipts != Set(), root' = root, s' = { ...s, receipts:Set() } }
  action rootUnavailable = all { s.rootAvailable, root' = root, s' = { ...s, rootAvailable:false } }
  action rootAvailable = all { not(s.rootAvailable), root' = root, s' = { ...s, rootAvailable:true } }
  pure def canCacheKey(r: Root, x: State, a: AgentId, p: AgentId): bool = x.rootAvailable and
    x.stores.get(a).phase == Ready and x.stores.get(a).alive and x.stores.get(a).disk.wrappedKeys.contains(p) and
    not(r.pending.contains(p)) and not(r.destroyedKeys.contains(p)) and not(x.stores.get(a).cachedKeys.contains(p))
  action cacheKey(a: AgentId, p: AgentId): bool = all {
    canCacheKey(root,s,a,p), root' = root,
    s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), cachedKeys:s.stores.get(a).cachedKeys.union(Set(p)) }) },
  }
  pure def canBeginEffect(r: Root, x: State, a: AgentId, e: EventId): bool = {
    val b = x.stores.get(a)
    EVENT_DEST.get(e) == a and b.phase == Ready and b.alive and b.writer == -1 and
      b.incarnation == r.incarnations.get(a) and b.cachedKeys.contains(EVENT_SUBJECT.get(e)) and
      not(b.fences.contains(EVENT_SUBJECT.get(e)))
  }
  action beginEffect(a: AgentId, e: EventId): bool = all {
    canBeginEffect(root,s,a,e), root' = root, s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), writer:e }) },
  }
  pure def effectCommitted(x: State, a: AgentId): State = {
    val b = x.stores.get(a)
    val apply = not(b.disk.seen.contains(b.writer))
    { ...x, stores:x.stores.set(a,{ ...b, writer:-1,
      disk:{ ...b.disk, seen:b.disk.seen.union(Set(b.writer)), effects:b.disk.effects.union(Set(b.writer)) } }),
      staleEffect:x.staleEffect or (apply and x.everRevoked.contains(EVENT_SUBJECT.get(b.writer))),
      // Applying an acknowledged event again is a rerun; it must follow a declared loss.
      silentRerun:x.silentRerun or (apply and x.everAcked.contains(b.writer) and
        not(x.everDeclared.contains(lossAt(b.writer,b.incarnation)))) }
  }
  action commitEffect(a: AgentId): bool = all {
    s.stores.get(a).alive, s.stores.get(a).writer != -1, root' = root, s' = effectCommitted(s,a),
  }
  // This durable authority record precedes an externally successful ACK. An
  // archive need not yet exist; an old backup then cannot safely be activated.
  action recordOutcome(e: EventId): bool = all {
    s.rootAvailable, not(root.committed.contains(e)), s.stores.get(EVENT_DEST.get(e)).phase == Ready,
    hasOutcomes(s.stores.get(EVENT_DEST.get(e)).disk,Set(e)),
    root' = { ...root, committed:root.committed.union(Set(e)) }, s' = { ...s, everAcked:s.everAcked.union(Set(e)) },
  }
  // The rerun of a declared-lost job is recorded like a first outcome: after its
  // local commit, before the external ACK. The loss record itself stays.
  action recordRerun(e: EventId): bool = {
    val a = EVENT_DEST.get(e)
    val b = s.stores.get(a)
    val loss = lossAt(e,b.incarnation)
    all {
      s.rootAvailable, b.phase == Ready, b.incarnation == root.incarnations.get(a),
      root.lost.contains(loss), not(root.rerun.contains(loss)), hasOutcomes(b.disk,Set(e)),
      root' = { ...root, rerun:root.rerun.union(Set(loss)) }, s' = s,
    }
  }
  // The caller-visible state of an event, read in the authority for the current
  // image of its store.
  pure def outcomeStatus(r: Root, x: State, e: EventId): OutcomeStatus = {
    val loss = lossAt(e,x.stores.get(EVENT_DEST.get(e)).incarnation)
    if (not(r.committed.contains(e))) Unrecorded
    else if (r.rerun.contains(loss)) RerunConfirmed
    else if (r.lost.contains(loss)) LostRescheduled
    else Confirmed
  }
  // A declared-lost job is due again until it reruns, unless its subject is revoked.
  pure def due(r: Root, x: State, e: EventId): bool = outcomeStatus(r,x,e) == LostRescheduled and
    not(hasOutcomes(x.stores.get(EVENT_DEST.get(e)).disk,Set(e))) and not(r.pending.contains(EVENT_SUBJECT.get(e)))
  action crashStore(a: AgentId): bool = all {
    s.stores.get(a).alive, root' = root,
    s' = { ...s, stores:s.stores.set(a,{ ...s.stores.get(a), alive:false, writer:-1, cachedKeys:Set() }) },
  }
  pure def cachesGone(x: State, p: AgentId): bool = STORES.forall(a => not(x.stores.get(a).cachedKeys.contains(p)))
  action destroyKey(p: AgentId): bool = all {
    s.rootAvailable, root.revoked.contains(p), not(root.destroyedKeys.contains(p)),
    not(STORES.contains(p)) or root.sealed.contains(p),
    not(CACHE_GUARD) or cachesGone(s,p),
    root' = { ...root, destroyedKeys:root.destroyedKeys.union(Set(p)) }, s' = { ...s, everDestroyed:s.everDestroyed.union(Set(p)) },
  }
  pure def canDecryptBackup(r: Root, x: State, a: AgentId, p: AgentId): bool =
    x.backups.get(a).wrappedKeys.contains(p) and (RAW_KEK or not(cachesGone(x,p)) or
      (x.rootAvailable and not(r.pending.contains(p)) and not(r.destroyedKeys.contains(p))))
  // A surviving global KEK or cached plaintext DEK can bypass a logical deny.
  // Successful erasure requires their absence, not just a catalogue entry.
  action decryptBackup(a: AgentId, p: AgentId): bool = all {
    canDecryptBackup(root,s,a,p), root' = root,
    s' = { ...s, leakedRevokedData:s.leakedRevokedData or s.everDestroyed.contains(p) },
  }
  action loseArchive(a: AgentId): bool = all {
    s.archiveAvailable.contains(a), root' = root, s' = { ...s, archiveAvailable:s.archiveAvailable.exclude(Set(a)) },
  }
  val retiredBeforeInstall = STORES.forall(a => Set(Installing,Sealed).contains(s.stores.get(a).phase) implies
    not(s.stores.get(a).alive) and s.stores.get(a).writer == -1)
  val identitiesFresh = STORES.forall(a => root.incarnations.get(a) >= s.highIncarnation.get(a))
  val permanentSeals = s.everSealed.forall(a => root.sealed.contains(a) and s.stores.get(a).phase == Sealed)
  val revocationsSurvive = s.everRevoked.subseteq(root.revoked)
  val acksSound = STORES.forall(a => root.acks.get(a).incarnation == root.incarnations.get(a) implies
    (s.stores.get(a).incarnation == root.incarnations.get(a) and root.acks.get(a).subjects.subseteq(s.stores.get(a).fences)))
  val noRestoredRevocation = STORES.forall(a => executes(s,a) implies root.revoked.subseteq(s.stores.get(a).fences))
  val activationCurrent = not(s.badActivation)
  val noStaleEffect = not(s.staleEffect)
  val keyDestructionSurvives = s.everDestroyed.subseteq(root.destroyedKeys)
  val erasedKeysUnavailable = not(s.leakedRevokedData)
  // Option B: an acknowledged outcome may be missing from an active store only
  // if its loss was declared for that store's current image.
  val noUndeclaredLoss = not(s.undeclaredLoss) and STORES.forall(a => s.stores.get(a).phase == Ready implies
    accounted(s.stores.get(a).disk,ackedFor(s,a),s.everDeclared,s.stores.get(a).incarnation))
  val declaredLossesSurvive = s.everDeclared.subseteq(root.lost)
  val lossesNameAcknowledgedWork = root.lost.forall(l => s.everAcked.contains(l.event))
  val rerunsFollowDeclaredLoss = root.rerun.subseteq(root.lost)
  val noSilentRerun = not(s.silentRerun)
  // The guarantee before option B. It is no longer part of safety: a declared
  // loss violates it by design (negative witness in the tests).
  val noLostAcknowledgedOutcome = not(s.lostAcknowledgedEffect) and STORES.forall(a =>
    s.stores.get(a).phase == Ready implies hasOutcomes(s.stores.get(a).disk,ackedFor(s,a)))
  val safety = retiredBeforeInstall and identitiesFresh and permanentSeals and revocationsSurvive and
    acksSound and noRestoredRevocation and activationCurrent and noStaleEffect and
    keyDestructionSurvives and erasedKeysUnavailable and noUndeclaredLoss and declaredLossesSurvive and
    lossesNameAcknowledgedWork and rerunsFollowDeclaredLoss and noSilentRerun
  action step = any {
    nondet a = STORES.oneOf()
    any { takeBackup(a), captureArchive(a), beginRestore(a), beginSeal(a), retire(a), skipRetirement(a), install(a), launchRestore(a), repairHistory(a), declareLoss(a), seal(a) },
    { nondet a = STORES.oneOf(); any { scan(a), synchronize(a), activate(a) } },
    { nondet p = SUBJECTS.oneOf(); any { beginRevocation(p), finishRevocation(p) } },
    { nondet receipt = s.receipts.oneOf(); recordReceipt(receipt) },
    { nondet a = STORES.oneOf(); nondet p = SUBJECTS.oneOf(); any { cacheKey(a,p), decryptBackup(a,p) } },
    { nondet a = STORES.oneOf(); nondet e = EVENTS.oneOf(); beginEffect(a,e) },
    { nondet a = STORES.oneOf(); any { commitEffect(a), crashStore(a), loseArchive(a) } },
    { nondet e = EVENTS.oneOf(); any { recordOutcome(e), recordRerun(e) } },
    { nondet p = SUBJECTS.oneOf(); destroyKey(p) },
    takeControlBackup, loseReceipts, rootUnavailable, rootAvailable,
  }
}
module restoreAuthorityOk {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityTiny {
  import restoreAuthority(STORES=Set(0), SUBJECTS=Set(0), EVENT_DEST=Map(0->0), EVENT_SUBJECT=Map(0->0),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityRollback {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=true, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityOldReceipt {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=false, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityStaleActivation {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=false, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityMissingHistory {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=false,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthoritySurvivingKEK {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=true, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityCachedDEK {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=false).*
}

module restoreAuthorityNoRetirement {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=false, SEAL_GUARD=true, CACHE_GUARD=true).*
}

module restoreAuthorityRevivedSeal {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=false, CACHE_GUARD=true).*
}
