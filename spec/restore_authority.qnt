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
 * D-05 option (a) (docs/adr/005-keys-outside-restored-domain.md): the root has a
 * replica on the standby. A write returns only once the replica holds it on
 * disk. A promotion makes the replica the root under a new epoch, and the old
 * primary's epoch is refused. In degraded mode (the standby unreachable past a
 * delay) some kinds of write continue unreplicated; if a disaster ends that
 * period, they are announced as a time window and every bearer token issued
 * before the failover is revoked. After a failover PostgreSQL is older than the
 * root; it is reconciled with the root before the API opens.
 * Archive availability, authenticated receipts, physical retirement, key/copy
 * erasure and stopping the old primary before a promotion remain
 * implementation/operator contracts. Losing both hosts is outside the model.
 * Logical subjects and store identities use separate roles even when numerically
 * equal. Crypto is symbolic: a surviving raw KEK is an explicit negative case.
 */
module restoreAuthority {
  type AgentId = int
  type EventId = int
  type AccessId = int
  type StorePhase = Ready | Draining | Installing | Reconciling | Sealed
  // What a caller can learn about one event, for the current image of its store.
  type OutcomeStatus = Unrecorded | Confirmed | LostRescheduled | RerunConfirmed
  // The kinds of root write. Degraded mode lets some of them continue unreplicated.
  type WriteKind = OutcomeRecord | FenceRevision | RevocationIntent | RevocationDone
    | TokenRevocation | GrantRevocation | Reservation | Declaration | Seal | KeyDestruction
  // A declared loss names the event and the restored image (incarnation) that lacks it.
  type Loss = { event: EventId, incarnation: int }
  // A receipt is signed under the epoch of the authority that scanned it.
  type Receipt = { store: AgentId, incarnation: int, revision: int, subjects: Set[AgentId], epoch: int }
  type Root = { revision: int, pending: Set[AgentId], revoked: Set[AgentId], destroyedKeys: Set[AgentId],
    incarnations: AgentId -> int, committed: Set[EventId], acks: AgentId -> Receipt, sealed: Set[AgentId],
    lost: Set[Loss], rerun: Set[Loss], accessRevoked: Set[AccessId] }
  // PostgreSQL's copies: access revocations, revocation subjects
  // (revocation_catalogue), deleted stores and incarnations (store_enrollments).
  type Database = { accessRevoked: Set[AccessId], subjects: Set[AgentId], sealed: Set[AgentId],
    incarnations: AgentId -> int }
  type Disk = { catalogue: Set[AgentId], wrappedKeys: Set[AgentId],
    seen: Set[EventId], effects: Set[EventId] }
  type Store = { phase: StorePhase, incarnation: int, alive: bool,
    writer: EventId, cachedKeys: Set[AgentId], fences: Set[AgentId], disk: Disk }
  type State = { rootAvailable: bool, stores: AgentId -> Store,
    backups: AgentId -> Disk, controlBackup: Root, archives: AgentId -> Disk,
    archiveAvailable: Set[AgentId], scans: AgentId -> Receipt, scanned: Set[AgentId], receipts: Set[Receipt],
    everRevoked: Set[AgentId], everDestroyed: Set[AgentId], everSealed: Set[AgentId], everAcked: Set[EventId],
    everDeclared: Set[Loss], highIncarnation: AgentId -> int, leakedRevokedData: bool, staleEffect: bool,
    badActivation: bool, lostAcknowledgedEffect: bool, undeclaredLoss: bool, silentRerun: bool,
    // D-05. The writer's epoch. The standby: present, reachable, its replica on
    // disk and what it has received. Degraded mode on the primary.
    epoch: int, hasStandby: bool, link: bool, degraded: bool, replica: Root, received: Root,
    // A disaster on the primary, the promotion, and the old primary's host.
    primaryLost: bool, failedOver: bool, oldUp: bool, oldEpoch: int, oldRoot: Root,
    // PostgreSQL, the copy the standby can promote (the database window), the API.
    pg: Database, pgBackup: Database, apiOpen: bool, reconciled: bool, reported: Set[AgentId],
    // Acknowledged access revocations; writes acknowledged in degraded mode and
    // not yet on the replica; announced windows; the blanket token revocation.
    everRevokedAccess: Set[AccessId], degradedAcks: Set[EventId], degradedRevoked: Set[AgentId],
    degradedAccess: Set[AccessId], window: Set[EventId], blanket: bool, blanketCovered: Set[AccessId],
    staleWriter: bool }
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
  // D-05. Guards: the replica acknowledges only what is on its disk; the
  // promoted authority refuses an older epoch; a promotion takes a new epoch;
  // PostgreSQL is reconciled before the API opens.
  const SYNC_ACK: bool
  const FENCE_OLD: bool
  const NEW_EPOCH: bool
  const REPLAY_FIRST: bool
  // Degraded mode exactly as decided: every revocation, including its
  // completion and the revocation of a standing grant, continues unreplicated.
  const DECIDED_REVOCATIONS: bool
  // Broken: key destruction continues in degraded mode.
  const DESTROY_DEGRADED: bool
  pure val EVENTS = EVENT_DEST.keys()
  // One bearer token (it also stands for a delegated JWT) and one standing
  // grant (a membership, team membership, assignment, mandate, delegation
  // trust, organization or LLM provider).
  pure val TOKENS: Set[AccessId] = Set(0)
  pure val GRANTS: Set[AccessId] = Set(1)
  pure val ACCESS = TOKENS.union(GRANTS)
  // What continues unreplicated in degraded mode. Seals, new keys, key
  // destruction, reservations and declarations always wait.
  pure val DEGRADED: Set[WriteKind] = Set(OutcomeRecord, FenceRevision, RevocationIntent, TokenRevocation)
    .union(if (DECIDED_REVOCATIONS) Set(RevocationDone, GrantRevocation) else Set())
    .union(if (DESTROY_DEGRADED) Set(KeyDestruction) else Set())
  pure def blankReceipt(a: AgentId): Receipt = {store:a,incarnation:0,revision:-1,subjects:Set(),epoch:0}
  pure val emptyDisk: Disk = { catalogue:Set(), wrappedKeys:SUBJECTS, seen:Set(), effects:Set() }
  pure val initialRoot: Root = { revision:0, pending:Set(), revoked:Set(), destroyedKeys:Set(),
    incarnations:STORES.mapBy(_ => 1), committed:Set(), acks:STORES.mapBy(a => blankReceipt(a)), sealed:Set(),
    lost:Set(), rerun:Set(), accessRevoked:Set() }
  pure val initialDatabase: Database = { accessRevoked:Set(), subjects:Set(), sealed:Set(),
    incarnations:STORES.mapBy(_ => 1) }
  pure val initialState: State = { rootAvailable:true,
    stores:STORES.mapBy(_ => { phase:Ready, incarnation:1, alive:true, writer:-1,
      cachedKeys:Set(), fences:Set(), disk:emptyDisk }),
    backups:STORES.mapBy(_ => emptyDisk), controlBackup:initialRoot,
    archives:STORES.mapBy(_ => emptyDisk), archiveAvailable:Set(),
    scans:STORES.mapBy(a => blankReceipt(a)), scanned:Set(), receipts:Set(),
    everRevoked:Set(), everDestroyed:Set(), everSealed:Set(), everAcked:Set(),
    everDeclared:Set(), highIncarnation:STORES.mapBy(_ => 1), leakedRevokedData:false, staleEffect:false,
    badActivation:false, lostAcknowledgedEffect:false, undeclaredLoss:false, silentRerun:false,
    epoch:1, hasStandby:true, link:true, degraded:false, replica:initialRoot, received:initialRoot,
    primaryLost:false, failedOver:false, oldUp:false, oldEpoch:0, oldRoot:initialRoot,
    pg:initialDatabase, pgBackup:initialDatabase, apiOpen:true, reconciled:true, reported:Set(),
    everRevokedAccess:Set(), degradedAcks:Set(), degradedRevoked:Set(), degradedAccess:Set(),
    window:Set(), blanket:false, blanketCovered:Set(), staleWriter:false }
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
  // What a caller was told: a loss declared for this image, or an outcome
  // acknowledged in a degraded period that a disaster ended (a time window).
  pure def announced(x: State, e: EventId, i: int): bool =
    x.everDeclared.contains(lossAt(e,i)) or x.window.contains(e)
  pure def announcedFor(x: State, d: Disk, es: Set[EventId], i: int): bool =
    missingOutcomes(d,es).forall(e => announced(x,e,i))
  pure def archiveRepairs(r: Root, x: State, a: AgentId): bool =
    x.archiveAvailable.contains(a) and hasOutcomes(x.archives.get(a),required(r,a))
  // D-05. A write proceeds while the replica is in step; when the authority runs
  // alone after a promotion (no replica exists, so nothing can roll it back);
  // or in degraded mode, for the kinds degraded mode lets through.
  pure def canWrite(x: State, k: WriteKind): bool =
    not(x.hasStandby) or (x.link and not(x.degraded)) or (x.degraded and DEGRADED.contains(k))
  // The replica's side of a write. With SYNC_ACK the write returns once the
  // replica has it on disk; without, once the replica has merely received it.
  // In degraded mode, and with no standby, the replica does not get it.
  pure def replicated(x: State, r: Root): State =
    if (x.hasStandby and x.link and not(x.degraded))
      { ...x, received:r, replica:if (SYNC_ACK) r else x.replica }
    else x

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
  action beginRestore(a: AgentId): bool = {
    val reserved = root.incarnations.get(a)+1
    val r = { ...root, incarnations:root.incarnations.set(a,reserved), acks:root.acks.set(a,blankReceipt(a)) }
    all {
      canRestore(root,s,a), canWrite(s,Reservation), root' = r,
      s' = replicated({ ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Draining }),
        scanned:s.scanned.exclude(Set(a)), highIncarnation:s.highIncarnation.set(a,reserved),
        pg:{ ...s.pg, incarnations:s.pg.incarnations.set(a,reserved) } }, r),
    }
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
    val r = { ...root, lost:root.lost.union(losses) }
    all {
      s.rootAvailable, b.phase == Reconciling, b.alive, b.incarnation == root.incarnations.get(a),
      not(archiveRepairs(root,s,a)), not(losses.subseteq(root.lost)), canWrite(s,Declaration),
      root' = r, s' = replicated({ ...s, everDeclared:s.everDeclared.union(losses) }, r),
    }
  }
  action seal(a: AgentId): bool = {
    val r = { ...root, sealed:root.sealed.union(Set(a)) }
    all {
      s.rootAvailable, s.stores.get(a).phase == Installing, not(s.stores.get(a).alive), canWrite(s,Seal),
      root' = r,
      s' = replicated({ ...s, stores:s.stores.set(a,{ ...s.stores.get(a), phase:Sealed }),
        everSealed:s.everSealed.union(Set(a)), pg:{ ...s.pg, sealed:s.pg.sealed.union(Set(a)) } }, r),
    }
  }
  // The subject is also in PostgreSQL's revocation_catalogue.
  action beginRevocation(p: AgentId): bool = {
    val r = { ...root, pending:root.pending.union(Set(p)), revision:root.revision+1 }
    all {
      s.rootAvailable, not(root.pending.contains(p)), canWrite(s,RevocationIntent),
      root' = r, s' = replicated({ ...s, pg:{ ...s.pg, subjects:s.pg.subjects.union(Set(p)) } }, r),
    }
  }
  pure def canScan(x: State, a: AgentId): bool = x.rootAvailable and x.stores.get(a).alive and
    Set(Ready,Reconciling).contains(x.stores.get(a).phase)
  pure def scanned(r: Root, x: State, a: AgentId): State = { ...x, scanned:x.scanned.union(Set(a)),
    scans:x.scans.set(a,{ store:a, incarnation:x.stores.get(a).incarnation, revision:r.revision,
      subjects:r.pending, epoch:x.epoch }) }
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
  // D-05: a receipt signed under another epoch is refused. After a promotion
  // the revision counter may reuse a number the old primary gave out unreplicated.
  pure def canRecord(r: Root, x: State, receipt: Receipt): bool = x.rootAvailable and x.receipts.contains(receipt) and
    Set(Ready,Reconciling).contains(x.stores.get(receipt.store).phase) and
    x.stores.get(receipt.store).incarnation == r.incarnations.get(receipt.store) and
    (not(ACK_EPOCH) or receipt.incarnation == r.incarnations.get(receipt.store)) and
    receipt.revision >= r.acks.get(receipt.store).revision and receipt.epoch == x.epoch
  // A SQL ACK attaches to the current manifest. Checking the signed incarnation
  // BEFORE attaching it is essential; the broken variant rebinds an old receipt.
  action recordReceipt(receipt: Receipt): bool = {
    val r = { ...root, acks:root.acks.set(receipt.store,{ ...receipt, incarnation:root.incarnations.get(receipt.store) }) }
    all { canRecord(root,s,receipt), canWrite(s,FenceRevision), root' = r, s' = replicated(s,r) }
  }
  pure def subjectAcknowledged(r: Root, a: AgentId, p: AgentId): bool =
    r.acks.get(a).incarnation == r.incarnations.get(a) and r.acks.get(a).subjects.contains(p)
  pure def canFinishRevocation(r: Root, x: State, p: AgentId): bool = x.rootAvailable and r.pending.contains(p) and
    not(r.revoked.contains(p)) and STORES.forall(a => not(executes(x,a)) or subjectAcknowledged(r,a,p))
  // A physically stopped or restricted restoration image cannot execute old
  // work. It must catch up before any subsequent ordinary activation.
  action finishRevocation(p: AgentId): bool = {
    val r = { ...root, revoked:root.revoked.union(Set(p)) }
    all {
      canFinishRevocation(root,s,p), canWrite(s,RevocationDone), root' = r,
      s' = replicated({ ...s, everRevoked:s.everRevoked.union(Set(p)),
        degradedRevoked:if (s.degraded) s.degradedRevoked.union(Set(p)) else s.degradedRevoked }, r),
    }
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
      undeclaredLoss:x.undeclaredLoss or not(announcedFor(x,b.disk,ackedFor(x,a),b.incarnation)) }
  }
  action activate(a: AgentId): bool = all { canActivate(root,s,a), root' = root, s' = activated(root,s,a) }
  action loseReceipts = all { s.receipts != Set(), root' = root, s' = { ...s, receipts:Set() } }
  action rootUnavailable = all { s.rootAvailable, root' = root, s' = { ...s, rootAvailable:false } }
  action rootAvailable = all { not(s.rootAvailable), not(s.primaryLost), root' = root, s' = { ...s, rootAvailable:true } }
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
      // Applying an acknowledged event again is a rerun; it must follow a
      // declared loss, or fall in an announced time window.
      silentRerun:x.silentRerun or (apply and x.everAcked.contains(b.writer) and
        not(announced(x,b.writer,b.incarnation))) }
  }
  action commitEffect(a: AgentId): bool = all {
    s.stores.get(a).alive, s.stores.get(a).writer != -1, root' = root, s' = effectCommitted(s,a),
  }
  // This durable authority record precedes an externally successful ACK. An
  // archive need not yet exist; an old backup then cannot safely be activated.
  action recordOutcome(e: EventId): bool = {
    val r = { ...root, committed:root.committed.union(Set(e)) }
    all {
      s.rootAvailable, not(root.committed.contains(e)), s.stores.get(EVENT_DEST.get(e)).phase == Ready,
      hasOutcomes(s.stores.get(EVENT_DEST.get(e)).disk,Set(e)), canWrite(s,OutcomeRecord),
      root' = r, s' = replicated({ ...s, everAcked:s.everAcked.union(Set(e)),
        degradedAcks:if (s.degraded) s.degradedAcks.union(Set(e)) else s.degradedAcks }, r),
    }
  }
  // The rerun of a declared-lost job is recorded like a first outcome: after its
  // local commit, before the external ACK. The loss record itself stays.
  action recordRerun(e: EventId): bool = {
    val a = EVENT_DEST.get(e)
    val b = s.stores.get(a)
    val loss = lossAt(e,b.incarnation)
    val r = { ...root, rerun:root.rerun.union(Set(loss)) }
    all {
      s.rootAvailable, b.phase == Ready, b.incarnation == root.incarnations.get(a),
      root.lost.contains(loss), not(root.rerun.contains(loss)), hasOutcomes(b.disk,Set(e)), canWrite(s,OutcomeRecord),
      root' = r, s' = replicated(s,r),
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
  // Destruction waits for the replica: a key that only the replica still held
  // would come back with a promotion.
  action destroyKey(p: AgentId): bool = {
    val r = { ...root, destroyedKeys:root.destroyedKeys.union(Set(p)) }
    all {
      s.rootAvailable, root.revoked.contains(p), not(root.destroyedKeys.contains(p)),
      not(STORES.contains(p)) or root.sealed.contains(p),
      not(CACHE_GUARD) or cachesGone(s,p), canWrite(s,KeyDestruction),
      root' = r, s' = replicated({ ...s, everDestroyed:s.everDestroyed.union(Set(p)) }, r),
    }
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

  // D-05: access revocations. The record is written to the root before the
  // PostgreSQL transaction commits; the model does both in one step.
  action revokeAccess(g: AccessId): bool = {
    val k = if (TOKENS.contains(g)) TokenRevocation else GrantRevocation
    val r = { ...root, accessRevoked:root.accessRevoked.union(Set(g)) }
    all {
      s.rootAvailable, s.apiOpen, not(s.pg.accessRevoked.contains(g)), canWrite(s,k), root' = r,
      s' = replicated({ ...s, pg:{ ...s.pg, accessRevoked:s.pg.accessRevoked.union(Set(g)) },
        everRevokedAccess:s.everRevokedAccess.union(Set(g)),
        degradedAccess:if (s.degraded) s.degradedAccess.union(Set(g)) else s.degradedAccess }, r),
    }
  }
  // D-05: the link to the standby, degraded mode and catching up.
  action loseLink = all { s.hasStandby, s.link, root' = root, s' = { ...s, link:false } }
  // After the delay (30 seconds by default) without the standby.
  action enterDegraded = all {
    s.hasStandby, not(s.link), not(s.degraded), not(s.primaryLost), root' = root, s' = { ...s, degraded:true },
  }
  action restoreLink = all { s.hasStandby, not(s.link), root' = root, s' = { ...s, link:true } }
  // The replica catches up from its last sequence number. Degraded mode ends:
  // its writes are now on the replica.
  action resync = all {
    s.hasStandby, s.link, s.degraded, not(s.primaryLost), root' = root,
    s' = { ...s, received:root, replica:if (SYNC_ACK) root else s.replica, degraded:false,
      degradedAcks:Set(), degradedRevoked:Set(), degradedAccess:Set() },
  }
  // The standby restarts: what it had received but not written to disk is gone.
  action crashStandby = all { s.hasStandby, s.received != s.replica, root' = root, s' = { ...s, received:s.replica } }
  action flushReplica = all { s.hasStandby, s.received != s.replica, root' = root, s' = { ...s, replica:s.received } }
  // PostgreSQL's WAL reaches the standby: the database window closes up to here.
  action shipWal = all { not(s.primaryLost), s.pgBackup != s.pg, root' = root, s' = { ...s, pgBackup:s.pg } }
  // A disaster: the primary host is lost with its stores, its worker and its
  // PostgreSQL. Losing both hosts is outside the model.
  action losePrimary = all {
    not(s.primaryLost), s.hasStandby, root' = root,
    s' = { ...s, primaryLost:true, rootAvailable:false, apiOpen:false, oldUp:false, oldEpoch:s.epoch, oldRoot:root,
      stores:STORES.mapBy(a => { ...s.stores.get(a), alive:false, writer:-1, cachedKeys:Set() }) },
  }
  // The operator promotes the standby once the old primary is stopped. The
  // replica becomes the root under a new epoch; PostgreSQL is promoted from its
  // older copy. If a degraded period was running, its acknowledged outcomes are
  // announced as a time window and every bearer token issued before the
  // failover is revoked (delegation trusts' minimum_iat moves to the failover).
  // The promoted authority runs alone until a new standby is seeded.
  action promote = {
    val promoted = { ...s.received, accessRevoked:s.received.accessRevoked.union(if (s.degraded) TOKENS else Set()) }
    all {
      s.primaryLost, s.hasStandby, root' = promoted,
      s' = { ...s, primaryLost:false, rootAvailable:true, failedOver:true,
        epoch:if (NEW_EPOCH) s.epoch+1 else s.epoch,
        hasStandby:false, link:false, degraded:false, replica:promoted, received:promoted,
        window:if (s.degraded) s.window.union(s.degradedAcks) else s.window, blanket:s.blanket or s.degraded,
        blanketCovered:s.blanketCovered.union(s.degradedAccess.intersect(TOKENS)),
        degradedAcks:Set(), degradedRevoked:Set(), degradedAccess:Set(),
        pg:s.pgBackup, apiOpen:false, reconciled:false },
    }
  }
  // The old primary's host comes back after the promotion, with its old root.
  action oldPrimaryReturns = all { s.failedOver, not(s.oldUp), root' = root, s' = { ...s, oldUp:true } }
  // It resends the tail of its log under its epoch. Fencing refuses an older
  // epoch. Accepted, the old primary's state becomes the authority's again: the
  // worst case of applying its log over the new epoch.
  action oldPrimaryResends = all {
    s.oldUp, s.rootAvailable, not(FENCE_OLD) or s.oldEpoch >= s.epoch, root != s.oldRoot,
    root' = s.oldRoot,
    s' = { ...s, staleWriter:true, replica:if (s.hasStandby) s.oldRoot else s.replica,
      received:if (s.hasStandby) s.oldRoot else s.received },
  }
  // A new standby (or the old host, wiped) starts from a snapshot of the root.
  action seedStandby = all {
    not(s.hasStandby), not(s.primaryLost), s.rootAvailable, root' = root,
    s' = { ...s, hasStandby:true, link:true, degraded:false, replica:root, received:root },
  }
  // Before the API opens: the root's access records are replayed into
  // PostgreSQL, its revocation subjects copied back, its seals resume the
  // deletions, and every store whose incarnation differs is reported.
  // PostgreSQL's own newer records are kept in the root too.
  action reconcileDatabase = {
    val r = { ...root, accessRevoked:root.accessRevoked.union(s.pg.accessRevoked) }
    all {
      s.rootAvailable, not(s.reconciled), canWrite(s,GrantRevocation), root' = r,
      s' = replicated({ ...s, reconciled:true,
        pg:{ ...s.pg, accessRevoked:s.pg.accessRevoked.union(root.accessRevoked),
          subjects:s.pg.subjects.union(root.pending), sealed:s.pg.sealed.union(root.sealed) },
        reported:s.reported.union(STORES.filter(a => s.pg.incarnations.get(a) != root.incarnations.get(a))) }, r),
    }
  }
  action openApi = all {
    s.rootAvailable, not(s.apiOpen), not(REPLAY_FIRST) or s.reconciled, root' = root, s' = { ...s, apiOpen:true },
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
  // if its loss was declared for that store's current image. D-05 adds the
  // time window announced after a disaster that ended a degraded period.
  val noUndeclaredLoss = not(s.undeclaredLoss) and STORES.forall(a => s.stores.get(a).phase == Ready implies
    announcedFor(s,s.stores.get(a).disk,ackedFor(s,a),s.stores.get(a).incarnation))
  val declaredLossesSurvive = s.everDeclared.subseteq(root.lost)
  val lossesNameAcknowledgedWork = root.lost.forall(l => s.everAcked.contains(l.event))
  val rerunsFollowDeclaredLoss = root.rerun.subseteq(root.lost)
  val noSilentRerun = not(s.silentRerun)
  // The guarantee before option B. It is no longer part of safety: a declared
  // loss violates it by design (negative witness in the tests).
  val noLostAcknowledgedOutcome = not(s.lostAcknowledgedEffect) and STORES.forall(a =>
    s.stores.get(a).phase == Ready implies hasOutcomes(s.stores.get(a).disk,ackedFor(s,a)))
  // D-05. Every acknowledged write is on the replica's disk, except what
  // degraded mode let through since the standby was last in step.
  val acknowledgedWritesReplicated = s.hasStandby implies all {
    s.everAcked.subseteq(s.replica.committed.union(s.degradedAcks).union(s.window)),
    s.everRevoked.subseteq(s.replica.revoked.union(s.degradedRevoked)),
    s.everRevokedAccess.subseteq(s.replica.accessRevoked.union(s.degradedAccess)),
    s.everSealed.subseteq(s.replica.sealed),
    s.everDestroyed.subseteq(s.replica.destroyedKeys),
    s.everDeclared.subseteq(s.replica.lost),
    STORES.forall(a => s.replica.incarnations.get(a) >= s.highIncarnation.get(a)),
  }
  // The promoted authority never takes the old primary's writes.
  val oldPrimaryFenced = not(s.staleWriter)
  // Once the API is open, PostgreSQL holds every acknowledged access revocation:
  // the older database revives no access.
  val noRevivedAccess = s.apiOpen implies s.everRevokedAccess.subseteq(s.pg.accessRevoked)
  // ... every revocation subject of the root,
  val subjectsCopiedBack = s.apiOpen implies root.pending.subseteq(s.pg.subjects)
  // ... every store the root has sealed, so its deletion resumes and no deleted
  // agent (nor its destroyed key) comes back,
  val deletionsResumed = s.apiOpen implies root.sealed.subseteq(s.pg.sealed)
  // ... and every store whose incarnation in PostgreSQL differs from the root's
  // is reported.
  val divergenceReported = s.apiOpen implies STORES.forall(a =>
    s.pg.incarnations.get(a) != root.incarnations.get(a) implies s.reported.contains(a))
  val safety = retiredBeforeInstall and identitiesFresh and permanentSeals and revocationsSurvive and
    acksSound and noRestoredRevocation and activationCurrent and noStaleEffect and
    keyDestructionSurvives and erasedKeysUnavailable and noUndeclaredLoss and declaredLossesSurvive and
    lossesNameAcknowledgedWork and rerunsFollowDeclaredLoss and noSilentRerun and
    acknowledgedWritesReplicated and oldPrimaryFenced and noRevivedAccess and subjectsCopiedBack and
    deletionsResumed and divergenceReported
  // D-05 steps, also weighted by the focused simulation.
  action failoverStep = any {
    loseLink, enterDegraded, restoreLink, resync, crashStandby, flushReplica,
    losePrimary, promote, oldPrimaryReturns, oldPrimaryResends, seedStandby,
    shipWal, reconcileDatabase, openApi,
    { nondet g = ACCESS.oneOf(); revokeAccess(g) },
  }
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
    failoverStep,
  }
  // The focused simulation. Each D-05 step, and each step of a restore and of an
  // acknowledged delivery, is a branch of its own, so a failover followed by
  // restores is common. A disaster waits for an acknowledged outcome: it
  // explores fewer behaviors, not other ones. The full step stays one branch.
  action focusedStep = any {
    loseLink, enterDegraded, restoreLink, resync, all { s.everAcked != Set(), losePrimary }, promote,
    oldPrimaryReturns, oldPrimaryResends, seedStandby, shipWal, reconcileDatabase, openApi,
    { nondet g = ACCESS.oneOf(); revokeAccess(g) },
    { nondet a = STORES.oneOf(); beginRestore(a) },
    { nondet a = STORES.oneOf(); retire(a) },
    { nondet a = STORES.oneOf(); install(a) },
    { nondet a = STORES.oneOf(); launchRestore(a) },
    { nondet a = STORES.oneOf(); scan(a) },
    { nondet a = STORES.oneOf(); synchronize(a) },
    { nondet receipt = s.receipts.oneOf(); recordReceipt(receipt) },
    { nondet a = STORES.oneOf(); declareLoss(a) },
    { nondet a = STORES.oneOf(); activate(a) },
    { nondet a = STORES.oneOf(); nondet p = SUBJECTS.oneOf(); cacheKey(a,p) },
    { nondet a = STORES.oneOf(); nondet e = EVENTS.oneOf(); beginEffect(a,e) },
    { nondet a = STORES.oneOf(); commitEffect(a) },
    { nondet e = EVENTS.oneOf(); recordOutcome(e) },
    { nondet p = SUBJECTS.oneOf(); any { beginRevocation(p), finishRevocation(p), destroyKey(p) } },
    step,
  }
  // Counted by --witnesses in the simulations.
  val degradedWitness = s.degraded
  val promotedWitness = s.failedOver
  val windowWitness = s.window != Set()
  val blanketWitness = s.blanket
  val tokenCoveredWitness = s.blanketCovered != Set()
  val reconciledWitness = s.failedOver and s.reconciled
  val reopenedWitness = s.failedOver and s.apiOpen
  // Every store dies with the primary: one that is Ready and alive after a
  // promotion was restored on the standby.
  val restoredAfterFailoverWitness = s.failedOver and STORES.exists(a =>
    s.stores.get(a).alive and s.stores.get(a).phase == Ready)
  val windowRestoredWitness = windowWitness and restoredAfterFailoverWitness
  val declaredAfterFailoverWitness = s.failedOver and root.lost != Set()
  val seededWitness = s.failedOver and s.hasStandby
  val secondFailoverWitness = s.failedOver and s.epoch >= 3
}
module restoreAuthorityOk {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

// The focused simulation's configuration: three incarnations, so that a store
// restored before a disaster can be restored again after it.
module restoreAuthorityFailover {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=3, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityTiny {
  import restoreAuthority(STORES=Set(0), SUBJECTS=Set(0), EVENT_DEST=Map(0->0), EVENT_SUBJECT=Map(0->0),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityRollback {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=true, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityOldReceipt {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=false, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityStaleActivation {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=false, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityMissingHistory {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=false,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthoritySurvivingKEK {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=true, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityCachedDEK {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=false,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityNoRetirement {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=false, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityRevivedSeal {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=false, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

// D-05 negative configurations. Each disables one guard of option (a).
module restoreAuthorityEarlyAck {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=false, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityUnfenced {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=false, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthoritySameEpoch {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=false, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

module restoreAuthorityDegradedDestruction {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=true).*
}

module restoreAuthorityEarlyOpen {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=false, DECIDED_REVOCATIONS=false, DESTROY_DEGRADED=false).*
}

// Degraded mode exactly as decided on November 13, 2026: a finding, not a
// guard. Every revocation continues unreplicated.
module restoreAuthorityDecidedDegraded {
  import restoreAuthority(STORES=Set(0,1), SUBJECTS=Set(0,1), EVENT_DEST=Map(0->1,1->0), EVENT_SUBJECT=Map(0->0,1->1),
    MAX_INC=2, ROOT_ROLLBACK=false, ACK_EPOCH=true, RECHECK=true, HISTORY_GUARD=true,
    RAW_KEK=false, RETIRE_GUARD=true, SEAL_GUARD=true, CACHE_GUARD=true,
    SYNC_ACK=true, FENCE_OLD=true, NEW_EPOCH=true, REPLAY_FIRST=true, DECIDED_REVOCATIONS=true, DESTROY_DEGRADED=false).*
}
