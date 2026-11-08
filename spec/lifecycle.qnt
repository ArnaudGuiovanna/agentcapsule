// -*- mode: Bluespec; -*-
/**
 * Model 1 — Companion lifecycle on the worker side.
 *
 * Covers (section numbers refer to the original, unpublished design specification):
 *   - point 1: exclusive lease, generation, worker crash, reconciliation (§6.3, §8.3);
 *   - point 5: deletion and crypto-shredding (§6.7);
 *   - point 6: admission control (§6.4).
 *
 * Abstractions:
 *   - a single worker (a single host) running several concurrent jobs (goroutines);
 *   - a worker crash kills the jobs but NOT the Firecracker processes, which survive;
 *   - time is not modeled: lease expiry is a nondeterministic action;
 *   - quiesce/stop/forced stop are grouped into a single `stop` action.
 *
 * The HOST_LOCK and RECONCILE_SCAN constants enable the design mechanisms.
 * Disabling them must produce a counterexample (see the instance modules at the end of the file).
 */
module lifecycle {
  const AGENTS: Set[str]
  const JOBS: Set[str]
  const MAX_ACTIVE: int
  const MAX_GEN: int
  // Exclusive host lock per volume (e.g. flock), held by the VM process or by the
  // deletion procedure; released by the kernel when the process dies.
  const HOST_LOCK: bool
  // On restart, the worker scans the Firecracker processes that are actually alive.
  const RECONCILE_SCAN: bool

  type Phase = Idle | Acquired | Fenced | Launched
  type AState = Stopped | Starting | Running | Deleting | Deleted
  type Job = { phase: Phase, agent: str, gen: int }
  type Vm = { agent: str, gen: int }
  type Lease = { holder: str, gen: int, valid: bool }

  // --- state ---
  var workerUp: bool
  var reconciled: bool
  var jobs: str -> Job
  var vms: Set[Vm]            // processus Firecracker vivants, volume ouvert en RW
  var known: Set[Vm]          // worker's in-memory view (admission counter)
  var lease: str -> Lease     // bail en base (PostgreSQL)
  var gen: str -> int         // current generation in the database
  var st: str -> AState       // agent state in the database
  var hostLock: str -> str    // "" | "vm" | "deleter"
  var deleteRequested: str -> bool
  var dekDestroyed: str -> bool

  val idleJob: Job = { phase: Idle, agent: "", gen: 0 }

  pure def vmsOf(s: Set[Vm], a: str): Set[Vm] = s.filter(v => v.agent == a)

  // --- initialisation ---
  action init = all {
    workerUp' = true,
    reconciled' = true,
    jobs' = JOBS.mapBy(j => idleJob),
    vms' = Set(),
    known' = Set(),
    lease' = AGENTS.mapBy(a => { holder: "", gen: 0, valid: false }),
    gen' = AGENTS.mapBy(a => 0),
    st' = AGENTS.mapBy(a => Stopped),
    hostLock' = AGENTS.mapBy(a => ""),
    deleteRequested' = AGENTS.mapBy(a => false),
    dekDestroyed' = AGENTS.mapBy(a => false),
  }

  // --- VM start, in several steps to expose interleavings ---

  // 1. A job takes the lease in the database (transaction) and increments the generation.
  action acquire(j: str, a: str): bool = {
    val g = gen.get(a) + 1
    all {
      workerUp, reconciled,
      jobs.get(j).phase == Idle,
      not(deleteRequested.get(a)),
      st.get(a) == Stopped,
      not(lease.get(a).valid),
      g <= MAX_GEN,
      lease' = lease.set(a, { holder: j, gen: g, valid: true }),
      gen' = gen.set(a, g),
      st' = st.set(a, Starting),
      jobs' = jobs.set(j, { phase: Acquired, agent: a, gen: g }),
      workerUp' = workerUp, reconciled' = reconciled, vms' = vms, known' = known,
      hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // 2. The job rereads the database (fencing token). The read is not atomic with the launch.
  action fence(j: str): bool = {
    val jb = jobs.get(j)
    val l = lease.get(jb.agent)
    all {
      workerUp,
      jb.phase == Acquired,
      l.valid, l.holder == j, l.gen == jb.gen,
      jobs' = jobs.set(j, { ...jb, phase: Fenced }),
      workerUp' = workerUp, reconciled' = reconciled, vms' = vms, known' = known,
      lease' = lease, gen' = gen, st' = st,
      hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // 3. Launch of the Firecracker process. Admission control uses the view
  //    in the worker's memory; the host lock (if enabled) is taken by the kernel.
  action launch(j: str): bool = {
    val jb = jobs.get(j)
    val a = jb.agent
    all {
      workerUp,
      jb.phase == Fenced,
      known.size() < MAX_ACTIVE,
      not(dekDestroyed.get(a)),          // the volume cannot be opened without the key
      if (HOST_LOCK) hostLock.get(a) == "" else true,
      vms' = vms.union(Set({ agent: a, gen: jb.gen })),
      known' = known.union(Set({ agent: a, gen: jb.gen })),
      hostLock' = hostLock.set(a, "vm"),
      jobs' = jobs.set(j, { ...jb, phase: Launched }),
      workerUp' = workerUp, reconciled' = reconciled,
      lease' = lease, gen' = gen, st' = st,
      deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // 3b. The host lock is already taken: the job gives up and releases the lease if it still holds it.
  action launchBlocked(j: str): bool = {
    val jb = jobs.get(j)
    val a = jb.agent
    val l = lease.get(a)
    val mine = l.valid and l.holder == j and l.gen == jb.gen
    all {
      workerUp, HOST_LOCK,
      jb.phase == Fenced,
      hostLock.get(a) != "",
      jobs' = jobs.set(j, idleJob),
      lease' = if (mine) lease.set(a, { ...l, valid: false }) else lease,
      st' = if (mine and st.get(a) == Starting) st.set(a, Stopped) else st,
      workerUp' = workerUp, reconciled' = reconciled, vms' = vms, known' = known,
      gen' = gen, hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // 4. Health check of ITS VM, then confirmation in the database (conditional update).
  //    If the VM is dead or the lease is no longer ours, the job kills its own VM
  //    (self-fencing) and, if it still holds the lease, puts the agent back to STOPPED.
  action confirm(j: str): bool = {
    val jb = jobs.get(j)
    val a = jb.agent
    val l = lease.get(a)
    val v = { agent: a, gen: jb.gen }
    val alive = vms.contains(v)
    val mine = l.valid and l.holder == j and l.gen == jb.gen and st.get(a) == Starting
    val ok = mine and alive
    all {
      workerUp,
      jb.phase == Launched,
      jobs' = jobs.set(j, idleJob),
      st' = if (ok) st.set(a, Running) else if (mine) st.set(a, Stopped) else st,
      lease' = if (not(ok) and mine) lease.set(a, { ...l, valid: false }) else lease,
      vms' = if (ok) vms else vms.exclude(Set(v)),
      known' = if (ok) known else known.exclude(Set(v)),
      hostLock' = if (ok or not(alive)) hostLock else hostLock.set(a, ""),
      workerUp' = workerUp, reconciled' = reconciled, gen' = gen,
      deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // The start job is declared failed (timeout): the lease expires, the agent goes back to STOPPED.
  // The job itself may just be slow and continue later (blocked goroutine).
  action timeoutStart(a: str): bool = all {
    lease.get(a).valid,
    st.get(a) == Starting,
    lease' = lease.set(a, { ...lease.get(a), valid: false }),
    st' = st.set(a, Stopped),
    workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, vms' = vms, known' = known,
    gen' = gen, hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
  }

  // Stop (quiesce then stop, possibly forced) of the current VM.
  action stop(a: str): bool = {
    val v = { agent: a, gen: gen.get(a) }
    all {
      workerUp, reconciled,
      st.get(a) == Running,
      vms.contains(v),
      vms' = vms.exclude(Set(v)),
      known' = known.exclude(Set(v)),
      hostLock' = hostLock.set(a, ""),
      st' = st.set(a, Stopped),
      lease' = lease.set(a, { ...lease.get(a), valid: false }),
      workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs,
      gen' = gen, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // A VM dies on its own (guest crash, OOM). The kernel releases the host lock.
  action vmCrash(a: str, g: int): bool = {
    val v = { agent: a, gen: g }
    all {
      vms.contains(v),
      vms' = vms.exclude(Set(v)),
      hostLock' = if (hostLock.get(a) == "vm") hostLock.set(a, "") else hostLock,
      workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, known' = known,
      lease' = lease, gen' = gen, st' = st,
      deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // The worker notices that a VM it knew has disappeared (FAILED -> STOPPED).
  action observeExit(a: str, g: int): bool = {
    val v = { agent: a, gen: g }
    val current = g == gen.get(a) and st.get(a) == Running
    all {
      workerUp, reconciled,
      known.contains(v),
      not(vms.contains(v)),
      known' = known.exclude(Set(v)),
      st' = if (current) st.set(a, Stopped) else st,
      lease' = if (current) lease.set(a, { ...lease.get(a), valid: false }) else lease,
      workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, vms' = vms,
      gen' = gen, hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // --- worker crash and restart ---

  action crashWorker: bool = all {
    workerUp,
    workerUp' = false,
    reconciled' = false,
    jobs' = JOBS.mapBy(j => idleJob),   // goroutines die
    known' = Set(),                     // in-memory state is lost
    vms' = vms,                         // Firecracker processes survive
    lease' = lease, gen' = gen, st' = st,
    hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
  }

  action restartWorker: bool = all {
    not(workerUp),
    workerUp' = true,
    reconciled' = false,
    jobs' = jobs, vms' = vms, known' = known, lease' = lease, gen' = gen, st' = st,
    hostLock' = hostLock, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
  }

  // Reconciliation (§8.3). With RECONCILE_SCAN: adopt the VM of the current generation
  // of a RUNNING agent, kill all the others, and rebuild the admission view.
  // Without a scan: naively assume all VMs are dead.
  action reconcile: bool = {
    val adopt = vms.filter(v => v.gen == gen.get(v.agent) and st.get(v.agent) == Running
                                and not(deleteRequested.get(v.agent)))
    val survivors = if (RECONCILE_SCAN) adopt else vms
    val nextSt = AGENTS.mapBy(a =>
      if (st.get(a) == Deleting or st.get(a) == Deleted) st.get(a)
      else if (vmsOf(adopt, a).size() > 0 and RECONCILE_SCAN) Running
      else Stopped)
    all {
      workerUp, not(reconciled),
      reconciled' = true,
      vms' = survivors,
      known' = if (RECONCILE_SCAN) adopt else Set(),
      hostLock' = AGENTS.mapBy(a =>
        if (hostLock.get(a) == "deleter") "deleter"
        else if (vmsOf(survivors, a).size() > 0) "vm"
        else ""),
      st' = nextSt,
      lease' = AGENTS.mapBy(a =>
        if (nextSt.get(a) == Running) lease.get(a) else { ...lease.get(a), valid: false }),
      workerUp' = workerUp, jobs' = jobs, gen' = gen,
      deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
    }
  }

  // --- suppression (§6.7) ---

  action requestDelete(a: str): bool = all {
    not(deleteRequested.get(a)),
    deleteRequested' = deleteRequested.set(a, true),
    workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, vms' = vms, known' = known,
    lease' = lease, gen' = gen, st' = st, hostLock' = hostLock, dekDestroyed' = dekDestroyed,
  }

  // The deletion procedure takes the host lock and never releases it.
  // Without a host lock, it relies on the worker's in-memory view.
  action lockForDelete(a: str): bool = all {
    workerUp, reconciled,
    deleteRequested.get(a),
    st.get(a) == Stopped,
    if (HOST_LOCK) hostLock.get(a) == "" else vmsOf(known, a).size() == 0,
    hostLock' = hostLock.set(a, "deleter"),
    st' = st.set(a, Deleting),
    lease' = lease.set(a, { ...lease.get(a), valid: false }),
    workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, vms' = vms, known' = known,
    gen' = gen, deleteRequested' = deleteRequested, dekDestroyed' = dekDestroyed,
  }

  action destroyKey(a: str): bool = all {
    st.get(a) == Deleting,
    if (HOST_LOCK) hostLock.get(a) == "deleter" else true,
    dekDestroyed' = dekDestroyed.set(a, true),
    st' = st.set(a, Deleted),
    workerUp' = workerUp, reconciled' = reconciled, jobs' = jobs, vms' = vms, known' = known,
    lease' = lease, gen' = gen, hostLock' = hostLock, deleteRequested' = deleteRequested,
  }

  // --- relation de transition ---
  action step = {
    nondet j = JOBS.oneOf()
    nondet a = AGENTS.oneOf()
    nondet g = 1.to(MAX_GEN).oneOf()
    any {
      acquire(j, a), fence(j), launch(j), launchBlocked(j), confirm(j),
      timeoutStart(a), stop(a), vmCrash(a, g), observeExit(a, g),
      crashWorker, restartWorker, reconcile,
      requestDelete(a), lockForDelete(a), destroyKey(a),
    }
  }

  // Exact same transition relation as step for nonempty choice domains (all instances here).
  // Distribute existential choices over disjunction and drop unused choices in each branch.
  // TLC otherwise enumerates their Cartesian product even for unrelated actions.
  // Keep step unchanged for comparison and historical random-simulation seeds.
  action stepCompact = any {
    {
      nondet j = JOBS.oneOf()
      nondet a = AGENTS.oneOf()
      acquire(j, a)
    },
    {
      nondet j = JOBS.oneOf()
      fence(j)
    },
    {
      nondet j = JOBS.oneOf()
      launch(j)
    },
    {
      nondet j = JOBS.oneOf()
      launchBlocked(j)
    },
    {
      nondet j = JOBS.oneOf()
      confirm(j)
    },
    {
      nondet a = AGENTS.oneOf()
      timeoutStart(a)
    },
    {
      nondet a = AGENTS.oneOf()
      stop(a)
    },
    {
      nondet a = AGENTS.oneOf()
      nondet g = 1.to(MAX_GEN).oneOf()
      vmCrash(a, g)
    },
    {
      nondet a = AGENTS.oneOf()
      nondet g = 1.to(MAX_GEN).oneOf()
      observeExit(a, g)
    },
    crashWorker,
    restartWorker,
    reconcile,
    {
      nondet a = AGENTS.oneOf()
      requestDelete(a)
    },
    {
      nondet a = AGENTS.oneOf()
      lockForDelete(a)
    },
    {
      nondet a = AGENTS.oneOf()
      destroyKey(a)
    },
  }

  // --- properties ---

  // Point 1: never two VMs writing to the same volume.
  val exclusiveVolume: bool = AGENTS.forall(a => vmsOf(vms, a).size() <= 1)

  // Point 6: the number of live VMs never exceeds the cap.
  val admission: bool = vms.size() <= MAX_ACTIVE

  // Point 5: no live VM for an agent whose key is destroyed; no deleted agent
  // n'a de VM.
  val noVmAfterDelete: bool = AGENTS.forall(a =>
    (dekDestroyed.get(a) or st.get(a) == Deleted) implies vmsOf(vms, a).size() == 0)

  // Consistency: if the database says RUNNING (and the worker is reconciled), the VM of the
  // current generation is alive or its death has not been observed yet.
  val runningIsCurrent: bool = (workerUp and reconciled) implies AGENTS.forall(a =>
    st.get(a) == Running implies known.contains({ agent: a, gen: gen.get(a) }))

  val safety: bool = exclusiveVolume and admission and noVmAfterDelete and runningIsCurrent
}

// --- instances ---

// Design that follows the spec: every property must hold.
module lifecycleOk {
  import lifecycle(AGENTS = Set("a", "b"), JOBS = Set("j1", "j2"), MAX_ACTIVE = 1, MAX_GEN = 3,
                   HOST_LOCK = true, RECONCILE_SCAN = true).*
}

// No host lock: the database lease and fencing are not enough.
module lifecycleNoHostLock {
  import lifecycle(AGENTS = Set("a", "b"), JOBS = Set("j1", "j2"), MAX_ACTIVE = 2, MAX_GEN = 3,
                   HOST_LOCK = false, RECONCILE_SCAN = true).*
}

// No process scan on restart: orphan VMs skew admission.
module lifecycleNoScan {
  import lifecycle(AGENTS = Set("a", "b"), JOBS = Set("j1", "j2"), MAX_ACTIVE = 1, MAX_GEN = 3,
                   HOST_LOCK = true, RECONCILE_SCAN = false).*
}

module lifecycleLarge {
  import lifecycle(AGENTS = Set("a", "b", "c"), JOBS = Set("j1", "j2", "j3"),
                   MAX_ACTIVE = 2, MAX_GEN = 3, HOST_LOCK = true, RECONCILE_SCAN = true).*
}
