/**
 * One ordinary LIVE boot owes one credential replacement. SQL stop/job commit,
 * physical retirement, lease/boot, SQL confirmation, durable host publication
 * and job completion are distinct. Generations/identity checks are abstracted
 * by old/starting/ready; this is NOT their refinement or a parametric proof.
 * Recovery reaps an unconfirmed host attempt but adopts a published ready boot.
 * A saved job snapshot is not authority after an explicit stop cancels the job.
 */
module credentialRenewal {
  const KEEP_UNTIL_HOST_READY: bool
  const RECHECK_JOB: bool
  type State = { sql: str, vm: str, worker: bool, capacity: bool, live: bool,
                 issued: bool, job: bool, snapshot: bool, owed: bool,
                 canceled: bool, completed: bool, unauthorizedWake: bool }
  var s: State
  action init = s' = { sql: "RUNNING", vm: "old", worker: true, capacity: true,
    live: true, issued: false, job: false, snapshot: false, owed: false,
    canceled: false, completed: false, unauthorizedWake: false }
  action request = all {
    s.worker, s.live, not(s.issued), not(s.canceled), s.sql == "RUNNING", s.vm == "old",
    s' = { ...s, sql: "STOPPING", issued: true, job: true, owed: true },
  }
  action retire = all {
    s.worker, s.sql == "STOPPING",
    s' = { ...s, sql: "STOPPED", vm: "absent" },
  }
  action readJob = all { s.worker, s.job, s' = { ...s, snapshot: true } }
  action start = all {
    s.worker, s.live, s.capacity, s.snapshot, s.sql == "STOPPED",
    if (RECHECK_JOB) s.job else true,
    s' = { ...s, sql: "STARTING", vm: "starting", snapshot: false,
      unauthorizedWake: s.unauthorizedWake or not(s.job) },
  }
  action confirmSQL = all {
    s.worker, s.live, s.sql == "STARTING", s.vm == "starting",
    s' = { ...s, sql: "RUNNING", job: if (KEEP_UNTIL_HOST_READY) s.job else false },
  }
  action publishHost = all {
    s.worker, s.sql == "RUNNING", s.vm == "starting",
    s' = { ...s, vm: "ready" },
  }
  action complete = all {
    s.worker, s.live, s.sql == "RUNNING", s.vm == "ready", s.job,
    s' = { ...s, job: false, owed: false, completed: true },
  }
  action cancelStop = all {
    not(s.canceled), s' = { ...s, canceled: true, job: false, owed: false, sql: "STOPPING" },
  }
  action delete = all {
    s.live, s' = { ...s, live: false, canceled: true, job: false, owed: false, sql: "STOPPING" },
  }
  action crash = all { s.worker, s' = { ...s, worker: false } }
  // The macro includes verified cleanup/STOPPED of a partial attempt. A real
  // worker can crash during cleanup; it must retry before claiming another boot.
  action recover = all {
    not(s.worker), s' = { ...s, worker: true,
      sql: if (s.vm == "starting") "STOPPED" else s.sql,
      vm: if (s.vm == "starting") "absent" else s.vm },
  }
  action changeCapacity = s' = { ...s, capacity: not(s.capacity) }
  action step = any { request, retire, readJob, start, confirmSQL, publishHost,
                     complete, cancelStop, delete, crash, recover, changeCapacity, s' = s }
  val wakeSurvives = (s.owed and s.vm == "absent") implies s.job
  val canceledWakeRefused = not(s.unauthorizedWake)
  val safety = wakeSurvives and canceledWakeRefused
  temporal fair = retire.weakFair(s) and readJob.weakFair(s) and start.weakFair(s)
    and confirmSQL.weakFair(s) and publishHost.weakFair(s) and complete.weakFair(s)
  // Success, distinct from cancellation, after faults cease and a slot remains
  // available. This says nothing about progress under infinite crashes/evictions.
  temporal progress = (fair and eventually(always(s.worker and s.capacity))
    and always(s.live and not(s.canceled))) implies
    always(s.owed implies eventually(s.completed))
}
module credentialRenewalOk {
  import credentialRenewal(KEEP_UNTIL_HOST_READY = true, RECHECK_JOB = true).*
  run confirmationCrashRetainsWakeTest = init.then(request).then(retire).then(readJob)
    .then(start).then(confirmSQL).then(crash).then(recover)
    .expect(s.job and s.owed and s.vm == "absent").then(readJob).then(start)
    .then(confirmSQL).then(publishHost).then(complete).expect(s.completed and safety)
  run canceledSnapshotTest = init.then(request).then(readJob).then(cancelStop)
    .then(retire).expect(safety).then(start.fail())
}
module credentialRenewalEarlyCompletion {
  import credentialRenewal(KEEP_UNTIL_HOST_READY = false, RECHECK_JOB = true).*
}
module credentialRenewalNoRecheck {
  import credentialRenewal(KEEP_UNTIL_HOST_READY = true, RECHECK_JOB = false).*
}
