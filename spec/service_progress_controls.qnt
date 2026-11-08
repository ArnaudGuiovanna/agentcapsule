/** Equivalent fairness-omission controls for TLC.
 * TLC rejects the original optional-fairness formula's normal form; the
 * remaining premises are stated directly here.
 * All original transitions and parameters remain conforming; only the stated
 * fairness premise is omitted. No new states or transitions are introduced.
 */
module serviceProgressNoSchedulingControl {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./service_progress"
  temporal checked = (eventually(s.stable) and recovery) implies
    (terminates and outcomeAvailable and notificationTerminates)
}
module serviceProgressNoRecoveryControl {
  import serviceProgress(REQUESTS=Set(0,1), STORES=Set(0,1), PRIORITY=true,
    SCHEDULED=true, RECOVERY=true, OUTBOX=true, RELIABLE=false, ALLOW_DELETE=true).* from "./service_progress"
  temporal checked = (eventually(s.stable) and scheduling) implies
    (terminates and outcomeAvailable and notificationTerminates)
}
