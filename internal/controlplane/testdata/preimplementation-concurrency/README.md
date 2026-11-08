# P1 conformance fixtures

The manifest, models, drivers, ITF traces and observations are copied without
modification from `quint/evidence/2026-11-06/preimplementation-concurrency-traces`.
The Go test pins the manifest hash and checks every selected input hash. This
fixture's original `prepared_not_executed` metadata describes its creation;
current replay results belong in `development-conformance.json` and the dated
Go campaign evidence, not in the immutable model artifact.

`TestPreimplementationP1ITF` selects 22 of the 24 schedules (267 transitions,
289 states, 5 refusals); dated campaign results establish whether they passed.
Its projection covers PostgreSQL agents,
placements, request/terminal states, closure intents, mandate budgets/expiry,
mailboxes, destination FIFO, leases and opaque tokens, outbox, barrier receipts,
SQLite effects, stored results, deduplication and durable fences. It also checks
real PostgreSQL row-lock exclusion while admitted transactions are suspended.
The two RPC slots can hold independent SQLite writer transactions simultaneously.

Model IDs bind to fixture agents a/b/c, actual request IDs and mailbox IDs.
Model lease numbers bind to the opaque tokens returned by ClaimDelivery; every
new claim must change the token. Logical expiry moves only the fixture deadline
behind the actual database clock. Actual production methods perform the ensuing
checks and state changes. The local SQL application records a durable effect.

Admission gates are test-schema triggers in the real idempotency insert, after
production authorization and agent locking. They delay execution without
reimplementing admission or changing business rows. `crashWorker` terminates the
actual in-flight PostgreSQL backend: it proves transaction rollback/reconnection
for this schedule, not a whole Go process or host crash. The gate and SQL/SQLite
transactions are always drained at test cleanup. Expected refusals exercise the
real call; they cannot be reported merely because an adapter rejects an action.

A rejected Go transaction rolls back and frees its locks, whereas the disabled
Quint action leaves the volatile admission record in place. The test requires
unchanged durable projections after that refusal and does not equate these two
volatile records. The fixture gives explicit Go outcomes for these cases.

Per-generation clients and servers now use the production mTLS protocol over
loopback. Claims capture the old boot's channel. The stale-channel refusal also
dials the live replacement with old credentials and requires a TLS certificate
verification error, with successful current-credential health checks before and
after. SQLite stores are closed and reopened across local-server replacement;
durable deduplication must survive. Interrupted application handlers are canceled
and drained before closing their store. This tests transaction rollback, not an
abrupt process kill or a VM crash. A restricted boot permits fences, not effects.

Physical VM state remains outside this adapter. Initial RUNNING placements and
caller identities are fixtures. SQL ObservePlacementStopped receives a fixture
retirement precondition; host allocation/publication/start ownership/retirement
are not checked by copying model state into adapter booleans. The nine additional
lifecycle schedules count only their SQL/SQLite/local-channel projection, not
the Firecracker registry, cgroups, encrypted volume or vsock obligations. The
SQL caller fixture is not evidence about authentication of VM-to-platform calls.

Two schedules remain pending: permanent sealing requires its host adapter, and
notification exhaustion exposes a CANCELED/DEAD projection discrepancy between
the model and the documented Go failure state. No archived observations are
coerced to make these cases pass. This does not replace the two-VM KVM path, P2
restoration tests, P3 scheduling tests or a refinement proof.
