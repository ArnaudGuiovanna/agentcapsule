package authoritylog

import "time"

// Degraded mode (docs/adr/005-keys-outside-restored-domain.md, question 2 and
// "What the code must do", items 16 to 18). When the primary cannot reach the
// replica for longer than a delay, some writes continue without it: they
// return once committed on the primary, and reach the replica when it comes
// back. The others wait for the replica. If a disaster ends a degraded period,
// what continued is lost with the primary, and the failover announces it.

// DefaultDegradedAfter is how long the replica may stay unreachable before
// degraded mode begins, unless the configuration says otherwise.
const DefaultDegradedAfter = 30 * time.Second

// Bounds of the configured delay.
const (
	MinDegradedAfter = 5 * time.Second
	MaxDegradedAfter = 10 * time.Minute
)

// The kinds of an authority operation, a closed vocabulary: degraded mode
// decides by kind, and the metrics count by kind. Every operation of both
// authorities names one; every statement of the stream maps to one.
const (
	// WriteRead writes nothing.
	WriteRead = "read"
	// WriteOutcome records a delivered outcome.
	WriteOutcome = "outcome"
	// WriteRerun records the rerun of an outcome declared lost.
	WriteRerun = "rerun"
	// WriteFence records the revision a store acknowledged.
	WriteFence = "fence"
	// WriteRevocationStart records a revocation subject and its revision.
	WriteRevocationStart = "revocation_start"
	// WriteRevocationDone holds the catalogue while the completion of a
	// revocation is published in PostgreSQL.
	WriteRevocationDone = "revocation_done"
	// WriteRegistration enrolls a new store.
	WriteRegistration = "registration"
	// WriteReservation reserves a store's next incarnation, for a restore.
	WriteReservation = "reservation"
	// WriteLoss declares outcomes lost for a restored image.
	WriteLoss = "loss"
	// WriteActivation holds the catalogue while a restored image is published.
	WriteActivation = "activation"
	// WriteSeal seals a store for good.
	WriteSeal = "seal"
	// WriteKeyCreate allocates a volume key.
	WriteKeyCreate = "key_create"
	// WriteKeyDestroy destroys a volume key.
	WriteKeyDestroy = "key_destroy"
)

// degradedPolicy is the classification: true when the kind continues in
// degraded mode, false when it waits for the replica. Every kind is listed;
// a kind missing here waits.
//
// Continue (item 17): outcome records, reruns included, and fence revisions.
// The start of a revocation continues too: it only denies, at once on the
// primary (fences, new key grants), and every answer to finding 1 keeps it.
//
// Wait: registrations, reservations, declared losses, activations, seals, new
// keys and key destruction (finding 4, restoreWitnessDegradedDestructionBroken).
// So creating, deleting and restoring an agent wait.
//
// Finding 1 was decided on November 15, 2026 (option (a)): the completion of
// a revocation waits, which is the model's safe configuration. Revocations of
// access (ADR 005 §5.4) do not exist yet: when they do, they get their own
// kinds here. A bearer token's continues; a standing grant's waits.
var degradedPolicy = map[string]bool{
	WriteRead:            true,
	WriteOutcome:         true,
	WriteRerun:           true,
	WriteFence:           true,
	WriteRevocationStart: true,
	WriteRevocationDone:  revocationDoneContinues,
	WriteRegistration:    false,
	WriteReservation:     false,
	WriteLoss:            false,
	WriteActivation:      false,
	WriteSeal:            false,
	WriteKeyCreate:       false,
	WriteKeyDestroy:      false,
}

// revocationDoneContinues is ADR 005's finding 1, decided as option (a):
// false holds the completion of a revocation until the replica holds every
// earlier record, so that a revocation is confirmed only once the standby
// has it. Access revocations will follow the same rule, except a bearer
// token's, which the blanket revocation at a failover covers.
const revocationDoneContinues = false

// WriteKinds lists every kind.
func WriteKinds() []string {
	return []string{WriteRead, WriteOutcome, WriteRerun, WriteFence, WriteRevocationStart, WriteRevocationDone,
		WriteRegistration, WriteReservation, WriteLoss, WriteActivation, WriteSeal, WriteKeyCreate, WriteKeyDestroy}
}

// ContinuesDegraded reports whether an operation of this kind continues in
// degraded mode. An unknown kind waits.
func ContinuesDegraded(kind string) bool { return degradedPolicy[kind] }
