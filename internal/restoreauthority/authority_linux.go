//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// Authority is what the worker needs of the authorities
// (docs/adr/006-authority-service.md §5). Local implements it in this
// process; the authority service's client implements it over the worker
// socket. Each method is one operation of the service's protocol.
//
// A hold runs its callback while the authorities exclude what today's
// callback excludes. Its context ends when the hold is lost: the service's
// connection ends, or the hold reaches its cap. A callback that publishes
// in PostgreSQL publishes in that context, and must not re-enter the
// authorities.
type Authority interface {
	Identity() string
	KeyAuthorityIdentity() string
	// SeparateFrom checks that dataRoot lies outside both authorities'
	// directories: the worker's runtime and archive roots.
	SeparateFrom(dataRoot string) error
	Lookup(ctx context.Context, store string) (Binding, error)
	Register(ctx context.Context, store, volume string) (Binding, error)
	// CheckBinding is WithBinding with an empty callback: nothing is held
	// once it returns.
	CheckBinding(ctx context.Context, b Binding) error
	// HoldBinding is WithBinding: no reservation and no seal while use runs.
	HoldBinding(ctx context.Context, b Binding, use func(context.Context) error) error
	// HoldKey is HoldBinding around the key authority's WithKey, in one
	// hold: the key of b's volume, which belongs to b's store (the worker
	// binds an agent's store to the agent's ID). Its destruction waits.
	HoldKey(ctx context.Context, b Binding, use func(context.Context, []byte) error) error
	ReserveIncarnation(ctx context.Context, old Binding, operation string) (Binding, error)
	BeginRevocation(ctx context.Context, subject string) (uint64, error)
	Scan(ctx context.Context, b Binding) (Receipt, error)
	RecordVerifiedFence(ctx context.Context, r Receipt) error
	// HoldFences is WithCurrentFences: no new revocation subject and no
	// reservation while publish runs.
	HoldFences(ctx context.Context, r Receipt, publish func(context.Context) error) error
	SubjectBarrier(ctx context.Context, b Binding, subject string) (acknowledged, sealed bool, err error)
	// HoldRevocation is WithRevocation: no reservation of a target while
	// publish runs.
	HoldRevocation(ctx context.Context, subject string, targets []Binding, publish func(context.Context) error) error
	RecordOutcome(ctx context.Context, b Binding, outcome Outcome) error
	RecordRerun(ctx context.Context, b Binding, outcome Outcome) error
	RecordRetiredSeal(ctx context.Context, b Binding) error
	Losses(ctx context.Context, store string) ([]Loss, error)
	OutcomeStatus(ctx context.Context, id string) (Status, []Loss, error)
	SignArchive(ctx context.Context, a Archive) (Archive, error)
	ValidateArchive(ctx context.Context, a Archive) error
	// ActivateRestored is Activate, with a publish that runs in the hold's
	// context.
	ActivateRestored(ctx context.Context, r Receipt, a Activation) ([]Loss, error)
}

// Activation is a Restoration whose Publish runs in the hold's context.
type Activation struct {
	Inspect Inspection
	Repair  func(missing []Outcome) error
	Publish func(context.Context) error
}

// Local is both authorities opened in this process: the implementation of
// Authority and keyauthority.Provider that the authority service runs, and
// the tests' double. Its holds are today's callbacks, run with the caller's
// context.
type Local struct {
	*Catalog
	Keys keyauthority.Provider
}

var (
	_ Authority             = Local{}
	_ keyauthority.Provider = Local{}
)

// SeparateFrom checks dataRoot against the catalogue's directory, and the
// key authority's when Keys can say where it is.
func (l Local) SeparateFrom(dataRoot string) error {
	if err := l.Catalog.SeparateFrom(dataRoot); err != nil {
		return err
	}
	if keys, ok := l.Keys.(interface{ SeparateFrom(string) error }); ok {
		return keys.SeparateFrom(dataRoot)
	}
	return nil
}

func (l Local) CheckBinding(ctx context.Context, b Binding) error {
	return l.WithBinding(ctx, b, func() error { return nil })
}

func (l Local) HoldBinding(ctx context.Context, b Binding, use func(context.Context) error) error {
	if use == nil {
		return ErrInput
	}
	return l.WithBinding(ctx, b, func() error { return use(ctx) })
}

func (l Local) HoldKey(ctx context.Context, b Binding, use func(context.Context, []byte) error) error {
	if use == nil || l.Keys == nil {
		return ErrInput
	}
	return l.WithBinding(ctx, b, func() error {
		return l.Keys.WithKey(ctx, b.Store, b.Volume, func(key []byte) error { return use(ctx, key) })
	})
}

func (l Local) HoldFences(ctx context.Context, r Receipt, publish func(context.Context) error) error {
	if publish == nil {
		return ErrInput
	}
	return l.WithCurrentFences(ctx, r, func() error { return publish(ctx) })
}

func (l Local) HoldRevocation(ctx context.Context, subject string, targets []Binding, publish func(context.Context) error) error {
	if publish == nil {
		return ErrInput
	}
	return l.WithRevocation(ctx, subject, targets, func() error { return publish(ctx) })
}

func (l Local) ActivateRestored(ctx context.Context, r Receipt, a Activation) ([]Loss, error) {
	if a.Publish == nil {
		return nil, ErrInput
	}
	return l.Activate(ctx, r, Restoration{Inspect: a.Inspect, Repair: a.Repair, Publish: func() error { return a.Publish(ctx) }})
}

func (l Local) Ensure(ctx context.Context, agent, volume string) error {
	if l.Keys == nil {
		return keyauthority.ErrInput
	}
	return l.Keys.Ensure(ctx, agent, volume)
}

func (l Local) WithKey(ctx context.Context, agent, volume string, use func([]byte) error) error {
	if l.Keys == nil {
		return keyauthority.ErrInput
	}
	return l.Keys.WithKey(ctx, agent, volume, use)
}

func (l Local) Revoke(ctx context.Context, agent, volume string) error {
	if l.Keys == nil {
		return keyauthority.ErrInput
	}
	return l.Keys.Revoke(ctx, agent, volume)
}

// Root is the catalogue's directory.
func (c *Catalog) Root() string { return c.root }

// KnownSubject reports whether a revocation of subject has begun: then
// BeginRevocation writes nothing.
func (c *Catalog) KnownSubject(ctx context.Context, subject string) (bool, error) {
	if !validName(subject) {
		return false, ErrInput
	}
	var known bool
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?)", subject).Scan(&known)
	})
	return known, err
}

// KnownReservation reports whether operation has reserved an incarnation:
// then ReserveIncarnation writes nothing.
func (c *Catalog) KnownReservation(ctx context.Context, operation string) (bool, error) {
	if !validName(operation) {
		return false, ErrInput
	}
	var known bool
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM reservations WHERE operation=?)", operation).Scan(&known)
	})
	return known, err
}

// RecordedOutcomes returns the outcomes recorded for r's store, each with its
// current digest, in ID order, under a current fenced receipt: the list an
// inspection receives. The authority service gives it to a worker that
// inspects the restored image outside any transaction (ADR 006 §3).
func (c *Catalog) RecordedOutcomes(ctx context.Context, r Receipt) ([]Outcome, error) {
	var outcomes []Outcome
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := c.currentFences(ctx, tx, r); err != nil {
			return err
		}
		withLosses, err := lossesAvailable(ctx, tx)
		if err != nil {
			return err
		}
		recorded, err := recordedOutcomes(ctx, tx, withLosses, "o.store=?", r.Store)
		if err != nil {
			return err
		}
		outcomes = make([]Outcome, len(recorded))
		for i, o := range recorded {
			outcomes[i] = o.Outcome
		}
		return nil
	})
	return outcomes, err
}

// DeclareLosses is the declaration step of Activate, for a caller that ran
// the repair itself: the authority service, on behalf of a worker that
// inspected and repaired the image outside any transaction (ADR 006 §3).
// The model allows a declaration only once no archive can repair: the
// caller must have run the repair first, as Activate does.
func (c *Catalog) DeclareLosses(ctx context.Context, r Receipt, inspect Inspection) ([]Loss, error) {
	if inspect == nil {
		return nil, ErrInput
	}
	return c.declareLosses(ctx, r, inspect)
}

// The modes of a process's link to the replica, as the authority service
// reports them.
const (
	// ModeStandalone: no replica; no protection against the host's loss.
	ModeStandalone = "standalone"
	// ModeSynchronous: every write waits for the replica.
	ModeSynchronous = "synchronous"
	// ModeDegraded: the replica is away; some writes continue without it.
	ModeDegraded = "degraded"
	// ModeWaiting: this process has not reached the replica at the
	// stream's epoch since it started, or since the replica refused it.
	// It runs nothing until it does (finding 2).
	ModeWaiting = "waiting"
)

// ReplicationMode returns this process's mode, and the start of degraded
// mode in degraded mode.
func (c *Catalog) ReplicationMode() (string, time.Time) {
	r := c.repl
	if r == nil {
		return ModeStandalone, time.Time{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.check()
	switch {
	case !r.since.IsZero():
		return ModeDegraded, r.since
	case !r.atEpoch:
		return ModeWaiting, time.Time{}
	}
	return ModeSynchronous, time.Time{}
}
