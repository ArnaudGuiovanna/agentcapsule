//go:build linux && cgo

package authorityservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// operation is one operation of the protocol. A hold names its kind.
type operation struct {
	api  bool // served on the API socket too
	hold string
	run  func(ctx context.Context, s *Server, args json.RawMessage, h *hold) (any, error)
}

// operations are those of wave 1 (ADR 006 §10). Each runs today's function
// of the authority packages, unchanged; a hold runs it with a callback that
// waits for the client's release.
var operations = map[string]operation{
	OpStatus: {api: true, run: func(_ context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		_, err := decode[struct{}](raw)
		if err != nil {
			return nil, err
		}
		return s.Status(), nil
	}},
	OpLookup: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[StoreArgs](raw)
		if err != nil {
			return nil, err
		}
		b, err := s.local.Lookup(ctx, a.Store)
		return BindingResult{b}, err
	}},
	OpCheckBinding: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[BindingArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.CheckBinding(ctx, a.Binding)
	}},
	OpHoldBinding: {hold: HoldBinding, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[BindingArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.WithBinding(ctx, a.Binding, func() error { return s.wait(ctx, h, nil) })
	}},
	OpEnsureKey: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[KeyArgs](raw)
		if err != nil || a.Incarnation != 0 {
			return nil, errors.Join(ErrProtocol, err)
		}
		return nil, s.local.Ensure(ctx, a.Agent, a.Volume)
	}},
	OpHoldKey: {hold: HoldKey, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[KeyArgs](raw)
		if err != nil {
			return nil, err
		}
		// A key is held under its binding only. A bare key hold would keep
		// the key's shared lock without the catalogue's transaction: a
		// destruction would then wait for the key inside that transaction,
		// and every catalogue operation behind it, up to max_key_hold.
		if a.Incarnation == 0 {
			return nil, restoreauthority.ErrInput
		}
		// One hold for both: the binding's transaction, then the shared
		// lock on the key; the key's destruction waits for both, outside
		// the transaction.
		use := func(key []byte) error { return s.wait(ctx, h, key) }
		b := restoreauthority.Binding{Store: a.Agent, Volume: a.Volume, Incarnation: a.Incarnation}
		return nil, s.local.WithBinding(ctx, b, func() error { return s.local.WithKey(ctx, a.Agent, a.Volume, use) })
	}},
	OpDestroyKey: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[KeyArgs](raw)
		if err != nil || a.Incarnation != 0 {
			return nil, errors.Join(ErrProtocol, err)
		}
		if err = s.quiet(ctx, s.writesAfter); err != nil {
			return nil, err
		}
		return nil, s.local.Revoke(ctx, a.Agent, a.Volume)
	}},
	OpRegister: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[RegisterArgs](raw)
		if err != nil {
			return nil, err
		}
		b, err := s.local.Register(ctx, a.Store, a.Volume)
		return BindingResult{b}, err
	}},
	OpReserveIncarnation: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[ReserveArgs](raw)
		if err != nil {
			return nil, err
		}
		// A repeated reservation writes nothing: it answers at once.
		known, err := s.local.KnownReservation(ctx, a.Operation)
		if err != nil {
			return nil, err
		}
		if !known {
			if err = s.quiet(ctx, s.writesAfter); err != nil {
				return nil, err
			}
		}
		b, err := s.local.ReserveIncarnation(ctx, a.Binding, a.Operation)
		return BindingResult{b}, err
	}},
	OpBeginRevocation: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[SubjectArgs](raw)
		if err != nil {
			return nil, err
		}
		// A known subject writes nothing: it answers at once.
		known, err := s.local.KnownSubject(ctx, a.Subject)
		if err != nil {
			return nil, err
		}
		if !known {
			if err = s.quiet(ctx, s.subjectsAfter); err != nil {
				return nil, err
			}
		}
		revision, err := s.local.BeginRevocation(ctx, a.Subject)
		return RevisionResult{revision}, err
	}},
	OpScan: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[BindingArgs](raw)
		if err != nil {
			return nil, err
		}
		r, err := s.local.Scan(ctx, a.Binding)
		return ReceiptResult{r}, err
	}},
	OpRecordFence: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[ReceiptArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.RecordVerifiedFence(ctx, a.Receipt)
	}},
	OpHoldFences: {hold: HoldFences, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[ReceiptArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.WithCurrentFences(ctx, a.Receipt, func() error { return s.wait(ctx, h, nil) })
	}},
	OpSubjectBarrier: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[BarrierArgs](raw)
		if err != nil {
			return nil, err
		}
		acknowledged, sealed, err := s.local.SubjectBarrier(ctx, a.Binding, a.Subject)
		return BarrierResult{acknowledged, sealed}, err
	}},
	OpHoldRevocation: {hold: HoldRevocation, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[RevocationArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.WithRevocation(ctx, a.Subject, a.Targets, func() error { return s.wait(ctx, h, nil) })
	}},
	OpRecordOutcome: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[OutcomeArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.RecordOutcome(ctx, a.Binding, a.Outcome)
	}},
	OpRecordRerun: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[OutcomeArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.RecordRerun(ctx, a.Binding, a.Outcome)
	}},
	OpRecordSeal: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[BindingArgs](raw)
		if err != nil {
			return nil, err
		}
		if err = s.quiet(ctx, s.writesAfter); err != nil {
			return nil, err
		}
		return nil, s.local.RecordRetiredSeal(ctx, a.Binding)
	}},
	OpLosses: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[StoreArgs](raw)
		if err != nil {
			return nil, err
		}
		losses, err := s.local.Losses(ctx, a.Store)
		return LossesResult{losses}, err
	}},
	OpOutcomeStatus: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[IDArgs](raw)
		if err != nil {
			return nil, err
		}
		status, losses, err := s.local.OutcomeStatus(ctx, a.ID)
		return OutcomeStatusResult{status, losses}, err
	}},
	OpSignArchive: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[ArchiveArgs](raw)
		if err != nil {
			return nil, err
		}
		signed, err := s.local.SignArchive(ctx, a.Archive)
		return ArchiveResult{signed}, err
	}},
	OpValidateArchive: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[ArchiveArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.ValidateArchive(ctx, a.Archive)
	}},
	OpRecordedOutcomes: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[RecordedArgs](raw)
		if err != nil {
			return nil, err
		}
		outcomes, err := s.local.RecordedOutcomes(ctx, a.Receipt)
		if err != nil {
			return nil, err
		}
		page := RecordedResult{Digest: OutcomesDigest(a.Receipt, outcomes), Outcomes: []restoreauthority.Outcome{}}
		from := sort.Search(len(outcomes), func(i int) bool { return outcomes[i].ID > a.After })
		to := min(from+OutcomesPage, len(outcomes))
		page.Outcomes = append(page.Outcomes, outcomes[from:to]...)
		if to < len(outcomes) {
			page.Next = outcomes[to-1].ID
		}
		return page, nil
	}},
	OpDeclareLosses: {run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[LossArgs](raw)
		if err != nil {
			return nil, err
		}
		losses, err := s.local.DeclareLosses(ctx, a.Receipt, inspection(a))
		return LossesResult{losses}, err
	}},
	OpHoldActivation: {hold: HoldActivation, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[LossArgs](raw)
		if err != nil {
			return nil, err
		}
		return nil, s.local.WithActivation(ctx, a.Receipt, inspection(a), func() error { return s.wait(ctx, h, nil) })
	}},
}

// inspection is the worker's inspection, made outside any transaction,
// checked in the service's: the recorded list must be the one the worker
// inspected, or the step is stale and the worker starts again. The
// catalogue still refuses an ID it never recorded for the store.
func inspection(a LossArgs) restoreauthority.Inspection {
	missing := a.Missing
	if missing == nil {
		missing = []string{}
	}
	return func(recorded []restoreauthority.Outcome) ([]string, error) {
		if OutcomesDigest(a.Receipt, recorded) != a.Digest {
			return nil, restoreauthority.ErrStale
		}
		return missing, nil
	}
}

// hold is one hold's state, shared by the operation, which waits in it,
// and the connection, which receives the release.
type hold struct {
	kind     string
	cap      time.Duration
	conn     *net.UnixConn
	deadline time.Time
	held     atomic.Bool
	release  chan struct{}
}

// wait is the callback of a hold, run inside today's function: it sends
// held, and for a key its 32 bytes after the frame, then waits for the
// release, the end of the connection, the request's deadline, or the cap.
// At the cap it ends the hold: today's function rolls back, and the
// connection closes.
func (s *Server) wait(ctx context.Context, h *hold, key []byte) error {
	if h.kind == "" || h.held.Load() || (h.kind == HoldKey) != (key != nil) {
		return ErrProtocol // one hold per request; a callback never re-enters
	}
	left := time.Until(h.deadline)
	d := min(h.cap, left)
	if d < time.Millisecond {
		return errors.Join(restoreauthority.ErrUnavailable, context.DeadlineExceeded)
	}
	capped := h.cap <= left
	s.c.Metrics.Holding(h.kind, 1)
	defer s.c.Metrics.Holding(h.kind, -1)
	h.held.Store(true)
	h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := writeFrame(h.conn, Response{Held: &Held{HoldMS: d.Milliseconds()}})
	if err == nil && key != nil {
		if len(key) != KeySize {
			return keyauthority.ErrUnavailable
		}
		// The key goes from the authority's buffer to the socket: no JSON,
		// no copy here. The authority clears its buffer once this returns.
		_, err = h.conn.Write(key)
	}
	if err != nil {
		return errors.Join(restoreauthority.ErrUnavailable, ErrHoldLost, err)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-h.release:
		return nil
	case <-timer.C:
		if !capped {
			return errors.Join(restoreauthority.ErrUnavailable, context.DeadlineExceeded)
		}
		s.c.Metrics.Expired(h.kind)
		s.c.Logger.Event("hold_expired", telemetry.Code("kind", h.kind))
		return ErrHoldExpired
	case <-ctx.Done():
		return errors.Join(restoreauthority.ErrUnavailable, context.Cause(ctx))
	}
}

// quiet waits for the end of the quiet period, until, for a write that a
// hold of the previous process could exclude.
func (s *Server) quiet(ctx context.Context, until time.Time) error {
	d := time.Until(until)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return errors.Join(restoreauthority.ErrUnavailable, context.Cause(ctx))
	}
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return ErrProtocol
	}
	return nil
}
