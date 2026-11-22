//go:build linux && cgo

package restoreauthority

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Degraded mode (ADR 005, question 2; "What the code must do", items 16 to
// 18). Its clock is replaced: the delay passes when a test says so, and the
// default 30 seconds stays in force.

// clock moves only when a test advances it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *clock) now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.t
}

func (k *clock) advance(d time.Duration) {
	k.mu.Lock()
	k.t = k.t.Add(d)
	k.mu.Unlock()
}

// useClock gives c's degraded mode a clock that moves only when the test says.
func useClock(c *Catalog) *clock {
	k := &clock{t: time.Unix(1_800_000_000, 0)}
	c.repl.mu.Lock()
	c.repl.now = k.now
	c.repl.mu.Unlock()
	return k
}

func isDegraded(c *Catalog) bool { return !c.repl.degradedSince().IsZero() }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stays checks cond for 300 ms, long enough for the monitor and the waiters
// to look at the clock several times.
func stays(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 30 {
		if !cond() {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func within(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}

// degrade stops the standby. A write finds it unreachable and fails at its
// deadline, as every write does within the delay; then the delay passes.
// A write that gives up before it tries the standby (100 ms did, under load)
// also starts the delay (TestAWriteGivenUpDuringItsCommitStartsTheDegradedDelay).
func degrade(t *testing.T, p *pair, k *clock, b Binding) {
	t.Helper()
	p.link.set(true)
	err := p.catalog.RecordOutcome(within(t, time.Second), b, Outcome{ID: "event-probe", Digest: digest("probe")})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("a write returned without the replica within the delay", err)
	}
	k.advance(authoritylog.DefaultDegradedAfter)
	eventually(t, "degraded mode", func() bool { return isDegraded(p.catalog) })
}

func committed(t *testing.T, c *Catalog) uint64 {
	t.Helper()
	s, err := c.Replication(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return s.Committed.Seq
}

func applied(t *testing.T, p *pair) uint64 {
	t.Helper()
	position, err := p.replica.Position(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return position.Seq
}

func scrape(r *telemetry.Registry) string {
	var out strings.Builder
	r.WriteTo(&out)
	return out.String()
}

func TestDegradedModeBeginsAfterTheDelayAndNotBefore(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	// Within the delay every write waits for the replica, and fails at its
	// deadline.
	p.link.set(true)
	err = p.catalog.RecordOutcome(within(t, 100*time.Millisecond), b, Outcome{ID: "event-1", Digest: digest("one")})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrWaitsForReplica) {
		t.Fatal(err)
	}
	k.advance(authoritylog.DefaultDegradedAfter - time.Second)
	stays(t, "degraded mode began before the delay", func() bool { return !isDegraded(p.catalog) })
	// This one is not even committed: the barrier holds it behind event-1.
	err = p.catalog.RecordOutcome(within(t, 100*time.Millisecond), b, Outcome{ID: "event-2", Digest: digest("two")})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("a write returned without the replica before the delay", err)
	}
	// A write still waiting when the delay passes returns: it is a degraded
	// write.
	done := make(chan error, 1)
	go func() {
		done <- p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-3", Digest: digest("three")})
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case err = <-done:
		t.Fatal("a write returned before the delay", err)
	default:
	}
	k.advance(time.Second)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !isDegraded(p.catalog) {
		t.Fatal("not degraded after the delay")
	}
	// From now on such a write returns once committed here.
	before := applied(t, p)
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-4", Digest: digest("four")}); err != nil {
		t.Fatal(err)
	}
	// event-1, committed before the delay and never confirmed, then event-3
	// and event-4, degraded writes.
	if applied(t, p) != before || committed(t, p.catalog) != before+3 {
		t.Fatal("degraded writes", applied(t, p), committed(t, p.catalog))
	}
	if status, _, err := p.catalog.OutcomeStatus(t.Context(), "event-2"); err != nil || status != StatusUnrecorded {
		t.Fatal("event-2", status, err)
	}
}

func TestOutcomesAndFenceRevisionsContinueInDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.catalog.Register(ctx, "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	// Before the outage: an outcome, then a restore that lacks it, so that
	// a rerun is due.
	if err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	next, err := p.catalog.ReserveIncarnation(ctx, b, "restore-1")
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.catalog.Scan(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = p.catalog.Activate(ctx, r, Restoration{Inspect: everythingMissing, Publish: func() error { return nil }}); err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, other)
	before := applied(t, p)
	// Writes of the kinds degraded mode lets through, and reads.
	if err = p.catalog.RecordOutcome(ctx, next, Outcome{ID: "event-2", Digest: digest("two")}); err != nil {
		t.Fatal("outcome", err)
	}
	if err = p.catalog.RecordRerun(ctx, next, Outcome{ID: "event-1", Digest: digest("rerun")}); err != nil {
		t.Fatal("rerun", err)
	}
	if _, err = p.catalog.BeginRevocation(ctx, "agent/one"); err != nil {
		t.Fatal("start of a revocation", err)
	}
	if r, err = p.catalog.Scan(ctx, next); err != nil || !slices.Contains(r.Subjects, "agent/one") {
		t.Fatal("scan", r, err)
	}
	if err = p.catalog.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal("fence revision", err)
	}
	booted := false
	if err = p.catalog.WithCurrentFences(ctx, r, func() error { booted = true; return nil }); err != nil || !booted {
		t.Fatal("boot", err)
	}
	if _, err = p.catalog.Lookup(ctx, "store-a"); err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.WithBinding(ctx, next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if acknowledged, _, err := p.catalog.SubjectBarrier(ctx, next, "agent/one"); err != nil || !acknowledged {
		t.Fatal("subject barrier", acknowledged, err)
	}
	if err = p.catalog.WithSubjectKey(ctx, "agent/two", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if status, _, err := p.catalog.OutcomeStatus(ctx, "event-1"); err != nil || status != StatusRerunConfirmed {
		t.Fatal(status, err)
	}
	if _, err = p.catalog.Losses(ctx, "store-a"); err != nil {
		t.Fatal(err)
	}
	// None of it reached the replica: the probe of degrade, and four
	// degraded writes.
	if applied(t, p) != before || committed(t, p.catalog) != before+5 {
		t.Fatal("degraded writes", before, applied(t, p), committed(t, p.catalog))
	}
	// The standby returns: everything reaches it, and degraded mode ends.
	p.link.set(false)
	eventually(t, "the end of degraded mode", func() bool { return !isDegraded(p.catalog) })
	eventually(t, "the replica catching up", func() bool { return applied(t, p) == committed(t, p.catalog) })
	p.same(t)
}

func TestWritesThatWaitForTheReplicaInDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	// The deleted agent: the seal, then the key's destruction, both held.
	gone := Binding{Store: streamAgent, Volume: streamVolume, Incarnation: 1}
	if _, err = p.catalog.Register(ctx, gone.Store, gone.Volume); err != nil {
		t.Fatal(err)
	}
	if err = p.keys.Ensure(ctx, streamAgent, streamVolume); err != nil {
		t.Fatal(err)
	}
	if _, err = p.catalog.BeginRevocation(ctx, "agent/one"); err != nil {
		t.Fatal(err)
	}
	r, err := p.catalog.Scan(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	before := committed(t, p.catalog)
	published := false
	publish := func() error { published = true; return nil }
	nothingMissing := func([]Outcome) ([]string, error) { return nil, nil }
	newVolume := "vol_" + strings.Repeat("d", 32)
	waits := []struct {
		kind string
		run  func(context.Context) error
	}{
		{authoritylog.WriteRegistration, func(ctx context.Context) error {
			_, err := p.catalog.Register(ctx, "store-new", "volume-new")
			return err
		}},
		{authoritylog.WriteRevocationDone, func(ctx context.Context) error {
			return p.catalog.WithRevocation(ctx, "agent/one", []Binding{b}, publish)
		}},
		{authoritylog.WriteLoss, func(ctx context.Context) error {
			_, err := p.catalog.Activate(ctx, r, Restoration{Inspect: nothingMissing, Publish: publish})
			return err
		}},
		{authoritylog.WriteActivation, func(ctx context.Context) error {
			return p.catalog.WithActivation(ctx, r, nothingMissing, publish)
		}},
		{authoritylog.WriteSeal, func(ctx context.Context) error { return p.catalog.RecordRetiredSeal(ctx, gone) }},
		{authoritylog.WriteKeyCreate, func(ctx context.Context) error { return p.keys.Ensure(ctx, streamAgent, newVolume) }},
		{authoritylog.WriteKeyDestroy, func(ctx context.Context) error { return p.keys.Revoke(ctx, streamAgent, streamVolume) }},
		{authoritylog.WriteReservation, func(ctx context.Context) error {
			_, err := p.catalog.ReserveIncarnation(ctx, b, "restore-1")
			return err
		}},
	}
	for _, w := range waits {
		if err = w.run(within(t, 200*time.Millisecond)); !errors.Is(err, ErrWaitsForReplica) || !errors.Is(err, ErrUnavailable) {
			t.Fatal(w.kind, "did not wait for the replica", err)
		}
	}
	// Nothing was written or published, here or on the replica.
	if published || committed(t, p.catalog) != before {
		t.Fatal("a held operation acted", published, committed(t, p.catalog), before)
	}
	if err = p.keys.WithKey(ctx, streamAgent, streamVolume, func([]byte) error { return nil }); err != nil {
		t.Fatal("a key was destroyed in degraded mode", err)
	}
	if err = p.keys.WithKey(ctx, streamAgent, newVolume, func([]byte) error { return nil }); err == nil {
		t.Fatal("a key was created in degraded mode")
	}
	metrics := scrape(registry)
	for _, w := range waits {
		for _, want := range []string{
			fmt.Sprintf(`agentcapsule_authority_replication_degraded_refused_total{kind="%s"} 1`+"\n", w.kind),
			fmt.Sprintf(`agentcapsule_authority_replication_degraded_waiting{kind="%s"} 0`+"\n", w.kind),
		} {
			if !strings.Contains(metrics, want) {
				t.Fatal("missing", want, metrics)
			}
		}
	}
	// They wait for the replica, not for ever: once it is back, each one
	// proceeds.
	p.link.set(false)
	for _, w := range waits {
		if err = w.run(ctx); err != nil {
			t.Fatal(w.kind, err)
		}
	}
	if !published {
		t.Fatal("nothing published")
	}
	p.same(t)
}

func TestStandbyReturnResendsDegradedWritesFirstThenEndsDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	gone := Binding{Store: "store-z", Volume: "volume-z", Incarnation: 1}
	if _, err = p.catalog.Register(ctx, gone.Store, gone.Volume); err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	for i := range 3 {
		if err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: fmt.Sprintf("event-%d", i), Digest: digest("result")}); err != nil {
			t.Fatal(err)
		}
	}
	from, last := applied(t, p), committed(t, p.catalog)
	// A seal waits meanwhile.
	sealed := make(chan error, 1)
	go func() { sealed <- p.catalog.RecordRetiredSeal(ctx, gone) }()
	eventually(t, "the seal waiting", func() bool {
		return strings.Contains(scrape(registry), `agentcapsule_authority_replication_degraded_waiting{kind="seal"} 1`+"\n")
	})
	// While the replica lacks the last degraded write, degraded mode stays.
	var early atomic.Bool
	p.link.mu.Lock()
	p.link.afterAck = func() {
		if position, err := p.replica.Position(context.Background()); err == nil && position.Seq < last && !isDegraded(p.catalog) {
			early.Store(true)
		}
	}
	sent := len(p.link.sent)
	p.link.mu.Unlock()
	p.link.set(false)
	if err = <-sealed; err != nil {
		t.Fatal(err)
	}
	eventually(t, "the end of degraded mode", func() bool { return !isDegraded(p.catalog) })
	if early.Load() {
		t.Fatal("degraded mode ended before the replica held the last degraded write")
	}
	// The degraded writes went first, in order, and the seal after them.
	var seqs []uint64
	for _, raw := range p.link.records()[sent:] {
		record, err := authoritylog.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, record.Seq)
	}
	seal := slices.Index(seqs, last+1)
	if len(seqs) == 0 || seqs[0] != from+1 || seal < 0 {
		t.Fatal("resent out of order", from, last, seqs)
	}
	for s := from + 1; s <= last; s++ {
		if i := slices.Index(seqs, s); i < 0 || i > seal {
			t.Fatal("a degraded write was resent after the seal", s, seqs)
		}
	}
	p.same(t)
	if !strings.Contains(scrape(registry), "agentcapsule_authority_replication_degraded_since_timestamp_seconds 0\n") {
		t.Fatal("degraded mode still reported")
	}
}

func TestDegradedModeEndsWhenTheStandbyReturnsWithoutAnotherOperation(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	// No operation follows: the monitor resends.
	p.link.set(false)
	eventually(t, "the end of degraded mode", func() bool { return !isDegraded(p.catalog) })
	eventually(t, "the replica catching up", func() bool { return applied(t, p) == committed(t, p.catalog) })
	p.same(t)
	// The monitor stops once the replica holds the whole log.
	eventually(t, "the monitor stopping", func() bool {
		p.catalog.repl.mu.Lock()
		defer p.catalog.repl.mu.Unlock()
		return !p.catalog.repl.watching
	})
}

// applyingNothing answers where the replica stands but refuses every record,
// as a standby whose disk is full or read-only does: its apply fails, and it
// refuses as unavailable, which fences nothing.
type applyingNothing struct {
	target  *Replica
	refuses atomic.Bool
}

func (l *applyingNothing) Sync(ctx context.Context, r authoritylog.Request) (authoritylog.Position, error) {
	if l.refuses.Load() && len(r.Records) > 0 {
		position, _ := l.target.Position(ctx)
		return authoritylog.Position{}, &authoritylog.Refusal{Kind: authoritylog.RefusedUnavailable, Position: position}
	}
	return l.target.Sync(ctx, r)
}

// A standby that answers but applies nothing is unreachable for the delay:
// its answers to where it stands must not restart the delay at each
// exchange. Once it applies again, the degraded writes reach it and the mode
// ends.
func TestStandbyThatAppliesNothingStillLeadsToDegradedMode(t *testing.T) {
	p := replicated(t)
	standby := &applyingNothing{target: p.replica}
	p.link.point(standby)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	standby.refuses.Store(true)
	err = p.catalog.RecordOutcome(within(t, 200*time.Millisecond), b, Outcome{ID: "event-probe", Digest: digest("probe")})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrWaitsForReplica) {
		t.Fatal("a write returned without the replica within the delay", err)
	}
	k.advance(authoritylog.DefaultDegradedAfter)
	eventually(t, "degraded mode", func() bool { return isDegraded(p.catalog) })
	if err = p.catalog.RecordOutcome(within(t, 2*time.Second), b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal("an outcome waited in degraded mode", err)
	}
	standby.refuses.Store(false)
	eventually(t, "the end of degraded mode", func() bool { return !isDegraded(p.catalog) })
	eventually(t, "the replica catching up", func() bool { return applied(t, p) == committed(t, p.catalog) })
	p.same(t)
}

// Finding 2: a primary that restarts cannot tell an unreachable standby from
// a promoted one. It writes nothing, and reads nothing, until it reaches the
// replica at its epoch, however long the standby stays away.
func TestRestartedPrimaryRefusesEveryWriteUntilItReachesTheReplica(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.catalog.Scan(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.catalog.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	if err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	before := committed(t, p.catalog)
	// The worker restarts while the standby is still away.
	link := &tap{target: p.replica, down: true}
	keys, restarted := p.reopen(t, link)
	k2 := useClock(restarted)
	refused := func() {
		t.Helper()
		for name, run := range map[string]func(context.Context) error{
			"outcome": func(ctx context.Context) error {
				return restarted.RecordOutcome(ctx, b, Outcome{ID: "event-2", Digest: digest("two")})
			},
			"fence revision": func(ctx context.Context) error { return restarted.RecordVerifiedFence(ctx, r) },
			"revocation": func(ctx context.Context) error {
				_, err := restarted.BeginRevocation(ctx, "agent/one")
				return err
			},
			"key": func(ctx context.Context) error { return keys.Ensure(ctx, streamAgent, streamVolume) },
			"read": func(ctx context.Context) error {
				_, err := restarted.Lookup(ctx, "store-a")
				return err
			},
		} {
			if err := run(within(t, 100*time.Millisecond)); !errors.Is(err, ErrUnavailable) {
				t.Fatal("a restarted primary ran", name, "without its replica", err)
			}
		}
	}
	refused()
	k2.advance(time.Hour)
	stays(t, "a restarted primary entered degraded mode", func() bool { return !isDegraded(restarted) })
	refused()
	if committed(t, restarted) != before {
		t.Fatal("a restarted primary wrote without its replica")
	}
	// It reaches the replica: what the process before it wrote in degraded
	// mode goes first, then it works.
	link.set(false)
	if _, err = restarted.Lookup(ctx, "store-a"); err != nil {
		t.Fatal(err)
	}
	if applied(t, p) != before {
		t.Fatal("degraded writes not resent first", applied(t, p), before)
	}
	if err = restarted.RecordOutcome(ctx, b, Outcome{ID: "event-2", Digest: digest("two")}); err != nil {
		t.Fatal(err)
	}
	p.same(t)

	// The same holds with an empty log: nothing is committed first.
	q := replicated(t)
	link = &tap{target: q.replica, down: true}
	_, empty := q.reopen(t, link)
	if _, err = empty.BeginRevocation(within(t, 100*time.Millisecond), "agent/one"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if committed(t, empty) != 0 {
		t.Fatal("a primary that never reached its replica committed a write")
	}
}

// Item 16: only a writer at the current epoch runs in degraded mode. Once
// the replica refuses it (here, promoted), degraded mode ends and every
// operation fails.
func TestReplicaRefusalEndsDegradedMode(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	if _, err = Promote(t.Context(), filepath.Join(p.dir, "replica"), filepath.Join(p.dir, "promoted-restore"), filepath.Join(p.dir, "promoted-keys"), p.unlock); err != nil {
		t.Fatal(err)
	}
	p.link.set(false)
	eventually(t, "the end of degraded mode", func() bool { return !isDegraded(p.catalog) })
	err = p.catalog.RecordOutcome(within(t, time.Second), b, Outcome{ID: "event-2", Digest: digest("two")})
	if !isRefusal(err, authoritylog.RefusedPromoted) {
		t.Fatal("the old primary wrote after the promotion", err)
	}
	k.advance(time.Hour)
	stays(t, "degraded mode began again after a refusal", func() bool { return !isDegraded(p.catalog) })
}

// Only the replica fences a writer: its refusal, or a history that differs.
// A local failure, such as an operation's deadline while the log is read,
// leaves degraded mode on.
func TestOnlyTheReplicaFencesAWriterInDegradedMode(t *testing.T) {
	for _, err := range []error{errors.Join(ErrUnavailable, context.DeadlineExceeded), errors.Join(ErrInput, authoritylog.ErrRecord),
		&authoritylog.Refusal{Kind: authoritylog.RefusedGap}, &authoritylog.Refusal{Kind: authoritylog.RefusedUnavailable},
		authoritylog.ErrProtocol, errors.New("standby unreachable")} {
		if fenced(err) {
			t.Fatal("fenced by", err)
		}
	}
	for _, err := range []error{authoritylog.ErrBehind, errors.Join(ErrUnavailable, ErrDiverged),
		&authoritylog.Refusal{Kind: authoritylog.RefusedOlderEpoch}, &authoritylog.Refusal{Kind: authoritylog.RefusedNewerEpoch},
		&authoritylog.Refusal{Kind: authoritylog.RefusedPromoted}, &authoritylog.Refusal{Kind: authoritylog.RefusedIdentity},
		&authoritylog.Refusal{Kind: authoritylog.RefusedConflict}, &authoritylog.Refusal{Kind: authoritylog.RefusedInvalid}} {
		if !fenced(err) {
			t.Fatal("not fenced by", err)
		}
	}
	p := replicated(t)
	k := useClock(p.catalog)
	b, err := p.catalog.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	degrade(t, p, k, b)
	r := p.catalog.repl
	r.mu.Lock()
	r.failed(errors.Join(ErrUnavailable, context.DeadlineExceeded), k.now())
	r.mu.Unlock()
	if !isDegraded(p.catalog) {
		t.Fatal("a local failure ended degraded mode")
	}
	if err = p.catalog.RecordOutcome(t.Context(), b, Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
}

type degradedCrash struct{ Dir, RestoreID, KeyID string }

// The primary dies in degraded mode, after committing a degraded write and
// before returning it. Restarted while the standby is still away, it runs
// nothing; once it reaches the replica, the degraded writes go first.
func TestPrimarySIGKILLInDegradedMode(t *testing.T) {
	p := replicated(t)
	if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	before := committed(t, p.catalog)
	killChild(t, "TestDegradedCrashChild", degradedCrash{Dir: p.dir, RestoreID: p.catalog.Identity(), KeyID: p.keys.Identity()})
	// Three outcomes committed, two of them in degraded mode; none on the
	// replica.
	if committed(t, p.catalog) != before+3 || applied(t, p) != before {
		t.Fatal("unexpected durable state", before, committed(t, p.catalog), applied(t, p))
	}
	link := &tap{target: p.replica, down: true}
	_, restarted := p.reopen(t, link)
	k := useClock(restarted)
	if _, err := restarted.Lookup(within(t, 100*time.Millisecond), "store-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a restarted primary read without its replica", err)
	}
	k.advance(time.Hour)
	stays(t, "a restarted primary entered degraded mode", func() bool { return !isDegraded(restarted) })
	link.set(false)
	if _, err := restarted.Lookup(t.Context(), "store-a"); err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, raw := range link.records() {
		record, err := authoritylog.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, record.Seq)
	}
	if !slices.Equal(seqs, []uint64{before + 1, before + 2, before + 3}) {
		t.Fatal("resent", seqs)
	}
	p.same(t)
	for _, id := range []string{"event-1", "event-2", "event-3"} {
		var store string
		if err := p.replica.db.QueryRow("SELECT store FROM outcomes WHERE id=?", id).Scan(&store); err != nil {
			t.Fatal("outcome missing on the replica", id, err)
		}
	}
}

func TestDegradedCrashChild(t *testing.T) {
	var conf degradedCrash
	if !childConfig(t, &conf) {
		return
	}
	keys, err := keyauthority.Open(filepath.Join(conf.Dir, "keys"), conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(t.Context(), filepath.Join(conf.Dir, "restore"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := OpenReplica(t.Context(), filepath.Join(conf.Dir, "replica"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	link := &tap{target: replica}
	if err = c.Replicate(t.Context(), link); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	k := useClock(c)
	b := Binding{Store: "store-a", Volume: "volume-a", Incarnation: 1}
	if _, err := c.Lookup(t.Context(), "store-a"); err != nil {
		t.Fatal(err) // the child reaches the replica first
	}
	link.set(true)
	if err := c.RecordOutcome(within(t, 100*time.Millisecond), b, Outcome{ID: "event-1", Digest: digest("one")}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	k.advance(authoritylog.DefaultDegradedAfter)
	eventually(t, "degraded mode", func() bool { return isDegraded(c) })
	if err := c.RecordOutcome(t.Context(), b, Outcome{ID: "event-2", Digest: digest("two")}); err != nil {
		t.Fatal(err)
	}
	c.hook = func(boundary string) {
		if boundary == "after_commit" {
			stopHere()
		}
	}
	if err := c.RecordOutcome(t.Context(), b, Outcome{ID: "event-3", Digest: digest("three")}); err != nil {
		t.Fatal(err)
	}
	t.Fatal("fault boundary was not reached")
}

func TestDegradedModeMetrics(t *testing.T) {
	p := replicated(t)
	k := useClock(p.catalog)
	registry := telemetry.NewRegistry()
	p.catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	ctx := t.Context()
	b, err := p.catalog.Register(ctx, "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	gone := Binding{Store: "store-z", Volume: "volume-z", Incarnation: 1}
	if _, err = p.catalog.Register(ctx, gone.Store, gone.Volume); err != nil {
		t.Fatal(err)
	}
	expect := func(lines ...string) {
		t.Helper()
		out := scrape(registry)
		for _, line := range lines {
			if !strings.Contains(out, line+"\n") {
				t.Fatal("missing", line, out)
			}
		}
	}
	expect("agentcapsule_authority_replication_degraded_since_timestamp_seconds 0",
		`agentcapsule_authority_replication_degraded_waiting{kind="seal"} 0`)
	degrade(t, p, k, b)
	since := p.catalog.repl.degradedSince()
	if !since.Equal(k.now()) {
		t.Fatal("degraded since", since, k.now())
	}
	for i := range 2 {
		if err = p.catalog.RecordOutcome(ctx, b, Outcome{ID: fmt.Sprintf("event-%d", i), Digest: digest("result")}); err != nil {
			t.Fatal(err)
		}
	}
	acknowledged, last := applied(t, p), committed(t, p.catalog)
	expect("agentcapsule_authority_replication_degraded_since_timestamp_seconds "+strconv.FormatFloat(float64(since.UnixNano())/1e9, 'g', -1, 64),
		fmt.Sprintf("agentcapsule_authority_replication_lag_records %d", last-acknowledged),
		fmt.Sprintf("agentcapsule_authority_replication_acknowledged_sequence %d", acknowledged),
		fmt.Sprintf("agentcapsule_authority_replication_committed_sequence %d", last))
	if last-acknowledged != 3 {
		t.Fatal("three records not acknowledged: the probe and two outcomes", acknowledged, last)
	}
	// A seal waits, then gives up at its deadline.
	sealed := make(chan error, 1)
	go func() { sealed <- p.catalog.RecordRetiredSeal(within(t, 500*time.Millisecond), gone) }()
	eventually(t, "the seal waiting", func() bool {
		return strings.Contains(scrape(registry), `agentcapsule_authority_replication_degraded_waiting{kind="seal"} 1`+"\n")
	})
	if err = <-sealed; !errors.Is(err, ErrWaitsForReplica) {
		t.Fatal(err)
	}
	expect(`agentcapsule_authority_replication_degraded_waiting{kind="seal"} 0`,
		`agentcapsule_authority_replication_degraded_refused_total{kind="seal"} 1`)
	// The standby returns.
	p.link.set(false)
	eventually(t, "the replica catching up", func() bool { return applied(t, p) == last && !isDegraded(p.catalog) })
	eventually(t, "the metrics", func() bool {
		out := scrape(registry)
		return strings.Contains(out, "agentcapsule_authority_replication_degraded_since_timestamp_seconds 0\n") &&
			strings.Contains(out, "agentcapsule_authority_replication_lag_records 0\n") &&
			strings.Contains(out, fmt.Sprintf("agentcapsule_authority_replication_acknowledged_sequence %d\n", last))
	})
}
