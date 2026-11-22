//go:build linux && cgo

// Package authorityclient is the client of the authority service
// (docs/adr/006-authority-service.md). It implements
// restoreauthority.Authority and keyauthority.Provider over the service's
// socket, so that the worker depends on the interfaces and its tests run
// against both implementations.
//
// The client keeps a small pool of connections; a request takes one, and a
// hold keeps it for its duration. Every error of the service comes back as
// today's sentinel errors. A connection that fails, or ends, is an outage
// (restoreauthority.ErrUnavailable), never a stale binding.
package authorityclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

const (
	// maxIdle bounds the pool of idle connections.
	maxIdle = 8
	// grace is how long the client waits past its deadline for the
	// service's answer: the service ends the operation at that deadline,
	// and says why (waits_for_replica).
	grace = time.Second
	// helloTimeout bounds a connection's hello when the context has no
	// deadline.
	helloTimeout = 10 * time.Second
	// writeTimeout bounds the write of one frame.
	writeTimeout = 10 * time.Second
	// holdMargin is how long before the hold's end its context ends, so
	// that a publish stops before the service ends the hold. A shorter
	// hold than five times this gets a fifth of its length.
	holdMargin = 5 * time.Second
	// activationAttempts bounds the restarts of an activation whose
	// recorded list changed meanwhile.
	activationAttempts = 3
	// maxSocketPath bounds a socket's path, as the service's configuration
	// does: a Unix socket path has at most 107 bytes.
	maxSocketPath = 100
	// maxWaitDelay bounds the delay between two attempts of Wait.
	maxWaitDelay = 5 * time.Second
)

// Client is a connection pool to the authority service.
type Client struct {
	path  string
	hello svc.Hello

	mu     sync.Mutex
	idle   []*net.UnixConn
	status *svc.Status
	closed bool
}

var (
	_ restoreauthority.Authority = (*Client)(nil)
	_ keyauthority.Provider      = (*Client)(nil)
)

// New returns a client of the service's socket at path, for role, pinning
// the two authorities' identities. It does not connect: each connection's
// hello checks the service.
func New(path, role, restoreAuthority, keyAuthority string) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxSocketPath || (role != svc.RoleWorker && role != svc.RoleAPI) ||
		!authoritylog.ValidID(restoreAuthority, "restoreauth_") || !authoritylog.ValidID(keyAuthority, "keyauth_") {
		return nil, restoreauthority.ErrInput
	}
	return &Client{path: path, hello: svc.Hello{Protocol: svc.Protocol, Role: role, RestoreAuthority: restoreAuthority, KeyAuthority: keyAuthority}}, nil
}

// Close closes the idle connections; later requests fail.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, conn := range c.idle {
		conn.Close()
	}
	c.idle = nil
	return nil
}

func (c *Client) Identity() string             { return c.hello.RestoreAuthority }
func (c *Client) KeyAuthorityIdentity() string { return c.hello.KeyAuthority }

// Status asks the service for its state.
func (c *Client) Status(ctx context.Context) (svc.Status, error) {
	var s svc.Status
	err := c.call(ctx, svc.OpStatus, struct{}{}, &s)
	return s, err
}

// Wait waits until the service answers, and returns its status. While the
// service does not answer, it tries again, at most every 5 seconds, as long
// as ctx lasts, and waiting receives each failed attempt. A service that
// holds another installation's authorities, serves another role on this
// socket, or speaks an older protocol is refused at once: waiting would not
// change it.
func (c *Client) Wait(ctx context.Context, waiting func(error)) (svc.Status, error) {
	delay := 100 * time.Millisecond
	for {
		s, err := c.Status(ctx)
		if err == nil {
			return s, nil
		}
		if errors.Is(err, svc.ErrIdentity) || errors.Is(err, svc.ErrProtocol) || errors.Is(err, svc.ErrRole) || ctx.Err() != nil {
			return svc.Status{}, err
		}
		if waiting != nil {
			waiting(err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return svc.Status{}, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		delay = min(2*delay, maxWaitDelay)
	}
}

// SeparateFrom checks that dataRoot lies outside both authorities'
// directories, as the last hello gave them.
func (c *Client) SeparateFrom(dataRoot string) error {
	c.mu.Lock()
	s := c.status
	c.mu.Unlock()
	if s == nil {
		return restoreauthority.ErrUnavailable
	}
	if err := restoreauthority.CheckSeparation(s.RestoreRoot, dataRoot); err != nil {
		return err
	}
	return restoreauthority.CheckSeparation(s.KeyRoot, dataRoot)
}

// outage is the error of a connection that failed or ended.
func outage(ctx context.Context, errs ...error) error {
	return errors.Join(append(append([]error{restoreauthority.ErrUnavailable}, errs...), ended(ctx))...)
}

func withContext(ctx context.Context, err error) error {
	if end := ended(ctx); end != nil {
		return errors.Join(err, end)
	}
	return err
}

// ended is ctx's error, and context.DeadlineExceeded as soon as its deadline
// has passed: the service ends an operation at that deadline, and its answer
// can arrive before ctx's own timer has run.
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return svc.ErrProtocol
	}
	return nil
}

// dial opens a connection and says hello.
func (c *Client) dial(ctx context.Context) (*net.UnixConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, outage(ctx, err)
	}
	conn := raw.(*net.UnixConn)
	deadline := time.Now().Add(helloTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	var r svc.Response
	err = authoritylog.WriteFrame(conn, c.hello)
	if err == nil {
		err = authoritylog.ReadFrame(conn, &r, svc.MaxResponse)
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, outage(ctx, err)
	}
	var s svc.Status
	switch {
	case r.Error != "":
		err = svc.ErrorOf(r.Error)
	case strictJSON(r.Result, &s) != nil || s.Protocol < svc.Protocol:
		err = svc.ErrorOf(svc.CodeProtocol) // a service older than this client needs
	case s.RestoreAuthority != c.hello.RestoreAuthority || s.KeyAuthority != c.hello.KeyAuthority:
		err = svc.ErrorOf(svc.CodeIdentity)
	}
	if err != nil {
		conn.Close()
		return nil, withContext(ctx, err)
	}
	conn.SetDeadline(time.Time{})
	c.mu.Lock()
	c.status = &s
	c.mu.Unlock()
	return conn, nil
}

// get takes an idle connection, or dials one.
func (c *Client) get(ctx context.Context) (conn *net.UnixConn, pooled bool, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, errors.Join(restoreauthority.ErrUnavailable, errors.New("authority client closed"))
	}
	if n := len(c.idle); n > 0 {
		conn = c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return conn, true, nil
	}
	c.mu.Unlock()
	conn, err = c.dial(ctx)
	return conn, false, err
}

func (c *Client) put(conn *net.UnixConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.idle) >= maxIdle {
		conn.Close()
		return
	}
	c.idle = append(c.idle, conn)
}

// closes reports whether the service ends the connection after code.
func closes(code string) bool {
	return code == svc.CodeProtocol || code == svc.CodeRole || code == svc.CodeIdentity || code == svc.CodeHoldExpired
}

// send takes a connection and sends one request. The deadline travels: the
// service runs the operation until the context's deadline, at most
// svc.MaxTimeout. A pooled connection that the service closed meanwhile
// fails at the write, before anything reached the service: send then dials
// once more.
func (c *Client) send(ctx context.Context, op string, args any) (*net.UnixConn, time.Time, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, time.Time{}, errors.Join(restoreauthority.ErrInput, err)
	}
	for retried := false; ; retried = true {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > svc.MaxTimeout {
			deadline = time.Now().Add(svc.MaxTimeout)
		}
		left := time.Until(deadline)
		if left < time.Millisecond || ctx.Err() != nil {
			return nil, deadline, outage(ctx, context.DeadlineExceeded)
		}
		conn, pooled, err := c.get(ctx)
		if err != nil {
			return nil, deadline, err
		}
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		// Rounded up: the service counts from its receipt, so its deadline
		// is never before the caller's.
		timeout := (left + time.Millisecond - 1).Milliseconds()
		err = authoritylog.WriteFrame(conn, svc.Request{Op: op, TimeoutMS: timeout, Args: raw})
		if err == nil {
			return conn, deadline, nil
		}
		conn.Close()
		if !pooled || retried {
			return nil, deadline, outage(ctx, err)
		}
	}
}

// receive reads one response, until until. A canceled context ends the
// wait at once; a context past its deadline waits for the service's
// answer, which comes at the same deadline.
func receive(ctx context.Context, conn *net.UnixConn, until time.Time) (svc.Response, error) {
	var r svc.Response
	conn.SetReadDeadline(until)
	stop := context.AfterFunc(ctx, func() {
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			conn.SetReadDeadline(time.Now())
		}
	})
	defer stop()
	err := authoritylog.ReadFrame(conn, &r, svc.MaxResponse)
	return r, err
}

// call runs one operation that is not a hold.
func (c *Client) call(ctx context.Context, op string, args, result any) (err error) {
	_, span := callSpan.Start(ctx)
	code := ""
	defer func() { endCall(span, op, code, false, false, err == nil) }()
	conn, deadline, err := c.send(ctx, op, args)
	if err != nil {
		return err
	}
	r, err := receive(ctx, conn, deadline.Add(grace))
	if err != nil {
		conn.Close()
		return outage(ctx, err)
	}
	code = r.Error
	switch {
	case r.Error != "":
		if closes(r.Error) {
			conn.Close()
		} else {
			c.put(conn)
		}
		return withContext(ctx, svc.ErrorOf(r.Error))
	case r.Held != nil:
		conn.Close()
		code = svc.CodeProtocol
		return svc.ErrorOf(svc.CodeProtocol)
	}
	c.put(conn)
	if result != nil && strictJSON(r.Result, result) != nil {
		code = svc.CodeProtocol
		return svc.ErrorOf(svc.CodeProtocol)
	}
	return nil
}

type answer struct {
	r   svc.Response
	err error
}

// hold runs use while the service holds op: use's context ends when the
// connection ends, and before the hold's end. Then it sends release and
// waits for released: only then does the hold succeed, with use's own
// result. granted reports whether the service granted the hold.
func (c *Client) hold(ctx context.Context, op string, args any, withKey bool, use func(context.Context, []byte) error) (granted bool, err error) {
	ctx, span := callSpan.Start(ctx)
	code, released := "", false
	defer func() { endCall(span, op, code, true, granted, released) }()
	var key []byte
	if withKey {
		// The key follows the frame as raw bytes, into a locked page
		// outside the Go heap (internal/keymem) that this client owns and
		// releases; it never goes through encoding/json. The page comes
		// first: nothing is asked without a place for the key.
		if key, err = keymem.Buffer(svc.KeySize); err != nil {
			return false, errors.Join(restoreauthority.ErrUnavailable, err)
		}
		defer keymem.Release(key)
	}
	conn, deadline, err := c.send(ctx, op, args)
	if err != nil {
		return false, err
	}
	r, err := receive(ctx, conn, deadline.Add(grace))
	if err != nil {
		conn.Close()
		return false, outage(ctx, err)
	}
	code = r.Error
	if r.Error != "" {
		if closes(r.Error) {
			conn.Close()
		} else {
			c.put(conn)
		}
		return false, withContext(ctx, svc.ErrorOf(r.Error))
	}
	if r.Held == nil || r.Held.HoldMS <= 0 {
		conn.Close()
		return false, svc.ErrorOf(svc.CodeProtocol)
	}
	heldAt := time.Now()
	length := time.Duration(r.Held.HoldMS) * time.Millisecond
	if withKey {
		conn.SetReadDeadline(heldAt.Add(length + grace))
		if _, err = io.ReadFull(conn, key); err != nil {
			conn.Close()
			return true, outage(ctx, svc.ErrHoldLost, err)
		}
	}
	held, end := context.WithCancelCause(ctx)
	defer end(nil)
	timer := time.AfterFunc(length-min(holdMargin, length/5), func() { end(svc.ErrHoldExpired) })
	defer timer.Stop()
	// The service sends nothing during a hold: the next frame is its
	// answer to the release, or the end of the hold (its cap, its own end).
	next := make(chan answer, 1)
	conn.SetReadDeadline(heldAt.Add(length + grace))
	go func() {
		var a answer
		a.err = authoritylog.ReadFrame(conn, &a.r, svc.MaxResponse)
		if a.r.Error == svc.CodeHoldExpired {
			end(svc.ErrHoldExpired)
		} else {
			end(svc.ErrHoldLost)
		}
		next <- a
	}()
	useErr := use(held, key)
	timer.Stop()
	var a answer
	select {
	case a = <-next:
		// The hold ended before use did: whatever use did, the
		// exclusion did not cover all of it.
		conn.Close()
		if a.err == nil && a.r.Error != "" {
			code = a.r.Error
			return true, withContext(ctx, svc.ErrorOf(a.r.Error))
		}
		return true, outage(ctx, svc.ErrHoldLost, a.err)
	default:
	}
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err = authoritylog.WriteFrame(conn, svc.Request{Op: svc.OpRelease}); err != nil {
		conn.Close()
		<-next
		return true, outage(ctx, svc.ErrHoldLost, err)
	}
	a = <-next
	switch {
	case a.err != nil:
		conn.Close()
		return true, outage(ctx, svc.ErrHoldLost, a.err)
	case a.r.Error != "":
		code = a.r.Error
		if closes(a.r.Error) {
			conn.Close()
		} else {
			c.put(conn)
		}
		return true, withContext(ctx, svc.ErrorOf(a.r.Error))
	case a.r.Held != nil || a.r.Result == nil:
		conn.Close()
		code = svc.CodeProtocol
		return true, svc.ErrorOf(svc.CodeProtocol)
	}
	conn.SetReadDeadline(time.Time{})
	c.put(conn)
	released = true
	return true, useErr
}

func (c *Client) Lookup(ctx context.Context, store string) (restoreauthority.Binding, error) {
	var r svc.BindingResult
	err := c.call(ctx, svc.OpLookup, svc.StoreArgs{Store: store}, &r)
	return r.Binding, err
}

func (c *Client) Register(ctx context.Context, store, volume string) (restoreauthority.Binding, error) {
	r := svc.BindingResult{Binding: restoreauthority.Binding{Store: store, Volume: volume, Incarnation: 1}}
	err := c.call(ctx, svc.OpRegister, svc.RegisterArgs{Store: store, Volume: volume}, &r)
	return r.Binding, err
}

func (c *Client) CheckBinding(ctx context.Context, b restoreauthority.Binding) error {
	return c.call(ctx, svc.OpCheckBinding, svc.BindingArgs{Binding: b}, nil)
}

func (c *Client) HoldBinding(ctx context.Context, b restoreauthority.Binding, use func(context.Context) error) error {
	if use == nil {
		return restoreauthority.ErrInput
	}
	_, err := c.hold(ctx, svc.OpHoldBinding, svc.BindingArgs{Binding: b}, false, func(ctx context.Context, _ []byte) error { return use(ctx) })
	return err
}

func (c *Client) HoldKey(ctx context.Context, b restoreauthority.Binding, use func(context.Context, []byte) error) error {
	if use == nil || b.Incarnation == 0 {
		return restoreauthority.ErrInput
	}
	_, err := c.hold(ctx, svc.OpHoldKey, svc.KeyArgs{Agent: b.Store, Volume: b.Volume, Incarnation: b.Incarnation}, true, use)
	return err
}

func (c *Client) ReserveIncarnation(ctx context.Context, old restoreauthority.Binding, operation string) (restoreauthority.Binding, error) {
	r := svc.BindingResult{Binding: old}
	err := c.call(ctx, svc.OpReserveIncarnation, svc.ReserveArgs{Binding: old, Operation: operation}, &r)
	return r.Binding, err
}

func (c *Client) BeginRevocation(ctx context.Context, subject string) (uint64, error) {
	var r svc.RevisionResult
	err := c.call(ctx, svc.OpBeginRevocation, svc.SubjectArgs{Subject: subject}, &r)
	return r.Revision, err
}

// BeginRevocations sends restoreauthority.MaxScopes subjects per request:
// one round trip, and one transaction of the service, for each.
func (c *Client) BeginRevocations(ctx context.Context, scopes []restoreauthority.Scope) error {
	if len(scopes) == 0 {
		return restoreauthority.ErrInput
	}
	for chunk := range slices.Chunk(scopes, restoreauthority.MaxScopes) {
		if err := c.call(ctx, svc.OpBeginRevocations, svc.ScopesArgs{Scopes: chunk}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) Scan(ctx context.Context, b restoreauthority.Binding) (restoreauthority.Receipt, error) {
	var r svc.ReceiptResult
	err := c.call(ctx, svc.OpScan, svc.BindingArgs{Binding: b}, &r)
	return r.Receipt, err
}

func (c *Client) RecordVerifiedFence(ctx context.Context, r restoreauthority.Receipt) error {
	return c.call(ctx, svc.OpRecordFence, svc.ReceiptArgs{Receipt: r}, nil)
}

func (c *Client) HoldFences(ctx context.Context, r restoreauthority.Receipt, publish func(context.Context) error) error {
	if publish == nil {
		return restoreauthority.ErrInput
	}
	_, err := c.hold(ctx, svc.OpHoldFences, svc.ReceiptArgs{Receipt: r}, false, func(ctx context.Context, _ []byte) error { return publish(ctx) })
	return err
}

func (c *Client) SubjectBarrier(ctx context.Context, b restoreauthority.Binding, subject string) (bool, bool, error) {
	var r svc.BarrierResult
	err := c.call(ctx, svc.OpSubjectBarrier, svc.BarrierArgs{Binding: b, Subject: subject}, &r)
	return r.Acknowledged, r.Sealed, err
}

func (c *Client) HoldRevocation(ctx context.Context, subject string, targets []restoreauthority.Binding, publish func(context.Context) error) error {
	if publish == nil {
		return restoreauthority.ErrInput
	}
	_, err := c.hold(ctx, svc.OpHoldRevocation, svc.RevocationArgs{Subject: subject, Targets: targets}, false,
		func(ctx context.Context, _ []byte) error { return publish(ctx) })
	return err
}

func (c *Client) RecordOutcome(ctx context.Context, b restoreauthority.Binding, o restoreauthority.Outcome) error {
	return c.call(ctx, svc.OpRecordOutcome, svc.OutcomeArgs{Binding: b, Outcome: o}, nil)
}

func (c *Client) RecordRerun(ctx context.Context, b restoreauthority.Binding, o restoreauthority.Outcome) error {
	return c.call(ctx, svc.OpRecordRerun, svc.OutcomeArgs{Binding: b, Outcome: o}, nil)
}

func (c *Client) RecordRetiredSeal(ctx context.Context, b restoreauthority.Binding) error {
	return c.call(ctx, svc.OpRecordSeal, svc.BindingArgs{Binding: b}, nil)
}

func (c *Client) Losses(ctx context.Context, store string) ([]restoreauthority.Loss, error) {
	var r svc.LossesResult
	err := c.call(ctx, svc.OpLosses, svc.StoreArgs{Store: store}, &r)
	return r.Losses, err
}

func (c *Client) OutcomeStatus(ctx context.Context, id string) (restoreauthority.Status, []restoreauthority.Loss, error) {
	var r svc.OutcomeStatusResult
	err := c.call(ctx, svc.OpOutcomeStatus, svc.IDArgs{ID: id}, &r)
	return r.Status, r.Losses, err
}

func (c *Client) SignArchive(ctx context.Context, a restoreauthority.Archive) (restoreauthority.Archive, error) {
	var r svc.ArchiveResult
	if err := c.call(ctx, svc.OpSignArchive, svc.ArchiveArgs{Archive: a}, &r); err != nil {
		return restoreauthority.Archive{}, err
	}
	return r.Archive, nil
}

func (c *Client) ValidateArchive(ctx context.Context, a restoreauthority.Archive) error {
	return c.call(ctx, svc.OpValidateArchive, svc.ArchiveArgs{Archive: a}, nil)
}

// RecordedOutcomes is the activation's first step: the outcomes recorded
// for r's store, page by page, and the digest of the whole list. A list
// that changed between pages is stale.
func (c *Client) RecordedOutcomes(ctx context.Context, r restoreauthority.Receipt) ([]restoreauthority.Outcome, string, error) {
	outcomes := []restoreauthority.Outcome{}
	digest, after := "", ""
	for {
		var page svc.RecordedResult
		if err := c.call(ctx, svc.OpRecordedOutcomes, svc.RecordedArgs{Receipt: r, After: after}, &page); err != nil {
			return nil, "", err
		}
		if digest != "" && page.Digest != digest {
			return nil, "", restoreauthority.ErrStale
		}
		digest = page.Digest
		outcomes = append(outcomes, page.Outcomes...)
		if page.Next == "" {
			break
		}
		if page.Next <= after {
			return nil, "", svc.ErrorOf(svc.CodeProtocol)
		}
		after = page.Next
	}
	if svc.OutcomesDigest(r, outcomes) != digest {
		return nil, "", restoreauthority.ErrStale
	}
	return outcomes, digest, nil
}

// DeclareLosses is the activation's declaration step: it declares lost
// each ID of missing, against the recorded list of digest.
func (c *Client) DeclareLosses(ctx context.Context, r restoreauthority.Receipt, digest string, missing []string) ([]restoreauthority.Loss, error) {
	var result svc.LossesResult
	err := c.call(ctx, svc.OpDeclareLosses, svc.LossArgs{Receipt: r, Digest: digest, Missing: missing}, &result)
	return result.Losses, err
}

// HoldActivation is the activation's last step: the catalogue's
// activation, holding while publish runs.
func (c *Client) HoldActivation(ctx context.Context, r restoreauthority.Receipt, digest string, missing []string, publish func(context.Context) error) error {
	_, err := c.holdActivation(ctx, r, digest, missing, publish)
	return err
}

func (c *Client) holdActivation(ctx context.Context, r restoreauthority.Receipt, digest string, missing []string, publish func(context.Context) error) (bool, error) {
	if publish == nil {
		return false, restoreauthority.ErrInput
	}
	return c.hold(ctx, svc.OpHoldActivation, svc.LossArgs{Receipt: r, Digest: digest, Missing: missing}, false,
		func(ctx context.Context, _ []byte) error { return publish(ctx) })
}

// ActivateRestored is Activate across the socket (ADR 006 §3): the
// inspection and the repair run here, outside any hold, against the
// recorded list; the declaration and the activation name that list's
// digest, and the service refuses them if it changed. Then the activation
// starts again, at most activationAttempts times.
func (c *Client) ActivateRestored(ctx context.Context, r restoreauthority.Receipt, a restoreauthority.Activation) ([]restoreauthority.Loss, error) {
	if a.Inspect == nil || a.Publish == nil {
		return nil, restoreauthority.ErrInput
	}
	for attempt := 1; ; attempt++ {
		recorded, digest, err := c.RecordedOutcomes(ctx, r)
		if err != nil {
			return nil, err
		}
		missing, err := a.Inspect(slices.Clone(recorded))
		if err != nil {
			return nil, err
		}
		if a.Repair != nil && len(missing) > 0 {
			lacking, err := named(recorded, missing)
			if err != nil {
				return nil, err
			}
			if err = a.Repair(lacking); err != nil {
				return nil, err
			}
			if missing, err = a.Inspect(slices.Clone(recorded)); err != nil {
				return nil, err
			}
		}
		losses, err := c.DeclareLosses(ctx, r, digest, missing)
		if errors.Is(err, restoreauthority.ErrStale) && attempt < activationAttempts {
			continue
		}
		if err != nil {
			return nil, err
		}
		granted, err := c.holdActivation(ctx, r, digest, missing, a.Publish)
		if !granted && errors.Is(err, restoreauthority.ErrStale) && attempt < activationAttempts {
			continue
		}
		return losses, err
	}
}

// named returns the recorded outcomes whose IDs are in ids; an ID never
// recorded for the store is refused, as the catalogue refuses it.
func named(recorded []restoreauthority.Outcome, ids []string) ([]restoreauthority.Outcome, error) {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := []restoreauthority.Outcome{}
	for _, o := range recorded {
		if want[o.ID] {
			out = append(out, o)
			delete(want, o.ID)
		}
	}
	if len(want) != 0 {
		return nil, restoreauthority.ErrInput
	}
	return out, nil
}

// Ensure creates the volume key, if it does not exist.
func (c *Client) Ensure(ctx context.Context, agent, volume string) error {
	return c.call(ctx, svc.OpEnsureKey, svc.KeyArgs{Agent: agent, Volume: volume}, nil)
}

// WithKey refuses: across the socket a key is held under its binding only,
// with HoldKey. The service refuses a bare key hold too. Held alone, the
// key's lock would make its destruction wait inside the catalogue's
// transaction, and every catalogue operation behind it.
func (c *Client) WithKey(context.Context, string, string, func([]byte) error) error {
	return keyauthority.ErrInput
}

// Revoke refuses: across the socket a key is destroyed under its sealed
// binding only, with DestroyKey. The service refuses a destruction without
// the binding too.
func (c *Client) Revoke(context.Context, string, string) error {
	return keyauthority.ErrInput
}

// DestroyKey destroys the key of b's volume, once the restore authority
// holds b's store sealed (restoreauthority.ErrNotSealed otherwise).
func (c *Client) DestroyKey(ctx context.Context, b restoreauthority.Binding) error {
	if b.Incarnation == 0 {
		return restoreauthority.ErrInput
	}
	return c.call(ctx, svc.OpDestroyKey, svc.KeyArgs{Agent: b.Store, Volume: b.Volume, Incarnation: b.Incarnation}, nil)
}

// AppendAccess is append_access, on either socket.
func (c *Client) AppendAccess(ctx context.Context, r restoreauthority.AccessRecord) (restoreauthority.AccessReceipt, error) {
	var res svc.AccessResult
	err := c.call(ctx, svc.OpAppendAccess, svc.AccessArgs{Record: r}, &res)
	return res.Receipt, err
}

// AccessStatus is on_replica, on either socket.
func (c *Client) AccessStatus(ctx context.Context, id string) (restoreauthority.AccessReceipt, error) {
	var res svc.AccessResult
	err := c.call(ctx, svc.OpOnReplica, svc.IDArgs{ID: id}, &res)
	return res.Receipt, err
}
