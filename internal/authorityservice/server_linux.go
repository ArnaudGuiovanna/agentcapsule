//go:build linux && cgo

package authorityservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The caps of a hold (ADR 006 §3).
const (
	// PublishCap bounds a hold that covers a PostgreSQL publish.
	PublishCap = 30 * time.Second
	// DefaultMaxKeyHold bounds a hold that covers a key in use, unless the
	// configuration's max_key_hold says otherwise, within its bounds.
	DefaultMaxKeyHold = 2 * time.Minute
	MinMaxKeyHold     = 30 * time.Second
	MaxMaxKeyHold     = 10 * time.Minute
)

const (
	// maxConnections bounds each socket's connections.
	maxConnections = 64
	// helloTimeout bounds the wait for a connection's hello.
	helloTimeout = 10 * time.Second
	// writeTimeout bounds the write of one frame to a client.
	writeTimeout = 30 * time.Second
)

// Config is a server's. Catalog and Keys are open and linked to the replica
// (Link), and nothing else opens their directories: the caller holds their
// Owner.
type Config struct {
	Catalog *restoreauthority.Catalog
	Keys    *keyauthority.Files
	// WorkerUID is the only account the worker socket admits: root. Tests
	// set their own.
	WorkerUID uint32
	// APIUID is the API's account; the API socket admits it and root.
	APIUID uint32
	// PublishCap and MaxKeyHold are the caps of the holds; PublishCap and
	// DefaultMaxKeyHold when zero. Tests shorten them.
	PublishCap time.Duration
	MaxKeyHold time.Duration
	// Started is when this process started, from which the quiet period
	// counts; the time New runs when zero.
	Started time.Time
	Metrics *Metrics
	// Logger receives the events of Vocabulary.
	Logger *telemetry.Logger
	// Events receives the creation and the destruction of each daily
	// receipt key; Now is the clock of their days, time.Now when nil. Tests
	// replace it.
	Events *telemetry.Logger
	Now    func() time.Time
	// AfterOperation runs once an operation's work is done, before its
	// request ends. Tests delay it to show that nothing reaches the client
	// before the request ends.
	AfterOperation func(op string)
}

// Vocabulary is the vocabulary of the service's log events.
func Vocabulary() map[string][]string {
	return map[string][]string{"event": {"peer_refused", "hold_expired", "receipt_key_created", "receipt_key_destroyed", "receipt_key_failed"},
		"socket": {RoleWorker, RoleAPI}, "kind": HoldKinds(), "step": {"create", "destroy"}}
}

// Server serves both authorities on the worker socket and the API socket.
type Server struct {
	c     Config
	local restoreauthority.Local
	epoch uint64
	// The quiet period (ADR 006 §3). A restarted service cannot know which
	// holds its previous process granted, nor whether their publishes still
	// run: until subjectsAfter, a new revocation subject waits; until
	// writesAfter, a new reservation, a seal and a key destruction wait.
	subjectsAfter, writesAfter time.Time
}

// New returns a server of the authorities in c.
func New(ctx context.Context, c Config) (*Server, error) {
	if c.Catalog == nil || c.Keys == nil || c.Keys.Identity() != c.Catalog.KeyAuthorityIdentity() || c.PublishCap < 0 || c.MaxKeyHold < 0 {
		return nil, restoreauthority.ErrInput
	}
	if c.PublishCap == 0 {
		c.PublishCap = PublishCap
	}
	if c.MaxKeyHold == 0 {
		c.MaxKeyHold = DefaultMaxKeyHold
	}
	if c.Started.IsZero() {
		c.Started = time.Now()
	}
	state, err := c.Catalog.Replication(ctx)
	if err != nil {
		return nil, err
	}
	// The epoch changes only at a promotion, which builds another
	// catalogue: it is read once, and status reads no database.
	s := &Server{c: c, local: restoreauthority.Local{Catalog: c.Catalog, Keys: c.Keys}, epoch: max(state.Committed.Epoch, 1)}
	s.subjectsAfter = c.Started.Add(c.PublishCap)
	s.writesAfter = c.Started.Add(max(c.PublishCap, c.MaxKeyHold))
	return s, nil
}

// Status is the service's state.
func (s *Server) Status() Status {
	mode, since := s.c.Catalog.ReplicationMode()
	st := Status{Protocol: Protocol, RestoreAuthority: s.c.Catalog.Identity(), KeyAuthority: s.c.Keys.Identity(),
		RestoreRoot: s.c.Catalog.Root(), KeyRoot: s.c.Keys.Root(), Epoch: s.epoch, Mode: mode}
	if !since.IsZero() {
		st.DegradedSince = since.UnixMilli()
	}
	return st
}

// Listen creates a socket at path with mode: 0600 for the worker's, 0660
// for the API's, whose account joins the socket directory's group. A
// leftover socket at path is replaced: the caller owns the authorities,
// so no other service listens there. Any other file is an error.
func Listen(path string, mode os.FileMode) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("authority socket path holds another file")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if err = os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve serves the worker socket and the API socket until ctx ends or a
// listener fails. Then it closes both, ends every connection, and so every
// hold, and waits for them. Either listener may be nil.
func (s *Server) Serve(ctx context.Context, worker, api net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listeners := map[string]net.Listener{}
	for role, l := range map[string]net.Listener{RoleWorker: worker, RoleAPI: api} {
		if l != nil {
			listeners[role] = l
		}
	}
	if len(listeners) == 0 {
		return restoreauthority.ErrInput
	}
	stop := context.AfterFunc(ctx, func() {
		for _, l := range listeners {
			l.Close()
		}
	})
	defer stop()
	var accepting, conns sync.WaitGroup
	var once sync.Once
	var failed error
	for role, l := range listeners {
		accepting.Go(func() {
			err := s.accept(ctx, l, role, &conns)
			if ctx.Err() == nil {
				once.Do(func() { failed = err })
				cancel()
			}
		})
	}
	accepting.Wait()
	conns.Wait()
	if failed != nil {
		return failed
	}
	return context.Cause(ctx)
}

func (s *Server) accept(ctx context.Context, l net.Listener, role string, conns *sync.WaitGroup) error {
	slots := make(chan struct{}, maxConnections)
	for {
		raw, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		conn, ok := raw.(*net.UnixConn)
		if !ok || !s.admits(conn, role) {
			s.c.Metrics.Refused(role)
			s.c.Logger.Event("peer_refused", telemetry.Code("socket", role))
			raw.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		conns.Go(func() {
			defer func() { <-slots }()
			s.serveConn(ctx, conn, role)
		})
	}
}

// peerUID returns the account of the process at the other end (SO_PEERCRED).
func peerUID(conn *net.UnixConn) (uint32, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var readErr error
	if err = raw.Control(func(fd uintptr) {
		cred, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || readErr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// admits checks the peer at accept: the socket gives the role. The worker
// socket admits root only, the API socket the API's account and root.
// Root can read the directories anyway: the roles protect against the
// API's account, not against root.
func (s *Server) admits(conn *net.UnixConn, role string) bool {
	uid, ok := peerUID(conn)
	if !ok {
		return false
	}
	if role == RoleWorker {
		return uid == s.c.WorkerUID
	}
	return uid == s.c.APIUID || uid == 0
}

type inbound struct {
	req Request
	err error
}

func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn, role string) {
	defer conn.Close()
	protocol, ok := s.hello(conn, role)
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The end of the service ends every read and write, so every hold.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	// One reader per connection: a frame that arrives during an operation
	// is a release, or the end of the connection, or a protocol error.
	frames := make(chan inbound)
	go func() {
		for {
			var in inbound
			in.err = readFrame(conn, &in.req, MaxRequest)
			select {
			case frames <- in:
			case <-ctx.Done():
				return
			}
			if in.err != nil {
				return
			}
		}
	}()
	for {
		var in inbound
		select {
		case in = <-frames:
		case <-ctx.Done():
			return
		}
		if in.err != nil {
			if errors.Is(in.err, authoritylog.ErrProtocol) {
				s.respond(conn, Response{Error: CodeProtocol})
			}
			return
		}
		if !s.handle(ctx, conn, role, protocol, in.req, frames) {
			return
		}
	}
}

// hello checks the client's first frame: its protocol version, its role
// against the socket, the identities it pins against the service's. A
// mismatch ends the connection: a worker never talks to another
// installation's authorities.
func (s *Server) hello(conn *net.UnixConn, role string) (int, bool) {
	conn.SetDeadline(time.Now().Add(helloTimeout))
	var h Hello
	if err := readFrame(conn, &h, MaxRequest); err != nil {
		if errors.Is(err, authoritylog.ErrProtocol) {
			writeFrame(conn, Response{Error: CodeProtocol})
		}
		return 0, false
	}
	code := ""
	switch {
	case h.Protocol < max(Protocol-1, 1) || h.Protocol > Protocol:
		code = CodeProtocol
	case h.Role != role:
		code = CodeRole
	case h.RestoreAuthority != s.c.Catalog.Identity() || h.KeyAuthority != s.c.Keys.Identity():
		code = CodeIdentity
	}
	if code != "" {
		writeFrame(conn, Response{Error: code})
		return 0, false
	}
	result, err := json.Marshal(s.Status())
	if err != nil || writeFrame(conn, Response{Result: result}) != nil {
		return 0, false
	}
	return h.Protocol, conn.SetDeadline(time.Time{}) == nil
}

func (s *Server) respond(conn *net.UnixConn, r Response) bool {
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return writeFrame(conn, r) == nil
}

type outcome struct {
	result any
	err    error
}

// handle runs one request. It returns false when the connection must end.
func (s *Server) handle(ctx context.Context, conn *net.UnixConn, role string, protocol int, req Request, frames <-chan inbound) bool {
	op, ok := operations[req.Op]
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	switch {
	case !ok:
		s.respond(conn, Response{Error: CodeProtocol})
		return false
	case role != RoleWorker && !op.api, role == RoleWorker && op.apiOnly:
		s.respond(conn, Response{Error: CodeRole})
		return false
	case timeout <= 0 || timeout > MaxTimeout:
		s.respond(conn, Response{Error: CodeProtocol})
		return false
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()
	ctx, lose := context.WithCancelCause(ctx)
	defer lose(nil)
	h := &hold{protocol: protocol, kind: op.hold, cap: s.c.PublishCap, conn: conn, release: make(chan struct{})}
	if op.hold == HoldKey {
		h.cap = s.c.MaxKeyHold
	}
	h.deadline, _ = ctx.Deadline()
	done := make(chan outcome, 1)
	go func() {
		result, err := op.run(ctx, s, req.Args, h)
		if s.c.AfterOperation != nil {
			s.c.AfterOperation(req.Op)
		}
		done <- outcome{result, err}
	}()
	released := false
	for {
		select {
		case out := <-done:
			lose(nil)
			if out.err != nil {
				code := Code(out.err)
				s.respond(conn, Response{Error: code})
				lost := h.held.Load() && !released
				return !lost && code != CodeProtocol && code != CodeRole && code != CodeHoldExpired
			}
			// A key goes after its frame, once the operation has ended.
			if a, ok := out.result.(keyAnswer); ok {
				defer keymem.Release(a.key)
				return sendKey(conn, a.result, a.key)
			}
			if out.result == nil {
				out.result = struct{}{}
			}
			result, err := json.Marshal(out.result)
			if err != nil {
				s.respond(conn, Response{Error: CodeUnavailable})
				return false
			}
			return s.respond(conn, Response{Result: result})
		case in := <-frames:
			if in.err == nil && in.req.Op == OpRelease && h.held.Load() && !released {
				released = true
				close(h.release)
				continue
			}
			// The client went away, or broke the protocol: a hold ends with
			// its connection, as it ended with the worker's process.
			lose(ErrHoldLost)
			if a, ok := (<-done).result.(keyAnswer); ok {
				keymem.Release(a.key) // never sent
			}
			return false
		}
	}
}

// decode reads an operation's arguments, refusing unknown fields.
func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := strictJSON(raw, &v); err != nil {
		return v, ErrProtocol
	}
	return v, nil
}
