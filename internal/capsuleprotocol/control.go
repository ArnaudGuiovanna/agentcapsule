package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

const MaxMessageBytes = 1 << 20
const MaxContentBytes = 512 << 10

var ErrProtocol = errors.New("invalid capsule control message")
var ErrTransport = errors.New("capsule transport unavailable or outcome unknown")
var ErrFenceOnly = errors.New("capsule boot permits barriers only")

type request struct {
	Protocol string              `json:"protocol"`
	Identity Identity            `json:"identity"`
	Event    *harnessstore.Event `json:"event,omitempty"`
	Subject  string              `json:"subject,omitempty"`
}
type response struct {
	Protocol         string                `json:"protocol"`
	Identity         Identity              `json:"identity"`
	Receipt          *harnessstore.Receipt `json:"receipt,omitempty"`
	Code             string                `json:"code,omitempty"`
	PreviousShutdown ShutdownState         `json:"previous_shutdown,omitempty"`
}

func validSubject(s string) bool {
	prefix, tail, ok := strings.Cut(s, "/")
	if !ok || tail == "" || len(s) > 512 {
		return false
	}
	return prefix == "agent" || prefix == "request" || prefix == "event" || prefix == "notification"
}

func validEvent(id Identity, e harnessstore.Event) bool {
	if e.ID == "" || len(e.ID) > 256 || len(e.Body) > MaxContentBytes || len(e.Subjects) < 1 || len(e.Subjects) > 16 {
		return false
	}
	for _, s := range e.Subjects {
		if !validSubject(s) {
			return false
		}
	}
	return slices.Contains(e.Subjects, "agent/"+id.AgentID)
}

func decode(r io.Reader, v any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrProtocol
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

// Server requires a trusted SQL handler in the same database transaction as its
// dedup marker/result. Cross-process callbacks or external side effects do not
// satisfy that contract. Protocol errors never include payloads or SQL details.
type Server struct {
	credentials      Credentials
	previousShutdown ShutdownState
	localAuth        func(*http.Request) bool
	store            *harnessstore.Store
	mutate           func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error)
	slots            chan struct{}
	// Tests can drop a connection after the durable commit, before the ACK.
	afterCommit func(http.ResponseWriter)
}

func NewServer(c Credentials, previous ShutdownState, store *harnessstore.Store, mutate func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error)) (*Server, error) {
	if !previous.Valid() || store == nil || mutate == nil {
		return nil, ErrProtocol
	}
	if _, err := c.TLS(true); err != nil {
		return nil, err
	}
	return &Server{credentials: c, previousShutdown: previous, store: store, mutate: mutate, slots: make(chan struct{}, 16)}, nil
}

func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s.localAuth != nil {
		return ErrProtocol
	}
	return ServeAuthenticated(ctx, l, s.credentials, s)
}

// ServeAuthenticated applies the same mandatory mTLS and bounded HTTP policy to
// each direction. The caller provides a per-boot listener and fixed-identity handler.
func ServeAuthenticated(ctx context.Context, l net.Listener, credentials Credentials, handler http.Handler) error {
	return serveAuthenticated(ctx, l, credentials, handler, time.Now)
}

func serveAuthenticated(ctx context.Context, l net.Listener, credentials Credentials, handler http.Handler, now func() time.Time) error {
	cfg, err := credentials.TLS(true)
	if err != nil {
		return err
	}
	before, after, err := credentials.Validity()
	if err != nil {
		return err
	}
	// TLS validates time at the handshake, not on subsequent HTTP/1.1 requests.
	// Recheck at request admission so a retained connection cannot extend a boot
	// credential's lifetime. Already admitted transactions keep their outcome.
	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := now()
		valid := !t.Before(before) && t.Before(after) && r.TLS != nil && len(r.TLS.VerifiedChains) > 0
		if valid {
			for _, cert := range r.TLS.VerifiedChains[0] {
				if t.Before(cert.NotBefore) || !t.Before(cert.NotAfter) {
					valid = false
					break
				}
			}
		}
		if !valid {
			w.Header().Set("Connection", "close")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
	h := &http.Server{Handler: guard, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: quiesceTransportTimeout,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx }}
	stop := context.AfterFunc(ctx, func() { _ = h.Close() })
	defer stop()
	err = h.Serve(tls.NewListener(l, cfg))
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := response{Protocol: Version, Identity: s.credentials.Identity}
	write := func(status int, code string) {
		reply.Code = code
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}
	authenticated := r.TLS != nil && len(r.TLS.VerifiedChains) > 0
	if s.localAuth != nil {
		authenticated = s.localAuth(r)
	}
	if !authenticated {
		write(http.StatusUnauthorized, "unauthenticated")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		write(http.StatusServiceUnavailable, "busy")
		return
	}
	if r.URL.Path == "/v1/capabilities" {
		s.serveCapabilities(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/health" {
		reply.PreviousShutdown = s.previousShutdown
		write(http.StatusOK, "")
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/v1/events" && r.URL.Path != "/v1/invoke" && r.URL.Path != "/v1/fences") {
		write(http.StatusNotFound, "unknown_operation")
		return
	}
	var in request
	if err := decode(http.MaxBytesReader(w, r.Body, MaxMessageBytes), &in); err != nil {
		write(http.StatusBadRequest, "invalid_envelope")
		return
	}
	if in.Protocol != Version || in.Identity != s.credentials.Identity {
		write(http.StatusForbidden, "wrong_identity")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var err error
	if r.URL.Path == "/v1/events" || r.URL.Path == "/v1/invoke" {
		if s.credentials.Identity.FenceOnly {
			write(http.StatusForbidden, "fence_only")
			return
		}
		if in.Event == nil || in.Subject != "" || !validEvent(s.credentials.Identity, *in.Event) {
			write(http.StatusBadRequest, "invalid_envelope")
			return
		}
		invocation := r.URL.Path == "/v1/invoke"
		if invocation {
			if _, err := DecodeInvocation(*in.Event, s.credentials.Identity.AgentID); err != nil {
				write(http.StatusBadRequest, "invalid_envelope")
				return
			}
		} else if isInvocation(*in.Event) {
			write(http.StatusBadRequest, "invalid_envelope")
			return
		}
		var receipt harnessstore.Receipt
		receipt, err = s.store.Apply(ctx, *in.Event, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
			result, err := s.mutate(ctx, *in.Event, tx)
			if len(result) > MaxContentBytes || invocation && !json.Valid(result) {
				return nil, ErrProtocol
			}
			return result, err
		})
		if err == nil {
			reply.Receipt = &receipt
		}
	} else {
		if in.Event != nil || !validSubject(in.Subject) {
			write(http.StatusBadRequest, "invalid_envelope")
			return
		}
		err = s.store.Fence(ctx, in.Subject)
	}
	if err != nil {
		switch {
		case errors.Is(err, harnessstore.ErrFenced):
			write(http.StatusConflict, "fenced")
		case errors.Is(err, harnessstore.ErrConflict):
			write(http.StatusConflict, "conflict")
		case errors.Is(err, harnessstore.ErrCommitUnknown):
			write(http.StatusServiceUnavailable, "commit_unknown")
		default:
			write(http.StatusServiceUnavailable, "unavailable")
		}
		return
	}
	if s.afterCommit != nil {
		s.afterCommit(w)
	}
	write(http.StatusOK, "")
}

type Client struct {
	identity   Identity
	serverName string
	scheme     string
	http       *http.Client
}

func (c *Client) endpoint(path string) string {
	scheme := c.scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + c.serverName + path
}

// NewClient accepts a boot-bound dialer. Neither endpoint nor identity may come
// from a user envelope; the host must derive both from its current placement.
func NewClient(c Credentials, dial func(context.Context) (net.Conn, error)) (*Client, error) {
	cfg, err := c.TLS(false)
	if err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, ErrProtocol
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 5 * time.Second,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dial(ctx)
			if err != nil {
				return nil, err
			}
			t := tls.Client(conn, cfg)
			if err = t.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return t, nil
		}}
	return &Client{identity: c.Identity, serverName: cfg.ServerName, http: &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) call(ctx context.Context, path string, in *request) (response, error) {
	method := http.MethodGet
	var body io.Reader
	if in != nil {
		in.Protocol = Version
		in.Identity = c.identity
		b, err := json.Marshal(in)
		if err != nil || len(b) > MaxMessageBytes {
			return response{}, ErrProtocol
		}
		method = http.MethodPost
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return response{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return response{}, errors.Join(ErrTransport, err)
	}
	defer resp.Body.Close()
	var out response
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessageBytes+1))
	if err != nil || len(b) > MaxMessageBytes {
		return out, ErrProtocol
	}
	if err = decode(bytes.NewReader(b), &out); err != nil {
		return out, err
	}
	if out.Protocol != Version || out.Identity != c.identity {
		return out, ErrIdentity
	}
	if resp.StatusCode != http.StatusOK || out.Code != "" {
		switch out.Code {
		case "invalid_envelope":
			return out, ErrProtocol
		case "fence_only":
			return out, ErrFenceOnly
		case "fenced":
			return out, harnessstore.ErrFenced
		case "conflict":
			return out, harnessstore.ErrConflict
		case "commit_unknown":
			return out, harnessstore.ErrCommitUnknown
		case "wrong_identity":
			return out, ErrIdentity
		default:
			return out, ErrTransport
		}
	}
	return out, nil
}

func (c *Client) Health(ctx context.Context) error {
	_, err := c.HealthStatus(ctx)
	return err
}
func (c *Client) Send(ctx context.Context, e harnessstore.Event) (harnessstore.Receipt, error) {
	if !validEvent(c.identity, e) {
		return harnessstore.Receipt{}, ErrProtocol
	}
	r, err := c.call(ctx, "/v1/events", &request{Event: &e})
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	if r.Receipt == nil {
		return harnessstore.Receipt{}, ErrProtocol
	}
	return *r.Receipt, nil
}
func (c *Client) Fence(ctx context.Context, subject string) error {
	if !validSubject(subject) {
		return ErrProtocol
	}
	_, err := c.call(ctx, "/v1/fences", &request{Subject: subject})
	return err
}
