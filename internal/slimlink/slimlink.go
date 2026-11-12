// Package slimlink carries the platform's deliveries between agents through the
// SLIM bridge (INT-04, docs/interop.md). The bridge is a separate process: it
// holds the SLIM credentials and speaks A2A over SLIM; this package is the
// worker's side of their local protocol, JSON over two Unix sockets.
//
// The mailbox, not SLIM, guarantees delivery. The worker claims an attempt,
// wakes the recipient and only then hands the event to the bridge, which sends
// it as an A2A message to the recipient's SLIM name. The bridge serving that
// name calls the worker back, and the worker delivers to the recipient's VM over
// vsock. The worker accepts a call back only for an attempt it is running
// itself: each attempt has a single-use nonce, and the event must match what
// the worker sent. Holding the SLIM secret is therefore not enough to deliver
// anything. The guest's receipt travels back as the A2A task's artifact, and the
// worker checks it against the receipt it saw.
package slimlink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event and Receipt mirror harnessstore's, so the bridge's contract does not
// depend on the guest store.
type Event struct {
	ID       string   `json:"id"`
	Subjects []string `json:"subjects"`
	Body     []byte   `json:"body"`
}

type Receipt struct {
	Result   []byte `json:"result"`
	Replayed bool   `json:"replayed"`
}

// The local protocol. The bridge serves ServePath, SendPath and HealthPath;
// the worker serves DeliverPath.
const (
	ServePath   = "/v1/serve"
	SendPath    = "/v1/send"
	HealthPath  = "/v1/health"
	DeliverPath = "/v1/deliver"
)

type ServeRequest struct {
	Name string `json:"name"`
}

type SendRequest struct {
	To    string `json:"to"`
	Nonce string `json:"nonce"`
	Event Event  `json:"event"`
}

type DeliverRequest struct {
	To     string `json:"to"`
	Caller string `json:"caller"`
	Nonce  string `json:"nonce"`
	Event  Event  `json:"event"`
}

type Health struct {
	Name string `json:"name"`
}

// Failure is the body of every refusal on either socket.
type Failure struct {
	Error string `json:"error"`
}

// Error codes. Unreachable: SLIM did not reach the name (no subscriber, node
// down). Refused: the side serving the name did not accept the call.
// Failed: the delivery to the VM failed. Invalid: a malformed call.
const (
	CodeUnreachable = "unreachable"
	CodeRefused     = "refused"
	CodeFailed      = "failed"
	CodeInvalid     = "invalid"
	CodeUnavailable = "unavailable"
)

// PlatformNamespace holds the bridges' own SLIM names; agents' names hold an
// organization (or "personal" for agents of a person) instead.
const PlatformNamespace = "agentcapsule/platform/"

const maxBody = 8 << 20 // a delivered event is bounded well below this

var (
	ErrInput = errors.New("slimlink: invalid name or event")
	// ErrReceipt: the bridge returned a receipt that is not the guest's.
	ErrReceipt = errors.New("slimlink: the bridge's receipt does not match the delivery")
	// ErrPeer: the process at the other end of a socket is not the expected user.
	ErrPeer = errors.New("slimlink: unexpected peer on the local socket")
)

// BridgeError is a refusal from the bridge, with its code.
type BridgeError struct {
	Status int
	Code   string
}

func (e *BridgeError) Error() string {
	return fmt.Sprintf("slimlink: bridge answered %d %s", e.Status, e.Code)
}

func validComponent(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Name is an agent's SLIM name, the same as its Directory record name:
// agentcapsule/<organization>/<agent>, or agentcapsule/personal/<agent>.
func Name(tenant, agent string) (string, error) {
	if tenant == "" {
		tenant = "personal"
	}
	if tenant == "platform" || !validComponent(tenant) || !validComponent(agent) {
		return "", ErrInput
	}
	return "agentcapsule/" + tenant + "/" + agent, nil
}

// ValidName accepts the three-component names this package uses.
func ValidName(s string) bool {
	parts := strings.Split(s, "/")
	return len(parts) == 3 && parts[0] == "agentcapsule" && validComponent(parts[1]) && validComponent(parts[2])
}

// digest binds an event's identity, subjects and body.
func digest(e Event) [32]byte {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte(e.ID))
	for _, s := range e.Subjects {
		field([]byte(s))
	}
	field(e.Body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

type outcome struct {
	receipt Receipt
	err     error
}

type handoff struct {
	event Event
	reply chan outcome // buffered: the attempt never blocks on it
}

type attempt struct {
	to      string
	digest  [32]byte
	claimed bool
	handoff chan *handoff
	done    chan struct{}
}

// Link is the worker's side. It is safe for concurrent use.
type Link struct {
	client *http.Client
	mu     sync.Mutex
	open   map[string]*attempt // by nonce
}

// Open returns a link to the bridge listening on socket, which must be owned
// by bridgeUID: each connection checks the peer's user. It does not connect.
func Open(socket string, bridgeUID uint32) *Link {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		if !peerIs(c, bridgeUID) {
			c.Close()
			return nil, ErrPeer
		}
		return c, nil
	}
	return &Link{
		client: &http.Client{Transport: &http.Transport{DialContext: dial, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second, DisableCompression: true}},
		open:   map[string]*attempt{},
	}
}

func (l *Link) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://bridge"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var f Failure
		_ = json.Unmarshal(data, &f)
		if f.Error == "" {
			f.Error = CodeUnavailable
		}
		return &BridgeError{Status: res.StatusCode, Code: f.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Health returns the bridge's own SLIM name once it is connected to the node.
func (l *Link) Health(ctx context.Context) (string, error) {
	var h Health
	err := l.call(ctx, http.MethodGet, HealthPath, nil, &h)
	return h.Name, err
}

// Serve asks the bridge to answer on an agent's SLIM name. The worker calls it
// once the agent's VM is ready and before it spends a delivery attempt, so an
// absent bridge or node delays the delivery without consuming an attempt.
func (l *Link) Serve(ctx context.Context, name string) error {
	if !ValidName(name) {
		return ErrInput
	}
	return l.call(ctx, http.MethodPost, ServePath, ServeRequest{Name: name}, nil)
}

// Deliver sends the event to the agent named to through the bridge and SLIM.
// When the bridge serving that name calls back with this attempt, local runs
// in the caller's goroutine, under the caller's context: it delivers the event
// that came through SLIM to the VM. A failure of local is returned unchanged;
// otherwise the receipt is the one the bridge returned, checked against local's.
func (l *Link) Deliver(ctx context.Context, to string, e Event, local func(context.Context, Event) (Receipt, error)) (Receipt, error) {
	if !ValidName(to) || e.ID == "" || len(e.Body) > maxBody {
		return Receipt{}, ErrInput
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Receipt{}, err
	}
	nonce := hex.EncodeToString(raw[:])
	a := &attempt{to: to, digest: digest(e), handoff: make(chan *handoff), done: make(chan struct{})}
	l.mu.Lock()
	l.open[nonce] = a
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.open, nonce)
		l.mu.Unlock()
		close(a.done)
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sent := make(chan outcome, 1)
	go func() {
		var r Receipt
		err := l.call(ctx, http.MethodPost, SendPath, SendRequest{To: to, Nonce: nonce, Event: e}, &r)
		sent <- outcome{r, err}
	}()
	var delivered *Receipt
	for {
		select {
		case h := <-a.handoff:
			r, err := local(ctx, h.event)
			h.reply <- outcome{r, err}
			if err != nil {
				return Receipt{}, err
			}
			delivered = &r
		case s := <-sent:
			if s.err != nil {
				return Receipt{}, s.err
			}
			if delivered == nil || !bytes.Equal(s.receipt.Result, delivered.Result) || s.receipt.Replayed != delivered.Replayed {
				return Receipt{}, ErrReceipt
			}
			return s.receipt, nil
		case <-ctx.Done():
			return Receipt{}, ctx.Err()
		}
	}
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Failure{Error: code})
}

// ServeHTTP answers the bridge's calls back (DeliverPath). It refuses a call
// that matches no running attempt, a second call for the same attempt, and a
// call whose name, event or caller differ from the attempt's.
func (l *Link) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != DeliverPath {
		fail(w, http.StatusNotFound, CodeInvalid)
		return
	}
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, CodeInvalid)
		return
	}
	var in DeliverRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 2*maxBody))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil || !ValidName(in.To) || in.Event.ID == "" {
		fail(w, http.StatusBadRequest, CodeInvalid)
		return
	}
	l.mu.Lock()
	a := l.open[in.Nonce]
	ok := a != nil && !a.claimed && a.to == in.To && a.digest == digest(in.Event) && strings.HasPrefix(in.Caller, PlatformNamespace)
	if ok {
		a.claimed = true
	}
	l.mu.Unlock()
	if !ok {
		fail(w, http.StatusForbidden, CodeRefused)
		return
	}
	h := &handoff{event: in.Event, reply: make(chan outcome, 1)}
	select {
	case a.handoff <- h:
	case <-a.done:
		fail(w, http.StatusGone, CodeRefused)
		return
	case <-r.Context().Done():
		return
	}
	var o outcome
	select {
	case o = <-h.reply:
	case <-r.Context().Done():
		return
	}
	if o.err != nil {
		fail(w, http.StatusBadGateway, CodeFailed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(o.receipt)
}
