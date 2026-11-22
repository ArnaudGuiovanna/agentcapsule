package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Request limits (v0.1.0 audit, findings S-07 and L-19). An authenticated
// request costs about twenty SQL round trips before its handler's work, so
// one noisy caller could starve the others. Each principal and each
// organization has a token bucket, and each source address a bucket of failed
// authentications. The buckets live in the process's memory: every API process
// keeps its own.

// RequestLimits bounds the requests of each principal and of each
// organization, and the failed authentications of each source. A rate of 0
// turns its limit off.
type RequestLimits struct {
	// PrincipalRate is what one principal may send, in requests per second,
	// once it has sent PrincipalBurst at once.
	PrincipalRate, PrincipalBurst int
	// OrganizationRate and OrganizationBurst bound all the principals of one
	// organization together.
	OrganizationRate, OrganizationBurst int
	// FailuresPerMinute bounds the failed authentications of one source: an
	// IPv4 address, or an IPv6 /64. A source past it is refused before any
	// database work, unless its credential authenticated recently.
	FailuresPerMinute int
}

// DefaultRequestLimits are agentcapsule-api's defaults. One principal stays
// well under what one process admits (ADR 014 §5); several principals are
// needed to spend an organization's bucket.
var DefaultRequestLimits = RequestLimits{PrincipalRate: 20, PrincipalBurst: 200, OrganizationRate: 100, OrganizationBurst: 1000, FailuresPerMinute: 60}

// Validate refuses a rate or a burst out of bounds, or a burst below one
// request for a rate that is on.
func (l RequestLimits) Validate() error {
	for _, v := range [][2]int{{l.PrincipalRate, l.PrincipalBurst}, {l.OrganizationRate, l.OrganizationBurst}, {l.FailuresPerMinute, l.FailuresPerMinute}} {
		if v[0] < 0 || v[0] > 100000 || v[1] < 0 || v[1] > 1000000 || (v[0] > 0 && v[1] < 1) {
			return controlplane.ErrInput
		}
	}
	return nil
}

// limitKinds name the limits that refuse a request, the values of
// agentcapsule_api_limited_requests_total.
var limitKinds = []string{"principal_rate", "organization_rate", "authentication_failures", "invocation_streams",
	"principal_streams", "organization_streams", "process_streams", "principal_uploads", "process_uploads"}

// guards holds the limits of the v0.1.0 audit: requests (S-07), uploads
// (S-09) and the key of the sources' pseudonyms (L-19). Its zero value is
// ready: no request limit, the default upload slots, a key drawn at first
// use.
type guards struct {
	requests  *requestLimiter
	uploads   uploadSlots
	keyOnce   sync.Once
	sourceKey []byte
}

// LimitRequests bounds each principal's and each organization's requests and
// each source's failed authentications. Call it before serving; without it,
// nothing is limited (the embedded servers of the tests).
func (s *Server) LimitRequests(l RequestLimits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	s.guards.requests = newRequestLimiter(l)
	return nil
}

// UseSourcePseudonymKey sets the key of the sources' pseudonyms in the
// authentication_failed events: with the same key, a source has the same
// pseudonym after a restart and in every API process. Without it, each
// process draws its own key, and its pseudonyms link its own events only.
// Call it before serving.
func (s *Server) UseSourcePseudonymKey(key []byte) error {
	if len(key) != 32 {
		return controlplane.ErrInput
	}
	s.guards.sourceKey = bytes.Clone(key)
	return nil
}

// sourcePseudonym is the first 64 bits of HMAC-SHA256 of the source under the
// process's key: never the address itself (docs/observability.md).
func (s *Server) sourcePseudonym(source string) string {
	s.guards.keyOnce.Do(func() {
		if s.guards.sourceKey == nil {
			s.guards.sourceKey = make([]byte, 32)
			_, _ = rand.Read(s.guards.sourceKey)
		}
	})
	return telemetry.Pseudonym(s.guards.sourceKey, source)
}

// sourceOf is what a request's failed authentications count against: its
// peer's IPv4 address, or the /64 of its IPv6 address, which one subscriber
// usually holds whole. Behind a proxy or a load balancer, it is the proxy's.
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	if a = a.Unmap().WithZone(""); a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// bearer is the credential of a request's one Bearer Authorization header,
// or "".
func bearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

// refuseLimited answers 429 for a limit of requests, with the seconds until
// the bucket holds one request again.
func (s *Server) refuseLimited(w http.ResponseWriter, limit string, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
	s.countLimited(limit)
	switch limit {
	case "principal_rate":
		problem(w, 429, "rate_limited")
	case "organization_rate":
		problem(w, 429, "organization_rate_limited")
	default:
		problem(w, 429, "authentication_rate_limited")
	}
}

func (s *Server) countLimited(limit string) {
	if s.telemetry != nil {
		s.telemetry.limited.Inc(limit)
	}
}

// admitAttempt refuses, before any database work, an attempt to authenticate
// that is not a bearer of the principal routes (an enrollment proof, an
// invitation's token) from a source past its failed authentications.
func (s *Server) admitAttempt(w http.ResponseWriter, r *http.Request) bool {
	l := s.guards.requests
	if l == nil {
		return true
	}
	l.mu.Lock()
	limit, wait := l.sourceRefusal(sourceOf(r), l.now())
	l.mu.Unlock()
	if limit != "" {
		s.refuseLimited(w, limit, wait)
		return false
	}
	return true
}

// downloadRoute serves the temporary links, which carry their credential.
const downloadRoute = "/v1/downloads/{token}"

// authenticationOutcome runs once a request is answered. A failed
// authentication (401, or the 404 of a link that does not open) counts
// against its source and forgets its credential. It and a refusal of the
// source write an authentication_failed event: the request's ID, its route
// and the source's pseudonym, never its address (L-19).
func (s *Server) authenticationOutcome(r *http.Request, route string, w *statusRecorder, requestID string) {
	failed := w.status == http.StatusUnauthorized || route == downloadRoute && w.status == http.StatusNotFound
	if !failed && w.problem != "authentication_rate_limited" {
		return
	}
	source := sourceOf(r)
	if l := s.guards.requests; failed && l != nil {
		l.failed(bearer(r), source)
	}
	if s.telemetry != nil {
		s.telemetry.log.Event("authentication_failed", telemetry.RequestID(requestID), telemetry.Code("route", route),
			telemetry.PseudonymField("source", s.sourcePseudonym(source)))
	}
}

// maxBuckets bounds each set of buckets and the known credentials; past it,
// the full buckets are forgotten (a full bucket is a new one), then
// arbitrary ones.
const maxBuckets = 65536

// knownFor is how long a credential that authenticated stays known: its
// requests are charged before the database, and pass its source's limit.
const knownFor = 15 * time.Minute

type bucket struct {
	tokens float64
	at     time.Time
}

type buckets struct {
	rate, burst float64 // tokens per second, and the most a bucket holds
	items       map[string]*bucket
}

func newBuckets(perSecond, burst float64) *buckets {
	if perSecond <= 0 {
		return nil
	}
	return &buckets{rate: perSecond, burst: burst, items: map[string]*bucket{}}
}

// get refills key's bucket up to now; a new bucket starts full.
func (b *buckets) get(key string, now time.Time) *bucket {
	k, ok := b.items[key]
	if !ok {
		if len(b.items) >= maxBuckets {
			b.sweep(now)
		}
		k = &bucket{tokens: b.burst, at: now}
		b.items[key] = k
		return k
	}
	if now.After(k.at) {
		k.tokens = min(b.burst, k.tokens+now.Sub(k.at).Seconds()*b.rate)
		k.at = now
	}
	return k
}

// wait is how long k takes to hold one token again.
func (b *buckets) wait(k *bucket) time.Duration {
	return time.Duration((1 - k.tokens) / b.rate * float64(time.Second))
}

func (b *buckets) sweep(now time.Time) {
	for key, k := range b.items {
		if k.tokens+now.Sub(k.at).Seconds()*b.rate >= b.burst {
			delete(b.items, key)
		}
	}
	for key := range b.items {
		if len(b.items) < maxBuckets-maxBuckets/10 {
			return
		}
		delete(b.items, key)
	}
}

type knownCredential struct {
	principal, organization string
	until                   time.Time
}

// requestLimiter holds the buckets. A credential is known by its keyed
// fingerprint, never kept itself; knowing one never admits a request: the
// database authenticates every request the limiter lets through, so a
// revocation takes effect as before (ADR 001, ADR 002).
type requestLimiter struct {
	mu                                 sync.Mutex
	now                                func() time.Time
	principals, organizations, sources *buckets
	known                              map[[16]byte]knownCredential
	key                                [32]byte
}

func newRequestLimiter(l RequestLimits) *requestLimiter {
	r := &requestLimiter{now: time.Now, known: map[[16]byte]knownCredential{},
		principals:    newBuckets(float64(l.PrincipalRate), float64(l.PrincipalBurst)),
		organizations: newBuckets(float64(l.OrganizationRate), float64(l.OrganizationBurst)),
		sources:       newBuckets(float64(l.FailuresPerMinute)/60, float64(l.FailuresPerMinute))}
	_, _ = rand.Read(r.key[:])
	return r
}

func (l *requestLimiter) fingerprint(credential string) [16]byte {
	m := hmac.New(sha256.New, l.key[:])
	m.Write([]byte(credential))
	var f [16]byte
	copy(f[:], m.Sum(nil))
	return f
}

func principalKey(p controlplane.Principal) string {
	return p.Kind + "\x00" + p.TenantID + "\x00" + p.ID
}

// charge takes one request from a principal's bucket and from its
// organization's, from both or from neither. It returns the limit that
// refused, and how long until it would admit.
func (l *requestLimiter) charge(principal, organization string, now time.Time) (string, time.Duration) {
	var p, o *bucket
	if l.principals != nil {
		if p = l.principals.get(principal, now); p.tokens < 1 {
			return "principal_rate", l.principals.wait(p)
		}
	}
	if l.organizations != nil && organization != "" {
		if o = l.organizations.get(organization, now); o.tokens < 1 {
			return "organization_rate", l.organizations.wait(o)
		}
	}
	if p != nil {
		p.tokens--
	}
	if o != nil {
		o.tokens--
	}
	return "", 0
}

// sourceRefusal refuses a source past its failed authentications. The
// caller holds l.mu.
func (l *requestLimiter) sourceRefusal(source string, now time.Time) (string, time.Duration) {
	if l.sources == nil {
		return "", 0
	}
	if b := l.sources.get(source, now); b.tokens < 1 {
		return "authentication_failures", l.sources.wait(b)
	}
	return "", 0
}

// before runs before the database looks the credential up. A known
// credential is charged to its principal and organization now, so a caller
// past its limit costs no SQL; an unknown one is refused while its source is
// past its failed authentications.
func (l *requestLimiter) before(credential, source string) (known bool, limit string, wait time.Duration) {
	now := l.now()
	f := l.fingerprint(credential)
	l.mu.Lock()
	defer l.mu.Unlock()
	if k, ok := l.known[f]; ok && now.Before(k.until) {
		limit, wait = l.charge(k.principal, k.organization, now)
		return true, limit, wait
	}
	limit, wait = l.sourceRefusal(source, now)
	return false, limit, wait
}

// authenticated remembers the credential of p, and charges p's request
// unless before did.
func (l *requestLimiter) authenticated(credential string, p controlplane.Principal, charged bool) (string, time.Duration) {
	now := l.now()
	f := l.fingerprint(credential)
	key := principalKey(p)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.known[f]; !ok && len(l.known) >= maxBuckets {
		l.sweepKnown(now)
	}
	l.known[f] = knownCredential{key, p.TenantID, now.Add(knownFor)}
	if charged {
		return "", 0
	}
	return l.charge(key, p.TenantID, now)
}

// admit charges a request whose principal comes from a sealed link.
func (l *requestLimiter) admit(p controlplane.Principal) (string, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.charge(principalKey(p), p.TenantID, now)
}

// failed counts a failed authentication against its source, and forgets
// its credential.
func (l *requestLimiter) failed(credential, source string) {
	now := l.now()
	var f [16]byte
	if credential != "" {
		f = l.fingerprint(credential)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if credential != "" {
		delete(l.known, f)
	}
	if l.sources != nil {
		b := l.sources.get(source, now)
		b.tokens = max(0, b.tokens-1)
	}
}

func (l *requestLimiter) sweepKnown(now time.Time) {
	for f, k := range l.known {
		if !now.Before(k.until) {
			delete(l.known, f)
		}
	}
	for f := range l.known {
		if len(l.known) < maxBuckets-maxBuckets/10 {
			return
		}
		delete(l.known, f)
	}
}
