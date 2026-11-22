package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// callFrom is call from another source address.
func callFrom(t *testing.T, s *Server, source, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = source
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// S-07: each principal and each organization has its bucket, and each source
// its failed authentications. A credential that authenticated is charged
// before the database looks it up again: past its limit it costs no SQL (the
// store is closed and the answer is still 429, not 503). An unknown credential
// from a source past its failures is refused before its lookup; a known one
// from the same source is not.
func TestRequestLimitsRefuseBeforeTheDatabase(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	apiAddMember(t, l, owner, "bob", "agent_user")
	bob := l.sign(t, at, "bob-limits", "bob", allAgentScopes)
	// Its own store, which the test closes.
	store, err := controlplane.Open(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	accounts, err := controlplane.NewAccounts(store, bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewForHost(store, accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	s.SetDelegatedIdentityVerifier(l.verifier)
	registry := telemetry.NewRegistry()
	var events bytes.Buffer
	s.EnableTelemetry(registry, &events)
	if err = s.LimitRequests(RequestLimits{PrincipalRate: 1, PrincipalBurst: 3, OrganizationRate: 1, OrganizationBurst: 4, FailuresPerMinute: 2}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.guards.requests.now = func() time.Time { return now }
	const home, away = "192.0.2.1:1234", "203.0.113.5:4321"
	expect := func(w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if w.Code != status || code != "" && !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
			t.Fatal("want", status, code, "got", w.Code, w.Body.String())
		}
		if status == 429 {
			if retry, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || retry < 1 {
				t.Fatal("429 without Retry-After", w.Header())
			}
		}
	}
	const path = "/v1/organizations/current"
	expect(callFrom(t, s, home, "GET", path, owner), 200, "")
	// Two credentials that the database does not know spend the source's
	// failures; a third is refused before it is looked up.
	for _, bad := range []string{"acps_" + strings.Repeat("a", 43), "acps_" + strings.Repeat("b", 43)} { // gitleaks:allow test fixture, not a credential
		expect(callFrom(t, s, home, "GET", path, bad), 401, "authentication_required")
	}
	expect(callFrom(t, s, home, "GET", path, "acps_"+strings.Repeat("c", 43)), 429, "authentication_rate_limited") // gitleaks:allow test fixture, not a credential
	// The owner's credential is known: it passes its source's limit. Bob's is
	// not, until it authenticates from elsewhere.
	expect(callFrom(t, s, home, "GET", path, owner), 200, "")
	expect(callFrom(t, s, home, "GET", path, bob), 429, "authentication_rate_limited")
	expect(callFrom(t, s, away, "GET", path, bob), 200, "")
	// The owner spends its burst; then bob, whose bucket is not empty, meets
	// the organization's.
	expect(callFrom(t, s, home, "GET", path, owner), 200, "")
	expect(callFrom(t, s, home, "GET", path, owner), 429, "rate_limited")
	expect(callFrom(t, s, away, "GET", path, bob), 429, "organization_rate_limited")
	// Without the database, both are still refused: no SQL was needed.
	store.Close()
	expect(callFrom(t, s, home, "GET", path, owner), 429, "rate_limited")
	expect(callFrom(t, s, away, "GET", path, bob), 429, "organization_rate_limited")
	// A second later each bucket holds a request again: the owner's reaches
	// the database, which is gone.
	now = now.Add(time.Second)
	expect(callFrom(t, s, home, "GET", path, owner), 503, "temporarily_unavailable")

	var exposition bytes.Buffer
	if _, err = registry.WriteTo(&exposition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`limit="authentication_failures"} 2`, `limit="principal_rate"} 2`, `limit="organization_rate"} 2`} {
		if !strings.Contains(exposition.String(), "agentcapsule_api_limited_requests_total{"+want) {
			t.Fatal("missing", want, exposition.String())
		}
	}
	failed := 0
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		if strings.Contains(line, `"event":"authentication_failed"`) {
			failed++
			if !strings.Contains(line, `"source":"`+s.sourcePseudonym("192.0.2.1")+`"`) {
				t.Fatal("an authentication failure from elsewhere", line)
			}
		}
	}
	if failed != 4 || strings.Contains(events.String(), "192.0.2.1") || strings.Contains(events.String(), "203.0.113.5") {
		t.Fatal("authentication_failed events", failed, events.String())
	}
}

type countingBody struct {
	r    io.Reader
	read atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func uploadRequest(path, token, key string, body io.Reader, size int64) *http.Request {
	r := httptest.NewRequest("POST", path, body)
	r.ContentLength = size
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Attachment-Name", "notes.txt")
	return r
}

// uploadLab is tenantInvocationLab, with the time its tokens are signed at.
func uploadLab(t *testing.T) (*apiDelegationFixture, time.Time, string, string, string) {
	t.Helper()
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x47}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if l.server, err = NewForHostWithTransit(l.store, l.server.accounts, "local", transit); err != nil {
		t.Fatal(err)
	}
	l.server.SetDelegatedIdentityVerifier(l.verifier)
	agent := apiActiveTenantAgent(t, l, owner, "uploads")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg",
		`{"principal_id":"`+bob.PrincipalID+`","permissions":["read_metadata","invoke","read_content"]}`); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	return l, at, agent, owner, l.sign(t, at, "bob-invoke", "bob", invokeScopes)
}

// S-09: an upload's rights and its organization's room are checked before
// its body is read: a caller who may not invoke the agent, or an
// organization past its storage quota, gets its answer with nothing read. A
// replay of a stored upload still gets its first answer. The bodies held at
// once are bounded per principal and in the process.
func TestUploadRightsAndRoomAreCheckedBeforeTheBody(t *testing.T) {
	l, at, agent, owner, bob := uploadLab(t)
	path := "/v1/agents/" + agent + "/attachments"
	send := func(token, key string, size int, want int, code string) {
		t.Helper()
		body := &countingBody{r: bytes.NewReader(bytes.Repeat([]byte("n"), size))}
		w := httptest.NewRecorder()
		l.server.ServeHTTP(w, uploadRequest(path, token, key, body, int64(size)))
		if w.Code != want || code != "" && !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
			t.Fatal(key, "want", want, code, "got", w.Code, w.Body.String())
		}
		if read := body.read.Load(); want/100 == 2 && read != int64(size) || want/100 != 2 && read != 0 {
			t.Fatal(key, "read", read, "of", size, "bytes for a", w.Code)
		}
	}
	// The owner administers the agent without an invoke assignment; a member
	// without any assignment does not see it.
	send(owner, "owner", 1024, 403, "forbidden")
	carol := l.sign(t, at, "carol-upload", "carol", invokeScopes)
	apiAddMember(t, l, owner, "carol", "agent_user")
	send(carol, "carol", 1024, 404, "not_found")
	// Room for one MiB: one MiB fits, then nothing more; its replay passes.
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "room", `{"max_pending_per_agent":100,"max_pending_tenant":1000,"max_attachment_bytes":1048576}`); r.Code != 200 {
		t.Fatal("limits", r.Code, r.Body.String())
	}
	send(bob, "big", 2<<20, 429, "attachment_quota_exceeded")
	send(bob, "fits", 1<<20, 201, "")
	send(bob, "more", 1, 429, "attachment_quota_exceeded")
	send(bob, "fits", 1<<20, 201, "")

	// One body per principal at once, two in the process.
	if r := call(t, l.server, "POST", "/v1/queue/limits", owner, "room-2", `{"max_pending_per_agent":100,"max_pending_tenant":1000,"max_attachment_bytes":67108864}`); r.Code != 200 {
		t.Fatal("limits", r.Code, r.Body.String())
	}
	if err := l.server.LimitUploads(2, 1); err != nil {
		t.Fatal(err)
	}
	dave := apiAddMember(t, l, owner, "dave", "agent_user")
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg-dave",
		`{"principal_id":"`+dave.PrincipalID+`","permissions":["invoke"]}`); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	daveToken := l.sign(t, at, "dave-upload", "dave", invokeScopes)
	hold := func(token, key string) (*io.PipeWriter, chan int) {
		reader, writer := io.Pipe()
		done := make(chan int, 1)
		go func() {
			w := httptest.NewRecorder()
			l.server.ServeHTTP(w, uploadRequest(path, token, key, reader, 10))
			done <- w.Code
		}()
		// The write returns once the handler reads: it holds its slot.
		if _, err := writer.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		return writer, done
	}
	first, firstDone := hold(bob, "held-1")
	send(bob, "held-2", 10, 429, "too_many_uploads")
	second, secondDone := hold(daveToken, "held-3")
	erinMember := apiAddMember(t, l, owner, "erin", "agent_user")
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg-erin",
		`{"principal_id":"`+erinMember.PrincipalID+`","permissions":["invoke"]}`); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	erin := l.sign(t, at, "erin-upload", "erin", invokeScopes)
	send(erin, "held-4", 10, 503, "upload_capacity")
	for _, held := range []struct {
		w    *io.PipeWriter
		done chan int
	}{{first, firstDone}, {second, secondDone}} {
		if _, err := held.w.Write([]byte("world")); err != nil {
			t.Fatal(err)
		}
		held.w.Close()
		if code := <-held.done; code != 201 {
			t.Fatal("a held upload", code)
		}
	}
	send(erin, "after", 10, 201, "")
}
