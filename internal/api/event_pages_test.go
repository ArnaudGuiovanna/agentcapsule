package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

type streamRead struct {
	authorize bool
	attempt   int
	after     int64
	view      controlplane.OutputStreamView
	err       error
}

// Only invocation pages are served in these cases. A build or result lookup
// would take a different catalog path.
type pageCatalog struct {
	eventCatalog
	t     *testing.T
	reads []streamRead
}

func (c *pageCatalog) read(ctx context.Context, p controlplane.Principal, op string, attempt int, after int64, limit int, authorize bool) (controlplane.OutputStreamView, error) {
	c.t.Helper()
	if len(c.reads) == 0 {
		c.t.Fatal("unexpected read")
	}
	want := c.reads[0]
	c.reads = c.reads[1:]
	if _, ok := ctx.Deadline(); !ok || p.ID != "reader" || op != "op1" || attempt != want.attempt || after != want.after || limit != 64 || authorize != want.authorize {
		c.t.Fatalf("read with principal %q, op %q, cursor %d:%d, limit %d, authorize %v, deadline %v", p.ID, op, attempt, after, limit, authorize, ok)
	}
	return want.view, want.err
}

func (c *pageCatalog) ReadOutputStreamPage(ctx context.Context, p controlplane.Principal, op string, attempt int, after int64, limit int) (controlplane.OutputStreamView, error) {
	return c.read(ctx, p, op, attempt, after, limit, true)
}

func (c *pageCatalog) ReadOutputStreamNews(ctx context.Context, p controlplane.Principal, op string, attempt int, after int64, limit int) (controlplane.OutputStreamView, error) {
	return c.read(ctx, p, op, attempt, after, limit, false)
}

func serveEventPages(t *testing.T, policy <-chan struct{}, reads ...streamRead) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s := Server{events: eventStreams{limit: 1, counts: make(map[subscriptionKey]int)}}
	catalog := pageCatalog{t: t, reads: reads}
	sub := subscriber{catalog: &catalog, principal: controlplane.Principal{ID: "reader"}, op: "op1", writer: eventWriter{w: w, controller: http.NewResponseController(w)}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	s.followEvents(ctx, w, &sub, nil, policy, nil)
	if len(catalog.reads) != 0 || s.events.active != 0 {
		t.Fatalf("%d requests missing, %d subscriptions left", len(catalog.reads), s.events.active)
	}
	return w
}

func eventPage(first, last int64) controlplane.OutputStreamView {
	v := controlplane.OutputStreamView{State: "completed", Attempt: 2, LastSeq: 65}
	for seq := first; seq <= last; seq++ {
		v.Chunks = append(v.Chunks, controlplane.StreamChunk{Attempt: 2, FirstSeq: seq, LastSeq: seq, Frames: []byte(fmt.Sprintf(`[{"type":"delta","text":"chunk","seq":%d}]`, seq))})
	}
	return v
}

func TestEventResponseDrainsPagesBeforeSendingTheOutcome(t *testing.T) {
	w := serveEventPages(t, nil, streamRead{authorize: true, view: eventPage(1, 64)}, streamRead{attempt: 2, after: 64, view: eventPage(65, 65)})
	events := strings.Split(strings.TrimSuffix(w.Body.String(), "\n\n"), "\n\n")
	if w.Code != 200 || len(events) != 67 || !strings.HasPrefix(events[0], "event: state\n") || !strings.HasPrefix(events[66], "event: end\n") {
		t.Fatalf("status %d and %d events, expected state, 65 frames and end", w.Code, len(events))
	}
	for seq := 1; seq <= 65; seq++ {
		if !strings.HasPrefix(events[seq], fmt.Sprintf("event: delta\nid: 2:%d\n", seq)) {
			t.Fatal(events[seq])
		}
	}
}

func TestEventResponseHandlesARefusalBeforeAndDuringTheStream(t *testing.T) {
	w := serveEventPages(t, nil, streamRead{authorize: true, err: controlplane.ErrForbidden})
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"forbidden"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	policy := make(chan struct{}, 1)
	policy <- struct{}{}
	w = serveEventPages(t, policy, streamRead{authorize: true, view: eventPage(1, 1)}, streamRead{authorize: true, attempt: 2, err: controlplane.ErrForbidden})
	body := w.Body.String()
	if w.Code != 200 || !strings.HasSuffix(body, "event: revoked\ndata: {}\n\n") || strings.Contains(body, "event: delta") {
		t.Fatal(w.Code, body)
	}
}
