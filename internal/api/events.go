package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

const (
	invocationEventsPath   = "/v1/invocations/{id}/events"
	buildEventsPath        = "/v1/corpus-builds/{id}/events"
	operationEventsPath    = "/v1/operations/{id}/events"
	streamChannel          = "agentcapsule_invocation_stream"
	policyChannel          = "agentcapsule_organization_policy"
	DefaultMaxEventStreams = 1000
	eventLifetime          = 15 * time.Minute
	eventReadTimeout       = 5 * time.Second
	eventRightsInterval    = 10 * time.Second
	eventHeartbeat         = 15 * time.Second
)

// DefaultMaxPrincipalEventStreams and DefaultMaxOrganizationEventStreams
// bound one principal's and one organization's subscriptions in the process,
// well under DefaultMaxEventStreams (v0.1.0 audit, S-08).
const (
	DefaultMaxPrincipalEventStreams    = 32
	DefaultMaxOrganizationEventStreams = 200
)

func isEventRoute(route string) bool {
	return route == invocationEventsPath || route == operationEventsPath || route == buildEventsPath
}

type subscriptionKey struct{ tenant, principal, invocation string }
type eventStreams struct {
	mu            sync.Mutex
	limit, active int
	counts        map[subscriptionKey]int
	hub           pgnotify.Hub
	gauge         *telemetry.Gauge

	// principal and organization bound one principal's and one
	// organization's subscriptions (0: the defaults); principals and
	// organizations count them.
	principal, organization   int
	principals, organizations map[string]int
}

// LimitEventStreams sets how many subscriptions one principal and one
// organization may hold in the process, each from 1 to 100,000. The
// smallest bound that applies refuses first; -max-event-streams still bounds
// them all. Call it before serving.
func (s *Server) LimitEventStreams(principal, organization int) error {
	if principal < 1 || principal > 100000 || organization < 1 || organization > 100000 {
		return controlplane.ErrInput
	}
	s.events.principal, s.events.organization = principal, organization
	return nil
}

// StartEventStreams starts the API's one shared LISTEN connection. Call it
// before serving. Embedded servers may use the one-second polling fallback.
func (s *Server) StartEventStreams(ctx context.Context, limit int) error {
	if limit < 1 || limit > 100000 {
		return controlplane.ErrInput
	}
	hub, err := pgnotify.New(s.store.Connect, streamChannel, policyChannel, "agentcapsule_corpus_build")
	if err != nil {
		return err
	}
	s.events.hub, s.events.limit = hub, limit
	go hub.Run(ctx)
	return nil
}

// acquire takes a subscription slot, or names the limit that refused:
// invocation_streams (4 to one invocation), principal_streams,
// organization_streams or process_streams.
func (e *eventStreams) acquire(key subscriptionKey) (release func(), refused string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	principal := key.tenant + "\x00" + key.principal
	perPrincipal, perOrganization := e.principal, e.organization
	if perPrincipal == 0 {
		perPrincipal, perOrganization = DefaultMaxPrincipalEventStreams, DefaultMaxOrganizationEventStreams
	}
	switch {
	case e.counts[key] >= 4:
		return nil, "invocation_streams"
	case e.principals[principal] >= perPrincipal:
		return nil, "principal_streams"
	case e.organizations[key.tenant] >= perOrganization:
		return nil, "organization_streams"
	case e.active >= e.limit:
		return nil, "process_streams"
	}
	if e.principals == nil {
		e.principals, e.organizations = map[string]int{}, map[string]int{}
	}
	e.counts[key]++
	e.principals[principal]++
	e.organizations[key.tenant]++
	e.active++
	if e.gauge != nil {
		e.gauge.Set(float64(e.active))
	}
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.counts[key]--
		if e.counts[key] == 0 {
			delete(e.counts, key)
		}
		if e.principals[principal]--; e.principals[principal] == 0 {
			delete(e.principals, principal)
		}
		if e.organizations[key.tenant]--; e.organizations[key.tenant] == 0 {
			delete(e.organizations, key.tenant)
		}
		e.active--
		if e.gauge != nil {
			e.gauge.Set(float64(e.active))
		}
	}, ""
}

var eventIDFormat = regexp.MustCompile(`^[0-9]{1,9}:[0-9]{1,18}$`)

type streamPosition struct {
	attempt int
	seq     int64
	haveID  bool
}

func eventPosition(values []string) (streamPosition, error) {
	if len(values) == 0 {
		return streamPosition{}, nil
	}
	if len(values) != 1 || !eventIDFormat.MatchString(values[0]) {
		return streamPosition{}, controlplane.ErrInput
	}
	a, b, _ := strings.Cut(values[0], ":")
	attempt, _ := strconv.Atoi(a)
	seq, _ := strconv.ParseInt(b, 10, 64)
	return streamPosition{attempt: attempt, seq: seq, haveID: true}, nil
}

type eventWriter struct {
	w          http.ResponseWriter
	controller *http.ResponseController
	last       time.Time
}

func (e *eventWriter) write(name, id string, data any) error {
	var buf []byte
	if name == "" {
		buf = []byte(": heartbeat\n\n")
	} else {
		body, err := json.Marshal(data)
		if err != nil {
			return err
		}
		buf = append(buf, "event: "+name+"\n"...)
		if id != "" {
			buf = append(buf, "id: "+id+"\n"...)
		}
		buf = append(buf, "data: "...)
		buf = append(buf, body...)
		buf = append(buf, '\n', '\n')
	}
	_ = e.controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := e.w.Write(buf); err != nil {
		return err
	}
	if err := e.controller.Flush(); err != nil {
		return err
	}
	e.last = time.Now()
	return nil
}

// eventCatalog supplies authorized pages, subsequent reads and final results
// to the HTTP subscription.
type eventCatalog interface {
	ReadOutputStreamPage(context.Context, controlplane.Principal, string, int, int64, int) (controlplane.OutputStreamView, error)
	ReadOutputStreamNews(context.Context, controlplane.Principal, string, int, int64, int) (controlplane.OutputStreamView, error)
	ReadCorpusBuildStream(context.Context, controlplane.Principal, string, int, int64, int) (controlplane.OutputStreamView, error)
	StreamResult(context.Context, controlplane.Principal, string, int) (json.RawMessage, error)
}

type subscriber struct {
	build                bool
	catalog              eventCatalog
	principal            controlplane.Principal
	op                   string
	writer               eventWriter
	pos                  streamPosition
	state                string
	truncated            bool
	missingResultAttempt int
	// authorized is when the rights were last checked; recheck asks for a
	// check at the next read (a policy notification).
	authorized time.Time
	recheck    bool
}

// read reads the subscription's state and new frames. An invocation's
// subscriber checks its rights with them every eventRightsInterval and when
// its organization's policy changes; in between, it reads only what is new,
// in one statement (P-11).
func (s *subscriber) read(ctx context.Context) (controlplane.OutputStreamView, error) {
	ctx, cancel := context.WithTimeout(ctx, eventReadTimeout)
	defer cancel()
	after := s.pos.seq
	if s.pos.attempt == 0 {
		after = 0
	}
	if s.build {
		return s.catalog.ReadCorpusBuildStream(ctx, s.principal, s.op, s.pos.attempt, after, 64)
	}
	if !s.recheck && !s.authorized.IsZero() && time.Since(s.authorized) < eventRightsInterval {
		return s.catalog.ReadOutputStreamNews(ctx, s.principal, s.op, s.pos.attempt, after, 64)
	}
	checked := time.Now()
	v, err := s.catalog.ReadOutputStreamPage(ctx, s.principal, s.op, s.pos.attempt, after, 64)
	if err == nil {
		s.authorized, s.recheck = checked, false
	}
	return v, err
}
func lostRights(err error) bool {
	return errors.Is(err, controlplane.ErrForbidden) || errors.Is(err, controlplane.ErrNotFound) || errors.Is(err, controlplane.ErrAuthentication)
}
func (s *subscriber) page(ctx context.Context, v controlplane.OutputStreamView, policy <-chan struct{}) (more, finished bool, err error) {
	if v.State != s.state || s.pos.attempt != v.Attempt {
		if err = s.writer.write("state", "", map[string]any{"state": v.State, "attempt": v.Attempt}); err != nil {
			return
		}
		s.state = v.State
	}
	if s.pos.haveID && s.pos.attempt != v.Attempt {
		if err = s.writer.write("reset", fmt.Sprintf("%d:0", v.Attempt), map[string]int{"attempt": v.Attempt}); err != nil {
			return
		}
		s.pos.seq = 0
		s.truncated = false
	}
	s.pos.attempt = v.Attempt
	s.pos.haveID = true
	recheck := time.Now().Add(eventRightsInterval)
	for _, chunk := range v.Chunks {
		var frames []capsuleprotocol.OutputFrame
		if err = json.Unmarshal(chunk.Frames, &frames); err != nil {
			return
		}
		for _, frame := range frames {
			if frame.Seq <= s.pos.seq {
				continue
			}
			select {
			case <-ctx.Done():
				return false, false, ctx.Err()
			case <-policy:
				s.recheck = true
				return true, false, nil
			default:
			}
			if !time.Now().Before(recheck) {
				return true, false, nil
			}
			data := map[string]any{"seq": frame.Seq}
			switch frame.Type {
			case "delta":
				data["text"] = frame.Text
			case "step":
				data["step"], data["state"] = frame.Step, frame.State
				if frame.Label != "" {
					data["label"] = frame.Label
				}
			default:
				return false, false, controlplane.ErrTransitPayload
			}
			if err = s.writer.write(frame.Type, fmt.Sprintf("%d:%d", v.Attempt, frame.Seq), data); err != nil {
				return
			}
			s.pos.seq = frame.Seq
		}
		// A build page may have filtered private frames from this chunk.
		s.pos.seq = max(s.pos.seq, chunk.LastSeq)
	}
	if len(v.Chunks) == 64 && s.pos.seq < v.LastSeq {
		return true, false, nil
	}
	if v.Truncated && !s.truncated {
		if err = s.writer.write("truncated", "", map[string]int{"attempt": v.Attempt}); err != nil {
			return
		}
		s.truncated = true
	}
	switch v.State {
	case "completed", "failed", "expired", "canceled", "REVIEW", "PUBLISHED", "FAILED", "CANCELED", "EXPIRED":
	case "lost":
		if v.ErrorCode == "" {
			return false, false, nil
		}
	default:
		return false, false, nil
	}
	end := map[string]any{"state": v.State, "attempt": v.Attempt}
	if v.ErrorCode != "" {
		end["error_code"] = v.ErrorCode
	}
	if v.State == "completed" {
		end["result_available"] = v.ResultAvailable
		if v.ResultAvailable {
			read, cancel := context.WithTimeout(ctx, eventReadTimeout)
			body, e := s.catalog.StreamResult(read, s.principal, s.op, v.Attempt)
			cancel()
			if errors.Is(e, controlplane.ErrNotFound) && s.missingResultAttempt != v.Attempt {
				// A purge or rerun may commit between the snapshot and this read.
				// Refresh once; a persistent refusal ends the subscription.
				s.missingResultAttempt = v.Attempt
				return true, false, nil
			}
			if e != nil {
				return false, false, e
			}
			if body != nil {
				delete(end, "result_available")
				end["result"] = body
				defer clear(body)
			}
		}
	}
	return false, true, s.writer.write("end", "", end)
}

func (s *Server) invocationEvents(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	auth, cancel := context.WithTimeout(r.Context(), eventReadTimeout)
	p, ok := s.principal(w, r.WithContext(auth))
	cancel()
	if !ok {
		return
	}
	if p.Kind != "tenant" || r.Pattern == operationEventsPath && p.IsApplicationMember() {
		failure(w, controlplane.ErrForbidden)
		return
	}
	pos, err := eventPosition(r.Header.Values("Last-Event-ID"))
	if err != nil {
		failure(w, err)
		return
	}
	sub := subscriber{build: r.Pattern == buildEventsPath, catalog: s.catalog, principal: p, op: r.PathValue("id"), pos: pos, writer: eventWriter{w: w, controller: http.NewResponseController(w)}}
	ctx := r.Context()
	var wake, policy <-chan struct{}
	var pollC <-chan time.Time
	if s.events.hub != nil {
		var stopOp, stopPolicy func()
		channel := streamChannel
		if sub.build {
			channel = "agentcapsule_corpus_build"
		}
		wake, stopOp = s.events.hub.Subscribe(channel, sub.op)
		defer stopOp()
		policy, stopPolicy = s.events.hub.Subscribe(policyChannel, p.TenantID)
		defer stopPolicy()
	} else {
		poll := time.NewTicker(time.Second)
		defer poll.Stop()
		// Embedded APIs without a listener poll on the same schedule.
		pollC = poll.C
	}
	s.followEvents(ctx, w, &sub, wake, policy, pollC)
}

func (s *Server) followEvents(ctx context.Context, w http.ResponseWriter, sub *subscriber, wake, policy <-chan struct{}, poll <-chan time.Time) {
	view, err := sub.read(ctx)
	if err != nil {
		failure(w, err)
		return
	}
	release, refused := s.events.acquire(subscriptionKey{sub.principal.TenantID, sub.principal.ID, sub.op})
	if release == nil {
		s.countLimited(refused)
		switch refused {
		case "invocation_streams":
			problem(w, 429, "too_many_streams")
		case "principal_streams":
			problem(w, 429, "too_many_principal_streams")
		case "organization_streams":
			problem(w, 429, "too_many_organization_streams")
		default:
			problem(w, 503, "stream_capacity")
		}
		return
	}
	defer release()
	if until, ok := ctx.Deadline(); ok {
		_ = sub.writer.controller.SetReadDeadline(until)
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	rights := time.NewTicker(eventRightsInterval)
	defer rights.Stop()
	heartbeat := time.NewTimer(eventHeartbeat)
	defer heartbeat.Stop()
	for ctx.Err() == nil {
		more, finished, e := sub.page(ctx, view, policy)
		if e != nil || finished {
			if lostRights(e) {
				_ = sub.writer.write("revoked", "", struct{}{})
			}
			return
		}
		if !more {
			heartbeat.Reset(time.Until(sub.writer.last.Add(eventHeartbeat)))
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if sub.writer.write("", "", nil) != nil {
					return
				}
			case <-rights.C:
				sub.recheck = true
			case <-wake:
			case <-policy:
				sub.recheck = true
			case <-poll:
			}
		}
		view, err = sub.read(ctx)
		if err != nil {
			if lostRights(err) {
				_ = sub.writer.write("revoked", "", struct{}{})
			}
			return
		}
	}
}
