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
	operationEventsPath    = "/v1/operations/{id}/events"
	streamChannel          = "agentcapsule_invocation_stream"
	policyChannel          = "agentcapsule_organization_policy"
	DefaultMaxEventStreams = 1000
	eventLifetime          = 15 * time.Minute
	eventReadTimeout       = 5 * time.Second
	eventRightsInterval    = 10 * time.Second
	eventHeartbeat         = 15 * time.Second
)

func isEventRoute(route string) bool {
	return route == invocationEventsPath || route == operationEventsPath
}

type subscriptionKey struct{ tenant, principal, invocation string }
type eventStreams struct {
	mu            sync.Mutex
	limit, active int
	counts        map[subscriptionKey]int
	hub           pgnotify.Hub
	gauge         *telemetry.Gauge
}

// StartEventStreams starts the API's one shared LISTEN connection. Call it
// before serving. Embedded servers may use the one-second polling fallback.
func (s *Server) StartEventStreams(ctx context.Context, limit int) error {
	if limit < 1 || limit > 100000 {
		return controlplane.ErrInput
	}
	hub, err := pgnotify.New(s.store.Connect, streamChannel, policyChannel)
	if err != nil {
		return err
	}
	s.events.hub, s.events.limit = hub, limit
	go hub.Run(ctx)
	return nil
}

func (e *eventStreams) acquire(key subscriptionKey) (release func(), perPrincipal bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.counts[key] >= 4 {
		return nil, true
	}
	if e.active >= e.limit {
		return nil, false
	}
	e.counts[key]++
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
		e.active--
		if e.gauge != nil {
			e.gauge.Set(float64(e.active))
		}
	}, false
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

type subscriber struct {
	catalog              *controlplane.AgentCatalog
	principal            controlplane.Principal
	op                   string
	writer               eventWriter
	pos                  streamPosition
	state                string
	truncated            bool
	missingResultAttempt int
}

func (s *subscriber) read(ctx context.Context) (controlplane.OutputStreamView, error) {
	ctx, cancel := context.WithTimeout(ctx, eventReadTimeout)
	defer cancel()
	after := s.pos.seq
	if s.pos.attempt == 0 {
		after = 0
	}
	return s.catalog.ReadOutputStreamPage(ctx, s.principal, s.op, s.pos.attempt, after, 64)
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
	case "completed", "failed", "expired", "canceled":
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
	sub := subscriber{catalog: s.catalog, principal: p, op: r.PathValue("id"), pos: pos, writer: eventWriter{w: w, controller: http.NewResponseController(w)}}
	ctx := r.Context()
	var wake, policy <-chan struct{}
	var pollC <-chan time.Time
	if s.events.hub != nil {
		var stopOp, stopPolicy func()
		wake, stopOp = s.events.hub.Subscribe(streamChannel, sub.op)
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
	release, personal := s.events.acquire(subscriptionKey{sub.principal.TenantID, sub.principal.ID, sub.op})
	if release == nil {
		if personal {
			problem(w, 429, "too_many_streams")
		} else {
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
			case <-wake:
			case <-policy:
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
