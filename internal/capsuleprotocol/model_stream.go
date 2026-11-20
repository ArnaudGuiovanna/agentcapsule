package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"regexp"
	"time"
)

const (
	ForwardLLMStreamPath  = "/v1/llm/forward/stream"
	CompleteLLMStreamPath = "/v1/llm/complete/stream"
)

func isModelStream(path string) bool {
	return path == ForwardLLMStreamPath || path == CompleteLLMStreamPath
}

type LLMStreamEvent struct {
	Name string          `json:"name,omitempty"`
	Data json.RawMessage `json:"data"`
}

// LLMStreamFrame is a start, event, text or end frame of the model channel.
// Only a completed end carries usage. Zero tokens and a false budget warning
// are both meaningful and travel explicitly.
type LLMStreamFrame struct {
	Type         string          `json:"type"`
	Protocol     string          `json:"protocol,omitempty"`
	Identity     *Identity       `json:"identity,omitempty"`
	Seq          int64           `json:"seq,omitempty"`
	Event        *LLMStreamEvent `json:"event,omitempty"`
	Text         string          `json:"text,omitempty"`
	Outcome      string          `json:"outcome,omitempty"`
	InputTokens  *int64          `json:"input_tokens,omitempty"`
	OutputTokens *int64          `json:"output_tokens,omitempty"`
	SoftExceeded *bool           `json:"soft_budget_exceeded,omitempty"`
	FinishReason string          `json:"finish_reason,omitempty"`
}

// Implementations send data frames and one end. A refusal before the first
// frame is an ordinary platform error. The guest also relays the host's start.
type LLMStreamAPI interface {
	ForwardLLMStream(context.Context, string, LLMForward, func(LLMStreamFrame) error) error
	CompleteLLMStream(context.Context, string, LLMRequest, func(LLMStreamFrame) error) error
}

var llmEventName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// Decode each variant separately: fields from another variant are invalid,
// even when they would have the zero value of their Go type.
func readModelFrame(line []byte, id Identity, path string, seq int64) (LLMStreamFrame, error) {
	fail := LLMStreamFrame{}
	t, err := frameType(line)
	if err != nil {
		return fail, err
	}
	f := LLMStreamFrame{Type: t, Seq: seq}
	if seq == 0 {
		var start struct {
			Type     string   `json:"type"`
			Protocol string   `json:"protocol"`
			Identity Identity `json:"identity"`
		}
		if t != "start" || decode(bytes.NewReader(line), &start) != nil {
			return fail, ErrProtocol
		}
		if start.Protocol != Version || start.Identity != id {
			return fail, ErrIdentity
		}
		f.Protocol, f.Identity = Version, &id
		return f, nil
	}
	switch t {
	case "text":
		var text deltaFrame
		if path != CompleteLLMStreamPath || decode(bytes.NewReader(line), &text) != nil || text.Seq != seq || text.Text == "" {
			return fail, ErrProtocol
		}
		f.Text = text.Text
	case "event":
		var event struct {
			Type  string          `json:"type"`
			Seq   int64           `json:"seq"`
			Event *LLMStreamEvent `json:"event"`
		}
		if path != ForwardLLMStreamPath || decode(bytes.NewReader(line), &event) != nil || event.Seq != seq || event.Event == nil {
			return fail, ErrProtocol
		}
		e := event.Event
		if len(e.Data) == 0 || e.Data[0] != '{' || e.Name != "" && !llmEventName.MatchString(e.Name) {
			return fail, ErrProtocol
		}
		f.Event = e
	case "end":
		var end struct {
			Type    string  `json:"type"`
			Seq     int64   `json:"seq"`
			Outcome string  `json:"outcome"`
			Input   *int64  `json:"input_tokens"`
			Output  *int64  `json:"output_tokens"`
			Soft    *bool   `json:"soft_budget_exceeded"`
			Finish  *string `json:"finish_reason"`
		}
		if decode(bytes.NewReader(line), &end) != nil || end.Seq != seq {
			return fail, ErrProtocol
		}
		switch end.Outcome {
		case "completed":
			if end.Input == nil || end.Output == nil || *end.Input < 0 || *end.Output < 0 || end.Soft == nil || path == ForwardLLMStreamPath && end.Finish != nil {
				return fail, ErrProtocol
			}
			f.InputTokens, f.OutputTokens, f.SoftExceeded = end.Input, end.Output, end.Soft
			if end.Finish != nil {
				f.FinishReason = *end.Finish
			}
		case "outcome_unknown":
			// No usage, budget flag or finish reason is known after a cut.
			var unknown struct {
				Type    string `json:"type"`
				Seq     int64  `json:"seq"`
				Outcome string `json:"outcome"`
			}
			if decode(bytes.NewReader(line), &unknown) != nil {
				return fail, ErrProtocol
			}
		default:
			return fail, ErrProtocol
		}
		f.Outcome = end.Outcome
	default:
		return fail, ErrProtocol
	}
	return f, nil
}

func (p *platformHandler) serveModelStream(ctx context.Context, w http.ResponseWriter, path string, in platformRequest) error {
	if in.Attachment != nil || in.Completion != nil || in.OwnerMessage != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key == "" || len(in.Key) > 200 {
		return &PlatformError{Code: "invalid"}
	}
	api, ok := p.api.(LLMStreamAPI)
	if !ok {
		return &PlatformError{Code: "unavailable"}
	}
	rc := http.NewResponseController(w)
	limit, _ := ctx.Deadline()
	out := &frameWriter{w: w, flush: rc.Flush, timeout: StreamIdleTimeout, deadline: func(t time.Time) error {
		if cap := limit.Add(5 * time.Second); t.After(cap) {
			t = cap
		}
		return rc.SetWriteDeadline(t)
	}}
	var seq int64
	ended := false
	emit := func(f LLMStreamFrame) error {
		if ended {
			return ErrProtocol
		}
		if seq == 0 {
			w.Header().Set("Content-Type", ndjsonType)
			w.Header().Set("Cache-Control", "no-store")
			seq = 1
			if err := out.write(LLMStreamFrame{Type: "start", Protocol: Version, Identity: &p.id}); err != nil {
				return err
			}
			if f.Type == "start" {
				return nil
			} // the guest is relaying its host's start
		}
		f.Seq = seq
		line, err := encodeFrame(f)
		if err != nil {
			return err
		}
		if _, err = readModelFrame(line[:len(line)-1], p.id, path, seq); err != nil {
			return err
		}
		if err = out.writeLine(line); err != nil {
			return err
		}
		seq++
		ended = f.Type == "end"
		return nil
	}
	var err error
	if path == ForwardLLMStreamPath {
		var flags struct {
			Stream bool `json:"stream"`
		}
		if in.Forward == nil || in.LLM != nil || in.Forward.Validate() != nil || json.Unmarshal(in.Forward.Body, &flags) != nil || !flags.Stream {
			return &PlatformError{Code: "invalid"}
		}
		err = api.ForwardLLMStream(ctx, in.Key, *in.Forward, emit)
	} else {
		if in.LLM == nil || in.Forward != nil || in.LLM.Validate() != nil {
			return &PlatformError{Code: "invalid"}
		}
		err = api.CompleteLLMStream(ctx, in.Key, *in.LLM, emit)
	}
	if seq == 0 {
		if err != nil {
			return err
		}
		return &PlatformError{Code: "outcome_unknown"}
	}
	if !ended {
		_ = emit(LLMStreamFrame{Type: "end", Outcome: "outcome_unknown"})
	}
	return nil
}

// ForwardLLMStream yields native provider events and the call's final usage.
func (p *PlatformClient) ForwardLLMStream(ctx context.Context, key string, in LLMForward) iter.Seq2[LLMStreamFrame, error] {
	return p.modelStream(ctx, ForwardLLMStreamPath, platformRequest{Key: key, Forward: &in})
}

// CompleteLLMStream yields text fragments and the call's final usage.
func (p *PlatformClient) CompleteLLMStream(ctx context.Context, key string, in LLMRequest) iter.Seq2[LLMStreamFrame, error] {
	return p.modelStream(ctx, CompleteLLMStreamPath, platformRequest{Key: key, LLM: &in})
}

func (p *PlatformClient) modelStream(parent context.Context, path string, in platformRequest) iter.Seq2[LLMStreamFrame, error] {
	in.Protocol, in.Identity = Version, p.client.identity
	return func(yield func(LLMStreamFrame, error) bool) {
		data, err := json.Marshal(in)
		if err != nil || len(data) > MaxMessageBytes {
			yield(LLMStreamFrame{}, ErrProtocol)
			return
		}
		ctx, cancel := context.WithTimeout(parent, llmClientTimeout)
		defer cancel()
		res, err := p.openStream(ctx, path, bytes.NewReader(data))
		if err != nil {
			yield(LLMStreamFrame{}, err)
			return
		}
		defer res.Body.Close()
		reader := newFrameReader(res.Body, nil)
		for seq := int64(0); ; seq++ {
			// Limit a pending read separately from user processing. Closing the
			// request context interrupts a blocked socket read at the bound.
			timer := time.AfterFunc(StreamIdleTimeout+5*time.Second, cancel)
			line, e := reader.next(0)
			timer.Stop()
			var f LLMStreamFrame
			if e == nil {
				f, e = readModelFrame(line, p.client.identity, path, seq)
			}
			if e != nil {
				yield(LLMStreamFrame{}, errors.Join(&PlatformError{Code: "outcome_unknown"}, e))
				return
			}
			if !yield(f, nil) || f.Type == "end" {
				return
			}
		}
	}
}

func relayModelStream(frames iter.Seq2[LLMStreamFrame, error], send func(LLMStreamFrame) error) error {
	for f, e := range frames {
		if e != nil {
			return e
		}
		if e = send(f); e != nil {
			return e
		}
	}
	return nil
}
