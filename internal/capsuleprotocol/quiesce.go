package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

var ErrQuiesce = errors.New("guest quiescence not confirmed")

const QuiesceTimeout = 30 * time.Second
const quiesceTransportTimeout = QuiesceTimeout + 5*time.Second

type quiesceResponse struct {
	Protocol string   `json:"protocol"`
	Identity Identity `json:"identity"`
	Quiesced bool     `json:"quiesced"`
	Code     string   `json:"code,omitempty"`
}

// NewQuiescingVolumeServer closes admission and drains admitted control calls
// before invoking quiesce. The callback must observe clean harness termination,
// synchronize and unmount its filesystem, and close its encrypted mapping. It
// must leave the control listener alive to acknowledge completion. An error is
// sticky for the boot; an interrupted response can be replayed without repeating
// shutdown. Neither an ACK nor its absence proves that the VMM has exited.
func NewQuiescingVolumeServer(c Credentials, prepare func(context.Context, VolumeBoot, []byte) (http.Handler, error), quiesce func(context.Context) error) (*VolumeServer, error) {
	if quiesce == nil {
		return nil, ErrProtocol
	}
	s, err := NewVolumeServer(c, prepare)
	if err != nil {
		return nil, err
	}
	s.quiesce = quiesce
	return s, nil
}

func (s *VolumeServer) serveQuiesce(w http.ResponseWriter, r *http.Request) {
	write := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(quiesceResponse{Protocol: Version, Identity: s.credentials.Identity, Quiesced: status == http.StatusOK, Code: code})
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.ContentLength != 0 ||
		r.Header.Get("X-Capsule-Protocol") != Version {
		write(http.StatusBadRequest, "invalid_quiesce")
		return
	}
	s.mu.Lock()
	if s.quiesce == nil {
		s.mu.Unlock()
		write(http.StatusServiceUnavailable, "quiesce_unavailable")
		return
	}
	if s.quiesced == nil {
		s.stopping = true
		s.quiesced = make(chan struct{})
		// Disconnecting the caller cannot reopen admission or interrupt a
		// partially completed shutdown. The operation has its own finite bound.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), QuiesceTimeout)
		go func() { defer cancel(); s.finishQuiesce(ctx) }()
	}
	done := s.quiesced
	s.mu.Unlock()
	select {
	case <-r.Context().Done():
		return
	case <-done:
	}
	s.mu.Lock()
	err := s.quiesceErr
	s.mu.Unlock()
	if err != nil {
		write(http.StatusServiceUnavailable, "quiesce_failed")
		return
	}
	write(http.StatusOK, "")
}

func (s *VolumeServer) finishQuiesce(ctx context.Context) {
	err := s.StopPreparation(ctx)
	if err == nil {
		s.mu.Lock()
		drained, ready := s.drained, s.handler != nil
		s.mu.Unlock()
		if !ready {
			err = ErrQuiesce
		} else if drained != nil {
			select {
			case <-drained:
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
	}
	if err == nil {
		err = s.quiesce(ctx)
	}
	// A callback returning nil after its budget expired is not a clean ACK.
	err = errors.Join(err, ctx.Err())
	s.mu.Lock()
	s.quiesceErr = err
	close(s.quiesced)
	s.mu.Unlock()
}

// Identity returns the immutable authenticated boot binding, not a caller
// assertion. In particular, stop callers must compare its generation before
// persisting STOPPING and retain only that session for the quiesce RPC.
func (c *Client) Identity() Identity { return c.identity }

func (c *Client) Quiesce(ctx context.Context) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/v1/lifecycle/quiesce"), nil)
	if err != nil {
		return err
	}
	r.Header.Set("X-Capsule-Protocol", Version)
	client := *c.http
	client.Timeout = quiesceTransportTimeout
	resp, err := client.Do(r)
	if err != nil {
		return errors.Join(ErrTransport, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) > 4096 {
		return ErrProtocol
	}
	var out quiesceResponse
	if err = decode(bytes.NewReader(b), &out); err != nil {
		return err
	}
	if out.Protocol != Version || out.Identity != c.identity {
		return ErrIdentity
	}
	if resp.StatusCode != http.StatusOK || out.Code != "" || !out.Quiesced {
		return ErrQuiesce
	}
	return nil
}
