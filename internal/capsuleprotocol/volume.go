package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var ErrVolumeBoot = errors.New("volume bootstrap rejected or unavailable")

// VolumeBoot is trusted host input, not a user-controlled destination. Its UUID
// identifies the LUKS container attached to this boot. Initialize permits first
// filesystem creation only; the guest must never luksFormat a published image.
// Restore marks the restricted boot of an image restored from an archive into
// a new incarnation: the guest moves the image's marker from its older
// incarnation of the same volume to this one, never back. Only a restricted
// boot may carry it, and never with Initialize.
type VolumeBoot struct {
	Incarnation      uint64        `json:"incarnation"`
	VolumeID         string        `json:"volume_id"`
	UUID             string        `json:"uuid"`
	Initialize       bool          `json:"initialize"`
	PreviousShutdown ShutdownState `json:"previous_shutdown"`
	Restore          bool          `json:"restore,omitempty"`
}

func (v VolumeBoot) Validate() error {
	if !v.valid() {
		return ErrProtocol
	}
	return nil
}

func (v VolumeBoot) valid() bool {
	if v.Incarnation == 0 || v.Incarnation > 1<<63-1 || !v.PreviousShutdown.Valid() || len(v.VolumeID) != 36 || !strings.HasPrefix(v.VolumeID, "vol_") ||
		(v.Restore && v.Initialize) {
		return false
	}
	h := v.VolumeID[4:]
	if _, err := hex.DecodeString(h); err != nil || strings.ToLower(h) != h {
		return false
	}
	return v.UUID == h[:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:]
}

type volumeResponse struct {
	Protocol string     `json:"protocol"`
	Identity Identity   `json:"identity"`
	Volume   VolumeBoot `json:"volume"`
	Code     string     `json:"code,omitempty"`
}

// net/http may finish closing a request body after Do returns. Own a separate
// buffer and serialize Read/Close so the authority can clear its borrowed slice
// as soon as OpenVolume returns, including cancellation and early responses.
type keyBody struct {
	mu     sync.Mutex
	key    [32]byte
	offset int
	closed bool
}

func (b *keyBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if b.offset == len(b.key) {
		return 0, io.EOF
	}
	n := copy(p, b.key[b.offset:])
	b.offset += n
	return n, nil
}
func (b *keyBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.key[:])
	b.closed = true
	return nil
}

// VolumeServer is capsule-init's boot gate. prepare opens/checks the real volume
// and starts the harness, then returns its local control proxy. It must not
// retain the key slice or return before its use has completed. An error is sticky
// for this boot: partial mount/process state must be retired before trying again.
// The harness itself owns each local SQL effect+dedup transaction.
type VolumeServer struct {
	credentials          Credentials
	prepare              func(context.Context, VolumeBoot, []byte) (http.Handler, error)
	mu                   sync.Mutex
	attempted, preparing bool
	stopping             bool
	prepared             chan struct{}
	volume               VolumeBoot
	keyHash              [32]byte
	handler              http.Handler
	quiesce              func(context.Context) error
	quiesced             chan struct{}
	quiesceErr           error
	inFlight             int
	drained              chan struct{}
}

// StopPreparation closes admission and waits for the physical preparation
// callback to finish before capsule-init unmounts storage during shutdown.
func (s *VolumeServer) StopPreparation(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	done := s.prepared
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func NewVolumeServer(c Credentials, prepare func(context.Context, VolumeBoot, []byte) (http.Handler, error)) (*VolumeServer, error) {
	if prepare == nil {
		return nil, ErrProtocol
	}
	if _, err := c.TLS(true); err != nil {
		return nil, err
	}
	return &VolumeServer{credentials: c, prepare: prepare}, nil
}

func (s *VolumeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(status int, volume VolumeBoot, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(volumeResponse{Protocol: Version, Identity: s.credentials.Identity, Volume: volume, Code: code})
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		write(http.StatusUnauthorized, VolumeBoot{}, "unauthenticated")
		return
	}
	if r.URL.Path == "/v1/lifecycle/quiesce" {
		s.serveQuiesce(w, r)
		return
	}
	if r.URL.Path != "/v1/volume" {
		s.mu.Lock()
		handler := s.handler
		if s.stopping {
			handler = nil
		}
		if handler != nil {
			if s.inFlight == 0 {
				s.drained = make(chan struct{})
			}
			s.inFlight++
		}
		s.mu.Unlock()
		if handler == nil {
			// Use the ordinary response shape so Health cannot confuse a
			// reachable bootstrap listener with an initialized harness.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(response{Protocol: Version, Identity: s.credentials.Identity, Code: "volume_unavailable"})
			return
		}
		defer func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.inFlight--
			if s.inFlight == 0 {
				close(s.drained)
			}
		}()
		handler.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/octet-stream" ||
		r.Header.Get("X-Capsule-Protocol") != Version || r.ContentLength != 32 {
		write(http.StatusBadRequest, VolumeBoot{}, "invalid_volume")
		return
	}
	flag := r.Header.Get("X-Capsule-Initialize")
	// A host that predates restores sends no restore header: an ordinary boot.
	restore := r.Header.Get("X-Capsule-Restore")
	v := VolumeBoot{VolumeID: r.Header.Get("X-Capsule-Volume"), UUID: r.Header.Get("X-Capsule-UUID"), Initialize: flag == "true", PreviousShutdown: ShutdownState(r.Header.Get("X-Capsule-Previous-Shutdown")),
		Restore: restore == "true"}
	var incarnationErr error
	v.Incarnation, incarnationErr = strconv.ParseUint(r.Header.Get("X-Capsule-Incarnation"), 10, 63)
	if incarnationErr != nil || !v.valid() || (flag != "true" && flag != "false") || (restore != "" && restore != "true" && restore != "false") {
		write(http.StatusBadRequest, VolumeBoot{}, "invalid_volume")
		return
	}
	if v.Incarnation != s.credentials.Identity.Incarnation {
		write(http.StatusForbidden, v, "stale_incarnation")
		return
	}
	if (v.Initialize || v.Restore) && !s.credentials.Identity.FenceOnly {
		write(http.StatusForbidden, v, "fence_only")
		return
	}
	key := make([]byte, 32)
	defer clear(key)
	body := http.MaxBytesReader(w, r.Body, 32)
	if _, err := io.ReadFull(body, key); err != nil {
		write(http.StatusBadRequest, v, "invalid_volume")
		return
	}
	var tail [1]byte
	if n, err := body.Read(tail[:]); n != 0 || err != io.EOF {
		write(http.StatusBadRequest, v, "invalid_volume")
		return
	}
	hash := sha256.Sum256(key)
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		write(http.StatusServiceUnavailable, v, "volume_unavailable")
		return
	}
	if s.attempted {
		code, status := "volume_unavailable", http.StatusServiceUnavailable
		if s.volume != v || s.keyHash != hash {
			code, status = "volume_conflict", http.StatusConflict
		} else if s.handler != nil {
			code, status = "", http.StatusOK
		} else if s.preparing {
			code = "volume_busy"
		}
		s.mu.Unlock()
		write(status, v, code)
		return
	}
	s.attempted, s.preparing, s.volume, s.keyHash = true, true, v, hash
	s.prepared = make(chan struct{})
	s.mu.Unlock()
	handler, err := s.prepare(r.Context(), v, key)
	clear(key)
	s.mu.Lock()
	s.preparing = false
	if err == nil && handler != nil {
		s.handler = handler
	}
	ready := s.handler != nil && !s.stopping
	close(s.prepared)
	s.mu.Unlock()
	if !ready {
		write(http.StatusServiceUnavailable, v, "volume_unavailable")
		return
	}
	write(http.StatusOK, v, "")
}

// OpenVolume sends the unlock secret only after the per-boot mTLS handshake.
// No key is included in the URL/headers, credentials/initrd, or response. A
// missing response is unknown: an identical retry on this boot is idempotent.
func (c *Client) OpenVolume(ctx context.Context, v VolumeBoot, key []byte) error {
	if !v.valid() || len(key) != 32 || v.Incarnation != c.identity.Incarnation {
		return ErrProtocol
	}
	if (v.Initialize || v.Restore) && !c.identity.FenceOnly {
		return ErrFenceOnly
	}
	body := &keyBody{}
	copy(body.key[:], key)
	defer body.Close()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/v1/volume"), body)
	if err != nil {
		return err
	}
	r.ContentLength = 32
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Capsule-Protocol", Version)
	r.Header.Set("X-Capsule-Volume", v.VolumeID)
	r.Header.Set("X-Capsule-Incarnation", strconv.FormatUint(v.Incarnation, 10))
	r.Header.Set("X-Capsule-UUID", v.UUID)
	r.Header.Set("X-Capsule-Initialize", strconv.FormatBool(v.Initialize))
	r.Header.Set("X-Capsule-Restore", strconv.FormatBool(v.Restore))
	r.Header.Set("X-Capsule-Previous-Shutdown", string(v.PreviousShutdown))
	resp, err := c.http.Do(r)
	if err != nil {
		return errors.Join(ErrTransport, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) > 4096 {
		return ErrProtocol
	}
	var out volumeResponse
	if err = decode(bytes.NewReader(b), &out); err != nil {
		return err
	}
	if out.Protocol != Version || out.Identity != c.identity {
		return ErrIdentity
	}
	if resp.StatusCode != http.StatusOK || out.Code != "" {
		return ErrVolumeBoot
	}
	if out.Volume != v {
		return ErrIdentity
	}
	return nil
}
