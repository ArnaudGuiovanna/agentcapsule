// Package guestinit implements the reusable in-VM volume and harness supervisor.
// It must never mount a guest filesystem in the host control-plane process.
package guestinit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

var ErrGuest = errors.New("guest preparation failed")

// HarnessBoot is a public startup record on inherited FD 3. The harness listens
// on inherited FD 4. Neither descriptor carries a TLS credential or volume key.
type HarnessBoot struct {
	Protocol         string                        `json:"protocol"`
	Identity         capsuleprotocol.Identity      `json:"identity"`
	DataDirectory    string                        `json:"data_directory"`
	SupervisorUID    uint32                        `json:"supervisor_uid"`
	PlatformSocket   string                        `json:"platform_socket,omitempty"`
	PreviousShutdown capsuleprotocol.ShutdownState `json:"previous_shutdown"`
}

func ReadHarnessBoot(r io.Reader) (HarnessBoot, error) {
	var b HarnessBoot
	raw, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil || len(raw) > 4096 {
		return b, ErrGuest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return b, ErrGuest
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return b, ErrGuest
	}
	if b.Protocol != capsuleprotocol.Version || b.Identity.Validate() != nil || !b.PreviousShutdown.Valid() || !filepath.IsAbs(b.DataDirectory) || filepath.Clean(b.DataDirectory) != b.DataDirectory {
		return b, ErrGuest
	}
	if b.PlatformSocket != "" && (b.Identity.FenceOnly || !filepath.IsAbs(b.PlatformSocket) || filepath.Clean(b.PlatformSocket) != b.PlatformSocket) {
		return b, ErrGuest
	}
	return b, nil
}
