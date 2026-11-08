//go:build linux && cgo

package restoreauthority

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Archive authenticates encrypted bytes captured by the trusted coordinator.
// It is not a retirement receipt or proof that all required effects are present.
// Neither a key nor unencrypted guest data belongs in this manifest.
type Archive struct {
	Version       int      `json:"version"`
	Authority     string   `json:"authority"`
	ID            string   `json:"id"`
	Binding       Binding  `json:"binding"`
	HarnessDigest string   `json:"harness_digest"`
	Size          int64    `json:"size"`
	Digest        [32]byte `json:"digest"`
	MAC           []byte   `json:"mac"`
}

func validArchive(a Archive) bool {
	if !validID(a.ID, "arc_") || a.Binding.Incarnation == 0 || a.Binding.Incarnation > 1<<63-1 ||
		!validName(a.Binding.Store) || !validName(a.Binding.Volume) || a.Size <= 0 || a.Size > 32<<30 ||
		len(a.HarnessDigest) != 71 || !strings.HasPrefix(a.HarnessDigest, "sha256:") || strings.ToLower(a.HarnessDigest) != a.HarnessDigest {
		return false
	}
	_, err := hex.DecodeString(a.HarnessDigest[7:])
	return err == nil
}

func signArchive(a Archive, secret []byte) []byte {
	a.MAC = nil
	data, _ := json.Marshal(a)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("agentcapsule-encrypted-archive-v1\x00"))
	m.Write(data)
	return m.Sum(nil)
}

// SignArchive follows a coherent, physically excluded copy. Only the trusted
// coordinator can establish that precondition. Reservation or seal during the
// copy prevents signing; the result never certifies restored activation.
func (c *Catalog) SignArchive(ctx context.Context, a Archive) (Archive, error) {
	if !validArchive(a) {
		return Archive{}, ErrInput
	}
	a.Version, a.Authority, a.MAC = 1, c.identity, nil
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, a.Binding); err != nil {
			return err
		}
		var secret []byte
		if err := tx.QueryRowContext(ctx, "SELECT secret FROM authority WHERE singleton=1").Scan(&secret); err != nil {
			return err
		}
		defer clear(secret)
		a.MAC = signArchive(a, secret)
		return nil
	})
	if err != nil {
		return Archive{}, err
	}
	return a, nil
}

// ValidateArchive permits authentic historical incarnations for inspection.
// Installing/reconciling/activating them requires the separate restore protocol.
func (c *Catalog) ValidateArchive(ctx context.Context, a Archive) error {
	if !validArchive(a) || a.Version != 1 || a.Authority != c.identity {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		var secret []byte
		if err := tx.QueryRowContext(ctx, "SELECT secret FROM authority WHERE singleton=1").Scan(&secret); err != nil {
			return err
		}
		defer clear(secret)
		if !hmac.Equal(a.MAC, signArchive(a, secret)) {
			return ErrStale
		}
		b, sealed, err := binding(ctx, tx, a.Binding.Store)
		if err != nil || b.Volume != a.Binding.Volume || b.Incarnation < a.Binding.Incarnation {
			return ErrStale
		}
		if sealed {
			return ErrSealed
		}
		return nil
	})
}
