//go:build linux && cgo

package volumestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// The LUKS2 header the platform writes (ac_luks_begin in luks_linux.go):
// one key slot, of the volume key (64 bytes, aes-xts-plain64) behind
// Argon2id over at most 64 MiB with one thread, for 100 ms where it is
// formatted (libcryptsetup measures the passes, at least 4); one segment;
// one PBKDF2-SHA256 digest, which libcryptsetup measures too; no token and
// no requirement. A guest holds its volume open, and may rewrite its header:
// a restore test reads the copy of an archive, so its header comes from the
// guest. The confined check refuses a header of any other shape, so that
// the key derivation costs at most what the platform's own costs.
const (
	// maxArgon2Memory is the platform's max_memory_kb, in KiB.
	maxArgon2Memory = 65536
	// maxArgon2Passes is four times the minimum, which libcryptsetup keeps
	// when 4 passes over 64 MiB take 100 ms or more: 16 passes in 100 ms
	// would need 10 GB/s, past any processor.
	maxArgon2Passes = 16
	// maxDigestIterations bounds the PBKDF2 of the digest: libcryptsetup
	// aims at 125 ms there; 2 million is four times what the fastest SHA-256
	// reaches in that time (60 000 on the development machine).
	maxDigestIterations = 2_000_000
)

// errShape: the header is not of the platform's shape.
var errShape = errors.New("the LUKS2 header is not one the platform creates")

// luksMetadata is the part of the LUKS2 metadata (crypt_dump_json) that the
// check reads; the rest is ignored.
type luksMetadata struct {
	Keyslots map[string]struct {
		Type    string `json:"type"`
		KeySize int    `json:"key_size"`
		AF      struct {
			Type    string `json:"type"`
			Stripes int    `json:"stripes"`
			Hash    string `json:"hash"`
		} `json:"af"`
		Area struct {
			Type       string `json:"type"`
			Encryption string `json:"encryption"`
			KeySize    int    `json:"key_size"`
		} `json:"area"`
		KDF struct {
			Type   string `json:"type"`
			Time   uint64 `json:"time"`
			Memory uint64 `json:"memory"`
			CPUs   uint64 `json:"cpus"`
		} `json:"kdf"`
	} `json:"keyslots"`
	Tokens   map[string]json.RawMessage `json:"tokens"`
	Segments map[string]struct {
		Type       string `json:"type"`
		Encryption string `json:"encryption"`
		SectorSize int    `json:"sector_size"`
	} `json:"segments"`
	Digests map[string]struct {
		Type       string   `json:"type"`
		Hash       string   `json:"hash"`
		Iterations uint64   `json:"iterations"`
		Keyslots   []string `json:"keyslots"`
		Segments   []string `json:"segments"`
	} `json:"digests"`
	Config struct {
		Requirements json.RawMessage `json:"requirements"`
	} `json:"config"`
}

// platformHeader fails unless metadata, the JSON of a LUKS2 header as
// libcryptsetup loaded it, has the platform's shape, within its key
// derivation bounds.
func platformHeader(metadata []byte) error {
	var m luksMetadata
	if err := json.Unmarshal(metadata, &m); err != nil {
		return fmt.Errorf("%w: %v", errShape, err)
	}
	if len(m.Keyslots) != 1 || len(m.Segments) != 1 || len(m.Digests) != 1 || len(m.Tokens) != 0 {
		return fmt.Errorf("%w: %d key slots, %d segments, %d digests, %d tokens", errShape, len(m.Keyslots), len(m.Segments), len(m.Digests), len(m.Tokens))
	}
	if r := m.Config.Requirements; len(r) != 0 && string(r) != "null" && string(r) != "{}" {
		return fmt.Errorf("%w: requirements", errShape)
	}
	var slot, segment string
	for id, k := range m.Keyslots {
		slot = id
		switch {
		case k.Type != "luks2" || k.KeySize != 64:
			return fmt.Errorf("%w: key slot type or key size", errShape)
		case k.AF.Type != "luks1" || k.AF.Stripes != 4000 || k.AF.Hash != "sha256":
			return fmt.Errorf("%w: anti-forensic splitter", errShape)
		case k.Area.Type != "raw" || k.Area.Encryption != "aes-xts-plain64" || k.Area.KeySize != 64:
			return fmt.Errorf("%w: key slot area", errShape)
		case k.KDF.Type != "argon2id" || k.KDF.Time < 1 || k.KDF.Time > maxArgon2Passes || k.KDF.Memory < 1 ||
			k.KDF.Memory > maxArgon2Memory || k.KDF.CPUs != 1:
			return fmt.Errorf("%w: key derivation (Argon2id at most %d passes over %d KiB, one thread)", errShape, maxArgon2Passes, maxArgon2Memory)
		}
	}
	for id, s := range m.Segments {
		segment = id
		if s.Type != "crypt" || s.Encryption != "aes-xts-plain64" || s.SectorSize != 512 {
			return fmt.Errorf("%w: segment", errShape)
		}
	}
	for _, d := range m.Digests {
		if d.Type != "pbkdf2" || d.Hash != "sha256" || d.Iterations < 1 || d.Iterations > maxDigestIterations ||
			!slices.Equal(d.Keyslots, []string{slot}) || !slices.Equal(d.Segments, []string{segment}) {
			return fmt.Errorf("%w: digest (PBKDF2-SHA256, at most %d iterations)", errShape, maxDigestIterations)
		}
	}
	return nil
}
