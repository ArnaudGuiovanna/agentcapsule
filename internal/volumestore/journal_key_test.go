//go:build linux && cgo

package volumestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// journalFields reads a volume's journal as the data domain holds it.
func journalFields(t *testing.T, s *Store, spec Spec) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.root, "volume-state", spec.VolumeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return fields, raw
}

// revealsNothing fails if the journal holds the key, its SHA-256, or any
// identifier of it.
func revealsNothing(t *testing.T, raw []byte, key []byte) {
	t.Helper()
	sum := sha256.Sum256(key)
	for _, secret := range []string{hex.EncodeToString(key), hex.EncodeToString(sum[:])} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("the journal holds the key or its SHA-256: %s", raw)
		}
	}
}

// L-18: the journal of a volume lies in the data domain, which archives and
// backups copy, and outlives the key's destruction. It identifies the key
// by a MAC under a random salt of its own, never by the key's SHA-256: two
// volumes of one key have different identifiers. It still refuses another
// key. Once the volume is removed (its key revoked before), the journal
// holds no identifier of the key at all.
func TestTheJournalIdentifiesTheKeyWithoutItsHash(t *testing.T) {
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	fields, raw := journalFields(t, s, spec)
	revealsNothing(t, raw, key)
	if _, ok := fields["key_hash"]; ok || fields["version"] != 2.0 || len(fields["key_salt"].(string)) != 64 || len(fields["key_mac"].(string)) != 64 {
		t.Fatalf("journal %s", raw)
	}
	other := Spec{AgentID: "agt_" + strings.Repeat("c", 32), VolumeID: "vol_" + strings.Repeat("d", 32), SizeMiB: spec.SizeMiB}
	if _, err = s.Prepare(t.Context(), other, key); err != nil {
		t.Fatal(err)
	}
	if second, _ := journalFields(t, s, other); second["key_mac"] == fields["key_mac"] || second["key_salt"] == fields["key_salt"] {
		t.Fatal("two volumes of one key have one identifier")
	}
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if _, err = s.Prepare(t.Context(), spec, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("another key:", err)
	}
	if again, err := s.Prepare(t.Context(), spec, key); err != nil || again != c {
		t.Fatal("the key:", again, err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); err != nil {
		t.Fatal(err)
	}
	fields, raw = journalFields(t, s, spec)
	for _, k := range []string{"key_hash", "key_salt", "key_mac"} {
		if _, ok := fields[k]; ok {
			t.Fatalf("a removed volume's journal keeps %s: %s", k, raw)
		}
	}
	if fields["stage"] != "REMOVED" {
		t.Fatalf("journal %s", raw)
	}
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrRemoved) {
		t.Fatal("a removed volume:", err)
	}
}

// writeVersionOne rewrites the journal of spec as a worker before the audit
// wrote it: version 1, with the key's SHA-256.
func writeVersionOne(t *testing.T, s *Store, spec Spec, key []byte) {
	t.Helper()
	fields, _ := journalFields(t, s, spec)
	sum := sha256.Sum256(key)
	legacy := map[string]any{"version": 1, "spec": fields["spec"], "key_hash": hex.EncodeToString(sum[:]), "stage": fields["stage"],
		"Device": fields["Device"], "Inode": fields["Inode"]}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.root, "volume-state", spec.VolumeID+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// L-18: a journal of version 1 (the key's SHA-256) still binds its key:
// another key is refused and changes nothing; the key adopts the volume and
// replaces the hash with the salted identifier. A version 1 journal's
// removal forgets the hash.
func TestAVersionOneJournalIsUpgradedByItsKey(t *testing.T) {
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	writeVersionOne(t, s, spec, key)
	_, before := journalFields(t, s, spec)
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if _, err = s.Prepare(t.Context(), spec, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("another key against a version 1 journal:", err)
	}
	if _, after := journalFields(t, s, spec); !bytes.Equal(before, after) {
		t.Fatal("another key changed the journal")
	}
	if again, err := s.Prepare(t.Context(), spec, key); err != nil || again != c {
		t.Fatal("the key against a version 1 journal:", again, err)
	}
	fields, raw := journalFields(t, s, spec)
	revealsNothing(t, raw, key)
	if _, ok := fields["key_hash"]; ok || fields["version"] != 2.0 || fields["key_mac"] == nil {
		t.Fatalf("not upgraded: %s", raw)
	}
	if _, err = s.Prepare(t.Context(), spec, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("another key against the upgraded journal:", err)
	}

	writeVersionOne(t, s, spec, key)
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); err != nil {
		t.Fatal(err)
	}
	fields, raw = journalFields(t, s, spec)
	if _, ok := fields["key_hash"]; ok {
		t.Fatalf("a removed version 1 journal keeps the hash: %s", raw)
	}
}
