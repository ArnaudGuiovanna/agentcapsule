//go:build linux && cgo

package restoreauthority

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// These tests project the key runs of spec/restore_authority_test.qnt that
// need the catalogue as well as the key authority. Each one names its Quint
// run. They are written by hand from the runs (ADR 005, "Model revision").
// The model's store 0 is the offboarded agent "agt_b…" with its volume key;
// store 1 is "agt_a…", whose old image is restored.

var (
	keyRunAgent  = "agt_" + strings.Repeat("a", 32)
	keyRunVolume = "vol_" + strings.Repeat("a", 32)
	offboarded   = "agt_" + strings.Repeat("b", 32)
	offboardedV  = "vol_" + strings.Repeat("b", 32)
)

// authorities is the pair the worker opens: the key authority and the
// catalogue bound to its identity.
func authorities(t *testing.T) (*keyauthority.Files, *Catalog) {
	t.Helper()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return keys, c
}

// wrappedBackup is a symbolic volume archive: its header holds the master key
// sealed under the volume key, as LUKS does. openBackup is the model's
// decryptBackup.
func wrappedBackup(t *testing.T, keys *keyauthority.Files, agent, volume string) []byte {
	t.Helper()
	var header []byte
	if err := keys.WithKey(t.Context(), agent, volume, func(key []byte) error {
		aead, err := keyAEAD(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		master := make([]byte, 32)
		if _, err = rand.Read(nonce); err == nil {
			_, err = rand.Read(master)
		}
		header = aead.Seal(nonce, nonce, master, []byte(volume))
		clear(master)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return header
}

func openBackup(t *testing.T, keys *keyauthority.Files, agent, volume string, header []byte) error {
	return keys.WithKey(t.Context(), agent, volume, func(key []byte) error {
		aead, err := keyAEAD(key)
		if err != nil {
			return err
		}
		n := aead.NonceSize()
		master, err := aead.Open(nil, header[:n], header[n:], []byte(volume))
		clear(master)
		return err
	})
}

func keyAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// destructionRequiresPermanentSealTest, in part. In the model a revoked but
// unsealed store's key cannot be destroyed. The catalogue supplies that
// evidence: after the revocation the store is acknowledged but not sealed, and
// Lookup still returns it; only RecordRetiredSeal makes it sealed for good.
// The refusal itself is not in these packages: keyauthority.Revoke takes no
// seal, and the worker orders RecordRetiredSeal before Revoke
// (RemoveDeletedStore). The authority service of ADR 005 §5 item 3 owns both
// directories and must check the seal in the destruction's own write.
func TestDestructionRequiresPermanentSeal(t *testing.T) {
	keys, c := authorities(t)
	b, err := c.Register(t.Context(), offboarded, offboardedV)
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	if _, err = c.BeginRevocation(t.Context(), offboarded); err != nil {
		t.Fatal(err)
	}
	receipt(t, c, b)
	acknowledged, sealed, err := c.SubjectBarrier(t.Context(), b, offboarded)
	if err != nil || !acknowledged || sealed {
		t.Fatal("revoked store must be acknowledged and not sealed", acknowledged, sealed, err)
	}
	if got, err := c.Lookup(t.Context(), offboarded); err != nil || got != b {
		t.Fatal("an unsealed store is still live", got, err)
	}
	header := wrappedBackup(t, keys, offboarded, offboardedV)
	if err = openBackup(t, keys, offboarded, offboardedV, header); err != nil {
		t.Fatal("key gone before the seal", err)
	}
	if err = c.RecordRetiredSeal(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if _, sealed, err = c.SubjectBarrier(t.Context(), b, offboarded); err != nil || !sealed {
		t.Fatal("seal not recorded", sealed, err)
	}
	if _, err = c.Lookup(t.Context(), offboarded); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store still live", err)
	}
	if _, err = c.ReserveIncarnation(t.Context(), b, "restore"); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store reserved an image", err)
	}
	if err = keys.Revoke(t.Context(), offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	if err = openBackup(t, keys, offboarded, offboardedV, header); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed key opened a backup", err)
	}
}

// oldImageDoesNotReviveDestroyedKeyTest (offboardedAfterBackup in the model).
// Store 1 is backed up; it then acknowledges a job for the offboarded agent,
// which is revoked, sealed and its key destroyed while store 1 restores the
// old image. The image declares its loss and activates. It brings back neither
// the revocation, nor the seal, nor the key: a backup made with the key stays
// closed.
func TestOldImageDoesNotReviveDestroyedKey(t *testing.T) {
	keys, c := authorities(t)
	a, err := c.Register(t.Context(), keyRunAgent, keyRunVolume)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Register(t.Context(), offboarded, offboardedV)
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	header := wrappedBackup(t, keys, offboarded, offboardedV)
	backup := image{} // takeBackup(1): the image before the job
	live := image{"event-0": digest("job for the offboarded agent")}
	if err = c.RecordOutcome(t.Context(), a, Outcome{ID: "event-0", Digest: live["event-0"]}); err != nil {
		t.Fatal(err)
	}
	// revoke(0), then permanentlySeal(0).
	if _, err = c.BeginRevocation(t.Context(), offboarded); err != nil {
		t.Fatal(err)
	}
	receipt(t, c, a)
	receipt(t, c, b)
	if err = c.RecordRetiredSeal(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	// restoreImage(1), then destroyKey(0).
	restored, err := c.ReserveIncarnation(t.Context(), a, "restore-old-image")
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Revoke(t.Context(), offboarded, offboardedV); err != nil {
		t.Fatal(err)
	}
	// reconcile(1), declareLoss(1), activate(1).
	r := receipt(t, c, restored)
	ready := false
	losses, err := c.Activate(t.Context(), r, Restoration{
		Inspect: func(recorded []Outcome) ([]string, error) {
			missing := []string{}
			for _, o := range recorded {
				if d, ok := backup[o.ID]; !ok || d != o.Digest {
					missing = append(missing, o.ID)
				}
			}
			return missing, nil
		},
		Publish: func() error { ready = true; return nil },
	})
	if err != nil || !ready || len(losses) != 1 || losses[0].ID != "event-0" || losses[0].Incarnation != restored.Incarnation {
		t.Fatal("old image did not declare its loss", losses, err)
	}
	if s, _, err := c.OutcomeStatus(t.Context(), "event-0"); err != nil || s != StatusLost {
		t.Fatal(s, err)
	}
	// Nothing came back.
	if err = c.WithSubjectKey(t.Context(), offboarded, func() error { t.Error("revoked subject got a key grant"); return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal("revocation revived", err)
	}
	if _, err = c.Lookup(t.Context(), offboarded); !errors.Is(err, ErrSealed) {
		t.Fatal("seal revived", err)
	}
	if err = openBackup(t, keys, offboarded, offboardedV, header); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed key revived", err)
	}
	if err = keys.Ensure(t.Context(), offboarded, offboardedV); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("destroyed volume received a new key", err)
	}
}
