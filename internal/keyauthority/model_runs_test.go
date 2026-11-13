//go:build linux

package keyauthority

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests project the key runs of spec/restore_authority_test.qnt onto the
// file provider. Each one names its Quint run. They are written by hand from
// the runs: no Go test reads the model's traces (ADR 005, "Model revision").
//
// A backup is symbolic, as in the model. A volume archive is a LUKS container
// whose header wraps the volume's master key under the authority's key. Here
// the header is that master key sealed with AES-GCM under the key. Decrypting
// a backup means borrowing the key and opening the header.

// sealedHeader wraps a fresh master key under the volume key, as LUKS does.
func sealedHeader(t *testing.T, s *Files, agent, volume string) (header, master []byte) {
	t.Helper()
	master = make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	if err := s.WithKey(t.Context(), agent, volume, func(key []byte) error {
		aead, err := gcm(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return err
		}
		header = aead.Seal(nonce, nonce, master, []byte(volume))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return header, master
}

// decryptBackup is the model's decryptBackup: it borrows the key and opens the
// header.
func decryptBackup(ctx context.Context, s *Files, agent, volume string, header []byte) ([]byte, error) {
	var master []byte
	err := s.WithKey(ctx, agent, volume, func(key []byte) error {
		aead, err := gcm(key)
		if err != nil {
			return err
		}
		n := aead.NonceSize()
		master, err = aead.Open(nil, header[:n], header[n:], []byte(volume))
		return err
	})
	return master, err
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// liveKeyDecryptsBackupTest: a live key opens a backup, also from a reopened
// authority. Without it no archive opens (ADR 005 §2).
func TestLiveKeyDecryptsBackup(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	header, master := sealedHeader(t, s, testAgent, testVolume)
	reopened, err := Open(s.root, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptBackup(t.Context(), reopened, testAgent, testVolume, header)
	if err != nil || !bytes.Equal(got, master) {
		t.Fatal("live key did not open its backup", err)
	}
}

// destructionWaitsForAllCachedCopiesTest: destruction waits while any holder
// has the key. Here a holder is an active WithKey callback, such as a boot
// handing the key to its guest. The model's cached copy also includes the
// guest's dm-crypt after the callback returns; retiring that guest is the
// worker's obligation (RemoveDeletedStore revokes the key only inside the
// host's sealed-volume callback), not this package's.
func TestDestructionWaitsForAllCachedCopies(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	header, master := sealedHeader(t, s, testAgent, testVolume)
	tombstone := filepath.Join(s.root, "revoked", testVolume)
	var holders [2]struct {
		entered, release chan struct{}
		done             chan error
	}
	for i := range holders {
		h := &holders[i]
		h.entered, h.release, h.done = make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			h.done <- s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error {
				close(h.entered)
				<-h.release
				return nil
			})
		}()
		<-h.entered
	}
	attempt := func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		return s.Revoke(ctx, testAgent, testVolume)
	}
	for i := range holders {
		if err := attempt(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("destruction with %d holder(s) left: %v", len(holders)-i, err)
		}
		if _, err := os.Lstat(tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused destruction published a tombstone", err)
		}
		close(holders[i].release)
		if err := <-holders[i].done; err != nil {
			t.Fatal(err)
		}
	}
	// The refused attempts destroyed nothing: the key still opens the backup.
	if got, err := decryptBackup(t.Context(), s, testAgent, testVolume, header); err != nil || !bytes.Equal(got, master) {
		t.Fatal("refused destruction changed the key", err)
	}
	if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal("destruction after the last holder", err)
	}
}

// destroyedKeyCannotDecryptOldBackupTest: once the key is destroyed, a backup
// made with it no longer opens, no second key is ever made for the volume, and
// no file of the authority still holds the key.
func TestDestroyedKeyCannotDecryptOldBackup(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	header, _ := sealedHeader(t, s, testAgent, testVolume)
	var key []byte // test-only copy, to search the authority's files for it
	if err := s.WithKey(t.Context(), testAgent, testVolume, func(k []byte) error { key = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*Files{s, reopened} {
		if _, err = decryptBackup(t.Context(), p, testAgent, testVolume, header); !errors.Is(err, ErrRevoked) {
			t.Fatal("destroyed key opened an old backup", err)
		}
		if err = p.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrRevoked) {
			t.Fatal("destroyed volume received a new key", err)
		}
	}
	err = filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(b)
		if bytes.Contains(b, key) {
			t.Errorf("%s still holds the destroyed key", strings.TrimPrefix(path, s.root))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
