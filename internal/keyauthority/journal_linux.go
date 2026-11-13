//go:build linux

package keyauthority

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Synchronous replication (docs/adr/005-keys-outside-restored-domain.md,
// option a). Without a journal, the authority is standalone: it keeps its
// keys on this host only, and gives no protection against the host's loss.
// With a journal, every key creation and destruction reaches the replica on
// the standby before it takes effect for its callers:
//
//   - Ensure publishes the key file, unusable without its allocation marker.
//     The journal records the key, wrapped to the operator's unlock key, and
//     waits for the replica. Only then does Ensure publish the marker. A crash
//     at any point leaves a key that no caller can use, and a retry of Ensure
//     records the same key again.
//   - Revoke publishes the tombstone at once: it only denies. The journal
//     records the destruction, and the replica deletes its wrapped copy in the
//     same transaction. Only then does Revoke remove the key file.

// Change is a write of this authority, handed to the journal. Key is the key
// of a creation; the journal clears it once it has wrapped it.
type Change struct {
	Revoke        bool
	Agent, Volume string
	Key           []byte
}

// Journal is the replication stream, shared with the restore authority.
type Journal interface {
	// Append runs write while it holds the stream's write lock, records the
	// change that write returns, if any, and returns only once the replica
	// holds that record, and every one before it, durably. write must not
	// re-enter the journal.
	Append(ctx context.Context, write func() (*Change, error)) error
}

// SetJournal makes every later Ensure and Revoke replicate through j. The
// caller sets it once, before any use.
func (s *Files) SetJournal(j Journal) { s.journal = j }

// Replicated reports whether a snapshot armed this authority for a replica.
// An armed authority refuses Ensure and Revoke without a journal, so that a
// process configured without the replica cannot write behind its back.
func (s *Files) Replicated() (bool, error) {
	st, err := os.Lstat(filepath.Join(s.root, "replicated"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return false, ErrUnavailable
	}
	return true, nil
}

// MarkReplicated arms this authority for a replica. It is permanent: a
// promotion builds a new, standalone authority on the standby.
func (s *Files) MarkReplicated() error {
	if err := s.checkIdentity(); err != nil {
		return err
	}
	armed, err := s.Replicated()
	if err != nil || armed {
		return err
	}
	if err = publish(filepath.Join(s.root, "replicated"), []byte("replicated\n"), nil, nil); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if armed, err = s.Replicated(); err == nil && !armed {
		err = ErrUnavailable
	}
	return err
}

func (s *Files) standalone() error {
	armed, err := s.Replicated()
	if err == nil && armed {
		err = ErrUnavailable
	}
	return err
}

func (s *Files) ensureJournaled(ctx context.Context, agent, volume string) error {
	if !valid(agent, "agt_") || !valid(volume, "vol_") {
		return ErrInput
	}
	path := filepath.Join(s.root, "records", volume)
	err := s.journal.Append(ctx, func() (*Change, error) {
		var change *Change
		err := s.withLock(ctx, agent, volume, true, func() error {
			if err := s.revoked(agent, volume); err != nil {
				return err
			}
			if err := s.cleanTemps("records", volume); err != nil {
				return err
			}
			b, err := read(path, "ACPKEY01", agent, volume)
			if err == nil {
				defer clear(b)
				// The marker follows the replica's acknowledgment: the
				// replica already holds this key.
				if s.allocation(agent, volume, false) == nil {
					return nil
				}
				change = &Change{Agent: agent, Volume: volume, Key: bytes.Clone(b[80:112])}
				return nil
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if _, err := os.Lstat(path + ".allocated"); err == nil || !errors.Is(err, os.ErrNotExist) {
				return ErrUnavailable
			}
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			b = record("ACPKEY01", agent, volume, key)
			defer clear(b)
			if err = publish(path, b, func() { s.boundary("key_written") }, func() { s.boundary("key_linked") }); err != nil {
				clear(key)
				return err
			}
			s.boundary("key_published")
			change = &Change{Agent: agent, Volume: volume, Key: key}
			return nil
		})
		return change, err
	})
	if err != nil {
		return err
	}
	s.boundary("key_replicated")
	return s.withLock(ctx, agent, volume, true, func() error {
		if err := s.revoked(agent, volume); err != nil {
			return err
		}
		b, err := read(path, "ACPKEY01", agent, volume)
		clear(b)
		if err != nil {
			return ErrUnavailable
		}
		return s.allocation(agent, volume, true)
	})
}

func (s *Files) revokeJournaled(ctx context.Context, agent, volume string) error {
	if !valid(agent, "agt_") || !valid(volume, "vol_") {
		return ErrInput
	}
	path := filepath.Join(s.root, "records", volume)
	err := s.journal.Append(ctx, func() (*Change, error) {
		err := s.withLock(ctx, agent, volume, true, func() error {
			err := s.revoked(agent, volume)
			if err != nil && !errors.Is(err, ErrRevoked) {
				return err
			}
			if b, e := read(path, "ACPKEY01", agent, volume); e == nil {
				clear(b)
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if err == nil {
				marker := record("ACPREV01", agent, volume, nil)
				defer clear(marker)
				if err = publish(filepath.Join(s.root, "revoked", volume), marker, nil, func() { s.boundary("revocation_linked") }); err != nil {
					return err
				}
			}
			if err = syncDir(filepath.Join(s.root, "revoked")); err != nil {
				return err
			}
			s.boundary("revocation_published")
			return nil
		})
		if err != nil {
			return nil, err
		}
		// Each call records the destruction: a tombstone left by a crash
		// before its record must still reach the replica.
		return &Change{Revoke: true, Agent: agent, Volume: volume}, nil
	})
	if err != nil {
		return err
	}
	s.boundary("revocation_replicated")
	return s.withLock(ctx, agent, volume, true, func() error {
		if err := s.cleanTemps("records", volume); err != nil {
			return err
		}
		if err := s.cleanTemps("revoked", volume); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(path))
	})
}

// Entry is the state of one volume, for a snapshot or a promotion.
type Entry struct {
	Agent, Volume string
	// Key is the volume key, nil once destroyed. In Export it is valid only
	// during the callback.
	Key       []byte
	Allocated bool
	Revoked   bool
}

// readBound reads a record of volume and returns its agent.
func readBound(path, magic, volume string) ([]byte, string, error) {
	b, err := readRecord(path, magic)
	if err != nil {
		return nil, "", err
	}
	agent := string(b[8:44])
	if string(b[44:80]) != volume || !valid(agent, "agt_") {
		clear(b)
		return nil, "", ErrUnavailable
	}
	return b, agent, nil
}

// Export lists every volume of the authority, in order, for a snapshot. Keys
// are read without locks: a published key file never changes, and the
// caller holds the journal's write lock, which every journaled write takes.
// A volume whose tombstone exists is reported revoked, even while its key
// file still exists.
func (s *Files) Export(ctx context.Context, each func(Entry) error) error {
	if err := s.checkIdentity(); err != nil {
		return err
	}
	entries := map[string]*Entry{}
	get := func(volume, agent string) (*Entry, error) {
		e := entries[volume]
		if e == nil {
			e = &Entry{Agent: agent, Volume: volume}
			entries[volume] = e
		}
		if e.Agent != agent {
			return nil, ErrUnavailable
		}
		return e, nil
	}
	keys := map[string][]byte{}
	defer func() {
		for _, k := range keys {
			clear(k)
		}
	}()
	// Keys and markers first, tombstones after: a key removed meanwhile
	// already has its tombstone.
	for _, directory := range []string{"records", "revoked"} {
		names, err := os.ReadDir(filepath.Join(s.root, directory))
		if err != nil {
			return err
		}
		for _, n := range names {
			if err = ctx.Err(); err != nil {
				return err
			}
			name := n.Name()
			if strings.HasPrefix(name, ".pending-") {
				continue
			}
			volume, marker := strings.CutSuffix(name, ".allocated")
			if !valid(volume, "vol_") || (marker && directory != "records") {
				return ErrUnavailable
			}
			magic := map[string]string{"records": "ACPKEY01", "revoked": "ACPREV01"}[directory]
			if marker {
				magic = "ACPALO01"
			}
			b, agent, err := readBound(filepath.Join(s.root, directory, name), magic, volume)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				clear(b)
				return ErrUnavailable
			}
			e, err := get(volume, agent)
			if err != nil {
				clear(b)
				return err
			}
			switch {
			case directory == "revoked":
				e.Revoked = true
			case marker:
				e.Allocated = true
			default:
				keys[volume] = bytes.Clone(b[80:112])
			}
			clear(b)
		}
	}
	volumes := make([]string, 0, len(entries))
	for v := range entries {
		volumes = append(volumes, v)
	}
	slices.Sort(volumes)
	for _, v := range volumes {
		e := *entries[v]
		if !e.Revoked {
			e.Key = keys[v]
		}
		if err := each(e); err != nil {
			return err
		}
	}
	return nil
}

// ensureRecord publishes b at path, or checks that path already holds b.
func ensureRecord(path, magic, agent, volume string, b []byte) error {
	got, err := read(path, magic, agent, volume)
	defer clear(got)
	if errors.Is(err, os.ErrNotExist) {
		return publish(path, b, nil, nil)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(got, b) {
		return ErrConflict
	}
	return nil
}

// Install builds the key authority of a promoted standby from its replica,
// with the identity of the authority it replicated. It never replaces another
// authority's identity or a different key. A repeated call completes an
// interrupted one. The new authority is standalone until a new snapshot arms
// it for a new replica.
func Install(ctx context.Context, root, identity string, entries []Entry) (*Files, error) {
	if !valid(identity, "keyauth_") {
		return nil, ErrInput
	}
	s, err := openDirectories(root, true)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.root, "initialize.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = lockFile(ctx, f, true); err != nil {
		return nil, err
	}
	id, err := readIdentity(s.root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		for _, name := range []string{"locks", "records", "revoked"} {
			names, err := os.ReadDir(filepath.Join(s.root, name))
			if err != nil || len(names) != 0 {
				return nil, ErrUnavailable
			}
		}
		if err = publish(filepath.Join(s.root, "identity"), []byte(identity), nil, nil); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case id != identity:
		return nil, ErrConflict
	}
	s.identity = identity
	for _, e := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !valid(e.Agent, "agt_") || !valid(e.Volume, "vol_") || (e.Key != nil && (len(e.Key) != 32 || e.Revoked)) {
			return nil, ErrInput
		}
		if e.Key != nil {
			b := record("ACPKEY01", e.Agent, e.Volume, e.Key)
			err = ensureRecord(filepath.Join(s.root, "records", e.Volume), "ACPKEY01", e.Agent, e.Volume, b)
			clear(b)
			if err != nil {
				return nil, err
			}
		}
		if e.Allocated || e.Key != nil {
			b := record("ACPALO01", e.Agent, e.Volume, nil)
			if err = ensureRecord(filepath.Join(s.root, "records", e.Volume+".allocated"), "ACPALO01", e.Agent, e.Volume, b); err != nil {
				return nil, err
			}
		}
		if e.Revoked {
			b := record("ACPREV01", e.Agent, e.Volume, nil)
			if err = ensureRecord(filepath.Join(s.root, "revoked", e.Volume), "ACPREV01", e.Agent, e.Volume, b); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range []string{"records", "revoked"} {
		if err = syncDir(filepath.Join(s.root, name)); err != nil {
			return nil, err
		}
	}
	return s, nil
}
