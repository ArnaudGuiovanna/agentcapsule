//go:build linux && cgo

package volumestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Store, Spec, []byte) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "managed"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return s, Spec{AgentID: "agt_" + strings.Repeat("a", 32), VolumeID: "vol_" + strings.Repeat("b", 32), SizeMiB: 64}, key
}
func header(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 16<<20)
	if _, err = f.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncryptedContainerConcurrentCreationAndReplay(t *testing.T) {
	s, spec, key := fixture(t)
	var wg sync.WaitGroup
	type outcome struct {
		c   Container
		err error
	}
	results := make(chan outcome, 6)
	for range 6 {
		wg.Go(func() { c, err := s.Prepare(t.Context(), spec, key); results <- outcome{c, err} })
	}
	wg.Wait()
	close(results)
	var first Container
	for o := range results {
		if o.err != nil {
			t.Fatal(o.err)
		}
		if first.Inode == 0 {
			first = o.c
		} else if o.c != first {
			t.Fatal("concurrent workers assigned different containers")
		}
	}
	before := header(t, first.Path)
	if !bytes.Equal(before[:6], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) || before[7] != 2 {
		t.Fatal("not a LUKS2 container")
	}
	if bytes.Contains(before, key) {
		t.Fatal("unlock secret stored in plaintext")
	}
	j, err := load(filepath.Join(s.root, "volume-state", spec.VolumeID+".json"))
	if err != nil || j.Stage != "READY" || j.Inode != first.Inode {
		t.Fatal("publication journal missing", err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	if _, err = s.Prepare(t.Context(), spec, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong reservation key accepted", err)
	}
	// Exercise libcryptsetup's actual key check independently of the journal hash.
	if err = luks(first.Path, first.UUID, wrong, false, nil); !errors.Is(err, ErrLUKS) {
		t.Fatal("wrong LUKS key accepted", err)
	}
	changed := spec
	changed.AgentID = "agt_" + strings.Repeat("c", 32)
	if _, err = s.Prepare(t.Context(), changed, key); !errors.Is(err, ErrConflict) {
		t.Fatal("volume assigned to another agent", err)
	}
	if _, err = s.Prepare(t.Context(), spec, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, header(t, first.Path)) {
		t.Fatal("retry changed a published LUKS header/key")
	}
}

func TestPublishedContainerCannotBeReformattedOrReplaced(t *testing.T) {
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	// The VMM uses this exact flock domain. Provisioning cannot enter while the
	// volume is in use, even with the original reservation and correct secret.
	f, err := os.OpenFile(c.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrBusy) {
		t.Fatal("writer lock bypassed", err)
	}
	f.Close()
	if err = os.Rename(c.Path, c.Path+".retained"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrState) || !absence(c.Path) {
		t.Fatal("missing published data silently recreated", err)
	}
	if err = os.WriteFile(c.Path, []byte("unrelated file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrState) {
		t.Fatal("replacement inode accepted", err)
	}
	b, err := os.ReadFile(c.Path)
	if err != nil || string(b) != "unrelated file" {
		t.Fatal("replacement file overwritten", err)
	}
	if err = os.Remove(c.Path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(c.Path+".retained", c.Path); err != nil {
		t.Fatal(err)
	}
	// Destroy both LUKS header magic values, keeping the original inode. The
	// failure must be surfaced without trying to repair by generating new keys.
	f, err = os.OpenFile(c.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{0, 16384} {
		if _, err = f.WriteAt([]byte("BROKEN"), offset); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before := sha256.Sum256(header(t, c.Path))
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrLUKS) {
		t.Fatal("damaged published volume accepted", err)
	}
	if sha256.Sum256(header(t, c.Path)) != before {
		t.Fatal("damaged published volume reformatted")
	}
}

type crashInput struct {
	Root, Boundary string
	Spec           Spec
	Key            []byte
}

func TestContainerProcessCrashRecovery(t *testing.T) {
	for _, boundary := range []string{"reserved", "allocated", "header_written", "formatted", "published", "committed"} {
		t.Run(boundary, func(t *testing.T) {
			s, spec, key := fixture(t)
			input, err := json.Marshal(crashInput{s.root, boundary, spec, key})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContainerCrashChild$")
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_VOLUME_CHILD=1")
			cmd.Stdin = bytes.NewReader(input) // Key is not in argv, environment or a file.
			if output, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != 93 || len(output) != 0 {
				t.Fatalf("child did not interrupt at %s (output withheld): %v", boundary, err)
			}
			path := filepath.Join(s.root, "volumes", spec.VolumeID+".luks")
			var before []byte
			if boundary == "formatted" {
				before = header(t, filepath.Join(s.root, "volumes", spec.VolumeID+".pending"))
			} else if !absence(path) {
				before = header(t, path)
			}
			c, err := s.Prepare(t.Context(), spec, key)
			if err != nil {
				t.Fatal("interrupted creation cannot resume", err)
			}
			if before != nil && !bytes.Equal(before, header(t, c.Path)) {
				t.Fatal("completed format was repeated during recovery")
			}
			if !absence(filepath.Join(s.root, "volumes", spec.VolumeID+".pending")) {
				t.Fatal("unnecessary volume alias retained after recovery")
			}
		})
	}
}

func TestContainerCrashChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_VOLUME_CHILD") != "1" {
		return
	}
	var in crashInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		os.Exit(91)
	}
	s, err := New(in.Root)
	if err != nil {
		os.Exit(92)
	}
	s.hook = func(boundary string) {
		if boundary == in.Boundary {
			os.Exit(93) // no deferred close/unlock or cleanup
		}
	}
	_, _ = s.Prepare(t.Context(), in.Spec, in.Key)
	os.Exit(94)
}

func TestContainerRefusesUnknownFileAndSymlink(t *testing.T) {
	s, spec, key := fixture(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(s.root, "volumes", spec.VolumeID+".pending")
	if err := os.Symlink(victim, pending); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrState) {
		t.Fatal("unowned file adopted", err)
	}
	b, err := os.ReadFile(victim)
	if err != nil || string(b) != "retain" {
		t.Fatal("symlink target changed", err)
	}
}
