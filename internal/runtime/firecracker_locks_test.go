//go:build linux

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// registryIdentity is the inode of registry.json: every write replaces it.
// The file stays open until the test ends, so that its inode number is not
// given to a later file.
func registryIdentity(t *testing.T, h *FirecrackerHost) os.FileInfo {
	t.Helper()
	f, err := os.Open(filepath.Join(h.root, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// volumeFixture gives agent id of an admission host a registered regular
// volume file holding content.
func volumeFixture(t *testing.T, h *FirecrackerHost, id, content string) (uint64, uint64) {
	t.Helper()
	path := filepath.Join(h.root, "volumes", id)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Sys().(*syscall.Stat_t)
	if err = h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents[id].Device, r.Agents[id].Inode = uint64(s.Dev), s.Ino
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	return uint64(s.Dev), s.Ino
}

// A volume copy of one agent, as the nightly archive takes, holds that
// agent's volume alone: another agent's copy and the host registry stay
// usable meanwhile (S-03).
func TestAVolumeCopyOfOneAgentDoesNotBlockAnother(t *testing.T) {
	h := admissionHost(t)
	devA, inoA := volumeFixture(t, h, "a", "volume of a")
	devB, inoB := volumeFixture(t, h, "b", "volume of b")
	copying, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.WithStoppedVolume(t.Context(), "a", 0, devA, inoA, func(r io.Reader) error {
			close(copying)
			<-release
			_, err := io.ReadAll(r)
			return err
		})
	}()
	<-copying
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var got []byte
	if err := h.WithStoppedVolume(ctx, "b", 0, devB, inoB, func(r io.Reader) error {
		var err error
		got, err = io.ReadAll(r)
		return err
	}); err != nil || string(got) != "volume of b" {
		t.Fatal("the copy of a blocked the copy of b:", err)
	}
	if _, err := h.HarnessOf(ctx, "b"); err != nil {
		t.Fatal("the copy of a blocked the registry:", err)
	}
	// The same agent's volume stays exclusive while it is copied.
	short, cancelShort := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelShort()
	if err := h.WithStoppedVolume(short, "a", 0, devA, inoA, func(io.Reader) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a second copy of a ran beside the first:", err)
	}
}

// An exclusive turn of one agent, as a delivery holds through its guest RPC,
// does not hold another agent's (S-02): a slow harness of a does not delay
// the delivery to b. Within an agent, the turn stays exclusive.
func TestAnAgentsExclusiveTurnDoesNotBlockAnotherAgent(t *testing.T) {
	h := admissionHost(t)
	slow, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.WithBarrier(t.Context(), "a", func(context.Context) error {
			close(slow)
			<-release
			return nil
		})
	}()
	<-slow
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ran := false
	if err := h.WithBarrier(ctx, "b", func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Fatal("a's turn blocked b's:", err)
	}
	short, cancelShort := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelShort()
	if err := h.WithBarrier(short, "a", func(context.Context) error { t.Error("two exclusive turns of a"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// Using a VM that needs nothing (its adoption succeeds, its run stays) does
// not write the host registry (P-09): each write is two fsyncs.
func TestRegistryUnchangedNotRewritten(t *testing.T) {
	l := newAdoptionLab(t, 3, true)
	before := registryIdentity(t, l.h)
	if _, err := l.h.ReconcileAgent(t.Context(), "agent-00"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.h.ControlForRetirement(t.Context(), "agent-01"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.h.CredentialRotation(t.Context(), "agent-02", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.h.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after := registryIdentity(t, l.h); !os.SameFile(before, after) {
		t.Fatal("the registry was rewritten though nothing changed")
	}
	// A change is still written.
	l.refuse["agent-01"] = ErrGeneration
	if _, err := l.h.ReconcileAgent(t.Context(), "agent-01"); err != nil {
		t.Fatal(err)
	}
	if after := registryIdentity(t, l.h); os.SameFile(before, after) {
		t.Fatal("a retired VM was not written")
	}
	l.expectRunning(t, "agent-00", "agent-02")
	// Reusing a running VM at a start writes nothing either.
	reuse := newAdoptionLab(t, 2, false)
	before = registryIdentity(t, reuse.h)
	if _, err := reuse.h.Start(t.Context(), "agent-00", 1); err != nil {
		t.Fatal(err)
	}
	if after := registryIdentity(t, reuse.h); !os.SameFile(before, after) {
		t.Fatal("reusing a VM rewrote the registry")
	}
}
