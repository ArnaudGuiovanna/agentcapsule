//go:build linux && cgo

package volumestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestVolumeRemovalChecksIdentityAndWriterExclusion(t *testing.T) {
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode+1); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	f, err := os.OpenFile(c.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); !errors.Is(err, ErrBusy) {
		t.Fatal("writer ignored", err)
	}
	f.Close()
	alias := c.Path + ".alias"
	if err = os.Link(c.Path, alias); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); !errors.Is(err, ErrState) {
		t.Fatal("extra hard link accepted", err)
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(c.Path, alias); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); !errors.Is(err, ErrState) {
		t.Fatal("unexplained absence accepted", err)
	}
	if err = os.WriteFile(c.Path, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); !errors.Is(err, ErrState) {
		t.Fatal("replacement removed", err)
	}
	if b, err := os.ReadFile(c.Path); err != nil || string(b) != "unrelated" {
		t.Fatal("replacement changed", err)
	}
	if err = os.Remove(c.Path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(alias, c.Path); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); err != nil {
		t.Fatal(err)
	}
	if !absence(c.Path) {
		t.Fatal("volume retained")
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); err != nil {
		t.Fatal("retry", err)
	}
	if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrRemoved) {
		t.Fatal("recreated deleted identity", err)
	}
	if err = os.WriteFile(c.Path, []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(t.Context(), spec, c.Device, c.Inode); !errors.Is(err, ErrState) {
		t.Fatal("resurrected file ignored", err)
	}
}

type removalCrashInput struct {
	Root, Boundary string
	Container      Container
}

func TestVolumeRemovalProcessCrashRecovery(t *testing.T) {
	for _, boundary := range []string{"removal_intent", "volume_unlinked", "removal_synced", "removal_committed"} {
		t.Run(boundary, func(t *testing.T) {
			s, spec, key := fixture(t)
			c, err := s.Prepare(t.Context(), spec, key)
			if err != nil {
				t.Fatal(err)
			}
			input, err := json.Marshal(removalCrashInput{s.root, boundary, c})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVolumeRemovalCrashChild$")
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_REMOVAL_CHILD=1")
			cmd.Stdin = bytes.NewReader(input)
			if output, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != 93 || len(output) != 0 {
				t.Fatalf("child did not interrupt at %s: %v", boundary, err)
			}
			if _, err = s.Prepare(t.Context(), spec, key); !errors.Is(err, ErrRemoved) {
				t.Fatal("interrupted removal allowed recreation", err)
			}
			s, err = New(s.root)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Remove(t.Context(), spec, c.Device, c.Inode); err != nil {
				t.Fatal(err)
			}
			j, err := load(filepath.Join(s.root, "volume-state", spec.VolumeID+".json"))
			if err != nil || j.Stage != "REMOVED" || !absence(c.Path) {
				t.Fatal("removal incomplete", err)
			}
		})
	}
}

func TestVolumeRemovalCrashChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_REMOVAL_CHILD") != "1" {
		return
	}
	var in removalCrashInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		os.Exit(91)
	}
	s, err := New(in.Root)
	if err != nil {
		os.Exit(92)
	}
	s.hook = func(boundary string) {
		if boundary == in.Boundary {
			os.Exit(93)
		}
	}
	_ = s.Remove(t.Context(), in.Container.Spec, in.Container.Device, in.Container.Inode)
	os.Exit(94)
}
