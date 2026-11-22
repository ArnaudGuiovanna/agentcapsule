//go:build linux && amd64 && root_integration

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REG-01: as root, the program, as the dedicated account, may make the
// system calls debugfs makes and no other.
func TestAsRootTheProgramIsKilledForAnyOtherSystemCall(t *testing.T) {
	o := requireRoot(t)
	o.TestTools = false
	for _, p := range syscallProbes {
		got := outcome(t, o, probe(t, p.nr, false, p.args...))
		if p.want == passed && got != killed {
			continue
		}
		if got != p.want {
			t.Errorf("%s: %s, not %s", p.name, got, p.want)
		}
	}
	confinedKillsAnotherArchitecture(t, o)
}

// S-21: as root, a program of this executable runs as the dedicated UID and
// GID, without supplementary groups or capabilities, under the self filter
// and its own; it reads an image in a directory only root enters, writes
// nothing, sees no device and is killed for any other call. Without a
// dedicated UID, nothing runs.
func TestAsRootASelfRunRunsAsTheDedicatedAccount(t *testing.T) {
	o := requireRoot(t)
	o.TestTools = false
	s := selfConfinedAs(t, o)
	if ids := "61999\t61999\t61999\t61999"; s["Uid"] != ids || s["Gid"] != ids || s["Groups"] != "" {
		t.Errorf("Uid %q Gid %q Groups %q", s["Uid"], s["Gid"], s["Groups"])
	}
	if _, err := (Options{}).RunSelf(t.Context(), "", nil, selfTestProgram, "status"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("as root without a dedicated UID: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("an image root may write"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := selfRun(t, o, image, nil, "image"); got != "an image root may write" {
		t.Errorf("the image reads %q", got)
	}
	for _, path := range []string{image, filepath.Join(dir, "written"), "/tmp/agentcapsule-self-written"} {
		if got := selfRun(t, o, image, nil, "write", path); !strings.HasPrefix(got, "refused: ") {
			t.Errorf("writing %s: %s", path, got)
		}
	}
	if got := selfRun(t, o, "", []byte("input"), "input"); got != "c96c6d5be8d08a12e7b5cdc1b207fa6b2430974c86803d8891675e76fd992c20" {
		t.Errorf("the input: %s", got)
	}
	selfProbes(t, o)
}
