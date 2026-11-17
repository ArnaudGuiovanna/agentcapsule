//go:build linux

package harnesspkg

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// packed builds an image whose entrypoint /bin/harness is executable.
func packed(t *testing.T) (string, HarnessManifest) {
	t.Helper()
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err = os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(src, "bin/harness"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), RootfsFile)
	if err = BuildRootfs(t.Context(), m, src, image, 2); err != nil {
		t.Fatal(err)
	}
	return image, m
}

// REG-01: confined, debugfs reads the image as it does when run directly:
// the same output, byte for byte, for every path the inspection reads and
// for one the image lacks.
func TestConfinedDebugfsGivesTheSameResult(t *testing.T) {
	image, m := packed(t)
	debugfs, err := debugfs()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(append([]string{}, MountPoints...), m.Entrypoint[0], "/absent") {
		cmd := exec.CommandContext(t.Context(), debugfs, "-R", "stat \""+p+"\"", image)
		cmd.Env = []string{"LC_ALL=C"}
		direct, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		confined, err := sandbox.Options{}.Run(t.Context(), image, debugfs, "-R", "stat \""+p+"\"", sandbox.ImagePath)
		if err != nil {
			t.Fatal(p, err)
		}
		if !bytes.Equal(direct, confined) {
			t.Errorf("%s: confined, debugfs printed\n%s\ninstead of\n%s", p, confined, direct)
		}
		if p != "/absent" && !statLine.Match(confined) {
			t.Errorf("%s: no type and mode in\n%s", p, confined)
		}
	}
	if err = CheckInspection(t.Context(), sandbox.Options{}); err != nil {
		t.Error("debugfs -V, confined:", err)
	}
}

// REG-01: InspectRootfs runs every debugfs confined. The debugfs found on
// PATH here answers as a valid image would only when it runs with
// no_new_privs, under seccomp and as PID 1 of its own namespace; the
// inspection then passes.
func TestInspectionRunsDebugfsConfined(t *testing.T) {
	image, m := packed(t)
	bin := t.TempDir()
	// Shell builtins only: the sandbox lets no process start another.
	fake := `#!/bin/sh
nnp= filter= pid=
while read -r key value rest; do
  case $key in NoNewPrivs:) nnp=$value;; Seccomp:) filter=$value;; NSpid:) pid=$value;; esac
done < /proc/self/status
[ "$nnp" = 1 ] && [ "$filter" = 2 ] && [ "$pid" = 1 ] && [ "$3" = ` + sandbox.ImagePath + ` ] || exit 0
case $2 in
  'stat "/bin/harness"') echo 'Inode: 12   Type: regular    Mode:  0755   Flags: 0x0' ;;
  *) echo 'Inode: 2   Type: directory    Mode:  0755   Flags: 0x0' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "debugfs"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{}); err != nil {
		t.Fatal("debugfs ran unconfined:", err)
	}
	// The same debugfs run directly finds nothing.
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{Unconfined: true}); !errors.Is(err, ErrInvalid) {
		t.Fatal("the probe cannot tell a confined debugfs", err)
	}
}
