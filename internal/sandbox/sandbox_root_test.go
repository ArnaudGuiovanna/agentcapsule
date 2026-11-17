//go:build linux && root_integration

package sandbox

// The parts of the sandbox that need root, as the worker runs in production:
//
//	sudo go test -tags root_integration -run AsRoot ./internal/sandbox ./internal/harnesspkg ./internal/worker
//
// They run only with this tag, and fail (never skip) under another account.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rootTestUID is the UID and GID the program runs as in these tests: no
// account's, on a test host.
const rootTestUID = 61999

func requireRoot(t *testing.T) Options {
	t.Helper()
	if !AsRoot() {
		t.Fatal("run as root in the initial user namespace (sudo go test -tags root_integration)")
	}
	return Options{UID: rootTestUID, GID: rootTestUID, TestTools: true}
}

// REG-01: as root, the program runs as the dedicated UID and GID, without
// supplementary groups or capabilities, under seccomp with no_new_privs, as
// PID 1 of its own mount, network, PID, IPC and UTS namespaces. Without a
// dedicated UID, nothing runs; nor with 65535 or a value from 2^31-1 up,
// which setresuid and setresgid may take as "unchanged"; nor unconfined.
func TestAsRootTheProgramRunsAsTheDedicatedAccount(t *testing.T) {
	o := requireRoot(t)
	s := confinedAs(t, o)
	if ids := "61999\t61999\t61999\t61999"; s["Uid"] != ids || s["Gid"] != ids || s["Groups"] != "" {
		t.Errorf("Uid %q Gid %q Groups %q", s["Uid"], s["Gid"], s["Groups"])
	}
	namespacesDiffer(t, o)
	for _, missing := range []Options{{}, {UID: rootTestUID}, {GID: rootTestUID}, {UID: 65535, GID: 65535},
		{UID: 4294967295, GID: 4294967295}, {UID: rootTestUID, GID: 4294967295}, {UID: 1<<31 - 1, GID: rootTestUID}} {
		missing.TestTools = true
		if out, err := missing.Run(t.Context(), "", sh(t), "-c", "echo RAN"); !errors.Is(err, ErrUnavailable) || len(out) != 0 {
			t.Errorf("as root with %+v: %v %s", missing, err, out)
		}
	}
	// Root never runs a program unconfined.
	if out, err := (Options{Unconfined: true}).Run(t.Context(), "", sh(t), "-c", "echo RAN"); !errors.Is(err, ErrUnavailable) || len(out) != 0 {
		t.Errorf("as root, unconfined: %v %s", err, out)
	}
}

// REG-01: the helper checks the credentials it took, whatever Run asked:
// started directly with -1 (4294967295) as its UID or GID, which setresuid
// and setresgid take as "unchanged", it refuses to run the program instead
// of running it as root.
func TestAsRootTheHelperChecksItsCredentials(t *testing.T) {
	requireRoot(t)
	for _, ids := range [][2]string{{"4294967295", "4294967295"}, {"61999", "4294967295"}, {"4294967295", "61999"}} {
		cmd, _, done := helperCommand(t, ids[0], ids[1], "1", testToolsFilter, "-", sh(t), "-c", "echo RAN")
		out, err := cmd.Output()
		reason := done()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 125 || strings.Contains(string(out), "RAN") || !strings.Contains(reason, "credentials") {
			t.Errorf("UID %s GID %s: %v %s (%s)", ids[0], ids[1], err, out, reason)
		}
	}
}

// REG-01: as root, an image root could write (0644), in a directory the
// dedicated account cannot enter (0700), is read through the descriptor the
// sandbox opened; the program writes neither it nor anything else.
func TestAsRootTheDedicatedAccountCannotWrite(t *testing.T) {
	o := requireRoot(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("an image root may write"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := o.Run(t.Context(), image, sh(t), "-c", "exec cat "+ImagePath)
	if err != nil || string(out) != "an image root may write" {
		t.Fatalf("the program could not read the image: %v %q", err, out)
	}
	cannotWrite(t, o, image, filepath.Join(dir, "written"))
}

// REG-01: as root (no user namespace), the program cannot reach the network.
func TestAsRootTheProgramCannotReachTheNetwork(t *testing.T) {
	requireRoot(t)
	cannotReachTheNetwork(t, nil, rootTestUID)
}

// REG-01: as root, a program that hangs is killed at the time limit, one
// that spins at the processor limit.
func TestAsRootTheProgramIsKilledAtItsLimits(t *testing.T) {
	killedAtLimits(t, requireRoot(t))
}

// REG-01: as root, the dedicated account opens no device node, /dev/null
// included.
func TestAsRootTheProgramCannotOpenDevices(t *testing.T) {
	cannotOpenDevices(t, requireRoot(t))
}
