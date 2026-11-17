//go:build linux

package worker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// hostTraps are programs a host could run a package's content with: an
// interpreter, a mount, a loop device, a container runtime, a filesystem
// tool that writes. Each one, in this test's PATH, announces itself.
var hostTraps = []string{"sh", "bash", "dash", "busybox", "env", "python3", "perl", "mount", "umount", "losetup", "chroot", "unshare",
	"nsenter", "mkfs.ext4", "mke2fs", "e2fsck", "fsck", "fuse2fs", "resize2fs", "tune2fs", "tar", "unsquashfs", "cp", "ln", "harness",
	"firecracker", "jailer", "docker", "podman", "runc", "crun", "cosign", "oras", "skopeo", "cryptsetup"}

// REG-007: the host pulls a package, validates it and boots it in a VM;
// nothing else runs it. The package here would announce any run on the
// host: its entrypoint, a script, and its manifest's text, written as shell,
// each write a marker file on the host. The import, the refill of a lost
// cache and the eviction run with a PATH where every program a host could
// run them with announces itself, and debugfs logs its arguments and whether
// it runs confined. Programs report through a FIFO, which a confined one can
// still write. None of the markers exists after; the only program started is
// debugfs, read-only (-R stat), confined (no_new_privs, seccomp, PID 1 of its
// namespace, REG-01), on the image its sandbox opened; and the cache holds
// the package's files byte for byte, none writable or executable.
func TestTheHostNeverRunsWhatAPackageHolds(t *testing.T) {
	l := newImportLab(t)
	ctx := t.Context()
	markers := t.TempDir()
	marker := func(name string) string { return filepath.Join(markers, name) }
	src := t.TempDir()
	script := "#!/bin/sh\necho ran > " + marker("entrypoint") + "\n"
	if err := os.WriteFile(filepath.Join(src, "harness"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "usr/bin/setup"), []byte("#!/bin/sh\necho ran > "+marker("setup")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "announcer", Version: "1.0.0", Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase,
		Entrypoint:  []string{"/harness", "$(echo ran > " + marker("argument") + ")"},
		Description: "`echo ran > " + marker("description") + "`"}
	built := t.TempDir()
	if err := harnesspkg.BuildRootfs(ctx, m, src, filepath.Join(built, harnesspkg.RootfsFile), 1); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(built, m); err != nil {
		t.Fatal(err)
	}
	ref, err := ociregistry.Push(ctx, l.rule, "acme/announcer", "1.0.0", built)
	if err != nil {
		t.Fatal(err)
	}

	// From here, every program is found in traps only.
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		t.Fatal(err)
	}
	traps := t.TempDir()
	// A confined program writes no file, but can write a FIFO: the reports
	// wait in it, read at the end.
	reports := filepath.Join(t.TempDir(), "reports")
	if err = syscall.Mkfifo(reports, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo, err := os.OpenFile(reports, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.Close()
	// debugfs reports its arguments, and whether it runs with no_new_privs,
	// under seccomp, as PID 1 of its namespace; with shell builtins only.
	trap := `#!/bin/sh
nnp= filter= pid=
while read -r key value rest; do
  case $key in NoNewPrivs:) nnp=$value;; Seccomp:) filter=$value;; NSpid:) pid=$value;; esac
done < /proc/self/status
confined=unconfined
[ "$nnp" = 1 ] && [ "$filter" = 2 ] && [ "$pid" = 1 ] && confined=confined
printf 'debugfs %s %s\n' "$confined" "$*" >> ` + reports + `
exec ` + debugfs + ` "$@"
`
	if err = os.WriteFile(filepath.Join(traps, "debugfs"), []byte(trap), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range hostTraps {
		trap := fmt.Sprintf("#!/bin/sh\nprintf 'forbidden %s %%s\\n' \"$*\" >> %s\nexit 1\n", name, reports)
		if err = os.WriteFile(filepath.Join(traps, name), []byte(trap), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", traps)

	imp := l.request(t, "announcer", ref.String())
	l.importOne(t)
	if done := l.state(t, imp.ID); done.State != "READY" {
		t.Fatal("the package was not imported", done)
	}
	dir := l.importer.PackageDir(ref.Digest)
	cachedAsBuilt := func(step string) {
		t.Helper()
		for _, name := range []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile} {
			want, err := os.ReadFile(filepath.Join(built, name))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal(step, ": the cached", name, "is not the published one", err)
			}
			if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o444 {
				t.Fatal(step, ": the cached", name, "is writable or executable", st.Mode(), err)
			}
		}
		if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o555 {
			t.Fatal(step, ": the package's directory", st.Mode(), err)
		}
	}
	cachedAsBuilt("import")

	// A host whose cache is lost fetches the package again (OPR-10).
	l.pinAgent(t, "announcer")
	if err = removeTree(dir); err != nil {
		t.Fatal(err)
	}
	l.importer.host = "local"
	if refilled, err := l.importer.Refill(ctx); err != nil || len(refilled) != 1 {
		t.Fatal("refill", refilled, err)
	}
	cachedAsBuilt("refill")
	// Its release deprecated and its agent gone, the package is evicted.
	if _, err = l.db.Exec(ctx, "UPDATE agents SET phase='DELETED' WHERE id=(SELECT agent_id FROM agent_specs WHERE name='On announcer')"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.accounts.DeprecateHarnessRelease(ctx, l.platform, l.state(t, imp.ID).ReleaseID, "deprecate-announcer"); err != nil {
		t.Fatal(err)
	}
	none := func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }
	l.importer.inUse.Store(&none)
	if evicted, err := l.importer.Evict(ctx); err != nil || len(evicted) != 1 {
		t.Fatal("eviction", evicted, err)
	}

	for _, name := range []string{"entrypoint", "setup", "argument", "description"} {
		if _, err = os.Stat(marker(name)); !os.IsNotExist(err) {
			t.Error("the host ran the package's", name, err)
		}
	}
	if err = fifo.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var log []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := fifo.Read(buf)
		log = append(log, buf[:n]...)
		if err != nil {
			break
		}
	}
	// Each mount point and the entrypoint, at the import and at the refill;
	// nothing else.
	readOnly := regexp.MustCompile(`^debugfs confined -R stat "/[^"]*" ` + regexp.QuoteMeta(sandbox.ImagePath) + `$`)
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(lines) != 2*(len(harnesspkg.MountPoints)+1) {
		t.Fatal("the programs started:", len(lines), lines)
	}
	for _, line := range lines {
		if !readOnly.MatchString(line) {
			t.Error("the host started a program other than debugfs, read-only and confined:", line)
		}
	}
}
