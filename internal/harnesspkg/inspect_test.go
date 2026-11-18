//go:build linux

package harnesspkg

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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

// corpus builds images that exercise debugfs beyond a packed harness: other
// file systems and features, special files where the entrypoint is
// expected, flags that ask for recovery, and damaged images (no superblock,
// truncated, garbage, empty, a damaged group descriptor or inode table,
// random bytes changed in the metadata). It returns their paths by name.
func corpus(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	tree := t.TempDir()
	for _, d := range append(append([]string{}, MountPoints...), "/bin", "/opt/app", "/big") {
		if err := os.MkdirAll(filepath.Join(tree, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(tree, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/harness", []byte("#!/bin/sh\n"), 0o755)
	write("opt/app/large", bytes.Repeat([]byte("large file "), 100000), 0o644)
	for i := range 40 {
		write(fmt.Sprintf("opt/app/small-%d", i), bytes.Repeat([]byte("x"), i), 0o644)
	}
	// Enough entries for an indexed (htree) directory.
	for i := range 600 {
		write(fmt.Sprintf("big/an-entry-with-a-rather-long-name-%d", i), nil, 0o644)
	}
	if err := os.Symlink("/bin/harness", filepath.Join(tree, "opt/app/fast-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/"+strings.Repeat("a-long-path-component/", 12)+"target", filepath.Join(tree, "opt/app/slow-link")); err != nil {
		t.Fatal(err)
	}
	images := map[string]string{}
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), name, args...)
		cmd.Env = []string{"LC_ALL=C", "E2FSPROGS_FAKE_TIME=1", "PATH=" + os.Getenv("PATH")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(name, args, err, string(out))
		}
	}
	for name, options := range map[string][]string{
		"ext4":            {"-t", "ext4"},
		"ext4-nojournal":  {"-t", "ext4", "-O", "^has_journal"},
		"ext2":            {"-t", "ext2"},
		"ext3":            {"-t", "ext3"},
		"ext4-1k":         {"-t", "ext4", "-b", "1024"},
		"ext4-64k":        {"-t", "ext4", "-b", "65536"},
		"ext4-inline":     {"-t", "ext4", "-O", "inline_data"},
		"ext4-bigalloc":   {"-t", "ext4", "-O", "bigalloc", "-C", "65536"},
		"ext4-casefold":   {"-t", "ext4", "-O", "casefold"},
		"ext4-mmp":        {"-t", "ext4", "-O", "mmp"},
		"ext4-quota":      {"-t", "ext4", "-O", "quota"},
		"ext4-encrypt":    {"-t", "ext4", "-O", "encrypt,verity"},
		"ext4-32bit":      {"-t", "ext4", "-O", "^metadata_csum,^64bit"},
		"ext4-metabg":     {"-t", "ext4", "-O", "meta_bg,^resize_inode"},
		"ext4-largedir":   {"-t", "ext4", "-O", "large_dir,ea_inode,huge_file"},
		"ext4-sparse2":    {"-t", "ext4", "-O", "sparse_super2"},
		"ext4-inode128":   {"-t", "ext4", "-I", "128"},
		"ext4-one-flexbg": {"-t", "ext4", "-G", "1"},
	} {
		images[name] = filepath.Join(dir, name)
		run("mke2fs", append(append([]string{"-q", "-F", "-N", "2048"}, options...), "-d", tree, images[name], "16M")...)
	}
	derive := func(name string, change func(path string)) {
		t.Helper()
		b, err := os.ReadFile(images["ext4"])
		if err != nil {
			t.Fatal(err)
		}
		images[name] = filepath.Join(dir, name)
		if err = os.WriteFile(images[name], b, 0o644); err != nil {
			t.Fatal(err)
		}
		change(images[name])
	}
	debugfsW := func(script string) func(string) {
		return func(path string) {
			cmd := exec.CommandContext(t.Context(), "debugfs", "-w", "-f", "-", path)
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(err, string(out))
			}
		}
	}
	overwrite := func(offset int64, data []byte) func(string) {
		return func(path string) {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err = f.WriteAt(data, offset); err != nil {
				t.Fatal(err)
			}
		}
	}
	random := rand.New(rand.NewPCG(1, 2))
	noise := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(random.Uint32())
		}
		return b
	}
	derive("entrypoint-fifo", debugfsW("rm /bin/harness\nmknod /bin/harness p\n"))
	derive("entrypoint-device", debugfsW("rm /bin/harness\nmknod /bin/harness c 1 3\n"))
	derive("needs-recovery", debugfsW("feature needs_recovery\n"))
	derive("errors", debugfsW("ssv state 2\n"))
	derive("no-superblock", overwrite(1024, make([]byte, 1024)))
	derive("group-descriptors", overwrite(4096, noise(4096)))
	derive("inode-table", overwrite(64<<10, noise(64<<10)))
	derive("truncated", func(path string) {
		if err := os.Truncate(path, 1<<20); err != nil {
			t.Fatal(err)
		}
	})
	images["garbage"] = filepath.Join(dir, "garbage")
	images["empty"] = filepath.Join(dir, "empty")
	for name, data := range map[string][]byte{"garbage": noise(1 << 20), "empty": nil} {
		if err := os.WriteFile(images[name], data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Bytes changed at random in the first megabyte, where the metadata lies.
	for n := range 12 {
		derive(fmt.Sprintf("fuzzed-%d", n), func(path string) {
			for range 64 {
				overwrite(1024+random.Int64N(1<<20-1024), noise(1))(path)
			}
		})
	}
	return images
}

// REG-01: confined, debugfs reads every image as it does when run directly:
// the same output, byte for byte, for every path the inspection reads, a
// symlink, a file deep in a large directory, and one the image lacks; on a
// packed harness, on images of other features, and on special and damaged
// ones. Run directly, it opens the image the same way: as its descriptor 3,
// through /proc/self/fd/3. The filter kills it for no call it makes.
func TestConfinedDebugfsGivesTheSameResult(t *testing.T) {
	image, m := packed(t)
	debugfs, err := debugfs()
	if err != nil {
		t.Fatal(err)
	}
	images := corpus(t)
	images["packed"] = image
	paths := append(append([]string{}, MountPoints...), m.Entrypoint[0], "/opt/app/fast-link",
		"/big/an-entry-with-a-rather-long-name-599", "/absent")
	for name, image := range images {
		for _, p := range paths {
			f, err := os.Open(image)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), debugfs, "-R", "stat \""+p+"\"", sandbox.ImagePath)
			cmd.Env, cmd.ExtraFiles = []string{"LC_ALL=C"}, []*os.File{f}
			direct, _ := cmd.Output()
			f.Close()
			confined, err := sandbox.Options{}.Run(t.Context(), image, debugfs, "-R", "stat \""+p+"\"", sandbox.ImagePath)
			if err != nil {
				t.Errorf("%s %s: %v", name, p, err)
				continue
			}
			if !bytes.Equal(direct, confined) {
				t.Errorf("%s %s: confined, debugfs printed\n%s\ninstead of\n%s", name, p, confined, direct)
			}
			// Every undamaged image answers for the files it holds.
			readable := name == "packed" || strings.HasPrefix(name, "ext")
			if readable && (slices.Contains(MountPoints, p) || p == m.Entrypoint[0]) && !statLine.Match(confined) {
				t.Errorf("%s %s: no type and mode in\n%s", name, p, confined)
			}
		}
	}
	if err = CheckInspection(t.Context(), sandbox.Options{}); err != nil {
		t.Error("debugfs -V, confined:", err)
	}
}

// fakeDebugfs puts a shell script named debugfs first on PATH.
func fakeDebugfs(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "debugfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// REG-01: InspectRootfs runs every debugfs confined. The debugfs found on
// PATH here answers as a valid image would only when it runs with
// no_new_privs, under seccomp and as PID 1 of its own namespace (a shell
// under the test tools' filter); the inspection then passes.
func TestInspectionRunsDebugfsConfined(t *testing.T) {
	image, m := packed(t)
	// Shell builtins only: the sandbox lets no process start another.
	fakeDebugfs(t, `#!/bin/sh
nnp= filter= pid=
while read -r key value rest; do
  case $key in NoNewPrivs:) nnp=$value;; Seccomp:) filter=$value;; NSpid:) pid=$value;; esac
done < /proc/self/status
[ "$nnp" = 1 ] && [ "$filter" = 2 ] && [ "$pid" = 1 ] && [ "$3" = `+sandbox.ImagePath+` ] || exit 0
case $2 in
  'stat "/bin/harness"') echo 'Inode: 12   Type: regular    Mode:  0755   Flags: 0x0' ;;
  *) echo 'Inode: 2   Type: directory    Mode:  0755   Flags: 0x0' ;;
esac
`)
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{TestTools: true}); err != nil {
		t.Fatal("debugfs ran unconfined:", err)
	}
	// The same debugfs run directly finds nothing.
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{Unconfined: true}); !errors.Is(err, ErrInvalid) {
		t.Fatal("the probe cannot tell a confined debugfs", err)
	}
}

// REG-01: InspectRootfs runs debugfs under the allow-list of debugfs's
// system calls: a debugfs that starts a process, as a compromised one
// would, is killed, and the inspection fails; run directly, it answers.
func TestInspectionKillsADebugfsThatStartsAProcess(t *testing.T) {
	image, m := packed(t)
	fakeDebugfs(t, `#!/bin/sh
answer=$(echo directory)
case $2 in
  'stat "/bin/harness"') echo 'Inode: 12   Type: regular    Mode:  0755   Flags: 0x0' ;;
  *) echo "Inode: 2   Type: $answer    Mode:  0755   Flags: 0x0" ;;
esac
`)
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{}); !errors.Is(err, sandbox.ErrSyscall) {
		t.Fatal("a debugfs that starts a process, confined:", err)
	}
	if err := InspectRootfs(t.Context(), image, m, sandbox.Options{Unconfined: true}); err != nil {
		t.Fatal("the same debugfs, run directly:", err)
	}
}
