//go:build linux

package ext4image

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// images builds images of several layouts and features with mke2fs, and
// derives special files from one with debugfs -w.
func images(t *testing.T) map[string]string {
	t.Helper()
	src := t.TempDir()
	write := func(name, data string) {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("corpus.json", "{}")
	write("INDEX.md", "# Index\n")
	write("search/fts.sqlite", strings.Repeat("s", 9000))
	for i := range 600 { // an indexed (htree) directory
		write(fmt.Sprintf("docs/d%04d/README.md", i), "x")
	}
	dir := t.TempDir()
	out := map[string]string{}
	for name, options := range map[string][]string{
		"ext4":          {"-t", "ext4", "-O", "^has_journal"},
		"ext4-journal":  {"-t", "ext4"},
		"ext2":          {"-t", "ext2"},
		"ext4-1k":       {"-t", "ext4", "-b", "1024"},
		"ext4-inline":   {"-t", "ext4", "-O", "inline_data"},
		"ext4-casefold": {"-t", "ext4", "-O", "casefold"},
		"ext4-32bit":    {"-t", "ext4", "-O", "^metadata_csum,^64bit"},
	} {
		out[name] = filepath.Join(dir, name)
		cmd := exec.CommandContext(t.Context(), "mke2fs", append(append([]string{"-q", "-F", "-N", "4096"}, options...), "-d", src, out[name], "32M")...)
		cmd.Env = []string{"LC_ALL=C", "E2FSPROGS_FAKE_TIME=1", "PATH=" + os.Getenv("PATH")}
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(name, err, string(b))
		}
	}
	b, err := os.ReadFile(out["ext4"])
	if err != nil {
		t.Fatal(err)
	}
	out["special"] = filepath.Join(dir, "special")
	if err = os.WriteFile(out["special"], b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "debugfs", "-w", "-f", "-", out["special"])
	// mknod names an entry of the working directory: with a path, the name
	// would hold its slashes.
	cmd.Stdin = strings.NewReader("mknod fifo p\ncd /docs\nmknod null c 1 3\nsymlink /docs/link /etc/passwd\n")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	return out
}

// REG-01: confined, debugfs lists and stats every image as it does when run
// directly, byte for byte, and the filter kills it for no call it makes:
// ls -p is not among the commands the allow-list was traced on, so it is
// compared here on each image.
func TestConfinedListAndStatGiveTheSameResult(t *testing.T) {
	debugfs, err := Debugfs()
	if err != nil {
		t.Fatal(err)
	}
	for name, image := range images(t) {
		for _, command := range []string{`ls -p "/"`, `ls -p "/docs"`, `ls -p "/docs/d0599"`, `stat "/INDEX.md"`, `stat "/absent"`} {
			f, err := os.Open(image)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), debugfs, "-R", command, sandbox.ImagePath)
			cmd.Env, cmd.ExtraFiles = []string{"LC_ALL=C"}, []*os.File{f}
			direct, _ := cmd.Output()
			f.Close()
			confined, err := sandbox.Options{}.Run(t.Context(), image, debugfs, "-R", command, sandbox.ImagePath)
			if err != nil {
				t.Errorf("%s %s: %v", name, command, err)
				continue
			}
			if !bytes.Equal(direct, confined) {
				t.Errorf("%s %s: confined, debugfs printed\n%s\ninstead of\n%s", name, command, confined, direct)
			}
		}
		root, err := List(t.Context(), sandbox.Options{}, debugfs, image, "/")
		if err != nil || len(root) < 4 {
			t.Errorf("%s: %v %v", name, root, err)
		}
		docs, err := List(t.Context(), sandbox.Options{}, debugfs, image, "/docs")
		if err != nil || len(docs) < 600 {
			t.Errorf("%s /docs: %d entries, %v", name, len(docs), err)
		}
		e, found, err := Stat(t.Context(), sandbox.Options{}, debugfs, image, "/search/fts.sqlite")
		if err != nil || !found || !e.IsRegular() || e.Size != 9000 || e.Mode&0o777 != 0o644 {
			t.Errorf("%s: %+v %v %v", name, e, found, err)
		}
		if _, found, err = Stat(t.Context(), sandbox.Options{}, debugfs, image, "/absent"); found || err != nil {
			t.Errorf("%s: an absent file: %v %v", name, found, err)
		}
	}
}

func TestListShowsEachEntrysTypeAndMode(t *testing.T) {
	debugfs, err := Debugfs()
	if err != nil {
		t.Fatal(err)
	}
	image := images(t)["special"]
	got := map[string]uint32{}
	for _, dir := range []string{"/", "/docs"} {
		entries, err := List(t.Context(), sandbox.Options{}, debugfs, image, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			got[strings.TrimPrefix(dir+"/", "//")+e.Name] = e.Mode & TypeMask
		}
	}
	for p, want := range map[string]uint32{"corpus.json": TypeRegular, "search": TypeDir, "fifo": 0o010000,
		"/docs/null": 0o020000, "/docs/link": TypeSymlink, "/docs/d0001": TypeDir} {
		if got[strings.TrimPrefix(p, "/")] != want && got[p] != want {
			t.Errorf("%s: %o, want %o", p, got[p], want)
		}
	}
}

// fakeDebugfs puts a shell script named debugfs first on PATH and returns
// its path. It runs under the test tools' filter: builtins only.
func fakeDebugfs(t *testing.T, script string) string {
	t.Helper()
	bin := t.TempDir()
	p := filepath.Join(bin, "debugfs")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A listing out of form is refused, whatever it holds: a name with a
// newline or a slash, a control character, a directory with a size, a
// listing the sandbox may have cut.
func TestListRefusesWhatItCannotParse(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{TestTools: true}
	good := `echo '/2/040755/0/0/.//'; echo '/2/040755/0/0/..//'; echo '/12/100644/0/0/a b/3/'`
	entries, err := List(t.Context(), sb, fakeDebugfs(t, good), image, "/")
	if err != nil || len(entries) != 1 || entries[0].Name != "a b" || entries[0].Size != 3 || !entries[0].IsRegular() {
		t.Fatal(entries, err)
	}
	for name, script := range map[string]string{
		"newline in a name": `echo '/12/100644/0/0/a'; echo 'b/3/'`,
		"slash in a name":   `echo '/12/100644/0/0/a/b/3/'`,
		"control character": `printf '/12/100644/0/0/a\tb/3/\n'`,
		"quote":             `echo '/12/100644/0/0/a"b/3/'`,
		"directory size":    `echo '/12/040755/0/0/a/3/'`,
		"file without size": `echo '/12/100644/0/0/a//'`,
		"short mode":        `echo '/12/644/0/0/a/3/'`,
		"other text":        `echo 'debugfs 1.47.2'`,
		"cut listing": `line='/12/100644/0/0/an-entry-with-a-rather-long-name-to-fill-the-output/3/'
i=0; while [ $i -lt 20000 ]; do echo "$line"; i=$((i+1)); done`,
	} {
		if _, err := List(t.Context(), sb, fakeDebugfs(t, script), image, "/"); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
