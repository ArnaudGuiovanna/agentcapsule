package ext4image

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes files (name to content) under a new directory and returns it
// with the image paths of its directories and files, in lexical order.
func tree(t *testing.T, files map[string]string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	seen := map[string]bool{}
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		for d := filepath.ToSlash(name); d != "."; d = filepath.ToSlash(filepath.Dir(d)) {
			seen["/"+d] = true
		}
	}
	var paths []string
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, p)
		if err == nil && rel != "." {
			paths = append(paths, "/"+filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil || len(paths) != len(seen) {
		t.Fatal(paths, err)
	}
	return dir, paths
}

func digest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// REG-04: Build runs exactly the commands harnesspkg.BuildRootfs ran before
// they were shared, so harness images keep their digests: the image equals
// the one those command lines, written out here, make.
func TestBuildRunsTheCommandsHarnessBuildsRan(t *testing.T) {
	dir, paths := tree(t, map[string]string{"bin/harness": "x", "opt/app/a": "aaa", "tmp/.keep": ""})
	uuid := SeedUUID(sha256.Sum256([]byte("echo\x001.0.0")))
	out := filepath.Join(t.TempDir(), "shared.ext4")
	err := Build(t.Context(), Spec{Kind: "a harness", Dir: dir, Out: out, SizeMiB: 2, Label: "harness", UUID: uuid,
		Options: []string{"-O", "^has_journal"}, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	literal := filepath.Join(t.TempDir(), "literal.ext4")
	env := append(os.Environ(), "E2FSPROGS_FAKE_TIME=1", "LC_ALL=C")
	mkfs := exec.CommandContext(t.Context(), "mkfs.ext4", "-q", "-F", "-t", "ext4", "-L", "harness", "-U", uuid,
		"-O", "^has_journal", "-E", "root_owner=0:0,hash_seed="+uuid, "-d", dir, literal, "2M")
	mkfs.Env = env
	if b, err := mkfs.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	var script strings.Builder
	for _, p := range append([]string{"/", "/lost+found"}, paths...) {
		fmt.Fprintf(&script, "sif \"%s\" uid 0\nsif \"%s\" gid 0\n", p, p)
		for _, field := range []string{"atime", "mtime", "ctime", "crtime"} {
			fmt.Fprintf(&script, "sif \"%s\" %s @1\nsif \"%s\" %s_extra 0\n", p, field, p, field)
		}
	}
	fix := exec.CommandContext(t.Context(), "debugfs", "-w", "-f", "-", literal)
	fix.Env, fix.Stdin = env, strings.NewReader(script.String())
	if b, err := fix.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	if digest(t, out) != digest(t, literal) {
		t.Fatal("the shared build made another image than the harness build's commands")
	}
}

// Modes replaces the modes mkfs.ext4 copied; every inode belongs to root
// and has the times 1, whoever built it.
func TestBuildSetsModesOwnersAndTimes(t *testing.T) {
	dir, paths := tree(t, map[string]string{"a/b": "x"})
	if err := os.Chmod(filepath.Join(dir, "a/b"), 0o4755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "image.ext4")
	err := Build(t.Context(), Spec{Kind: "a test image", Dir: dir, Out: out, SizeMiB: 2, Label: "test",
		UUID: "01234567-89ab-cdef-0123-456789abcdef", Options: []string{"-O", "^has_journal"}, Paths: paths,
		Modes: map[string]uint32{"/a/b": TypeRegular | 0o644, "/a": TypeDir | 0o750}})
	if err != nil {
		t.Fatal(err)
	}
	stat := func(p string) string {
		b, err := exec.CommandContext(t.Context(), "debugfs", "-R", "stat \""+p+"\"", out).Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for p, mode := range map[string]string{"/a/b": "Mode:  0644", "/a": "Mode:  0750"} {
		s := stat(p)
		if !strings.Contains(s, mode) || !strings.Contains(s, "User:     0   Group:     0") ||
			!strings.Contains(s, "mtime: 0x00000001:00000000") || !strings.Contains(s, "ctime: 0x00000001:00000000") {
			t.Errorf("%s:\n%s", p, s)
		}
	}
}

func TestReadSuperblockReadsTheFieldsAndRefusesDamage(t *testing.T) {
	dir, paths := tree(t, map[string]string{"f": "x"})
	out := filepath.Join(t.TempDir(), "image.ext4")
	uuid := "01234567-89ab-cdef-0123-456789abcdef"
	err := Build(t.Context(), Spec{Kind: "a test image", Dir: dir, Out: out, SizeMiB: 4, Label: "corpus", UUID: uuid,
		Options: []string{"-O", "^has_journal"}, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := ReadSuperblock(f, 4<<20)
	if err != nil || s.UUID != uuid || s.Label != "corpus" || s.BlockSize*s.Blocks != 4<<20 || s.Inodes == 0 ||
		s.State != 1 || s.Compat&CompatHasJournal != 0 || s.Incompat&IncompatExtents == 0 {
		t.Fatalf("%+v %v", s, err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for reason, change := range map[string]func([]byte){
		"is not an ext4 filesystem": func(b []byte) { b[1024+0x38] = 0 },
		"block size":                func(b []byte) { binary.LittleEndian.PutUint32(b[1024+0x18:], 9) },
		"is larger than its file":   func(b []byte) { binary.LittleEndian.PutUint32(b[1024+0x04:], 1<<30) },
	} {
		b := bytes.Clone(raw)
		change(b)
		var refusal *SuperblockError
		if _, err := ReadSuperblock(bytes.NewReader(b), int64(len(b))); !errors.As(err, &refusal) || refusal.Reason != reason {
			t.Errorf("%s: %v", reason, err)
		}
	}
	var refusal *SuperblockError
	if _, err := ReadSuperblock(bytes.NewReader(raw[:1500]), 1500); !errors.As(err, &refusal) || refusal.Reason != "superblock unreadable" {
		t.Error("a short image:", err)
	}
}
