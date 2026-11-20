// Package ext4image builds and checks the read-only ext4 images of harness
// and corpus packages, without root privileges and without mounting
// anything: reproducible builds with mkfs.ext4 -d (Build), the superblock
// the host reads directly (ReadSuperblock), and the confined debugfs that
// reads an image from outside (Stat, List).
package ext4image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Spec is one build. Dir is a prepared tree: its paths become the image's,
// with their modes and contents. Paths lists every path of Dir in the image
// ("/a/b"); Build sets each one's owner to root and its times to 1, and its
// mode when Modes names it.
type Spec struct {
	// Kind names what is built, for error messages: "a harness".
	Kind string
	Dir  string
	Out  string
	// SizeMiB is the filesystem's size; Out is created or truncated to it.
	SizeMiB int
	Label   string
	// UUID is the filesystem's UUID and its directory hash seed.
	UUID string
	// Options are extra mkfs.ext4 options, given before -E: features,
	// block size, inode count. Extended are extra -E options, after
	// root_owner and hash_seed: mkfs.ext4 reads only its last -E.
	Options  []string
	Extended []string
	Paths    []string
	// Modes sets the mode (type and permission bits, as stat's st_mode) of
	// the paths it names, after mkfs.ext4 copied Dir's.
	Modes map[string]uint32
}

// ErrFull: the filesystem's size or inode count is too small for the tree.
var ErrFull = errors.New("the image is too small for its tree")

// SeedUUID formats the first 16 bytes of seed as a UUID, as BuildRootfs
// derives a harness image's from its name and version.
func SeedUUID(seed [sha256.Size]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", seed[0:4], seed[4:6], seed[6:8], seed[8:10], seed[10:16])
}

// Build runs mkfs.ext4 -d on s.Dir, then debugfs -w on the image file to
// give every inode the same owner and times, whoever built it and whenever:
// mkfs copies owners, change times and nanoseconds from Dir, which cannot be
// set there. Identical inputs give an identical image. Nothing is mounted.
func Build(ctx context.Context, s Spec) error {
	mkfs, debugfs, err := tools(s.Kind)
	if err != nil {
		return err
	}
	env := append(os.Environ(), "E2FSPROGS_FAKE_TIME=1", "LC_ALL=C")
	args := append([]string{"-q", "-F", "-t", "ext4", "-L", s.Label, "-U", s.UUID}, s.Options...)
	extended := strings.Join(append([]string{"root_owner=0:0", "hash_seed=" + s.UUID}, s.Extended...), ",")
	args = append(args, "-E", extended, "-d", s.Dir, s.Out, strconv.Itoa(s.SizeMiB)+"M")
	cmd := exec.CommandContext(ctx, mkfs, args...)
	cmd.Env = env
	if b, err := cmd.CombinedOutput(); err != nil {
		if bytes.Contains(b, []byte("Could not allocate")) || bytes.Contains(b, []byte("No space left")) {
			return fmt.Errorf("mkfs.ext4 failed: %w: %w: %s", err, ErrFull, firstLine(b))
		}
		return fmt.Errorf("mkfs.ext4 failed: %w: %s", err, firstLine(b))
	}
	var script strings.Builder
	for _, p := range append([]string{"/", "/lost+found"}, s.Paths...) {
		fmt.Fprintf(&script, "sif \"%s\" uid 0\nsif \"%s\" gid 0\n", p, p)
		for _, field := range []string{"atime", "mtime", "ctime", "crtime"} {
			fmt.Fprintf(&script, "sif \"%s\" %s @1\nsif \"%s\" %s_extra 0\n", p, field, p, field)
		}
		if mode, ok := s.Modes[p]; ok {
			fmt.Fprintf(&script, "sif \"%s\" mode 0%o\n", p, mode)
		}
	}
	fix := exec.CommandContext(ctx, debugfs, "-w", "-f", "-", s.Out)
	fix.Env, fix.Stdin = env, strings.NewReader(script.String())
	if b, err := fix.CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs failed: %w: %s", err, firstLine(b))
	}
	return nil
}

// CheckTools reports whether mkfs.ext4 and debugfs (e2fsprogs) are on PATH,
// as Build needs them to build kind ("a harness").
func CheckTools(kind string) error {
	_, _, err := tools(kind)
	return err
}

func tools(kind string) (mkfs, debugfs string, err error) {
	if mkfs, err = exec.LookPath("mkfs.ext4"); err != nil {
		return "", "", fmt.Errorf("mkfs.ext4 (e2fsprogs) is required to build %s: %w", kind, err)
	}
	if debugfs, err = exec.LookPath("debugfs"); err != nil {
		return "", "", fmt.Errorf("debugfs (e2fsprogs) is required to build %s: %w", kind, err)
	}
	return mkfs, debugfs, nil
}

// Quotable reports whether a path can be named in a debugfs command between
// double quotes: debugfs has no escape for '"', a newline or a backslash.
func Quotable(p string) bool {
	return !strings.ContainsAny(p, "\"\n\\")
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' || i >= 200 {
			return string(b[:i])
		}
	}
	return string(b)
}
