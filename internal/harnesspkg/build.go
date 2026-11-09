package harnesspkg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// BuildRootfs creates a read-only harness filesystem from srcDir with
// `mkfs.ext4 -d`: no root privileges, no mount. The UUID, hash seed and
// timestamps are derived from the manifest so identical inputs give an
// identical image (file modes and contents still come from srcDir).
func BuildRootfs(ctx context.Context, m HarnessManifest, srcDir, out string, sizeMiB int) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if sizeMiB < 1 || sizeMiB > 64<<10 {
		return invalid("rootfs size")
	}
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		return fmt.Errorf("mkfs.ext4 (e2fsprogs) is required to build a harness: %w", err)
	}
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		return fmt.Errorf("debugfs (e2fsprogs) is required to build a harness: %w", err)
	}
	// Stage a copy with fixed timestamps, so checkout times do not leak in.
	stage, err := os.MkdirTemp("", "harness-rootfs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	paths, err := stageTree(srcDir, stage)
	if err != nil {
		return err
	}
	seed := sha256.Sum256([]byte(m.Name + "\x00" + m.Version))
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", seed[0:4], seed[4:6], seed[6:8], seed[8:10], seed[10:16])
	env := append(os.Environ(), "E2FSPROGS_FAKE_TIME=1", "LC_ALL=C")
	cmd := exec.CommandContext(ctx, mkfs, "-q", "-F", "-t", "ext4", "-L", "harness", "-U", uuid,
		"-O", "^has_journal", "-E", "root_owner=0:0,hash_seed="+uuid, "-d", stage, out, strconv.Itoa(sizeMiB)+"M")
	cmd.Env = env
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %w: %s", err, firstLine(b))
	}
	// Every inode belongs to root and carries the same times, whoever built it
	// and whenever: mkfs copies change times and nanoseconds from the staging
	// copy, which cannot be set there. debugfs edits the image file directly;
	// nothing is mounted.
	var script strings.Builder
	for _, p := range append([]string{"/", "/lost+found"}, paths...) {
		fmt.Fprintf(&script, "sif \"%s\" uid 0\nsif \"%s\" gid 0\n", p, p)
		for _, field := range []string{"atime", "mtime", "ctime", "crtime"} {
			fmt.Fprintf(&script, "sif \"%s\" %s @1\nsif \"%s\" %s_extra 0\n", p, field, p, field)
		}
	}
	fix := exec.CommandContext(ctx, debugfs, "-w", "-f", "-", out)
	fix.Env, fix.Stdin = env, strings.NewReader(script.String())
	if b, err := fix.CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs failed: %w: %s", err, firstLine(b))
	}
	return nil
}

// stageTree copies regular files, directories and symlinks with their modes
// and a fixed modification time, and returns the image paths ("/bin/x"). Any
// other file type, or a path debugfs cannot quote, is refused.
func stageTree(src, dst string) ([]string, error) {
	fixed := time.Unix(1, 0)
	var paths []string
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if strings.ContainsAny(rel, "\"\n\\") {
			return invalid("file name %q cannot be packaged", rel)
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case rel == ".":
			return nil
		case d.IsDir():
			err = os.Mkdir(target, info.Mode().Perm())
		case d.Type()&fs.ModeSymlink != 0:
			var link string
			if link, err = os.Readlink(p); err == nil {
				err = os.Symlink(link, target)
			}
		case d.Type().IsRegular():
			err = copyFile(p, target, info.Mode().Perm())
		default:
			return invalid("unsupported file type at %s", rel)
		}
		if err != nil {
			return err
		}
		paths = append(paths, "/"+filepath.ToSlash(rel))
		if d.Type()&fs.ModeSymlink == 0 {
			return os.Chtimes(target, fixed, fixed)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Directory times change as entries are added; fix them last, deepest first.
	for i := len(paths) - 1; i >= 0; i-- {
		t := filepath.Join(dst, filepath.FromSlash(paths[i]))
		if st, err := os.Lstat(t); err == nil && st.IsDir() {
			if err = os.Chtimes(t, fixed, fixed); err != nil {
				return nil, err
			}
		}
	}
	return paths, nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// WritePackage writes harness.yaml and checksums.json next to an existing
// dir/harness.ext4, completing a package ready for ociregistry.Push.
func WritePackage(dir string, m HarnessManifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	manifest, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, ManifestFile), manifest, 0o644); err != nil {
		return err
	}
	rootfs, err := os.ReadFile(filepath.Join(dir, RootfsFile))
	if err != nil {
		return err
	}
	sums, err := json.MarshalIndent(Checksums{Files: map[string]string{ManifestFile: Digest(manifest), RootfsFile: Digest(rootfs)}}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ChecksumsFile), append(sums, '\n'), 0o644)
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' || i >= 200 {
			return string(b[:i])
		}
	}
	return string(b)
}
