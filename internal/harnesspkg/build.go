package harnesspkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
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
	if err := ext4image.CheckTools("a harness"); err != nil {
		return err
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
	if paths, err = addMountPoints(stage, paths, m.Base); err != nil {
		return err
	}
	seed := sha256.Sum256([]byte(m.Name + "\x00" + m.Version))
	uuid := ext4image.SeedUUID(seed)
	return ext4image.Build(ctx, ext4image.Spec{Kind: "a harness", Dir: stage, Out: out, SizeMiB: sizeMiB,
		Label: "harness", UUID: uuid, Options: []string{"-O", "^has_journal"}, Paths: paths})
}

// stageTree copies regular files, directories and symlinks with their modes
// and a fixed modification time, and returns the image paths ("/bin/x"). Any
// other file type, or a path debugfs cannot quote, is refused.
func stageTree(src, dst string) ([]string, error) {
	fixed := time.Unix(1, 0)
	var paths []string
	links := make(map[[2]uint64]string)
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
			linked := false
			if id, ok := hardlinkID(info); ok {
				if first, exists := links[id]; exists {
					// Link only to our staged copy. Filesystems without hard-link
					// support retain the original copy-per-path behavior.
					linked = os.Link(first, target) == nil
				} else {
					links[id] = target
				}
			}
			if !linked {
				err = copyFile(p, target, info.Mode().Perm())
			}
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

// addMountPoints creates the empty directories the guest base mounts its
// runtime on (MountPointsOf), unless the harness already provides them as
// directories.
func addMountPoints(stage string, paths []string, base string) ([]string, error) {
	fixed := time.Unix(1, 0)
	for _, mp := range MountPointsOf(base) {
		parts := strings.Split(strings.TrimPrefix(mp, "/"), "/")
		for i := range parts {
			p := "/" + strings.Join(parts[:i+1], "/")
			target := filepath.Join(stage, filepath.FromSlash(p))
			st, err := os.Lstat(target)
			switch {
			case err == nil && st.IsDir():
				continue
			case err == nil:
				return nil, invalid("%s must be a directory: the guest mounts its runtime there", p)
			case !os.IsNotExist(err):
				return nil, err
			}
			if err = os.Mkdir(target, 0o755); err != nil {
				return nil, err
			}
			if err = os.Chtimes(target, fixed, fixed); err != nil {
				return nil, err
			}
			paths = append(paths, p)
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
	rootfs, err := os.Open(filepath.Join(dir, RootfsFile))
	if err != nil {
		return err
	}
	defer rootfs.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rootfs); err != nil {
		return err
	}
	sums, err := json.MarshalIndent(Checksums{Files: map[string]string{ManifestFile: Digest(manifest), RootfsFile: "sha256:" + hex.EncodeToString(h.Sum(nil))}}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ChecksumsFile), append(sums, '\n'), 0o644)
}
