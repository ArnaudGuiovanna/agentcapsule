package harnesspkg

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

var statLine = regexp.MustCompile(`Type: (\S+)\s+Mode:\s+([0-7]+)`)

// debugfs is the absolute path of debugfs on PATH.
func debugfs() (string, error) {
	p, err := exec.LookPath("debugfs")
	if err != nil {
		return "", fmt.Errorf("debugfs (e2fsprogs) is required to inspect harness images: %w", err)
	}
	return filepath.Abs(p)
}

// InspectRootfs checks, without mounting, that the image can start under the
// guest base: every mount point is a directory and the entrypoint is an
// executable regular file (or a symlink, resolved by the guest kernel). It
// reads the image with debugfs (e2fsprogs), read-only, confined by sb:
// debugfs parses an image downloaded from a registry, and a flaw of
// e2fsprogs must not reach the host (package sandbox).
func InspectRootfs(ctx context.Context, image string, m HarnessManifest, sb sandbox.Options) error {
	debugfs, err := debugfs()
	if err != nil {
		return err
	}
	stat := func(p string) (string, int64, error) {
		if strings.ContainsAny(p, "\"\n") {
			return "", 0, invalid("path %q", p)
		}
		out, err := sb.Run(ctx, image, debugfs, "-R", "stat \""+p+"\"", sandbox.ImagePath)
		if err != nil {
			return "", 0, fmt.Errorf("debugfs: %w", err)
		}
		match := statLine.FindSubmatch(out)
		if match == nil {
			return "", 0, nil // not found
		}
		mode, _ := strconv.ParseInt(string(match[2]), 8, 64)
		return string(match[1]), mode, nil
	}
	for _, mp := range MountPoints {
		kind, _, err := stat(mp)
		if err != nil {
			return err
		}
		if kind != "directory" {
			return invalid("mount point %s is missing", mp)
		}
	}
	kind, mode, err := stat(m.Entrypoint[0])
	if err != nil {
		return err
	}
	if kind == "symlink" || kind == "regular" && mode&0o111 != 0 {
		return nil
	}
	return invalid("entrypoint %s is not an executable file", m.Entrypoint[0])
}

// CheckInspection runs debugfs -V as InspectRootfs runs debugfs, confined by
// sb: whether this host can inspect images, before any is downloaded.
func CheckInspection(ctx context.Context, sb sandbox.Options) error {
	debugfs, err := debugfs()
	if err != nil {
		return err
	}
	if _, err = sb.Run(ctx, "", debugfs, "-V"); err != nil {
		return fmt.Errorf("debugfs: %w", err)
	}
	return nil
}
