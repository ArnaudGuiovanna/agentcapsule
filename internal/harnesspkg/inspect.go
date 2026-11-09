package harnesspkg

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var statLine = regexp.MustCompile(`Type: (\S+)\s+Mode:\s+([0-7]+)`)

// InspectRootfs checks, without mounting, that the image can start under the
// guest base: every mount point is a directory and the entrypoint is an
// executable regular file (or a symlink, resolved by the guest kernel). It
// reads the image with debugfs (e2fsprogs) in read-only mode.
func InspectRootfs(ctx context.Context, image string, m HarnessManifest) error {
	debugfs, err := exec.LookPath("debugfs")
	if err != nil {
		return fmt.Errorf("debugfs (e2fsprogs) is required to inspect harness images: %w", err)
	}
	stat := func(p string) (string, int64, error) {
		if strings.ContainsAny(p, "\"\n") {
			return "", 0, invalid("path %q", p)
		}
		cmd := exec.CommandContext(ctx, debugfs, "-R", "stat \""+p+"\"", image)
		cmd.Env = []string{"LC_ALL=C"}
		out, err := cmd.Output()
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
