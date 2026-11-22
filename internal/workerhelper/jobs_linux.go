//go:build linux

package workerhelper

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"golang.org/x/sys/unix"
)

// Sandbox runs the plan's program confined, as its UID (package sandbox):
// the image is the worker's descriptor, reopened read-only by its path in
// the confined namespace.
func (System) Sandbox(ctx context.Context, p SandboxPlan) ([]byte, error) {
	o := sandbox.Options{UID: p.UID, GID: p.UID, Timeout: p.Timeout, CPU: p.CPU}
	in, path := p.Image, p.ImagePath
	if in == nil {
		null, err := os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		defer null.Close()
		in, path = null, "-"
	}
	if p.Self != "" {
		return o.RunExecutable(ctx, in, path, p.Input, p.Executable, p.Self, p.Args...)
	}
	return o.RunFile(ctx, in, path, p.Input, p.Program, p.Args...)
}

// sandboxOutputFile carries a large listing in an anonymous file owned by this
// response. The worker reads it at offset zero. It has no path on disk.
func sandboxOutputFile(output []byte) ([]*os.File, error) {
	if len(output) > sandbox.MaxOutput {
		return nil, fmt.Errorf("%w: sandbox output exceeds its limit", ErrFailed)
	}
	fd, err := unix.MemfdCreate("sandbox-output", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "sandbox-output")
	if _, err = f.Write(output); err == nil {
		_, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return []*os.File{f}, nil
}

// Fetch runs the archive shipper's fetch of one archive from one store into
// the archive root. The shipper runs rclone as its own account and writes
// the archive as Owner (agentcapsule-archive-ship.py --owner).
func (System) Fetch(ctx context.Context, p FetchPlan) error {
	args := append(slices.Clone(p.Command[1:]), "--archive-root", p.Root, "fetch", "--store", p.Store, "--archive", p.Archive, "--owner", p.Owner)
	cmd := exec.CommandContext(ctx, p.Command[0], args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		return fmt.Errorf("%w: fetch from %s: %v: %s", ErrFailed, p.Store, err, lines[len(lines)-1])
	}
	return nil
}
