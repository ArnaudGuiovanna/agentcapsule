//go:build linux

package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// statusFD is the helper's descriptor for the reason it could not set the
// sandbox up. It is closed when the program starts.
const statusFD = 4

// helperPath is this executable, even if replaced on disk since it started.
const helperPath = "/proc/self/exe"

// AsRoot reports whether runs here take Options.UID and GID: the caller is
// root in the initial user namespace. Root of another user namespace (a
// container, a test under unshare -r) cannot, and runs the program in a user
// namespace of its own like any other account.
func AsRoot() bool {
	if os.Geteuid() != 0 {
		return false
	}
	b, err := os.ReadFile("/proc/self/uid_map")
	f := strings.Fields(string(b))
	return err == nil && len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}

// Run runs program, an absolute path, with args, confined (see the package
// documentation), and returns its standard output, at most 1 MiB of it.
// image, when not empty, is open read-only for the program as ImagePath. The
// program's environment is LC_ALL=C alone, its standard input empty, its
// standard error discarded. A sandbox that cannot be set up fails with
// ErrUnavailable, a program killed at its limits with ErrLimit.
func (o Options) Run(ctx context.Context, image, program string, args ...string) ([]byte, error) {
	o = o.withDefaults()
	if !filepath.IsAbs(program) {
		return nil, fmt.Errorf("sandbox: %s is not an absolute path", program)
	}
	root := AsRoot()
	if root && !o.Unconfined && (o.UID == 0 || o.GID == 0) {
		return nil, fmt.Errorf("%w: as root, a dedicated UID and GID other than 0 are required", ErrUnavailable)
	}
	if o.TestTools && !testing.Testing() {
		return nil, fmt.Errorf("%w: the test tools' filter outside a test binary", ErrUnavailable)
	}
	path := "-"
	if image != "" {
		abs, err := filepath.Abs(image)
		if err != nil {
			return nil, err
		}
		path = abs
	}
	in, err := os.Open(cmp.Or(image, os.DevNull))
	if err != nil {
		return nil, err
	}
	defer in.Close()
	status, report, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer status.Close()
	defer report.Close()
	limited, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	name, argv, files := program, args, []*os.File{in}
	var attributes *syscall.SysProcAttr
	if !o.Unconfined {
		uid, gid := o.UID, o.GID
		if !root {
			uid, gid = 0, 0 // root of the helper's own user namespace: the caller
		}
		name = helperPath
		filter := strictFilter
		if o.TestTools {
			filter = testToolsFilter
		}
		argv = append([]string{strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10),
			strconv.FormatUint(o.cpuSeconds(), 10), filter, path, program}, args...)
		files = append(files, report)
		attributes = namespaces(root)
	}
	cmd := exec.CommandContext(limited, name, argv...)
	if !o.Unconfined {
		cmd.Args[0] = HelperName
	}
	cmd.SysProcAttr = attributes
	cmd.Env = []string{"LC_ALL=C"}
	cmd.ExtraFiles = files
	var out bounded
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	// The helper is killed when the thread that started it ends (Pdeathsig):
	// keep that thread until it is done.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = cmd.Start(); err != nil {
		if o.Unconfined {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	report.Close()
	err = cmd.Wait()
	reason, _ := io.ReadAll(io.LimitReader(status, 4096))
	var exit *exec.ExitError
	switch {
	case len(reason) > 0:
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, reason)
	case err == nil:
		return out.Bytes(), nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case limited.Err() != nil:
		return nil, fmt.Errorf("%w: %s elapsed", ErrLimit, o.Timeout)
	case errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signaled():
		switch exit.Sys().(syscall.WaitStatus).Signal() {
		case syscall.SIGKILL:
			return nil, fmt.Errorf("%w: killed (processor time or memory)", ErrLimit)
		case syscall.SIGSYS:
			return nil, ErrSyscall
		}
	}
	return nil, err
}

// namespaces are the helper's: new mount, network, PID, IPC and UTS
// namespaces, and a user namespace of its own unless the caller is root. It
// has no terminal, and dies with its parent.
func namespaces(root bool) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Setsid:     true,
		Pdeathsig:  syscall.SIGKILL,
	}
	if !root {
		a.Cloneflags |= syscall.CLONE_NEWUSER
		a.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		a.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	}
	return a
}

// bounded keeps the first maxOutput bytes written and discards the rest.
type bounded struct{ bytes.Buffer }

func (b *bounded) Write(p []byte) (int, error) {
	if room := maxOutput - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
