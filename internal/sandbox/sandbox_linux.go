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

// The helper's descriptors besides the image (3): the pipe for the reason it
// could not set the sandbox up, and the reading end of its lifeline, a pipe
// whose writing end only Run holds. Both are closed when the program starts.
const (
	statusFD   = 4
	lifelineFD = 5
)

// helperPath is this executable, even if replaced on disk since it started.
const helperPath = "/proc/self/exe"

// AsRoot reports whether runs here take Options.UID and GID: the caller is
// root in the initial user namespace. Root of another user namespace (a
// container, a test under unshare -r) cannot, and Run refuses it; any other
// account runs the program in a user namespace of its own.
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
	return o.RunInput(ctx, image, nil, program, args...)
}

// RunInput is Run with input, at most MaxProgramInput bytes, as the
// program's standard input, through a pipe: commands for it (debugfs -f -), never a secret. The
// confinement is Run's.
func (o Options) RunInput(ctx context.Context, image string, input []byte, program string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(program) {
		return nil, fmt.Errorf("sandbox: %s is not an absolute path", program)
	}
	if len(input) > MaxProgramInput {
		return nil, fmt.Errorf("sandbox: %d bytes of input, at most %d", len(input), MaxProgramInput)
	}
	filter := strictFilter
	if o.TestTools {
		filter = testToolsFilter
	}
	if o.Delegate != nil {
		return o.delegate(ctx, image, Delegated{Program: program, Args: args, Input: input})
	}
	return o.run(ctx, image, input, filter, program, "", args)
}

// delegate runs through o.Delegate, with the image opened by this process.
func (o Options) delegate(ctx context.Context, image string, d Delegated) ([]byte, error) {
	if o.Unconfined || o.TestTools {
		return nil, fmt.Errorf("%w: a delegated run is confined, under the strict or the self filter", ErrUnavailable)
	}
	o = o.withDefaults()
	d.Timeout, d.CPU = o.Timeout, o.CPU
	if image != "" {
		abs, err := filepath.Abs(image)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(abs)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		d.Image, d.ImagePath = f, abs
	}
	return o.Delegate.RunConfined(ctx, d)
}

// RunFile is Run on an image already open, at path: for the worker's
// helper, which runs what a worker that is not root asked (ADR 024). It is
// never unconfined.
func (o Options) RunFile(ctx context.Context, image *os.File, path string, input []byte, program string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(program) || o.Unconfined || o.Delegate != nil || len(input) > MaxProgramInput {
		return nil, fmt.Errorf("%w: an open image runs confined, with an absolute program", ErrUnavailable)
	}
	filter := strictFilter
	if o.TestTools {
		filter = testToolsFilter
	}
	return o.runOpen(ctx, image, path, input, filter, program, "", args)
}

// RunExecutable is RunSelf for the program name of another executable,
// executable, an absolute path: the worker's own, for its helper (ADR 024).
// The image is open already, at path.
func (o Options) RunExecutable(ctx context.Context, image *os.File, path string, input []byte, executable, name string, args ...string) ([]byte, error) {
	if !selfName(name) || !filepath.IsAbs(executable) {
		return nil, fmt.Errorf("sandbox: %q is not a program of %q", name, executable)
	}
	if o.Unconfined || o.TestTools || o.Delegate != nil || len(input) > MaxInput {
		return nil, fmt.Errorf("%w: a program of an executable runs only confined, with at most %d bytes of input", ErrUnavailable, MaxInput)
	}
	return o.runOpen(ctx, image, path, input, selfExecutableFilter, name, executable, args)
}

// RunSelf runs this executable again, confined, as the program that a
// package registered under name (see Self), with args, and returns its
// standard output, at most 1 MiB of it. image is open for it as for Run.
// input, at most MaxInput bytes, is its standard input, through a pipe: a secret goes there, never in args or the environment. The
// confinement is Run's, with the self filter and limits (see the package
// documentation). It is never unconfined, nor under the test tools' filter.
func (o Options) RunSelf(ctx context.Context, image string, input []byte, name string, args ...string) ([]byte, error) {
	if !selfName(name) {
		return nil, fmt.Errorf("sandbox: %q is not the name of a program of this executable", name)
	}
	if o.Unconfined || o.TestTools || len(input) > MaxInput {
		return nil, fmt.Errorf("%w: a program of this executable runs only confined, with at most %d bytes of input", ErrUnavailable, MaxInput)
	}
	if o.Delegate != nil {
		return o.delegate(ctx, image, Delegated{Self: name, Args: args, Input: input})
	}
	return o.run(ctx, image, input, selfFilter, name, "", args)
}

// selfName: the name of a program of this executable, as RunSelf and Self
// take it, is agentcapsule- and lower-case letters and dashes, and not the
// helper's.
func selfName(name string) bool {
	rest, ok := strings.CutPrefix(name, "agentcapsule-")
	if !ok || rest == "" || name == HelperName || len(name) > 64 {
		return false
	}
	return strings.Trim(rest, "abcdefghijklmnopqrstuvwxyz-") == ""
}

func (o Options) run(ctx context.Context, image string, input []byte, filter, program, executable string, args []string) ([]byte, error) {
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
	return o.runOpen(ctx, in, path, input, filter, program, executable, args)
}

// runOpen runs program confined on in, the image at path ("-": none, in is
// then /dev/null). executable, for the self-executable filter, is the
// executable whose program runs.
func (o Options) runOpen(ctx context.Context, in *os.File, path string, input []byte, filter, program, executable string, args []string) ([]byte, error) {
	o = o.withDefaults()
	root := AsRoot()
	if o.Unconfined && os.Geteuid() == 0 {
		return nil, fmt.Errorf("%w: unconfined as root", ErrUnavailable)
	}
	// Root of another user namespace cannot take UID and GID, and would run
	// the program as that root, owner of every file root owns there.
	if os.Geteuid() == 0 && !root && !o.Unconfined {
		return nil, fmt.Errorf("%w: root of a user namespace that is not the host's (a container): "+
			"run as root of the host, or as another account", ErrUnavailable)
	}
	if root && !o.Unconfined && (!Reservable(o.UID) || !Reservable(o.GID)) {
		return nil, fmt.Errorf("%w: as root, a dedicated UID and GID are required: not 0 or 65535, below 2147483647", ErrUnavailable)
	}
	if o.TestTools && !testing.Testing() {
		return nil, fmt.Errorf("%w: the test tools' filter outside a test binary", ErrUnavailable)
	}
	if in == nil || path != "-" && !filepath.IsAbs(path) {
		return nil, fmt.Errorf("sandbox: an image needs its absolute path")
	}
	status, report, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer status.Close()
	defer report.Close()
	// The lifeline: this process alone holds its writing end, until the
	// program has exited.
	life, lifeline, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer life.Close()
	defer lifeline.Close()
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
		argv = []string{strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10),
			strconv.FormatUint(o.cpuSeconds(), 10), filter, path, program}
		if filter == selfExecutableFilter {
			argv = append(argv, executable)
		}
		argv = append(argv, args...)
		files = append(files, report, life)
		attributes = namespaces(root)
	}
	cmd := exec.CommandContext(limited, name, argv...)
	if !o.Unconfined {
		cmd.Args[0] = HelperName
	}
	cmd.SysProcAttr = attributes
	cmd.Env = []string{"LC_ALL=C"}
	if input != nil {
		// Some hosts have pipes smaller than a batch. Feed it while the child reads.
		cmd.Stdin = bytes.NewReader(input)
	}
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
	life.Close()
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
