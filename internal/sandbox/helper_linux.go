//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The helper runs before anything else in a process started as HelperName,
// and never returns: it executes the program, or reports why it cannot and
// exits with status 125.
func init() {
	if len(os.Args) == 0 || os.Args[0] != HelperName {
		return
	}
	// no_new_privs, the capabilities and the seccomp filter are set on this
	// thread, which then executes the program.
	runtime.LockOSThread()
	err := confine(os.Args[1:])
	var st unix.Stat_t
	if unix.Fstat(statusFD, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFIFO {
		_, _ = unix.Write(statusFD, []byte(err.Error()))
	}
	fmt.Fprintln(os.Stderr, "sandbox:", err)
	os.Exit(125)
}

// The filters the helper is asked for, by name.
const (
	strictFilter    = "strict"
	testToolsFilter = "test-tools"
)

// confine sets the sandbox up and executes the program; it returns only on
// failure. args: UID, GID, processor seconds, the filter, the image's
// absolute path (or "-"), the program, then the program's arguments.
// Descriptor 3 is the image the caller opened (or /dev/null), 4 the pipe for
// a failure's reason.
func confine(args []string) error {
	if len(args) < 6 {
		return errors.New("usage: UID GID CPU-SECONDS FILTER IMAGE|- PROGRAM [ARGUMENT...]")
	}
	uid, err1 := strconv.ParseUint(args[0], 10, 32)
	gid, err2 := strconv.ParseUint(args[1], 10, 32)
	cpu, err3 := strconv.ParseUint(args[2], 10, 32)
	if err := errors.Join(err1, err2, err3); err != nil || cpu < 1 {
		return errors.New("invalid UID, GID or processor seconds")
	}
	var filter policy
	switch args[3] {
	case strictFilter:
		filter = strict()
	case testToolsFilter:
		if !testing.Testing() {
			return errors.New("the test tools' filter outside a test binary")
		}
		filter = testTools()
	default:
		return errors.New("unknown filter")
	}
	image, program, argv := args[4], args[5], args[5:]
	unix.CloseOnExec(statusFD)
	if err := alone(); err != nil {
		return err
	}
	// Mounts: none propagates to the host; a /proc of this PID namespace;
	// then every mount read-only and nosuid.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mounts: %w", err)
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	// Under memory pressure, the kernel kills the program first.
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0); err != nil {
		return err
	}
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID}
	if err := unix.MountSetattr(unix.AT_FDCWD, "/", unix.AT_RECURSIVE, &attr); err != nil {
		return fmt.Errorf("read-only mounts: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if image != "-" {
		if err := reopen(image); err != nil {
			return err
		}
	}
	// Limits: processor seconds (SIGKILL when spent), no byte written to any
	// file, no core dump, 64 open files.
	for _, l := range []struct {
		resource int
		value    uint64
	}{{unix.RLIMIT_CPU, cpu}, {unix.RLIMIT_FSIZE, 0}, {unix.RLIMIT_CORE, 0}, {unix.RLIMIT_NOFILE, 64}} {
		// syscall's Setrlimit, so that Exec does not restore Go's own limit on
		// open files.
		if err := syscall.Setrlimit(l.resource, &syscall.Rlimit{Cur: l.value, Max: l.value}); err != nil {
			return fmt.Errorf("limit %d: %w", l.resource, err)
		}
	}
	// Capabilities: none left to the program, nor any it could gain.
	for c := 0; ; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); errors.Is(err, unix.EINVAL) {
			break
		} else if err != nil {
			return fmt.Errorf("bounding set: %w", err)
		}
	}
	if uid != 0 {
		if err := syscall.Setgroups([]int{}); err != nil {
			return fmt.Errorf("groups: %w", err)
		}
		if err := syscall.Setresgid(int(gid), int(gid), int(gid)); err != nil {
			return fmt.Errorf("GID: %w", err)
		}
		if err := syscall.Setresuid(int(uid), int(uid), int(uid)); err != nil {
			return fmt.Errorf("UID: %w", err)
		}
	}
	var none [2]unix.CapUserData
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &none[0]); err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}
	// A change of credentials cleared the parent-death signal: set it again.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := installFilter(filter); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	return fmt.Errorf("exec %s: %w", program, unix.Exec(program, argv, os.Environ()))
}

// reopen replaces descriptor 3 with the image opened read-only through this
// namespace's read-only mounts. The caller's descriptor refers to the
// caller's mount, which is writable: reopened through /proc/self/fd/3 for
// writing, it would let the program write the image. The file must be the
// one the caller opened.
func reopen(image string) error {
	var want, got unix.Stat_t
	if err := unix.Fstat(3, &want); err != nil {
		return fmt.Errorf("image descriptor: %w", err)
	}
	fd, err := unix.Open(image, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("reopen the image: %w", err)
	}
	defer unix.Close(fd)
	if err = unix.Fstat(fd, &got); err != nil {
		return err
	}
	if got.Dev != want.Dev || got.Ino != want.Ino || got.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("the image changed since the caller opened it")
	}
	// Without O_CLOEXEC: descriptor 3 stays open in the program.
	return unix.Dup3(fd, 3, 0)
}

// alone refuses to run anywhere but in the namespaces Run creates: the helper
// changes mounts, and must never change the host's. It must be PID 1 of a new
// PID namespace, and in another mount and network namespace than PID 1 of the
// host when it can see it (as root).
func alone() error {
	if os.Getpid() != 1 {
		return errors.New("not PID 1 of a new PID namespace: started outside Run")
	}
	for _, ns := range []string{"mnt", "net"} {
		self, err := os.Readlink("/proc/self/ns/" + ns)
		if err != nil {
			return err
		}
		if host, err := os.Readlink("/proc/1/ns/" + ns); err == nil && host == self {
			return fmt.Errorf("in the host's %s namespace: started outside Run", ns)
		}
	}
	return nil
}
