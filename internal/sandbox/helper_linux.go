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
	"unsafe"

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
	// then every mount read-only, nosuid and nodev. A read-only mount does
	// not stop a write to a device node: nodev refuses to open any.
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
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
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
	// file, no core dump, 64 open files; the address space last (see
	// execFiltered). No RLIMIT_NPROC: the filter refuses every process and
	// thread, and that limit counts every process of the real UID, so
	// concurrent runs would fail.
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
	if err := checkCredentials(int(uid), int(gid)); err != nil {
		return err
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
	// Descriptors: the program keeps 0 to 3 only. Go's fork marks only its
	// own descriptors close-on-exec; the caller's C code (libcryptsetup, in
	// the worker) may hold a volume or a device open without the flag, which
	// the program could truncate or map for writing without any check.
	if err := unix.CloseRange(4, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("close-on-exec: %w", err)
	}
	return fmt.Errorf("exec %s: %w", program, execFiltered(filter, program, argv, os.Environ()))
}

// execve is the system call that executes the program: the helper's only
// start of a program (cmd/agentcapsule-api's audit of the worker counts it).
const execve = unix.SYS_EXECVE

// execFiltered installs the filter of p on this thread and executes the
// program. Once the filter is in place, no Go code may run on the thread: a
// signal handler, the scheduler or the allocator would make calls the
// allow-list refuses, and the kernel would kill the helper. So everything is
// prepared first; then every signal is blocked, and the filter and the
// execution are raw system calls. The program starts with every signal
// blocked: SIGKILL and its own faults still reach it.
func execFiltered(p policy, program string, argv, env []string) error {
	prog, err := filterProgram(p)
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	path, err := syscall.BytePtrFromString(program)
	if err != nil {
		return err
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return err
	}
	// The address space is limited here: this Go process already maps more,
	// and could not grow its heap past it.
	space := unix.Rlimit{Cur: addressSpace, Max: addressSpace}
	if _, _, e := unix.RawSyscall6(unix.SYS_PRLIMIT64, 0, unix.RLIMIT_AS, uintptr(unsafe.Pointer(&space)), 0, 0, 0); e != 0 {
		return fmt.Errorf("address space: %w", e)
	}
	all := ^uint64(0)
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&all)), 0, 8, 0, 0); e != 0 {
		return fmt.Errorf("signals: %w", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog))); e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	_, _, e := unix.RawSyscall(execve, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&argvp[0])), uintptr(unsafe.Pointer(&envp[0])))
	runtime.KeepAlive(prog)
	runtime.KeepAlive(path)
	runtime.KeepAlive(argvp)
	runtime.KeepAlive(envp)
	return e
}

// checkCredentials fails unless the real, effective and saved UIDs are all
// uid and the GIDs all gid, without supplementary groups when uid is not 0:
// setresuid(-1) and the like change nothing and do not fail. For uid 0 (root
// of the helper's own user namespace) the caller's supplementary groups
// remain: an account that is not root cannot drop them (the kernel refuses
// setgroups in a user namespace it creates).
func checkCredentials(uid, gid int) error {
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	if ruid != uid || euid != uid || suid != uid || rgid != gid || egid != gid || sgid != gid {
		return fmt.Errorf("credentials: UIDs %d %d %d and GIDs %d %d %d, not %d and %d", ruid, euid, suid, rgid, egid, sgid, uid, gid)
	}
	if uid == 0 {
		return nil
	}
	groups, err := unix.Getgroups()
	if err != nil || len(groups) != 0 {
		return fmt.Errorf("credentials: supplementary groups %v %v", groups, err)
	}
	return nil
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
