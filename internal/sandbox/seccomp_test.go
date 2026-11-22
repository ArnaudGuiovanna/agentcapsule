//go:build linux && amd64

package sandbox

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// The futex operations of <linux/futex.h> the filter refuses, and two
// ioctl requests of <asm-generic/ioctls.h> the kernel answers on any
// descriptor.
const (
	futexRequeue, futexCmpRequeue, futexWakeOp, futexLockPI, futexUnlockPI = 3, 4, 5, 6, 7
	futexWaitRequeuePI, futexLockPI2                                       = 11, 13
	fioclex, fionbio                                                       = 0x5451, 0x5421
)

// seccompData is the kernel's struct seccomp_data.
type seccompData struct {
	nr   uint32
	arch uint32
	args [6]uint64
}

// evaluate runs a seccomp program on d as the kernel does, for the
// instructions compile writes.
func evaluate(t *testing.T, prog []unix.SockFilter, d seccompData) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		f := prog[pc]
		jump := func(taken bool) {
			if taken {
				pc += int(f.Jt)
			} else {
				pc += int(f.Jf)
			}
		}
		switch f.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch k := f.K; {
			case k == 0:
				a = d.nr
			case k == 4:
				a = d.arch
			case k >= 16 && k < 64 && k%8 == 0:
				a = uint32(d.args[(k-16)/8])
			case k >= 16 && k < 64 && k%8 == 4:
				a = uint32(d.args[(k-16)/8] >> 32)
			default:
				t.Fatalf("load at %d", k)
			}
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			a &= f.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			jump(a == f.K)
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			jump(a >= f.K)
		case unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K:
			jump(a > f.K)
		case unix.BPF_RET | unix.BPF_K:
			return f.K
		default:
			t.Fatalf("instruction %#x", f.Code)
		}
	}
	t.Fatal("the program ends without an answer")
	return 0
}

// measured is the allow-list as the measurement gave it (docs/registry.md),
// written a second time: a call added to or dropped from allowed fails the
// test until it is added here too.
var measured = []uint32{
	unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_LSEEK, unix.SYS_WRITE, unix.SYS_WRITEV, unix.SYS_OPENAT, unix.SYS_OPEN,
	unix.SYS_CLOSE, unix.SYS_FSYNC, unix.SYS_FADVISE64, unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STAT, unix.SYS_LSTAT,
	unix.SYS_ACCESS, unix.SYS_READLINK, unix.SYS_BRK, unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MREMAP,
	unix.SYS_MADVISE, unix.SYS_EXECVE, unix.SYS_ARCH_PRCTL, unix.SYS_SET_TID_ADDRESS, unix.SYS_SET_ROBUST_LIST, unix.SYS_RSEQ,
	unix.SYS_PRLIMIT64, unix.SYS_GETRANDOM, unix.SYS_SCHED_GETAFFINITY, unix.SYS_RT_SIGACTION, unix.SYS_EXIT_GROUP,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_CLOCK_GETTIME, unix.SYS_GETTIMEOFDAY,
	unix.SYS_TIME,
}

// REG-01: the filter allows the measured calls and nothing else, for every
// number of the table: it kills the process for any other, answers ioctl,
// prctl and fcntl itself beyond the values it allows, lets futex wait and
// wake only, gives ENOSYS above the table, and kills another architecture
// and the x32 calls. Every jump fits its 8 bits.
func TestFilterAllowsOnlyWhatDebugfsCalls(t *testing.T) {
	prog, err := compile(strict())
	if err != nil {
		t.Fatal(err)
	}
	call := func(nr uint32, args ...uint64) seccompData {
		d := seccompData{nr: nr, arch: unix.AUDIT_ARCH_X86_64}
		copy(d.args[:], args)
		return d
	}
	special := map[uint32]bool{unix.SYS_IOCTL: true, unix.SYS_PRCTL: true, unix.SYS_FCNTL: true, unix.SYS_FUTEX: true}
	for nr := uint32(0); nr <= newest; nr++ {
		want := uint32(kill)
		if slices.Contains(measured, nr) {
			want = unix.SECCOMP_RET_ALLOW
		}
		if got := evaluate(t, prog, call(nr)); !special[nr] && got != want {
			t.Errorf("system call %d: %#x, not %#x", nr, got, want)
		}
	}
	allow, enotty, einval, enosys := uint32(unix.SECCOMP_RET_ALLOW), errno(unix.ENOTTY), errno(unix.EINVAL), errno(unix.ENOSYS)
	for _, c := range []struct {
		name string
		d    seccompData
		want uint32
	}{
		{"ioctl TCGETS", call(unix.SYS_IOCTL, 1, unix.TCGETS), enotty},
		{"ioctl FIOCLEX", call(unix.SYS_IOCTL, 1, fioclex), enotty},
		{"prctl PR_GET_DUMPABLE", call(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE), allow},
		{"prctl PR_GET_DUMPABLE, high bits", call(unix.SYS_PRCTL, 1<<32|unix.PR_GET_DUMPABLE), allow},
		{"prctl PR_SET_DUMPABLE", call(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 1), einval},
		{"prctl PR_SET_SECCOMP", call(unix.SYS_PRCTL, unix.PR_SET_SECCOMP), einval},
		{"fcntl F_GETFD", call(unix.SYS_FCNTL, 3, unix.F_GETFD), allow},
		{"fcntl F_SETFD", call(unix.SYS_FCNTL, 3, unix.F_SETFD, unix.FD_CLOEXEC), allow},
		{"fcntl F_GETFL", call(unix.SYS_FCNTL, 3, unix.F_GETFL), allow},
		{"fcntl F_SETFL", call(unix.SYS_FCNTL, 3, unix.F_SETFL), allow},
		{"fcntl F_DUPFD", call(unix.SYS_FCNTL, 3, unix.F_DUPFD), einval},
		{"fcntl F_DUPFD_CLOEXEC", call(unix.SYS_FCNTL, 3, unix.F_DUPFD_CLOEXEC), einval},
		{"fcntl F_SETLEASE", call(unix.SYS_FCNTL, 3, unix.F_SETLEASE), einval},
		{"fcntl F_SETOWN", call(unix.SYS_FCNTL, 3, unix.F_SETOWN), einval},
		{"futex FUTEX_WAIT", call(unix.SYS_FUTEX, 0, futexWait), allow},
		{"futex FUTEX_WAKE_PRIVATE", call(unix.SYS_FUTEX, 0, futexWake|futexPrivate), allow},
		{"futex FUTEX_WAIT_BITSET, realtime", call(unix.SYS_FUTEX, 0, futexWaitBitset|futexPrivate|futexClockRealtime), allow},
		{"futex FUTEX_WAKE_BITSET", call(unix.SYS_FUTEX, 0, futexWakeBitset), allow},
		{"futex FUTEX_REQUEUE", call(unix.SYS_FUTEX, 0, futexRequeue), kill},
		{"futex FUTEX_CMP_REQUEUE", call(unix.SYS_FUTEX, 0, futexCmpRequeue), kill},
		{"futex FUTEX_WAKE_OP", call(unix.SYS_FUTEX, 0, futexWakeOp), kill},
		{"futex FUTEX_LOCK_PI", call(unix.SYS_FUTEX, 0, futexLockPI), kill},
		{"futex FUTEX_UNLOCK_PI", call(unix.SYS_FUTEX, 0, futexUnlockPI), kill},
		{"futex FUTEX_WAIT_REQUEUE_PI", call(unix.SYS_FUTEX, 0, futexWaitRequeuePI), kill},
		{"futex FUTEX_LOCK_PI2", call(unix.SYS_FUTEX, 0, futexLockPI2), kill},
		{"futex FUTEX_WAKE with an unknown flag", call(unix.SYS_FUTEX, 0, futexWake|0x1000), kill},
		{"above the table", call(newest + 1), enosys},
		{"far above the table", call(0x3fffffff), enosys},
		{"x32 read", call(0x40000000 | unix.SYS_READ), kill},
		{"x32 rt_sigaction", call(0x40000000 + 512), kill},
		{"x32 above the table", call(0x40000000 + 1000), kill},
		{"bit 31", call(0x80000000 | unix.SYS_READ), kill},
		{"i386 read", seccompData{nr: 3, arch: unix.AUDIT_ARCH_I386}, kill},
		{"aarch64 read", seccompData{nr: 63, arch: unix.AUDIT_ARCH_AARCH64}, kill},
	} {
		if got := evaluate(t, prog, c.d); got != c.want {
			t.Errorf("%s: %#x, not %#x", c.name, got, c.want)
		}
	}

	// The test tools' filter refuses process creation and sockets only, and
	// keeps the architecture, x32 and table checks.
	tools, err := compile(testTools())
	if err != nil {
		t.Fatal(err)
	}
	for nr := uint32(0); nr <= newest; nr++ {
		want := uint32(unix.SECCOMP_RET_ALLOW)
		if slices.Contains(testToolsDenied, nr) {
			want = kill
		}
		if got := evaluate(t, tools, call(nr)); got != want {
			t.Errorf("test tools, system call %d: %#x, not %#x", nr, got, want)
		}
	}
	for _, d := range []seccompData{call(0x40000000 | unix.SYS_READ), {nr: 3, arch: unix.AUDIT_ARCH_I386}} {
		if got := evaluate(t, tools, d); got != kill {
			t.Errorf("test tools, %+v: %#x", d, got)
		}
	}
	if got := evaluate(t, tools, call(newest+1)); got != enosys {
		t.Errorf("test tools above the table: %#x", got)
	}

	// A checked call with more values than a jump can skip is refused.
	if _, err := compile(policy{checked: []argRule{{nr: unix.SYS_FCNTL, arg: 1, values: make([]uint32, 200)}}}); err == nil {
		t.Error("a jump past 255 instructions was written")
	}
}

// selfMeasured are the calls a program of this executable adds to debugfs's
// (docs/registry.md), written a second time.
var selfMeasured = []uint32{
	unix.SYS_RT_SIGPROCMASK, unix.SYS_SIGALTSTACK, unix.SYS_RT_SIGRETURN, unix.SYS_GETPID, unix.SYS_GETTID, unix.SYS_TGKILL,
	unix.SYS_NANOSLEEP, unix.SYS_SCHED_YIELD, unix.SYS_READLINKAT, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT,
	unix.SYS_EVENTFD2, unix.SYS_SECCOMP, unix.SYS_STATFS, unix.SYS_FSTATFS, unix.SYS_UNAME, unix.SYS_SYSINFO, unix.SYS_MLOCK,
	unix.SYS_MUNLOCK, unix.SYS_UMASK,
}

// S-21: the self filter (RunSelf) allows debugfs's calls and the measured
// ones, and nothing else: a clone that starts a thread, never a process or
// a namespace; clone3, mkdir and request_key answered without the kernel;
// the rest as the strict filter. The program's own filter kills execve and
// execveat and lets everything else through.
func TestSelfFilterAllowsOnlyWhatAProgramOfThisExecutableCalls(t *testing.T) {
	prog, err := compile(selfPolicy())
	if err != nil {
		t.Fatal(err)
	}
	call := func(nr uint32, args ...uint64) seccompData {
		d := seccompData{nr: nr, arch: unix.AUDIT_ARCH_X86_64}
		copy(d.args[:], args)
		return d
	}
	special := map[uint32]bool{unix.SYS_IOCTL: true, unix.SYS_PRCTL: true, unix.SYS_FCNTL: true, unix.SYS_FUTEX: true,
		unix.SYS_CLONE: true, unix.SYS_CLONE3: true, unix.SYS_MKDIR: true, unix.SYS_MKDIRAT: true, unix.SYS_REQUEST_KEY: true}
	for nr := uint32(0); nr <= newest; nr++ {
		want := uint32(kill)
		if slices.Contains(measured, nr) || slices.Contains(selfMeasured, nr) {
			want = unix.SECCOMP_RET_ALLOW
		}
		if got := evaluate(t, prog, call(nr)); !special[nr] && got != want {
			t.Errorf("system call %d: %#x, not %#x", nr, got, want)
		}
	}
	thread := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
		unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	for _, c := range []struct {
		name string
		d    seccompData
		want uint32
	}{
		{"clone of a thread", call(unix.SYS_CLONE, thread), allow},
		{"clone of a process", call(unix.SYS_CLONE, uint64(unix.SIGCHLD)), kill},
		{"clone of a process sharing memory", call(unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_VFORK|uint64(unix.SIGCHLD)), kill},
		{"clone of a thread in a new user namespace", call(unix.SYS_CLONE, thread|unix.CLONE_NEWUSER), kill},
		{"clone of a thread in a new mount namespace", call(unix.SYS_CLONE, thread|unix.CLONE_NEWNS), kill},
		{"clone of a thread in a new network namespace", call(unix.SYS_CLONE, thread|unix.CLONE_NEWNET), kill},
		{"clone of a thread in a new PID namespace", call(unix.SYS_CLONE, thread|unix.CLONE_NEWPID), kill},
		{"clone3", call(unix.SYS_CLONE3), errno(unix.ENOSYS)},
		{"mkdir", call(unix.SYS_MKDIR), errno(unix.EROFS)},
		{"mkdirat", call(unix.SYS_MKDIRAT), errno(unix.EROFS)},
		{"request_key", call(unix.SYS_REQUEST_KEY), errno(unix.ENOSYS)},
		{"keyctl", call(unix.SYS_KEYCTL), kill},
		{"unshare", call(unix.SYS_UNSHARE, unix.CLONE_NEWUSER), kill},
		{"fork", call(unix.SYS_FORK), kill},
		{"vfork", call(unix.SYS_VFORK), kill},
		{"socket", call(unix.SYS_SOCKET, unix.AF_UNIX), kill},
		{"flock", call(unix.SYS_FLOCK), kill},
		{"ioctl TCGETS", call(unix.SYS_IOCTL, 1, unix.TCGETS), errno(unix.ENOTTY)},
		{"prctl PR_SET_NO_NEW_PRIVS", call(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS), errno(unix.EINVAL)},
		{"futex FUTEX_LOCK_PI", call(unix.SYS_FUTEX, 0, futexLockPI), kill},
		{"futex FUTEX_WAKE_PRIVATE", call(unix.SYS_FUTEX, 0, futexWake|futexPrivate), allow},
		{"above the table", call(newest + 1), errno(unix.ENOSYS)},
		{"x32 read", call(0x40000000 | unix.SYS_READ), kill},
		{"i386 read", seccompData{nr: 3, arch: unix.AUDIT_ARCH_I386}, kill},
	} {
		if got := evaluate(t, prog, c.d); got != c.want {
			t.Errorf("%s: %#x, not %#x", c.name, got, c.want)
		}
	}

	exec, err := compile(noExec())
	if err != nil {
		t.Fatal(err)
	}
	for nr := uint32(0); nr <= newest; nr++ {
		want := uint32(unix.SECCOMP_RET_ALLOW)
		if nr == unix.SYS_EXECVE || nr == unix.SYS_EXECVEAT {
			want = kill
		}
		if got := evaluate(t, exec, call(nr)); got != want {
			t.Errorf("the program's own filter, system call %d: %#x, not %#x", nr, got, want)
		}
	}
}
