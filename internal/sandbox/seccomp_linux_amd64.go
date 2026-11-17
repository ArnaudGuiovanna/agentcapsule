//go:build linux && amd64

package sandbox

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// denied are the system calls the program gets EPERM for: a tool that reads
// an image needs none of them. They start a process, open or use a socket,
// mount or change namespaces, change credentials, reach another process or
// the kernel's own state. Every other call is allowed: the namespaces, the
// read-only mounts, the limits and the absence of capabilities confine it.
var denied = []uint32{
	unix.SYS_FORK, unix.SYS_VFORK,
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
	unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK,
	unix.SYS_MOUNT_SETATTR,
	unix.SYS_SETUID, unix.SYS_SETGID, unix.SYS_SETREUID, unix.SYS_SETREGID, unix.SYS_SETRESUID, unix.SYS_SETRESGID,
	unix.SYS_SETGROUPS, unix.SYS_SETFSUID, unix.SYS_SETFSGID, unix.SYS_CAPSET,
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD, unix.SYS_KCMP,
	unix.SYS_PROCESS_MADVISE, unix.SYS_PERF_EVENT_OPEN, unix.SYS_BPF, unix.SYS_USERFAULTFD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_SYSLOG, unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD,
	unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_FANOTIFY_INIT,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
	unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME, unix.SYS_VHANGUP, unix.SYS_LOOKUP_DCOOKIE, unix.SYS_USELIB,
}

// filter is the seccomp program: another architecture than x86_64 kills the
// process, the x32 calls and those of denied get EPERM, clone is allowed for
// a thread only (EPERM otherwise) and clone3, whose flags it cannot read,
// gets ENOSYS, so that the C library falls back to clone.
func filter() []unix.SockFilter {
	const (
		load   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		equal  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		above  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		has    = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		answer = unix.BPF_RET | unix.BPF_K
		x32    = 0x40000000
	)
	// Offsets in struct seccomp_data: nr, arch, then args[0] at 16 (its low
	// half on this little-endian machine).
	prog := []unix.SockFilter{
		{Code: load, K: 4},
		{Code: equal, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: answer, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load, K: 0},
	}
	type check struct {
		code   uint16
		k      uint32
		target string
	}
	checks := []check{{above, x32, "eperm"}, {equal, unix.SYS_CLONE, "clone"}, {equal, unix.SYS_CLONE3, "enosys"}}
	for _, nr := range denied {
		checks = append(checks, check{equal, nr, "eperm"})
	}
	first := len(prog)
	allow := first + len(checks)
	clone := allow + 1
	eperm := clone + 3
	enosys := eperm + 1
	targets := map[string]int{"eperm": eperm, "clone": clone, "enosys": enosys}
	for i, c := range checks {
		prog = append(prog, unix.SockFilter{Code: c.code, Jt: uint8(targets[c.target] - (first + i) - 1), K: c.k})
	}
	prog = append(prog,
		unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: load, K: 16},
		unix.SockFilter{Code: has, Jt: 0, Jf: 1, K: unix.CLONE_THREAD},
		unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	)
	return prog
}

// installFilter applies filter to the calling thread; no_new_privs must be
// set.
func installFilter() error {
	prog := filter()
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0)
}
