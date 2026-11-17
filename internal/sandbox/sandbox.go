// Package sandbox runs a host program on untrusted input, confined: the
// e2fsprogs programs that read a harness image downloaded from a registry
// (REG-01, REG-007). A flaw of such a program must not reach the host.
//
// Run starts this same executable again, as a helper named HelperName, in
// new mount, network, PID, IPC and UTS namespaces. The helper, PID 1 of its
// namespace, mounts a /proc of its own that shows its process only and an
// empty /sys, makes every mount read-only, nosuid and nodev, pins itself to
// one processor, drops its capabilities and, when the caller is root, takes
// the dedicated UID and GID of Options, without supplementary groups, and
// checks them. It checks that its caller still lives, sets no_new_privs and
// the limits (processor time, 256 MiB of address space, no file written, no
// core dump, 64 open files), marks every descriptor but 0 to 3
// close-on-exec, blocks every signal, and executes the program under a
// seccomp filter. The filter is an allow-list of the system calls debugfs
// makes; any other kills the program: it cannot start another process or
// thread, open a socket, mount, trace or change its credentials. Its network
// namespace has no interface but an unconfigured loopback. The image is open
// read-only as its file descriptor 3, ImagePath; Run kills it at
// Options.Timeout.
//
// A caller that is not root (a test, a publisher's machine) runs the helper
// in a user namespace of its own instead, where it is root without any
// capability on the host, and the program keeps the caller's account. Root
// of a user namespace that is not the host's (a container's root) is
// refused: it can take no reserved UID.
package sandbox

import (
	"errors"
	"time"
)

const (
	// HelperName is the name the helper runs under: this executable, started
	// with it as argv[0], runs the helper before anything else (see init).
	HelperName = "agentcapsule-sandbox"
	// ImagePath is where the program finds the image Run opened for it.
	ImagePath = "/proc/self/fd/3"
	// DefaultTimeout and DefaultCPU bound one run when Options leave them
	// zero.
	DefaultTimeout = time.Minute
	DefaultCPU     = 30 * time.Second
	// maxOutput bounds the standard output kept; the rest is read and
	// discarded.
	maxOutput = 1 << 20
	// addressSpace bounds the program's virtual memory (RLIMIT_AS): debugfs
	// needs about 24 MiB on the images measured; a mapping past it fails.
	addressSpace = 256 << 20
)

var (
	// ErrUnavailable: the sandbox could not be set up on this host (no user
	// or mount namespace, a kernel without mount_setattr, a missing UID as
	// root). The program did not run.
	ErrUnavailable = errors.New("sandbox unavailable")
	// ErrLimit: the program was killed at its time or processor limit.
	ErrLimit = errors.New("sandboxed program killed at its limit")
	// ErrSyscall: the program was killed for a system call outside the
	// filter's allow-list. debugfs never makes one: the image led it astray,
	// or this host's C library calls one the list lacks.
	ErrSyscall = errors.New("sandboxed program killed for a system call outside its allow-list")
)

// Options of a confined run.
type Options struct {
	// UID and GID the program runs as when the caller is root in the initial
	// user namespace: a UID and a GID reserved for this use, which own no
	// file and are no agent's. Required then, and Reservable. Any other
	// caller runs the program in a user namespace of its own, as itself, and
	// they are not used.
	UID, GID uint32
	// Timeout bounds the run's duration, CPU the program's processor time;
	// zero means DefaultTimeout and DefaultCPU. CPU is counted in whole
	// seconds, at least one.
	Timeout, CPU time.Duration
	// Unconfined runs the program directly, under Timeout only. It is for the
	// publisher's tool (agentcapsule-harness verify --unconfined) on a
	// machine where the sandbox is unavailable, never for the platform host.
	// Run refuses it as root: the worker, which runs as root, never runs a
	// program unconfined.
	Unconfined bool
	// TestTools, in a test binary only (testing.Testing), lets the program
	// also make the system calls of the shells and tools that tests run
	// confined: all but those that start a process or open a socket. Outside
	// a test binary, Run refuses it.
	TestTools bool
}

// Reservable reports whether id may be the UID or GID of a run as root: not
// 0, not 65535, and below 2^31-1. setresuid and setresgid take -1
// (4294967295) as "unchanged", older interfaces take 65535 the same way, and
// a value from 2^31 up is negative for some.
func Reservable(id uint32) bool {
	return id != 0 && id != 65535 && id < 1<<31-1
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.CPU <= 0 {
		o.CPU = DefaultCPU
	}
	return o
}

// cpuSeconds is the processor limit in whole seconds, at least one.
func (o Options) cpuSeconds() uint64 {
	return max(uint64((o.CPU+time.Second-1)/time.Second), 1)
}
