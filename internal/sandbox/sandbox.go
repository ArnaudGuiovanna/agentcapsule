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
//
// RunSelf runs this executable itself as the program, under a name a package
// registered with Self: Go code that hands untrusted input to a C library
// (libcryptsetup, for the LUKS2 header a guest could write, S-21). The
// confinement is the same, but for what a Go program and its C libraries
// need: the self filter also allows threads (a clone that shares the
// address space, never a new process or namespace) and the runtime's signal
// and scheduling calls; 256 MiB of private writable memory (RLIMIT_DATA)
// bound it, since the Go runtime reserves more address space than debugfs
// maps (RLIMIT_AS is 4 GiB there); /dev holds two empty regular files,
// random and urandom, which libcryptsetup opens at start and the check never
// reads. Its standard input carries a secret, through a pipe, never an
// argument or the environment. Once started, the program adds a filter of
// its own that refuses to execute any program.
package sandbox

import (
	"context"
	"errors"
	"os"
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
	// MaxOutput is maxOutput for callers: an output of that length may have
	// been cut.
	MaxOutput = maxOutput
	// addressSpace bounds the program's virtual memory (RLIMIT_AS): debugfs
	// needs about 24 MiB on the images measured; a mapping past it fails.
	addressSpace = 256 << 20
	// selfData bounds a self run's private writable memory (RLIMIT_DATA):
	// what it uses, as the Go runtime maps it. selfAddressSpace bounds its
	// virtual memory: the runtime reserves about 1.1 GiB that it never uses
	// (its page summaries), which RLIMIT_DATA does not count.
	selfData         = 256 << 20
	selfAddressSpace = 4 << 30
	// MaxInput bounds the standard input of a self run.
	MaxInput = 4096
	// MaxProgramInput bounds the standard input of a program's run
	// (RunInput), including one batch of debugfs commands.
	MaxProgramInput = 32 << 10
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
	// Delegate, when set, runs the program through a process that is root
	// of the host: the worker's helper (ADR 024), for a worker that is not
	// root. The helper confines it as its configured inspection UID; UID and
	// GID are not used. The image is opened here, by the caller, and handed
	// over as a descriptor; the helper runs a program of this executable as
	// the worker's own executable, never as itself.
	Delegate Delegate
}

// Delegate runs a confined program in another process (Options.Delegate).
// It returns the errors Run returns: ErrUnavailable, ErrLimit, ErrSyscall.
type Delegate interface {
	RunConfined(ctx context.Context, r Delegated) ([]byte, error)
}

// Delegated is one run a Delegate makes: Program, an absolute path, or Self,
// the name of a program of the caller's executable (RunSelf).
type Delegated struct {
	// Image is open read-only, at ImagePath; nil for none.
	Image     *os.File
	ImagePath string
	Program   string
	Self      string
	Args      []string
	Input     []byte
	// Timeout and CPU are Options', with their defaults applied.
	Timeout, CPU time.Duration
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
