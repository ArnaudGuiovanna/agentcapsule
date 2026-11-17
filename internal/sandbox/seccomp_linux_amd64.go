//go:build linux && amd64

package sandbox

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// newest is the highest system call number of the kernel this filter was
// written against (Linux 6.18). A newer kernel's calls get ENOSYS, as an
// older kernel would answer: the C library then falls back to an older call.
const newest = unix.SYS_RSEQ_SLICE_YIELD

// allowed are the system calls debugfs makes when it reads an image, and
// nothing else. They were measured by tracing debugfs -V and debugfs -R
// "stat PATH" /proc/self/fd/3, as harnesspkg runs it, on 72 images (the
// reference harnesses, unusual ext2, ext3 and ext4 features, damaged and
// fuzzed images), with glibc 2.36, 2.39 and 2.43 and with musl (e2fsprogs
// 1.47.0 to 1.47.4): docs/registry.md says how. A few calls the C library
// makes on other paths are added, each named below.
var allowed = []uint32{
	// The image, the files the C library reads (its libraries,
	// /etc/localtime, /etc/blkid.conf), and the answer on standard output.
	unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_LSEEK, unix.SYS_WRITE, unix.SYS_WRITEV,
	unix.SYS_OPENAT, unix.SYS_OPEN, unix.SYS_CLOSE, unix.SYS_FSYNC, unix.SYS_FADVISE64,
	unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_ACCESS, unix.SYS_READLINK,
	// Memory. mremap (glibc's realloc of a large block) and madvise (musl's
	// allocator) were not measured.
	unix.SYS_BRK, unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MREMAP, unix.SYS_MADVISE,
	// The program's start and end, as the C library runs them.
	unix.SYS_EXECVE, unix.SYS_ARCH_PRCTL, unix.SYS_SET_TID_ADDRESS, unix.SYS_SET_ROBUST_LIST, unix.SYS_RSEQ,
	unix.SYS_PRLIMIT64, unix.SYS_GETRANDOM, unix.SYS_SCHED_GETAFFINITY, unix.SYS_RT_SIGACTION, unix.SYS_EXIT_GROUP,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
	// Clocks, which debugfs reads through the vDSO; the kernel answers when
	// the vDSO cannot. Not measured.
	unix.SYS_CLOCK_GETTIME, unix.SYS_GETTIMEOFDAY, unix.SYS_TIME,
}

// checked are the system calls allowed with some argument values only; any
// other value gets their answer.
var checked = []argRule{
	// No ioctl reaches the kernel. debugfs only asks whether a descriptor is
	// a terminal (TCGETS, TCGETS2, TIOCGWINSZ) or a block device
	// (BLKDISCARDZEROES): on the image, a pipe and /dev/null, the kernel
	// answers ENOTTY, as the filter does.
	{nr: unix.SYS_IOCTL, answer: errno(unix.ENOTTY)},
	// Whether the process may dump core, which e2fsprogs reads before it
	// reads its environment; the rest is refused as an older kernel would.
	{nr: unix.SYS_PRCTL, arg: 0, values: []uint32{unix.PR_GET_DUMPABLE}, answer: errno(unix.EINVAL)},
	// Descriptor and status flags (musl marks the files it opens close-on-exec).
	{nr: unix.SYS_FCNTL, arg: 1, values: []uint32{unix.F_GETFD, unix.F_SETFD, unix.F_GETFL, unix.F_SETFL}, answer: errno(unix.EINVAL)},
	// The C library's locks: wait and wake only, no priority inheritance or
	// requeue, whatever the private and clock flags.
	{nr: unix.SYS_FUTEX, arg: 1, mask: ^uint32(futexPrivate | futexClockRealtime),
		values: []uint32{futexWait, futexWake, futexWaitBitset, futexWakeBitset}, answer: kill},
}

// Futex operations and flags of <linux/futex.h>.
const (
	futexWait, futexWake, futexWaitBitset, futexWakeBitset = 0, 1, 9, 10
	futexPrivate, futexClockRealtime                       = 128, 256
)

// testToolsDenied are the only calls the shells and tools of the package's
// tests are refused (Options.TestTools): starting a process, opening a
// socket.
var testToolsDenied = []uint32{unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_CLONE, unix.SYS_CLONE3, unix.SYS_SOCKET, unix.SYS_SOCKETPAIR}

const kill = unix.SECCOMP_RET_KILL_PROCESS

func errno(e unix.Errno) uint32 { return unix.SECCOMP_RET_ERRNO | uint32(e) }

// argRule allows its system call when the low 32 bits of argument arg, under
// mask (all bits when 0), are one of values; otherwise the answer is answer.
type argRule struct {
	nr, mask uint32
	arg      int
	values   []uint32
	answer   uint32
}

// policy is what a filter allows: deny first, then allow and checked; any
// other call gets otherwise.
type policy struct {
	deny, allow []uint32
	checked     []argRule
	otherwise   uint32
}

// strict is the filter of every program Run executes: the allow-list, and
// the death of the process for anything else.
func strict() policy {
	return policy{allow: allowed, checked: checked, otherwise: kill}
}

// testTools is the filter of Options.TestTools.
func testTools() policy {
	return policy{deny: testToolsDenied, otherwise: unix.SECCOMP_RET_ALLOW}
}

// compile writes p as a seccomp program. Whatever the policy: another
// architecture than x86_64 and the x32 calls kill the process, and a number
// above newest gets ENOSYS. Every jump is forward and short; compile fails
// if one would not fit its 8 bits.
func compile(p policy) ([]unix.SockFilter, error) {
	const (
		load    = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		and     = unix.BPF_ALU | unix.BPF_AND | unix.BPF_K
		equal   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		atLeast = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		above   = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
		answer  = unix.BPF_RET | unix.BPF_K
		x32     = 0x40000000
	)
	// Offsets in struct seccomp_data: nr, arch, then args[i] at 16+8i (its
	// low half on this little-endian machine).
	prog := []unix.SockFilter{
		{Code: load, K: 4},
		{Code: equal, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: answer, K: kill},
		{Code: load, K: 0},
		{Code: atLeast, Jf: 1, K: x32},
		{Code: answer, K: kill},
		{Code: above, Jf: 1, K: newest},
		{Code: answer, K: errno(unix.ENOSYS)},
	}
	for _, nr := range p.deny {
		prog = append(prog, unix.SockFilter{Code: equal, Jf: 1, K: nr}, unix.SockFilter{Code: answer, K: kill})
	}
	for _, nr := range p.allow {
		prog = append(prog, unix.SockFilter{Code: equal, Jf: 1, K: nr}, unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ALLOW})
	}
	for _, r := range p.checked {
		// The block ends with an answer: past it, the accumulator still holds
		// the number.
		block := []unix.SockFilter{{Code: load, K: 16 + 8*uint32(r.arg)}}
		if r.mask != 0 {
			block = append(block, unix.SockFilter{Code: and, K: r.mask})
		}
		for _, v := range r.values {
			block = append(block, unix.SockFilter{Code: equal, Jf: 1, K: v}, unix.SockFilter{Code: answer, K: unix.SECCOMP_RET_ALLOW})
		}
		block = append(block, unix.SockFilter{Code: answer, K: r.answer})
		if len(block) > 255 || r.arg < 0 || r.arg > 5 {
			return nil, errors.New("a checked system call has too many values")
		}
		prog = append(prog, unix.SockFilter{Code: equal, Jf: uint8(len(block)), K: r.nr})
		prog = append(prog, block...)
	}
	prog = append(prog, unix.SockFilter{Code: answer, K: p.otherwise})
	if len(prog) > unix.BPF_MAXINSNS {
		return nil, errors.New("the filter is too long")
	}
	return prog, nil
}

// installFilter applies the filter of p to the calling thread, which
// executes the program next; no_new_privs must be set. The program is built
// first.
func installFilter(p policy) error {
	prog, err := compile(p)
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0)
}
