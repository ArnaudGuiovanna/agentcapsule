//go:build linux && amd64

package sandbox

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// probe writes a static x86_64 program of a few instructions, with no C
// library: it makes one system call, nr with args, and exits with the
// call's errno, or 0 when the call succeeds. With compat, it enters the
// kernel through the 32-bit gate (int 0x80), as an i386 program would. This
// test binary cannot be the probe: the Go runtime needs threads and futexes,
// which the filter refuses; this program runs under exactly the filter
// debugfs runs under.
func probe(t *testing.T, nr uint64, compat bool, args ...uint64) string {
	t.Helper()
	le := binary.LittleEndian
	code := le.AppendUint64([]byte{0x48, 0xb8}, nr) // mov rax, nr
	// mov rdi, rsi, rdx, r10, r8, r9: the arguments.
	for i, op := range [][]byte{{0x48, 0xbf}, {0x48, 0xbe}, {0x48, 0xba}, {0x49, 0xba}, {0x49, 0xb8}, {0x49, 0xb9}} {
		var a uint64
		if i < len(args) {
			a = args[i]
		}
		code = le.AppendUint64(append(code, op...), a)
	}
	if compat {
		code = append(code, 0xcd, 0x80) // int 0x80
	} else {
		code = append(code, 0x0f, 0x05) // syscall
	}
	code = append(code,
		0x48, 0x89, 0xc7, // mov rdi, rax
		0x48, 0xf7, 0xdf, // neg rdi: the errno, when rax is negative
		0x48, 0x85, 0xc0, // test rax, rax
		0x78, 0x02, // js +2
		0x31, 0xff, // xor edi, edi: 0 otherwise
		0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231 (exit_group)
		0x0f, 0x05) // syscall
	const base, headers = 0x400000, 64 + 56
	size := uint64(headers + len(code))
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	elf = le.AppendUint16(elf, 2)    // ET_EXEC
	elf = le.AppendUint16(elf, 0x3e) // EM_X86_64
	elf = le.AppendUint32(elf, 1)
	elf = le.AppendUint64(elf, base+headers) // entry
	elf = le.AppendUint64(elf, 64)           // program headers
	elf = le.AppendUint64(elf, 0)            // no section headers
	elf = le.AppendUint32(elf, 0)
	elf = le.AppendUint16(elf, 64)
	elf = le.AppendUint16(elf, 56)
	elf = le.AppendUint16(elf, 1)
	elf = le.AppendUint16(elf, 0)
	elf = le.AppendUint16(elf, 0)
	elf = le.AppendUint16(elf, 0)
	elf = le.AppendUint32(elf, 1) // PT_LOAD
	elf = le.AppendUint32(elf, 5) // readable, executable
	elf = le.AppendUint64(elf, 0)
	elf = le.AppendUint64(elf, base)
	elf = le.AppendUint64(elf, base)
	elf = le.AppendUint64(elf, size)
	elf = le.AppendUint64(elf, size)
	elf = le.AppendUint64(elf, 0x1000)
	elf = append(elf, code...)
	// Readable by the dedicated account when the test runs as root.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "probe")
	if err := os.WriteFile(path, elf, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// The outcomes of a probe.
const (
	killed = "killed"
	passed = "passed" // the kernel ran the call, whatever it answered
)

func refused(e unix.Errno) string { return "errno " + strconv.Itoa(int(e)) }

// outcome runs a probe confined by o and says what became of its call.
func outcome(t *testing.T, o Options, path string) string {
	t.Helper()
	_, err := o.Run(t.Context(), "", path)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return refused(0)
	case errors.Is(err, ErrSyscall):
		return killed
	case errors.As(err, &exit) && exit.Exited():
		return refused(unix.Errno(exit.ExitCode()))
	case errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGSYS:
		return killed
	}
	t.Fatal(path, err)
	return ""
}

// syscallProbe is one call, its arguments, and what the filter must make of
// it.
type syscallProbe struct {
	name string
	nr   uint64
	args []uint64
	want string
}

// syscallProbes are the calls the filter must refuse, and some it must let
// through. Removing an entry, or answering one otherwise, fails the test.
var syscallProbes = []syscallProbe{
	// Allowed: debugfs makes them.
	{"getuid", unix.SYS_GETUID, nil, refused(0)},
	{"write of nothing", unix.SYS_WRITE, []uint64{1, 0, 0}, refused(0)},
	{"prctl PR_GET_DUMPABLE", unix.SYS_PRCTL, []uint64{unix.PR_GET_DUMPABLE}, refused(0)},
	{"fcntl F_GETFD", unix.SYS_FCNTL, []uint64{1, unix.F_GETFD}, refused(0)},
	{"futex FUTEX_WAKE", unix.SYS_FUTEX, []uint64{0, futexWake | futexPrivate, 1}, passed},
	// Answered without the kernel: any ioctl, another prctl or fcntl.
	{"ioctl FIOCLEX", unix.SYS_IOCTL, []uint64{1, fioclex}, refused(unix.ENOTTY)},
	{"ioctl FIONBIO", unix.SYS_IOCTL, []uint64{1, fionbio}, refused(unix.ENOTTY)},
	{"prctl PR_SET_DUMPABLE", unix.SYS_PRCTL, []uint64{unix.PR_SET_DUMPABLE, 0}, refused(unix.EINVAL)},
	{"prctl PR_SET_NAME", unix.SYS_PRCTL, []uint64{unix.PR_SET_NAME}, refused(unix.EINVAL)},
	{"fcntl F_DUPFD", unix.SYS_FCNTL, []uint64{1, unix.F_DUPFD, 10}, refused(unix.EINVAL)},
	{"fcntl F_GETPIPE_SZ", unix.SYS_FCNTL, []uint64{1, unix.F_GETPIPE_SZ}, refused(unix.EINVAL)},
	// A newer kernel's call: as an older kernel answers.
	{"a number above the table", newest + 1, nil, refused(unix.ENOSYS)},
	// Killed: everything else.
	{"futex FUTEX_LOCK_PI", unix.SYS_FUTEX, []uint64{0, futexLockPI}, killed},
	{"futex FUTEX_CMP_REQUEUE", unix.SYS_FUTEX, []uint64{0, futexCmpRequeue}, killed},
	{"mount", unix.SYS_MOUNT, nil, killed},
	{"umount2", unix.SYS_UMOUNT2, nil, killed},
	{"mount_setattr", unix.SYS_MOUNT_SETATTR, nil, killed},
	{"open_tree", unix.SYS_OPEN_TREE, nil, killed},
	{"fsopen", unix.SYS_FSOPEN, nil, killed},
	{"pivot_root", unix.SYS_PIVOT_ROOT, nil, killed},
	{"chroot", unix.SYS_CHROOT, nil, killed},
	{"unshare", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWUSER}, killed},
	{"setns", unix.SYS_SETNS, nil, killed},
	{"ptrace", unix.SYS_PTRACE, []uint64{unix.PTRACE_TRACEME}, killed},
	{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV, nil, killed},
	{"kcmp", unix.SYS_KCMP, nil, killed},
	{"bpf", unix.SYS_BPF, nil, killed},
	{"perf_event_open", unix.SYS_PERF_EVENT_OPEN, nil, killed},
	{"socket", unix.SYS_SOCKET, []uint64{unix.AF_INET, unix.SOCK_STREAM}, killed},
	{"socketpair", unix.SYS_SOCKETPAIR, []uint64{unix.AF_UNIX, unix.SOCK_STREAM}, killed},
	{"connect", unix.SYS_CONNECT, nil, killed},
	{"memfd_create", unix.SYS_MEMFD_CREATE, nil, killed},
	{"splice", unix.SYS_SPLICE, nil, killed},
	{"vmsplice", unix.SYS_VMSPLICE, nil, killed},
	{"tee", unix.SYS_TEE, nil, killed},
	{"pipe2", unix.SYS_PIPE2, nil, killed},
	{"personality", unix.SYS_PERSONALITY, []uint64{0xffffffff}, killed},
	{"io_uring_setup", unix.SYS_IO_URING_SETUP, nil, killed},
	{"io_uring_enter", unix.SYS_IO_URING_ENTER, nil, killed},
	{"userfaultfd", unix.SYS_USERFAULTFD, nil, killed},
	{"mbind", unix.SYS_MBIND, nil, killed},
	{"move_pages", unix.SYS_MOVE_PAGES, nil, killed},
	{"migrate_pages", unix.SYS_MIGRATE_PAGES, nil, killed},
	{"pidfd_open", unix.SYS_PIDFD_OPEN, nil, killed},
	{"pidfd_getfd", unix.SYS_PIDFD_GETFD, nil, killed},
	{"shmget", unix.SYS_SHMGET, nil, killed},
	{"msgget", unix.SYS_MSGGET, nil, killed},
	{"keyctl", unix.SYS_KEYCTL, nil, killed},
	{"add_key", unix.SYS_ADD_KEY, nil, killed},
	{"setresuid", unix.SYS_SETRESUID, nil, killed},
	{"setgroups", unix.SYS_SETGROUPS, nil, killed},
	{"capset", unix.SYS_CAPSET, nil, killed},
	{"name_to_handle_at", unix.SYS_NAME_TO_HANDLE_AT, nil, killed},
	{"open_by_handle_at", unix.SYS_OPEN_BY_HANDLE_AT, nil, killed},
	{"rt_sigreturn", unix.SYS_RT_SIGRETURN, nil, killed},
	{"getpid", unix.SYS_GETPID, nil, killed},
	{"kill", unix.SYS_KILL, []uint64{1, 0}, killed},
	{"execveat", unix.SYS_EXECVEAT, nil, killed},
	{"fork", unix.SYS_FORK, nil, killed},
	{"vfork", unix.SYS_VFORK, nil, killed},
	{"clone of a process", unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, killed},
	{"clone of a thread", unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD}, killed},
	{"clone3", unix.SYS_CLONE3, nil, killed},
	// The x32 calls: a number with bit 30 set.
	{"x32 getuid", 0x40000000 | unix.SYS_GETUID, nil, killed},
	{"x32 read", 0x40000000 | unix.SYS_READ, nil, killed},
	{"x32 rt_sigaction", 0x40000000 + 512, nil, killed},
}

// REG-01: the confined program may make the system calls debugfs makes, and
// no other: each probe runs confined, alone, and the filter kills it,
// answers for the kernel, or lets the call through, as its entry says.
func TestConfinedProgramIsKilledForAnyOtherSystemCall(t *testing.T) {
	for _, p := range syscallProbes {
		got := outcome(t, Options{}, probe(t, p.nr, false, p.args...))
		if p.want == passed && got != killed {
			continue
		}
		if got != p.want {
			t.Errorf("%s: %s, not %s", p.name, got, p.want)
		}
	}
	confinedKillsAnotherArchitecture(t, Options{})
}

// confinedKillsAnotherArchitecture: a call through the 32-bit gate
// (AUDIT_ARCH_I386) kills the program. Run directly, the same probe gets
// its PID; a kernel without that gate (ia32_emulation=0) faults it before
// any filter, and the probe shows nothing more there.
func confinedKillsAnotherArchitecture(t *testing.T, o Options) {
	t.Helper()
	path := probe(t, 20, true) // getpid in the i386 table
	err := exec.CommandContext(t.Context(), path).Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signaled() && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGSEGV {
		t.Log("this kernel has no 32-bit gate: the filter's architecture check cannot be reached here")
		return
	}
	if err != nil {
		t.Fatal("the probe of the 32-bit gate, run directly:", err)
	}
	if got := outcome(t, o, path); got != killed {
		t.Errorf("a call through the 32-bit gate: %s, not %s", got, killed)
	}
}

// REG-01: the program's address space is bounded: a program that maps 1 GiB
// is refused (ENOMEM), one that maps 64 MiB is not; run directly, both map.
func TestConfinedProgramCannotAllocateBeyondItsLimit(t *testing.T) {
	mapping := func(size uint64) string {
		return probe(t, unix.SYS_MMAP, false, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}
	big, small := mapping(1<<30), mapping(64<<20)
	for _, path := range []string{big, small} {
		if err := exec.CommandContext(t.Context(), path).Run(); err != nil {
			t.Fatal("run directly, the probe could not map its memory:", err)
		}
	}
	if got := outcome(t, Options{}, big); got != refused(unix.ENOMEM) {
		t.Errorf("1 GiB: %s, not %s", got, refused(unix.ENOMEM))
	}
	if got := outcome(t, Options{}, small); got != refused(0) {
		t.Errorf("64 MiB: %s", got)
	}
}

// REG-01: once the filter is in place, the helper runs no Go code until the
// program starts: a signal on its thread then (Go's scheduler sends SIGURG
// to preempt) would run a handler whose return the filter refuses, and the
// kernel would kill the helper. Started as Run starts it, the helper's
// thread receives SIGURG without pause until it exits; the probe, an
// allowed call, must run every time.
func TestHelperSurvivesSignalsUnderTheFilter(t *testing.T) {
	path := probe(t, unix.SYS_GETUID, false)
	for i := range 20 {
		cmd, _, done := helperCommand(t, "0", "0", "1", strictFilter, "-", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		go func(pid int) {
			for {
				select {
				case <-stop:
					return
				default:
					_ = unix.Tgkill(pid, pid, unix.SIGURG)
				}
			}
		}(cmd.Process.Pid)
		err := cmd.Wait()
		close(stop)
		if reason := done(); err != nil {
			t.Fatalf("run %d: %v %s", i, err, reason)
		}
	}
}
