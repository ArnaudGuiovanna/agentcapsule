//go:build linux && amd64

package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// selfTestProgram is a program of this test binary that RunSelf runs: what
// it does is its first argument.
const selfTestProgram = "agentcapsule-sandbox-test"

func init() {
	if Self(selfTestProgram) {
		os.Exit(selfTest(os.Args[1:]))
	}
}

// selfTest is the program. It writes with raw calls, as the LUKS2 check does,
// and exits 0 when its action ran, whatever the action found.
func selfTest(args []string) int {
	out := func(s string) { _, _ = unix.Write(1, []byte(s)) }
	read := func(path string) string {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return "error: " + err.Error()
		}
		defer unix.Close(fd)
		b := make([]byte, 1<<16)
		n, _ := unix.Read(fd, b)
		return string(b[:max(n, 0)])
	}
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "status":
		out(read("/proc/self/status"))
	case "identity":
		// The arguments and the environment, as the kernel holds them.
		out(read("/proc/self/cmdline") + "\n" + read("/proc/self/environ"))
	case "input":
		b := make([]byte, MaxInput+1)
		n := 0
		for n < len(b) {
			r, err := unix.Read(0, b[n:])
			if err != nil || r == 0 {
				break
			}
			n += r
		}
		sum := sha256.Sum256(b[:n])
		out(hex.EncodeToString(sum[:]))
	case "descriptors":
		// Every descriptor from 4 up is closed (fcntl F_GETFD fails).
		var open []string
		for fd := 4; fd < 64; fd++ {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
				open = append(open, strconv.Itoa(fd))
			}
		}
		out(strings.Join(open, " "))
	case "devices":
		for _, name := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/kvm", "/dev/mapper/control"} {
			var st unix.Stat_t
			if err := unix.Stat(name, &st); err != nil {
				out(name + " absent\n")
				continue
			}
			out(fmt.Sprintf("%s mode %o size %d %q\n", name, st.Mode, st.Size, read(name)))
		}
	case "image":
		out(read(ImagePath))
	case "memory":
		// Allocates and touches MiB, from the second argument.
		mib, _ := strconv.Atoi(args[1])
		b := make([]byte, mib<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		out("allocated " + strconv.Itoa(len(b)>>20))
	case "write":
		fd, err := unix.Open(args[1], unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
		if err == nil {
			unix.Close(fd)
			out("wrote")
		} else {
			out("refused: " + err.Error())
		}
	case "exec":
		// execve itself: the program's own filter kills it.
		path, _ := unix.BytePtrFromString("/bin/true")
		argv := []*byte{path, nil}
		_, _, e := unix.RawSyscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&argv[0])), 0)
		out("execve returned " + e.Error())
	case "probe":
		// One raw call, its number and arguments in decimal; the program
		// exits with its errno.
		var n [7]uintptr
		for i, a := range args[1:] {
			v, _ := strconv.ParseUint(a, 10, 64)
			n[i] = uintptr(v)
		}
		_, _, e := unix.RawSyscall6(n[0], n[1], n[2], n[3], n[4], n[5], n[6])
		return int(e)
	default:
		return 2
	}
	return 0
}

// selfRun runs the test program confined by o with args.
func selfRun(t *testing.T, o Options, image string, input []byte, args ...string) string {
	t.Helper()
	out, err := o.RunSelf(t.Context(), image, input, selfTestProgram, args...)
	if err != nil {
		t.Fatalf("%v: %v %s", args, err, out)
	}
	return string(out)
}

// selfConfinedAs checks what every program of this executable is: no
// capability, none it could gain, no_new_privs, two seccomp filters (the
// self filter, then its own), PID 1 of its own namespace.
func selfConfinedAs(t *testing.T, o Options) map[string]string {
	t.Helper()
	s := map[string]string{}
	for _, line := range strings.Split(selfRun(t, o, "", nil, "status"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			s[k] = strings.TrimSpace(v)
		}
	}
	for _, c := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if s[c] != "0000000000000000" {
			t.Errorf("%s = %q: the program holds capabilities", c, s[c])
		}
	}
	// Two filters more than this process holds (none, unless it runs in a
	// container that installs one).
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	mine := 0
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp_filters:"); ok {
			mine, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if s["NoNewPrivs"] != "1" || s["Seccomp"] != "2" || s["Seccomp_filters"] != strconv.Itoa(mine+2) || s["NSpid"] != "1" {
		t.Errorf("NoNewPrivs %q, Seccomp %q, Seccomp_filters %q (this process %d), NSpid %q", s["NoNewPrivs"], s["Seccomp"], s["Seccomp_filters"], mine, s["NSpid"])
	}
	return s
}

// S-21: a program of this executable runs confined as debugfs does, under
// the self filter and its own: no privilege, PID 1 of its namespaces, as the
// caller in a user namespace of its own (not root here). Its arguments and
// environment hold nothing but its name, its arguments and LC_ALL=C.
func TestSelfRunIsConfined(t *testing.T) {
	if AsRoot() {
		t.Fatal("run as an account other than root; root runs sandbox_root_test.go (-tags root_integration)")
	}
	s := selfConfinedAs(t, Options{})
	if s["Uid"] != "0\t0\t0\t0" || s["Gid"] != "0\t0\t0\t0" || s["Cpus_allowed_list"] == "" || strings.ContainsAny(s["Cpus_allowed_list"], ",-") {
		t.Errorf("Uid %q Gid %q Cpus_allowed_list %q", s["Uid"], s["Gid"], s["Cpus_allowed_list"])
	}
	if got := selfRun(t, Options{}, "", nil, "identity"); got != selfTestProgram+"\x00identity\x00\nLC_ALL=C\x00" {
		t.Errorf("arguments and environment: %q", got)
	}
	if got := selfRun(t, Options{}, "", nil, "descriptors"); got != "" {
		t.Errorf("descriptors from 4 up are open: %s", got)
	}
}

// S-21: the input reaches the program on its standard input only, never in
// its arguments or environment; RunSelf refuses more than MaxInput bytes, a
// name that is not a program's, the test tools' filter and an unconfined
// run.
func TestSelfRunTakesItsInputOnStandardInputOnly(t *testing.T) {
	input := []byte("a key that must never be an argument")
	sum := sha256.Sum256(input)
	if got := selfRun(t, Options{}, "", input, "input"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("the program read %s", got)
	}
	if got := selfRun(t, Options{}, "", input, "identity"); strings.Contains(got, string(input)) {
		t.Errorf("the input is in the arguments or the environment: %q", got)
	}
	for _, o := range []Options{{Unconfined: true}, {TestTools: true}} {
		if _, err := o.RunSelf(t.Context(), "", nil, selfTestProgram, "status"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	if _, err := (Options{}).RunSelf(t.Context(), "", make([]byte, MaxInput+1), selfTestProgram, "input"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an input of %d bytes: %v", MaxInput+1, err)
	}
	for _, name := range []string{"", "debugfs", "/bin/sh", HelperName, "agentcapsule-", "agentcapsule-../x", "agentcapsule-Test"} {
		if _, err := (Options{}).RunSelf(t.Context(), "", nil, name); err == nil {
			t.Errorf("the name %q was run", name)
		}
	}
}

// S-21: the program reads its image read-only, writes no file, sees two
// empty regular files in /dev and no device, and executes no program: its
// own filter kills it at execve, although the self filter allows the call
// that started it.
func TestSelfRunCannotWriteExecuteOrOpenDevices(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("an image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := selfRun(t, Options{}, image, nil, "image"); got != "an image" {
		t.Errorf("the image reads %q", got)
	}
	for _, path := range []string{image, filepath.Join(dir, "written")} {
		if got := selfRun(t, Options{}, image, nil, "write", path); !strings.HasPrefix(got, "refused: read-only file system") {
			t.Errorf("writing %s: %s", path, got)
		}
	}
	want := "/dev/null absent\n/dev/zero absent\n/dev/random mode 100444 size 0 \"\"\n/dev/urandom mode 100444 size 0 \"\"\n" +
		"/dev/kvm absent\n/dev/mapper/control absent\n"
	if got := selfRun(t, Options{}, "", nil, "devices"); got != want {
		t.Errorf("devices:\n%s", got)
	}
	if out, err := (Options{}).RunSelf(t.Context(), "", nil, selfTestProgram, "exec"); !errors.Is(err, ErrSyscall) {
		t.Errorf("execve: %v %s", err, out)
	}
}

// S-21: a program of this executable may start threads, never a process or
// a namespace, and opens no socket; the rest of debugfs's list holds.
func TestSelfRunIsKilledForAnyOtherSystemCall(t *testing.T) {
	selfProbes(t, Options{})
}

func selfProbes(t *testing.T, o Options) {
	t.Helper()
	thread := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD)
	for _, p := range []syscallProbe{
		{"getpid", unix.SYS_GETPID, nil, refused(0)},
		// CLONE_THREAD without CLONE_SIGHAND: the kernel refuses it, so it
		// reaches the kernel and starts nothing.
		{"clone of a thread, as the kernel refuses it", unix.SYS_CLONE, []uint64{unix.CLONE_THREAD}, refused(unix.EINVAL)},
		{"clone3", unix.SYS_CLONE3, nil, refused(unix.ENOSYS)},
		{"mkdir", unix.SYS_MKDIR, nil, refused(unix.EROFS)},
		{"request_key", unix.SYS_REQUEST_KEY, nil, refused(unix.ENOSYS)},
		{"clone of a process", unix.SYS_CLONE, []uint64{uint64(unix.SIGCHLD)}, killed},
		{"clone of a thread in a new user namespace", unix.SYS_CLONE, []uint64{thread | unix.CLONE_NEWUSER}, killed},
		{"fork", unix.SYS_FORK, nil, killed},
		{"vfork", unix.SYS_VFORK, nil, killed},
		{"unshare", unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWUSER}, killed},
		{"setns", unix.SYS_SETNS, nil, killed},
		{"execveat", unix.SYS_EXECVEAT, nil, killed},
		{"socket", unix.SYS_SOCKET, []uint64{unix.AF_INET, unix.SOCK_STREAM}, killed},
		{"socketpair", unix.SYS_SOCKETPAIR, []uint64{unix.AF_UNIX, unix.SOCK_STREAM}, killed},
		{"mount", unix.SYS_MOUNT, nil, killed},
		{"ptrace", unix.SYS_PTRACE, []uint64{unix.PTRACE_TRACEME}, killed},
		{"keyctl", unix.SYS_KEYCTL, nil, killed},
		{"add_key", unix.SYS_ADD_KEY, nil, killed},
		{"bpf", unix.SYS_BPF, nil, killed},
		{"io_uring_setup", unix.SYS_IO_URING_SETUP, nil, killed},
		{"memfd_create", unix.SYS_MEMFD_CREATE, nil, killed},
		{"setresuid", unix.SYS_SETRESUID, nil, killed},
		{"kill", unix.SYS_KILL, []uint64{1, 0}, killed},
		{"flock", unix.SYS_FLOCK, []uint64{0, unix.LOCK_SH}, killed},
		{"chroot", unix.SYS_CHROOT, nil, killed},
		{"pidfd_open", unix.SYS_PIDFD_OPEN, nil, killed},
	} {
		args := []string{"probe", strconv.FormatUint(p.nr, 10)}
		for _, a := range p.args {
			args = append(args, strconv.FormatUint(a, 10))
		}
		_, err := o.RunSelf(t.Context(), "", nil, selfTestProgram, args...)
		var exit *exec.ExitError
		got := ""
		switch {
		case err == nil:
			got = refused(0)
		case errors.Is(err, ErrSyscall):
			got = killed
		case errors.As(err, &exit) && exit.Exited():
			got = refused(unix.Errno(exit.ExitCode()))
		default:
			t.Fatalf("%s: %v", p.name, err)
		}
		if got != p.want {
			t.Errorf("%s: %s, not %s", p.name, got, p.want)
		}
	}
}

// S-21: a program of this executable has 256 MiB of memory it can write
// (eight times as much under the race detector): it allocates 64 MiB (the
// Argon2id of a LUKS2 key slot), and the Go runtime fails to allocate 256
// MiB more than its limit; the mapping fails, nothing is written.
func TestSelfRunCannotAllocateBeyondItsLimit(t *testing.T) {
	if got := selfRun(t, Options{}, "", nil, "memory", "64"); got != "allocated 64" {
		t.Errorf("64 MiB: %s", got)
	}
	limit := uint64(selfData)
	if raceBuild {
		limit *= 8
	}
	beyond := strconv.FormatUint(limit>>20+256, 10)
	out, err := (Options{}).RunSelf(t.Context(), "", nil, selfTestProgram, "memory", beyond)
	if err == nil || bytes.Contains(out, []byte("allocated")) {
		t.Errorf("%s MiB: %v %s", beyond, err, out)
	}
}

// S-21: started under its name but outside RunSelf, the program refuses to
// run, and says why.
func TestSelfRefusesToRunUnconfined(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "status")
	cmd.Args[0] = selfTestProgram
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || len(out) != 0 || !strings.Contains(stderr.String(), "not started by RunSelf") {
		t.Errorf("%v %q %q", err, out, stderr.String())
	}
	if exit != nil && exit.Sys().(syscall.WaitStatus).Signaled() {
		t.Errorf("killed: %v", err)
	}
}
