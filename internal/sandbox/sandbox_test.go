//go:build linux

package sandbox

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tools confines the shells and tools of these tests: the program may make
// any system call but those that start a process or open a socket. The
// allow-list of every other run is tested on its own (probe_test.go,
// seccomp_test.go), and on debugfs (internal/harnesspkg).
var tools = Options{TestTools: true}

// sh is the shell the probes run in; they use builtins and exec only, since
// the sandbox lets no process start another.
func sh(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// status reads the fields of /proc/self/status as the program sees them.
func status(t *testing.T, o Options) map[string]string {
	t.Helper()
	out, err := o.Run(t.Context(), "", sh(t), "-c", "exec cat /proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

// confinedAs checks what every confined program is: no capability, none it
// could gain, no_new_privs, a seccomp filter, PID 1 of its own namespace.
func confinedAs(t *testing.T, o Options) map[string]string {
	t.Helper()
	s := status(t, o)
	for _, c := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if s[c] != "0000000000000000" {
			t.Errorf("%s = %q: the program holds capabilities", c, s[c])
		}
	}
	if s["NoNewPrivs"] != "1" || s["Seccomp"] != "2" || s["NSpid"] != "1" {
		t.Errorf("NoNewPrivs %q, Seccomp %q, NSpid %q", s["NoNewPrivs"], s["Seccomp"], s["NSpid"])
	}
	return s
}

// namespacesDiffer checks that the program's namespaces all differ from
// this process's, but for the cgroup namespace.
func namespacesDiffer(t *testing.T, o Options) {
	t.Helper()
	kinds := []string{"mnt", "net", "pid", "ipc", "uts"}
	if !AsRoot() {
		kinds = append(kinds, "user")
	}
	args := []string{"-c", "exec readlink \"$@\"", "sh"}
	for _, ns := range kinds {
		args = append(args, "/proc/self/ns/"+ns)
	}
	out, err := o.Run(t.Context(), "", sh(t), args...)
	if err != nil {
		t.Fatal(err)
	}
	theirs := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(theirs) != len(kinds) {
		t.Fatalf("the program lists %d namespaces, not %d: %s", len(theirs), len(kinds), out)
	}
	for i, ns := range kinds {
		mine, err := os.Readlink("/proc/self/ns/" + ns)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(theirs[i], ns+":[") || theirs[i] == mine {
			t.Errorf("the program's %s namespace is %s, this process's %s", ns, theirs[i], mine)
		}
	}
}

// cannotWrite runs probes that try to change the image, to write elsewhere,
// and to start a process; none may succeed, and the image keeps its bytes.
// It returns what the write attempts printed.
func cannotWrite(t *testing.T, o Options, image, elsewhere string) string {
	t.Helper()
	before, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	// Each attempt is a regular shell builtin (a special one, such as ":",
	// would end the shell on a failed redirection): it opens the file in the
	// shell itself.
	script := `exec 2>&1
true 1<> ` + ImagePath + ` && echo OPENED-IMAGE-FOR-WRITING
printf x 1<> ` + ImagePath + ` && echo WROTE-IMAGE
printf x >> ` + ImagePath + ` && echo APPENDED-IMAGE
true > ` + ImagePath + ` && echo TRUNCATED-IMAGE
true 1<> '` + image + `' && echo OPENED-IMAGE-PATH-FOR-WRITING
printf x > '` + elsewhere + `' && echo WROTE-ELSEWHERE
echo done`
	out, err := o.Run(t.Context(), image, sh(t), "-c", script)
	if err != nil {
		t.Fatal(err, string(out))
	}
	for _, mark := range []string{"OPENED-IMAGE-FOR-WRITING", "WROTE-IMAGE", "APPENDED-IMAGE", "TRUNCATED-IMAGE",
		"OPENED-IMAGE-PATH-FOR-WRITING", "WROTE-ELSEWHERE"} {
		if strings.Contains(string(out), mark) {
			t.Errorf("the program could do it: %s\n%s", mark, out)
		}
	}
	// Each attempt fails: on the read-only mounts or, for the dedicated
	// account, on the file's or the directory's permissions.
	refused := strings.Count(string(out), "Read-only file system") + strings.Count(string(out), "Permission denied")
	if !strings.HasSuffix(string(out), "done\n") || refused != 6 {
		t.Errorf("the probe did not run to its end, or an attempt failed otherwise:\n%s", out)
	}
	writes := string(out)
	// The shell gives up when it cannot fork: nothing after runs.
	out, err = o.Run(t.Context(), image, sh(t), "-c", "exec 2>&1; x=$(echo forked) && echo FORKED")
	if err == nil || strings.Contains(string(out), "FORKED") {
		t.Errorf("the program started another process: %v %s", err, out)
	}
	after, err := os.ReadFile(image)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("the image changed: %x to %x %v", sha256.Sum256(before), sha256.Sum256(after), err)
	}
	if _, err = os.Stat(elsewhere); !os.IsNotExist(err) {
		t.Errorf("the program created %s: %v", elsewhere, err)
	}
	return writes
}

// killedAtLimits: a program that sleeps is killed at Timeout, one that spins
// at CPU, each well before the other limit.
func killedAtLimits(t *testing.T, o Options) {
	t.Helper()
	o.Timeout, o.CPU = time.Second, 30*time.Second
	start := time.Now()
	_, err := o.Run(t.Context(), "", sh(t), "-c", "exec sleep 600")
	if !errors.Is(err, ErrLimit) || time.Since(start) > 10*time.Second {
		t.Errorf("a sleeping program: %v after %s", err, time.Since(start))
	}
	o.Timeout, o.CPU = time.Minute, time.Second
	start = time.Now()
	_, err = o.Run(t.Context(), "", sh(t), "-c", "while :; do :; done")
	if !errors.Is(err, ErrLimit) || time.Since(start) > 20*time.Second {
		t.Errorf("a spinning program: %v after %s", err, time.Since(start))
	}
}

// REG-01: the confined program holds no capability, cannot gain any, runs
// under seccomp as PID 1 of its own namespaces, and (as an account that is
// not root) keeps this account's identity: root of its own user namespace,
// this account on the host.
func TestConfinedProgramHoldsNoPrivilege(t *testing.T) {
	if AsRoot() {
		t.Fatal("run as an account other than root; root runs sandbox_root_test.go (-tags root_integration)")
	}
	s := confinedAs(t, tools)
	if s["Uid"] != "0\t0\t0\t0" || s["Gid"] != "0\t0\t0\t0" {
		t.Errorf("in its user namespace the program is Uid %q Gid %q, not root of it", s["Uid"], s["Gid"])
	}
	namespacesDiffer(t, tools)
}

// REG-01: the image is open read-only; the program can write neither it, by
// its descriptor or its path, nor any other file, and cannot start a process.
// The image and its directory belong to the program's account, which may
// write them: the read-only mounts refuse each attempt, the descriptor's
// included (the sandbox reopens the image through them).
func TestConfinedProgramCannotWrite(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, bytes.Repeat([]byte("image"), 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := cannotWrite(t, tools, image, filepath.Join(dir, "written")); strings.Count(out, "Read-only file system") != 6 {
		t.Errorf("an attempt was not refused by the read-only mounts:\n%s", out)
	}
}

// REG-01: the program inherits descriptors 0 to 3 only. A file this process
// holds open for writing without close-on-exec, as C code linked by the
// worker may hold a volume, is not the program's: it is not listed in its
// /proc/self/fd, and the program cannot truncate the file through it.
func TestConfinedProgramInheritsNoOtherDescriptor(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "volume")
	if err := os.WriteFile(victim, []byte("another tenant's volume"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(victim, unix.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	// A high number, which Run's own descriptors cannot take.
	const leaked = 100
	if err = unix.Dup2(fd, leaked); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(leaked)
	script := "exec 2>&1\n" +
		"true > /proc/self/fd/" + strconv.Itoa(leaked) + " && echo TRUNCATED\n" +
		`for f in /proc/self/fd/*; do echo "${f##*/}"; done`
	out, err := tools.Run(t.Context(), "", sh(t), "-c", script)
	if err != nil {
		t.Fatal(err, string(out))
	}
	var fds []string
	for _, line := range strings.Split(string(out), "\n") {
		if _, err := strconv.Atoi(line); err == nil {
			fds = append(fds, line)
		}
	}
	// 4 is the directory the shell lists.
	if strings.Contains(string(out), "TRUNCATED") || !slices.Equal(fds, []string{"0", "1", "2", "3", "4"}) {
		t.Errorf("the program holds other descriptors, or truncated the file:\n%s", out)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "another tenant's volume" {
		t.Errorf("the file changed: %q %v", b, err)
	}
}

// cannotOpenDevices: no device node opens in the sandbox, for writing or
// reading, whatever its permissions: /dev/null, and those this account may
// open (/dev/kvm through the kvm group, a terminal multiplexer, a network
// tunnel). Read-only mounts do not stop writes to a device.
func cannotOpenDevices(t *testing.T, o Options) {
	t.Helper()
	devices := []string{"/dev/null"}
	for _, d := range []string{"/dev/kvm", "/dev/vhost-net", "/dev/net/tun", "/dev/fuse", "/dev/ptmx"} {
		if f, err := os.OpenFile(d, os.O_RDWR, 0); err == nil {
			f.Close()
			devices = append(devices, d)
		}
	}
	script := "exec 2>&1\n"
	for _, d := range devices {
		script += "true 1<> " + d + " && echo OPENED " + d + "\ntrue < " + d + " && echo READ " + d + "\n"
	}
	out, err := o.Run(t.Context(), "", sh(t), "-c", script+"echo done")
	if err != nil {
		t.Fatal(err, string(out))
	}
	if strings.Contains(string(out), "OPENED") || strings.Contains(string(out), "READ") ||
		strings.Count(string(out), "Permission denied") != 2*len(devices) || !strings.HasSuffix(string(out), "done\n") {
		t.Errorf("the program opened a device (of %v):\n%s", devices, out)
	}
}

// REG-01: the program opens no device node.
func TestConfinedProgramCannotOpenDevices(t *testing.T) {
	cannotOpenDevices(t, tools)
}

// seesNoKernelState: the program's /proc holds its own process only
// (subset=pid: no /proc/sys, kallsyms, cpuinfo or mounts), and its /sys is
// empty.
func seesNoKernelState(t *testing.T, o Options) {
	t.Helper()
	script := `for p in /proc/sys /proc/kallsyms /proc/cpuinfo /proc/meminfo /proc/mounts /proc/net /sys/kernel /sys/class /sys/devices /sys/fs; do
  [ -e "$p" ] && echo "SEES $p"
done
[ -r /proc/self/status ] && echo SELF
for f in /sys/*; do echo "SYS $f"; done
echo done`
	out, err := o.Run(t.Context(), "", sh(t), "-c", script)
	if err != nil {
		t.Fatal(err, string(out))
	}
	if string(out) != "SELF\nSYS /sys/*\ndone\n" {
		t.Errorf("the program sees the kernel's state:\n%s", out)
	}
}

// REG-01: the program sees no more of the kernel than its own process.
func TestConfinedProgramSeesNoKernelState(t *testing.T) {
	seesNoKernelState(t, tools)
}

// REG-01: a program that hangs is killed at the time limit, one that spins at
// the processor limit.
func TestConfinedProgramIsKilledAtItsLimits(t *testing.T) {
	killedAtLimits(t, tools)
}

// REG-01: root of a user namespace other than the host's (a container's
// root, a test under unshare -r) cannot take a reserved UID: Run refuses it,
// rather than run the program as that root in a user namespace of its own,
// with access to every file that root owns.
func TestRootOfAnotherUserNamespaceIsRefused(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Fatal("unshare (util-linux) is required:", err)
	}
	cmd := exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--",
		os.Args[0], "-test.run", "^TestRunAsRootOfAnotherUserNamespace$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_SANDBOX_USERNS_ROOT=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestRunAsRootOfAnotherUserNamespace ") {
		t.Fatalf("as root of another user namespace: %v\n%s", err, out)
	}
}

// TestRunAsRootOfAnotherUserNamespace runs only under
// TestRootOfAnotherUserNamespaceIsRefused.
func TestRunAsRootOfAnotherUserNamespace(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_SANDBOX_USERNS_ROOT") == "" {
		return
	}
	if os.Geteuid() != 0 || AsRoot() {
		t.Fatal("not root of another user namespace")
	}
	for _, o := range []Options{tools, {UID: 61999, GID: 61999, TestTools: true}} {
		if out, err := o.Run(t.Context(), "", sh(t), "-c", "echo RAN"); !errors.Is(err, ErrUnavailable) || len(out) != 0 {
			t.Errorf("%+v: %v %s", o, err, out)
		}
	}
}

// helperCommand is the helper as Run starts it, with args: in its own
// namespaces, descriptor 3 on /dev/null, 4 the pipe for the reason it
// fails, 5 its lifeline, whose writing end only this process holds (closing
// it plays the caller's death). done, once the helper has exited, closes
// what remains and returns that reason.
func helperCommand(t *testing.T, args ...string) (cmd *exec.Cmd, lifeline *os.File, done func() string) {
	t.Helper()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	status, report, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.CommandContext(t.Context(), helperPath, args...)
	cmd.Args[0] = HelperName
	cmd.SysProcAttr = namespaces(AsRoot())
	cmd.ExtraFiles = []*os.File{null, report, life}
	cmd.Env = []string{"LC_ALL=C"}
	done = func() string {
		for _, f := range []*os.File{null, report, life, lifeline} {
			f.Close()
		}
		reason, _ := io.ReadAll(status)
		status.Close()
		return string(reason)
	}
	return cmd, lifeline, done
}

// REG-01: the helper runs the program only while its caller lives. Taking
// the reserved UID clears the parent-death signal until the helper sets it
// again; it then checks its lifeline, a pipe whose writing end only the
// caller holds. Started with that end already closed, as if the caller had
// died in between, it refuses to run the program.
func TestHelperRunsNothingOnceItsCallerIsGone(t *testing.T) {
	cmd, lifeline, done := helperCommand(t, "0", "0", "1", testToolsFilter, "-", sh(t), "-c", "echo RAN")
	lifeline.Close()
	out, err := cmd.Output()
	reason := done()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || strings.Contains(string(out), "RAN") || !strings.Contains(reason, "caller") {
		t.Fatalf("the helper without its caller: %v %s (%s)", err, out, reason)
	}
	// With its caller, the same helper runs the program.
	cmd, _, done = helperCommand(t, "0", "0", "1", testToolsFilter, "-", sh(t), "-c", "echo RAN")
	out, err = cmd.Output()
	if reason := done(); err != nil || string(out) != "RAN\n" {
		t.Fatalf("the helper with its caller: %v %s (%s)", err, out, reason)
	}
}

// The helper refuses to run outside the namespaces Run creates: started
// directly under its name, it changes nothing and exits 125.
func TestHelperRefusesToRunOutsideItsNamespaces(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), helperPath, "0", "0", "1", strictFilter, "-", sh(t), "-c", "echo RAN")
	cmd.Args[0] = HelperName
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || strings.Contains(string(out), "RAN") ||
		!strings.Contains(string(out), "not PID 1") {
		t.Fatalf("the helper outside Run: %v %s", err, out)
	}
}
