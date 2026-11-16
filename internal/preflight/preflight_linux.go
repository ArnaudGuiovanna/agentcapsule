//go:build linux

// Package preflight checks a host and its configuration before the platform
// runs there (RUN-012, docs/adr/010-transport-security-and-preflight.md). It
// only reads: it creates no file, writes no setting and loads no module. A
// check that fails says what to fix. The worker runs the mandatory host checks
// at every start and refuses Firecracker without them; the full set runs on
// demand (agentcapsule-worker -preflight, agentcapsule-api -preflight).
package preflight

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FirecrackerVersion is the release of runtime/firecracker/manifest.json; the
// binaries' --version must name it.
const FirecrackerVersion = "1.17.0"

type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Result is one check. Detail and Fix hold paths, versions and names from the
// operator's configuration, never a secret or a connection string.
type Result struct {
	Check  string
	Status Status
	Detail string
	Fix    string
}

func ok(check, detail string) Result { return Result{check, OK, detail, ""} }
func warn(check, detail, fix string) Result {
	return Result{check, Warn, detail, fix}
}
func fail(check, detail, fix string) Result { return Result{check, Fail, detail, fix} }

// Failed reports whether any result failed.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

// Write prints one line per check, and the fix under each check that is not
// ok, then preflight_passed or preflight_failed.
func Write(w io.Writer, results []Result) error {
	b := bufio.NewWriter(w)
	for _, r := range results {
		fmt.Fprintf(b, "%-4s %s: %s\n", r.Status, r.Check, r.Detail)
		if r.Status != OK && r.Fix != "" {
			fmt.Fprintf(b, "     fix: %s\n", r.Fix)
		}
	}
	if Failed(results) {
		fmt.Fprintln(b, "preflight_failed")
	} else {
		fmt.Fprintln(b, "preflight_passed")
	}
	return b.Flush()
}

// Host is the machine under check. Root prefixes the fixed system paths
// (/dev/kvm, /proc, /sys): "/" on a real host, a directory in tests. Paths
// from the operator's configuration are used as they are.
type Host struct {
	Root string
	// Release returns the running kernel's release (uname -r).
	Release func() (string, error)
	// KVM opens the KVM device read-write and returns its API version and
	// the capabilities it lacks among those asked.
	KVM func(path string, capabilities []KVMCapability) (int, []KVMCapability, error)
	// Statfs describes the file system holding path.
	Statfs func(path string) (syscall.Statfs_t, error)
	// ClockSynchronized asks the kernel whether NTP keeps the clock in sync.
	ClockSynchronized func() (bool, error)
	// Version runs a binary with --version and returns its output.
	Version func(ctx context.Context, binary string) (string, error)
	Now     func() time.Time
}

// System is the real host.
func System() Host {
	return Host{Root: "/", Release: release, KVM: probeKVM, Statfs: statfs, ClockSynchronized: clockSynchronized,
		Version: version, Now: time.Now}
}

func (h Host) path(p string) string { return filepath.Join(h.Root, p) }

func release() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", err
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b), nil
}

func statfs(path string) (syscall.Statfs_t, error) {
	var st syscall.Statfs_t
	err := syscall.Statfs(path, &st)
	return st, err
}

// clockSynchronized reads the kernel's NTP state without changing it
// (adjtimex with no mode bits set).
func clockSynchronized() (bool, error) {
	var t syscall.Timex
	state, err := syscall.Adjtimex(&t)
	if err != nil {
		return false, err
	}
	const timeError, staUnsync = 5, 0x0040
	return state != timeError && t.Status&staUnsync == 0, nil
}

func version(ctx context.Context, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	out, err := cmd.Output()
	return string(out), err
}

// KVMCapability is a KVM_CAP_* number of linux/kvm.h.
type KVMCapability struct {
	Name   string
	Number uintptr
}

// FirecrackerCapabilities are the capabilities Firecracker 1.17 requires of
// KVM on x86_64 (src/vmm/src/arch/x86_64/kvm.rs); it refuses to start
// without any of them.
var FirecrackerCapabilities = []KVMCapability{
	{"KVM_CAP_IRQCHIP", 0}, {"KVM_CAP_IOEVENTFD", 36}, {"KVM_CAP_IRQFD", 32}, {"KVM_CAP_USER_MEMORY", 3},
	{"KVM_CAP_SET_TSS_ADDR", 4}, {"KVM_CAP_PIT2", 33}, {"KVM_CAP_PIT_STATE2", 35}, {"KVM_CAP_ADJUST_CLOCK", 39},
	{"KVM_CAP_DEBUGREGS", 50}, {"KVM_CAP_MP_STATE", 14}, {"KVM_CAP_VCPU_EVENTS", 41}, {"KVM_CAP_XCRS", 56},
	{"KVM_CAP_XSAVE", 55}, {"KVM_CAP_EXT_CPUID", 7},
}

const (
	kvmAPIVersion     = 12
	kvmGetAPIVersion  = 0xAE00 // _IO(KVMIO, 0x00)
	kvmCheckExtension = 0xAE03 // _IO(KVMIO, 0x03)
)

// probeKVM asks the device; opening /dev/kvm and these two ioctls create no
// VM and change nothing.
func probeKVM(path string, capabilities []KVMCapability) (int, []KVMCapability, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	api, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmGetAPIVersion, 0)
	if errno != 0 {
		return 0, nil, errno
	}
	var missing []KVMCapability
	for _, c := range capabilities {
		r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmCheckExtension, c.Number)
		if errno != 0 || r == 0 {
			missing = append(missing, c)
		}
	}
	return int(api), missing, nil
}

// KVM checks /dev/kvm: the KVM character device (10:232), open read-write,
// API version 12, and every capability Firecracker requires.
func KVM(h Host) Result {
	const check = "kvm"
	path := h.path("/dev/kvm")
	fix := "run on a host with hardware virtualization (VT-x or AMD-V enabled in the firmware, or nested virtualization), with kvm_intel or kvm_amd loaded"
	st, err := os.Stat(path)
	if err != nil {
		return fail(check, "/dev/kvm is missing", fix)
	}
	if st.Mode()&os.ModeCharDevice == 0 || st.Mode()&os.ModeDevice == 0 {
		return fail(check, "/dev/kvm is not a character device", fix)
	}
	rdev := st.Sys().(*syscall.Stat_t).Rdev
	if major, minor := (rdev>>8)&0xfff, (rdev&0xff)|((rdev>>12)&0xfff00); major != 10 || minor != 232 {
		return fail(check, fmt.Sprintf("/dev/kvm is device %d:%d, not KVM (10:232)", major, minor), fix)
	}
	api, missing, err := h.KVM(path, FirecrackerCapabilities)
	if err != nil {
		return fail(check, "/dev/kvm cannot be opened read-write: "+errnoText(err),
			"run the worker as root, and check that no security module denies /dev/kvm")
	}
	if api != kvmAPIVersion {
		return fail(check, fmt.Sprintf("KVM API version %d, Firecracker needs %d", api, kvmAPIVersion), "use a kernel with the standard KVM API")
	}
	if len(missing) > 0 {
		names := make([]string, len(missing))
		for i, c := range missing {
			names[i] = c.Name
		}
		return fail(check, "KVM lacks "+strings.Join(names, ", "), "use a host kernel and CPU that Firecracker supports (x86_64 with a full KVM)")
	}
	return ok(check, fmt.Sprintf("/dev/kvm read-write, KVM API %d, the %d capabilities Firecracker requires", api, len(FirecrackerCapabilities)))
}

func errnoText(err error) string {
	if e, ok := err.(*os.PathError); ok {
		err = e.Err
	}
	return err.Error()
}

// Kernel checks the running kernel: 5.14 or later, since the worker kills an
// attempt's processes with cgroup.kill (5.14) and places them at fork with
// clone3 (5.7). A kernel Firecracker 1.17 does not validate (5.10, 6.1 and
// 6.18 are) is reported as a warning.
func Kernel(h Host) Result {
	const check = "kernel"
	text, err := h.Release()
	if err != nil {
		return fail(check, "the kernel release cannot be read", "check uname -r")
	}
	major, minor, parsed := kernelVersion(text)
	if !parsed {
		return fail(check, "kernel release "+text+" does not parse", "use a Linux kernel with a release of the form X.Y")
	}
	if major < 5 || major == 5 && minor < 14 {
		return fail(check, "kernel "+text+" is older than 5.14", "upgrade the host kernel to 6.1 or 6.18 (Firecracker 1.17's validated host kernels)")
	}
	validated := major == 6 && (minor == 1 || minor == 18)
	if !validated {
		return warn(check, "kernel "+text+" works but is not one Firecracker 1.17 validates (6.1, 6.18)",
			"prefer a 6.1 or 6.18 host kernel")
	}
	return ok(check, "kernel "+text)
}

func kernelVersion(release string) (int, int, bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	digits := parts[1]
	if i := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = digits[:i]
	}
	minor, err := strconv.Atoi(digits)
	return major, minor, err == nil
}

// Controllers the worker enables for its VMs (memory.max, cpu.max, pids.max).
var cgroupControllers = []string{"cpu", "memory", "pids"}

// Cgroups checks the unified cgroup v2 hierarchy at /sys/fs/cgroup and that
// its root delegates cpu, memory and pids to child groups, as the worker's
// group under the root needs them.
func Cgroups(h Host) Result {
	const check = "cgroups"
	root := h.path("/sys/fs/cgroup")
	st, err := h.Statfs(root)
	const cgroup2Magic = 0x63677270
	if err != nil || st.Type != cgroup2Magic {
		return fail(check, "/sys/fs/cgroup is not a cgroup v2 hierarchy",
			"boot with the unified hierarchy (systemd.unified_cgroup_hierarchy=1, the default since systemd 247)")
	}
	for _, file := range []string{"cgroup.controllers", "cgroup.subtree_control"} {
		b, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return fail(check, "/sys/fs/cgroup/"+file+" cannot be read", "mount cgroup v2 at /sys/fs/cgroup")
		}
		have := strings.Fields(string(b))
		var missing []string
		for _, c := range cgroupControllers {
			if !contains(have, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			if file == "cgroup.controllers" {
				return fail(check, "the kernel offers no "+strings.Join(missing, ", ")+" controller", "use a kernel built with the cpu, memory and pids cgroup controllers")
			}
			return fail(check, "the root group does not delegate "+strings.Join(missing, ", ")+" (/sys/fs/cgroup/cgroup.subtree_control)",
				"enable them for child groups: DefaultCPUAccounting=yes, DefaultMemoryAccounting=yes and DefaultTasksAccounting=yes in /etc/systemd/system.conf, then reboot")
		}
	}
	return ok(check, "cgroup v2, cpu, memory and pids delegated by the root group")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Namespaces checks the namespaces the jailer creates for each VM: mount,
// PID and network.
func Namespaces(h Host) Result {
	const check = "namespaces"
	var missing []string
	for _, ns := range []string{"mnt", "pid", "net"} {
		if _, err := os.Lstat(h.path("/proc/self/ns/" + ns)); err != nil {
			missing = append(missing, ns)
		}
	}
	if len(missing) > 0 {
		return fail(check, "no "+strings.Join(missing, ", ")+" namespace support", "use a kernel with CONFIG_NAMESPACES, PID_NS and NET_NS")
	}
	return ok(check, "mount, PID and network namespaces")
}

// Clock checks that NTP keeps the clock in sync: TLS certificates, delegated
// identities and leases depend on it.
func Clock(h Host) Result {
	const check = "clock"
	synced, err := h.ClockSynchronized()
	if err != nil {
		return fail(check, "the clock's synchronization state cannot be read", "check adjtimex support")
	}
	if !synced {
		return fail(check, "the clock is not synchronized", "enable a time service: systemctl enable --now systemd-timesyncd, or chrony")
	}
	return ok(check, "the clock is synchronized")
}

// Artifact is a file of the worker's configuration pinned by SHA-256. Pinned
// is the copy the worker keeps under its runtime root (<root>/bin/<name>),
// which stands in for a missing source once the worker has started once.
type Artifact struct {
	Name, Path, SHA256, Pinned string
}

func fileSHA256(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	d := sha256.New()
	if _, err = io.Copy(d, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(d.Sum(nil)), nil
}

// Artifacts checks each runtime artifact's digest, Firecracker's and the
// jailer's version, and that the kernel is an ELF image.
func Artifacts(ctx context.Context, h Host, artifacts []Artifact) []Result {
	var out []Result
	for _, a := range artifacts {
		check := "artifact_" + a.Name
		if len(a.SHA256) != 64 {
			out = append(out, fail(check, a.Name+" has no SHA-256 in the configuration", "write the file's SHA-256 (sha256sum) in the worker configuration"))
			continue
		}
		path := a.Path
		got, err := fileSHA256(path)
		if err != nil && a.Pinned != "" {
			path = a.Pinned
			got, err = fileSHA256(path)
		}
		if err != nil {
			out = append(out, fail(check, a.Path+" cannot be read", "install the file at the configured path"))
			continue
		}
		if got != a.SHA256 {
			out = append(out, fail(check, path+" has SHA-256 "+got+", the configuration pins "+a.SHA256,
				"install the pinned file, or pin the digest of the file you built (scripts/build-firecracker.py, scripts/build-guest-kernel.py)"))
			continue
		}
		detail := path + " matches its SHA-256"
		switch a.Name {
		case "firecracker", "jailer":
			label := map[string]string{"firecracker": "Firecracker", "jailer": "Jailer"}[a.Name]
			text, err := h.Version(ctx, path)
			if err != nil || !strings.Contains(text, label+" v"+FirecrackerVersion) {
				out = append(out, fail(check, path+" does not report "+label+" v"+FirecrackerVersion,
					"build the pinned release with scripts/build-firecracker.py (runtime/firecracker/manifest.json)"))
				continue
			}
			detail += ", " + label + " v" + FirecrackerVersion
		case "kernel":
			if !elf(path) {
				out = append(out, fail(check, path+" is not an ELF kernel image (vmlinux)", "give Firecracker the uncompressed vmlinux of scripts/build-guest-kernel.py"))
				continue
			}
		}
		out = append(out, ok(check, detail))
	}
	return out
}

func elf(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	_, err = io.ReadFull(f, magic)
	return err == nil && string(magic) == "\x7fELF"
}

// nearest returns the closest existing ancestor of path, itself included.
func nearest(path string) string {
	for {
		if _, err := os.Lstat(path); err == nil || path == "/" || path == "." {
			return path
		}
		path = filepath.Dir(path)
	}
}

const (
	stRdonly = 0x1
	stNodev  = 0x4
	stNoexec = 0x8
)

var fileSystems = map[int64]string{
	0xEF53: "ext4", 0x58465342: "xfs", 0x9123683E: "btrfs", 0x01021994: "tmpfs", 0x858458f6: "ramfs",
	0x6969: "nfs", 0x01021997: "9p", 0x65735546: "fuse", 0x794c7630: "overlayfs", 0x2fc12fc1: "zfs",
}

// RuntimeFileSystem checks the file system of the runtime root: kept across
// reboots, local, writable, and mounted without nodev or noexec, since the
// jailer creates device nodes in each VM's chroot and runs Firecracker there.
func RuntimeFileSystem(h Host, root string) Result {
	const check = "runtime_filesystem"
	if !filepath.IsAbs(root) {
		return fail(check, "the runtime root is not an absolute path", "set root to an absolute path")
	}
	at := nearest(root)
	st, err := h.Statfs(at)
	if err != nil {
		return fail(check, "the file system of "+root+" cannot be read", "create the runtime root's parent directory")
	}
	name, known := fileSystems[int64(st.Type)]
	if !known {
		name = fmt.Sprintf("0x%x", st.Type)
	}
	switch name {
	case "tmpfs", "ramfs":
		return fail(check, root+" is on "+name+": volumes would be lost at reboot", "put the runtime root on a local ext4 or xfs file system")
	case "nfs", "9p", "fuse", "overlayfs":
		return fail(check, root+" is on "+name+", which does not keep the volume locks", "put the runtime root on a local ext4 or xfs file system")
	}
	switch {
	case st.Flags&stRdonly != 0:
		return fail(check, root+" is on a read-only mount", "mount it read-write")
	case st.Flags&stNodev != 0:
		return fail(check, root+" is on a nodev mount: the jailer cannot create /dev/kvm in a VM's chroot", "mount it without nodev")
	case st.Flags&stNoexec != 0:
		return fail(check, root+" is on a noexec mount: the jailer cannot run Firecracker in a VM's chroot", "mount it without noexec")
	}
	if !known || name == "zfs" {
		return warn(check, root+" is on "+name+", not qualified", "prefer ext4 or xfs")
	}
	return ok(check, root+" is on "+name+", read-write, with devices and execution allowed")
}

// Disk checks the free space of the file system holding each path: a warning
// from 70% used, a failure from 80%, the levels of the disk alerts
// (docs/observability.md).
func Disk(h Host, name, path string) Result {
	check := "disk_" + name
	st, err := h.Statfs(nearest(path))
	if err != nil {
		return fail(check, "the file system of "+path+" cannot be read", "create the directory's parent")
	}
	used := uint64(st.Blocks - st.Bfree)
	total := used + st.Bavail
	if total == 0 {
		return fail(check, path+" is on a file system without space", "use a disk-backed file system")
	}
	percent := used * 100 / total
	free := st.Bavail * uint64(st.Bsize) >> 30
	detail := fmt.Sprintf("%s: %d%% used, %d GiB free", path, percent, free)
	switch {
	case percent >= 80:
		return fail(check, detail, "free space or grow the file system below 70% used")
	case percent >= 70:
		return warn(check, detail, "free space before the 80% alert")
	}
	return ok(check, detail)
}

// Mandatory are the checks without which the worker does not run Firecracker
// (RUN-012).
func Mandatory(ctx context.Context, h Host, runtimeRoot string, artifacts []Artifact) []Result {
	out := []Result{KVM(h), Kernel(h), Cgroups(h), Namespaces(h), RuntimeFileSystem(h, runtimeRoot)}
	return append(out, Artifacts(ctx, h, artifacts)...)
}
