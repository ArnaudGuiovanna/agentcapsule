//go:build linux

package workerhelper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Ops are the privileged operations, once a request is checked. System is
// the host's; the server's tests use a fake. The runtime, when it runs as
// root without a helper (laboratories, the KVM suites), calls System
// directly.
type Ops interface {
	Own(f *os.File, uid, gid uint32, mode os.FileMode, sync bool) error
	PrepareJail(p JailPlan) error
	Start(p StartPlan) error
	Observe(jail *os.File, t Target) (Observation, error)
	Populated(group string) (bool, error)
	Cleanup(runs *os.File, runID, group string) error
	Dial(jail *os.File, uid uint32) (*os.File, error)
	Listen(jail *os.File, uid uint32) (*os.File, error)
	LinkProbe(f *os.File, dir string) error
	Sandbox(ctx context.Context, p SandboxPlan) ([]byte, error)
	Fetch(ctx context.Context, p FetchPlan) error
}

// System performs the operations on this host.
type System struct{}

// Own gives f to uid and gid, sets its mode unless zero, and makes both
// durable when sync is set.
func (System) Own(f *os.File, uid, gid uint32, mode os.FileMode, sync bool) error {
	if err := f.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if mode != 0 {
		if err := f.Chmod(mode); err != nil {
			return err
		}
	}
	if sync {
		return f.Sync()
	}
	return nil
}

// PlacedFile is a file put into a jail under Name, open as File.
type PlacedFile struct {
	Name, Kind string
	File       *os.File
}

// JailPlan is a run's jail and cgroup, before its jailer starts.
type JailPlan struct {
	// Jail is the chroot to create, Jails/firecracker/<run>/root.
	Jail string
	// Kernel and Initrd are the cached boot images; Appendix, when set, the
	// boot's own files, appended to the initrd's copy.
	Kernel, Initrd, Appendix *os.File
	Files                    []PlacedFile
	Config                   []byte
	// Group is the run's cgroup, created with Limits.
	Group  string
	Limits map[string]string
}

// PrepareJail builds a run's jail and cgroup (internal/runtime, prepare): the
// kernel hard linked, the initrd cloned or copied with the appendix, the
// data volume, a corpus image and a build drive hard linked (never copied),
// a harness image linked or copied, config.json, then the cgroup with its
// limits. Nothing in it is synced: a jail does not survive a crash.
func (System) PrepareJail(p JailPlan) error {
	if err := os.MkdirAll(p.Jail, 0o700); err != nil {
		return err
	}
	if err := linkOrCopy(p.Kernel, filepath.Join(p.Jail, "kernel")); err != nil {
		return err
	}
	if err := copyBoot(p.Initrd, p.Appendix, filepath.Join(p.Jail, "initrd")); err != nil {
		return err
	}
	for _, f := range p.Files {
		var err error
		switch f.Kind {
		case KindHarness:
			err = linkOrCopy(f.File, filepath.Join(p.Jail, f.Name))
		default:
			err = link(f.File, filepath.Join(p.Jail, f.Name))
			if errors.Is(err, syscall.EXDEV) && f.Kind != KindVolume {
				err = ErrCrossDevice
			}
		}
		if err != nil {
			return err
		}
	}
	config := filepath.Join(p.Jail, "config.json")
	if err := os.WriteFile(config, p.Config, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(config, 0o444); err != nil {
		return err
	}
	if err := os.Mkdir(p.Group, 0o700); err != nil {
		return err
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range p.Limits {
			if !yield(k) {
				return
			}
		}
	}) {
		if err := os.WriteFile(filepath.Join(p.Group, name), []byte(p.Limits[name]), 0o600); err != nil {
			return err
		}
	}
	// A guest must not exceed memory.max by spilling into host swap. Kernels
	// booted without swap accounting do not expose this file, in which case
	// there is nothing to limit, so a failure is deliberately ignored.
	_ = os.WriteFile(filepath.Join(p.Group, "memory.swap.max"), []byte("0"), 0o600)
	return nil
}

// link hard links the open file f at dst: through its descriptor's /proc
// path, so the file linked is the one checked, whatever its name is now.
func link(f *os.File, dst string) error {
	return unix.Linkat(unix.AT_FDCWD, fdPath(f), unix.AT_FDCWD, dst, unix.AT_SYMLINK_FOLLOW)
}

// linkOrCopy links f at dst, or copies it, read-only, when it lives on
// another file system (a kernel or a harness image).
func linkOrCopy(f *os.File, dst string) error {
	err := link(f, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	return copyBoot(f, nil, dst)
}

// copyBoot writes a read-only copy of in at dst, a clone where the file
// system can (FICLONE), with appendix's bytes after it.
func copyBoot(in, appendix *os.File, dst string) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o444)
	if err != nil {
		return err
	}
	if unix.IoctlFileClone(int(out.Fd()), int(in.Fd())) == nil {
		_, err = out.Seek(0, io.SeekEnd)
	} else {
		_, err = io.Copy(out, io.NewSectionReader(in, 0, 1<<62))
	}
	if err == nil && appendix != nil {
		var n int64
		n, err = io.Copy(out, io.LimitReader(io.NewSectionReader(appendix, 0, MaxAppendix+1), MaxAppendix+1))
		if err == nil && n > MaxAppendix {
			err = invalid("boot appendix too long")
		}
	}
	if err == nil {
		err = out.Chmod(0o444)
	}
	return errors.Join(err, out.Close())
}

// StartPlan starts a run's jailer.
type StartPlan struct {
	// Jailer and Firecracker are the pinned binaries; ChrootBase the jails.
	Jailer, Firecracker, ChrootBase string
	RunID                           string
	UID                             uint32
	Cgroup, Group                   string
	Log                             *os.File
}

// JailerArgs are the jailer's arguments for a run: its own UID and GID,
// chroot, PID namespace and cgroup, with Firecracker's default seccomp
// filters. The VM gets no network device (config.json).
func JailerArgs(p StartPlan) []string {
	return []string{"--id", p.RunID, "--exec-file", p.Firecracker,
		"--uid", strconv.Itoa(int(p.UID)), "--gid", strconv.Itoa(int(p.UID)), "--chroot-base-dir", p.ChrootBase,
		"--new-pid-ns", "--cgroup-version", "2", "--parent-cgroup", strings.TrimPrefix(p.Group, "/sys/fs/cgroup/"),
		"--resource-limit", "no-file=256", "--", "--no-api", "--config-file", "/config.json"}
}

// Start starts the jailer of a run into its cgroup (clone3 with
// CLONE_INTO_CGROUP, so that no launcher escapes it) and a network namespace
// of its own (CLONE_NEWNET): the guest's only way out is the vsock to the
// host. The jailer executes Firecracker, which this process reaps.
func (System) Start(p StartPlan) error {
	group, err := os.Open(p.Group)
	if err != nil {
		return err
	}
	defer group.Close()
	cmd := exec.Command(p.Jailer, JailerArgs(p)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd()), Cloneflags: syscall.CLONE_NEWNET}
	cmd.Env = []string{}
	if p.Log != nil {
		cmd.Stdout, cmd.Stderr = p.Log, p.Log
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Target is the run observe identifies: its chroot, its VM's UID, its
// cgroup, the PID and start time recorded once it ran (zero before), and the
// agent's volume, whose lock is read when Lock is set.
type Target struct {
	UID    uint32
	Group  string
	PID    int
	Ticks  string
	Volume string
	Lock   bool
}

// Observe identifies the VMM of a run in jail: the PID its jailer wrote, a
// process of that start time if recorded, whose root is the jail, whose
// UIDs are the VM's, whose cgroup is the run's and whose executable is the
// jail's Firecracker; then, with Lock, whether it has the volume open and
// holds its lock (ErrAbsent when it is not identified).
func (System) Observe(jail *os.File, t Target) (Observation, error) {
	pid, ticks, err := identify(jail, t)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: %v", ErrAbsent, err)
	}
	o := Observation{PID: pid, Ticks: ticks}
	if t.Lock {
		var lockErr error
		o.Open, o.Locked, lockErr = VolumeLock(pid, t.Volume)
		if lockErr != nil {
			o.LockError = lockErr.Error()
		}
	}
	return o, nil
}

func identify(jail *os.File, t Target) (int, string, error) {
	pid, err := readPIDFile(jail, "firecracker.pid")
	if err != nil {
		return 0, "", err
	}
	ticks, err := ProcIdentity(pid)
	if err != nil {
		return 0, "", err
	}
	if t.PID != 0 && (pid != t.PID || ticks != t.Ticks) {
		return 0, "", errors.New("PID was reused")
	}
	var root, want unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d/root", pid), &root); err != nil {
		return 0, "", err
	}
	if err = unix.Fstat(int(jail.Fd()), &want); err != nil {
		return 0, "", err
	}
	if !isDir(want) || root.Dev != want.Dev || root.Ino != want.Ino {
		return 0, "", errors.New("unexpected VMM root")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, "", err
	}
	if !strings.Contains(string(status), fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", t.UID, t.UID, t.UID, t.UID)) {
		return 0, "", errors.New("unexpected VMM UID")
	}
	group, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, "", err
	}
	if strings.TrimSpace(string(group)) != "0::"+strings.TrimPrefix(t.Group, "/sys/fs/cgroup") {
		return 0, "", errors.New("unexpected VMM cgroup")
	}
	var exe, expected unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &exe); err != nil {
		return 0, "", err
	}
	if err = unix.Fstatat(int(jail.Fd()), "firecracker", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, "", err
	}
	if !isRegular(expected) || exe.Dev != expected.Dev || exe.Ino != expected.Ino {
		return 0, "", errors.New("unexpected VMM executable")
	}
	return pid, ticks, nil
}

// readPIDFile reads the PID the jailer wrote in a jail its VMM's user owns:
// at most 32 bytes of a regular file opened without following a link or
// blocking (L-15).
func readPIDFile(dir *os.File, name string) (int, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := stat(f)
	if err != nil {
		return 0, err
	}
	if !isRegular(st) {
		return 0, errors.New("PID file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return 0, err
	}
	if len(b) > 32 {
		return 0, errors.New("PID file too long")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid PID file")
	}
	return pid, nil
}

// ProcIdentity is a live process's start time, in clock ticks since boot.
func ProcIdentity(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return "", errors.New("invalid proc stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", errors.New("short proc stat")
	}
	if f[0] == "Z" {
		return "", errors.New("process exited")
	}
	return f[19], nil
}

// VolumeLock tells whether pid has volume open, and whether it holds the
// volume's exclusive lock through one of those descriptors.
func VolumeLock(pid int, volume string) (open, locked bool, err error) {
	want, err := os.Stat(volume)
	if err != nil {
		return false, false, err
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false, false, err
	}
	for _, entry := range entries {
		got, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil || !os.SameFile(want, got) {
			continue
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue // closed since, as by a VMM that exits
		}
		if err != nil {
			return true, false, err
		}
		open = true
		for _, line := range strings.Split(string(info), "\n") {
			f := strings.Fields(line)
			if len(f) >= 6 && f[0] == "lock:" && f[2] == "FLOCK" && f[3] == "ADVISORY" && f[4] == "WRITE" {
				return true, true, nil
			}
		}
	}
	return open, false, nil
}

// Populated tells whether a cgroup holds a process; a cgroup that does not
// exist holds none.
func (System) Populated(group string) (bool, error) {
	b, e := os.ReadFile(filepath.Join(group, "cgroup.events"))
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 1" {
			return true, nil
		}
		if line == "populated 0" {
			return false, nil
		}
	}
	return false, errors.New("missing populated cgroup field")
}

// Cleanup kills whatever runs in a run's cgroup and waits, ten seconds at
// most, until it is empty; then removes the cgroup and the run's directory
// under runs (base/firecracker), when runs is set. clone3 placed every
// launcher in its cgroup at fork, so none escapes.
func (s System) Cleanup(runs *os.File, runID, group string) error {
	busy, err := s.Populated(group)
	if err != nil {
		return err
	}
	if busy {
		if err = os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0o600); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for busy {
		if time.Now().After(deadline) {
			return errors.New("attempt cgroup still populated; volume remains unavailable")
		}
		time.Sleep(10 * time.Millisecond)
		if busy, err = s.Populated(group); err != nil {
			return err
		}
	}
	if err = os.Remove(group); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if runs == nil || !ValidRunID(runID) {
		return nil
	}
	// Through the descriptor of base/firecracker: the run's directory and
	// nothing else, whatever was renamed meanwhile; RemoveAll follows no
	// link below it.
	return os.RemoveAll(filepath.Join(fdPath(runs), runID))
}

// Dial connects to the VMM's vsock socket in jail, a socket of the VM's UID
// opened without following a link, and returns the connection.
func (System) Dial(jail *os.File, uid uint32) (*os.File, error) {
	fd, err := unix.Openat(int(jail.Fd()), "vsock", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	node := os.NewFile(uintptr(fd), "vsock")
	defer node.Close()
	st, err := stat(node)
	if err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid {
		return nil, errors.New("the VMM's socket was replaced in the jail")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.Dial("unix", fdPath(node))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*net.UnixConn).File()
}

// PlatformSocket is the name of the platform channel's socket in a jail,
// beside the VMM's own vsock socket (capsuleprotocol.PlatformPort).
const PlatformSocket = "vsock_5001"

// Listen binds the platform socket in jail for uid and gives it to uid
// (ListenInJail), and returns the listener's descriptor.
func (System) Listen(jail *os.File, uid uint32) (*os.File, error) {
	l, err := ListenInJail(jail, PlatformSocket, int(uid))
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return l.File()
}

// AfterBind runs between the bind and the change of owner: tests only.
var AfterBind func()

// ListenInJail binds the Unix socket name in the directory dir for uid, and
// gives it to uid. The socket is bound through the directory's descriptor,
// and its owner and mode set through a descriptor of the node itself, opened
// without following a link: a node the VMM swapped in is refused, never
// followed (L-15). The listener does not unlink on close: the jail goes with
// its run.
func ListenInJail(dir *os.File, name string, uid int) (*net.UnixListener, error) {
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(fdPath(dir), name), Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	if err = ownSocket(dir, name, uid); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func ownSocket(dir *os.File, name string, uid int) error {
	if AfterBind != nil {
		AfterBind()
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("platform socket replaced in the jail")
	}
	if err = unix.Fchownat(fd, "", uid, uid, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	// The descriptor pins the socket node: its /proc link reaches that node
	// and nothing else.
	return os.Chmod("/proc/self/fd/"+itoa(fd), 0o600)
}

// LinkProbe hard links f into dir under a random name and removes the link
// at once: whether f can be shared with a jail (ErrCrossDevice otherwise).
func (System) LinkProbe(f *os.File, dir string) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".link-probe-"+hex.EncodeToString(nonce))
	if err := link(f, probe); errors.Is(err, syscall.EXDEV) {
		return ErrCrossDevice
	} else if err != nil {
		return err
	}
	return os.Remove(probe)
}

// Pin installs a verified copy of source at destination, read-only, or
// checks the copy already there against want, a SHA-256 digest.
func Pin(source, destination, want string, mode os.FileMode) error {
	if !validDigest(want) {
		return errors.New("SHA-256 digest required for every runtime artifact")
	}
	if old, err := os.ReadFile(destination); err == nil {
		if got := sha256.Sum256(old); hex.EncodeToString(got[:]) != want {
			return errors.New("pinned runtime artifact mismatch")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(f, h), in); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("runtime artifact checksum mismatch")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(destination)); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// SetupCgroup creates the VMs' parent cgroup, which delegates the processor,
// memory and task controllers to the runs' cgroups.
func SetupCgroup(cgroup string) error {
	if err := os.MkdirAll(cgroup, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cgroup, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o600)
}
