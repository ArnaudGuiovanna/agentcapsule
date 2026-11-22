//go:build linux

// agentcapsule-worker-helper is the worker's root helper (ADR 024): the one
// process of the worker's side that keeps root. It answers the worker's
// account only, on a local socket, and does the operations that need root
// about the worker's own VMs and files: a volume or a build drive given to
// its VM's UID, a VM's jail and cgroup, the jailer, a run's observation and
// cleanup, a VM's sockets, a confined inspection and an archive fetch. It
// reads the worker's root-owned configuration and the worker's registry,
// opens no network socket, reads no database and holds no key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

func run() int {
	config := flag.String("config", "/etc/agentcapsule/worker.json", "the worker's root-owned JSON configuration")
	state := flag.String("state", "/var/lib/agentcapsule/vmm", "the helper's directory: the pinned jailer and Firecracker, and the jails")
	socket := flag.String("socket", "/run/agentcapsule-worker-helper/worker.sock", "the socket the worker reaches the helper on")
	account := flag.String("worker-user", "agentcapsule-worker", "the worker's account: the only one the socket admits")
	executable := flag.String("worker-executable", "/opt/agentcapsule/agentcapsule-worker", "the worker's executable, whose LUKS2 check runs confined (empty: none)")
	fetch := flag.String("archive-fetch", "", "the archive shipper (agentcapsule-archive-ship.py), for the worker's archive fetches (empty: none)")
	flag.Parse()
	fail := func(code string, err error) int {
		if err != nil {
			fmt.Fprintln(os.Stderr, code+":", err)
		} else {
			fmt.Fprintln(os.Stderr, code)
		}
		return 1
	}
	if flag.NArg() != 0 {
		return fail("usage_invalid", nil)
	}
	if os.Geteuid() != 0 {
		return fail("helper_requires_root", nil)
	}
	w, err := workerhelper.ReadWorkerConfig(*config)
	if err != nil {
		return fail("configuration_invalid", err)
	}
	u, err := user.Lookup(*account)
	if err != nil {
		return fail("worker_account_missing", err)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err = errors.Join(err1, err2); err != nil || uid == 0 {
		return fail("worker_account_invalid", err)
	}
	paths := workerhelper.Paths{State: *state}
	if *executable != "" {
		if err = rootsOnly(*executable); err != nil {
			return fail("worker_executable_invalid", err)
		}
		paths.Executable = *executable
	}
	if *fetch != "" {
		// The shipper is a Python script, run isolated (-I) by root's
		// interpreter, as the host operations run it.
		python, err := exec.LookPath("python3")
		if err == nil {
			err = errors.Join(rootsOnly(python), rootsOnly(*fetch))
		}
		if err != nil {
			return fail("archive_fetch_invalid", err)
		}
		paths.ArchiveFetch = []string{python, "-I", *fetch}
	}
	if p, err := exec.LookPath("debugfs"); err == nil && rootsOnly(p) == nil {
		paths.Debugfs = p
	}
	c, err := w.Config(paths, uint32(uid), uint32(gid), *account)
	if err != nil {
		return fail("configuration_invalid", err)
	}
	if err = inspectionUID(c); err != nil {
		return fail("inspection_uid_invalid", err)
	}
	if err = prepare(c, w); err != nil {
		return fail("helper_state_unavailable", err)
	}
	if err = checkHost(c); err != nil {
		return fail("host_unsupported", err)
	}
	s, err := workerhelper.NewServer(c, workerhelper.System{})
	if err != nil {
		return fail("configuration_invalid", err)
	}
	l, err := workerhelper.Listen(*socket, uint32(gid))
	if err != nil {
		return fail("socket_unavailable", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Println(`{"event":"helper_started"}`)
	if err = s.Serve(ctx, l); err != nil {
		return fail("helper_stopped", err)
	}
	return 0
}

// prepare creates the helper's directories, root's, and pins its own copies
// of the jailer and Firecracker, checked against the worker configuration's
// digests; then the VMs' parent cgroup.
func prepare(c workerhelper.Config, w workerhelper.WorkerConfig) error {
	state := filepath.Dir(c.Layout.Bin)
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{state, 0o711}, {c.Layout.Bin, 0o700}, {c.Layout.Jails, 0o700}, {filepath.Join(c.Layout.Jails, "firecracker"), 0o700}} {
		if err := os.Mkdir(d.path, d.mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		st, err := os.Lstat(d.path)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Mode().Perm()&0o022 != 0 {
			return errors.New(d.path + " must be a directory of root's, not writable by group or others")
		}
	}
	for _, a := range []struct {
		pin      string
		artifact workerhelper.Artifact
	}{{c.Jailer, w.Jailer}, {c.Firecracker, w.Firecracker}} {
		if err := workerhelper.Pin(a.artifact.Path, a.pin, a.artifact.SHA256, 0o500); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(a.pin), err)
		}
	}
	return workerhelper.SetupCgroup(c.Layout.Cgroup)
}

// inspectionUID checks the UID the confined programs run as, as the worker
// does (registry.inspection_uid): one setresuid takes as itself, outside the
// provisioning range, not the worker's, no account's and no group's.
func inspectionUID(c workerhelper.Config) error {
	uid := c.InspectionUID
	if uid == 0 {
		return nil // no confined program runs
	}
	if !sandbox.Reservable(uid) || uid >= c.FirstUID && uid <= c.LastUID || uid == c.WorkerUID || uid == c.WorkerGID {
		return fmt.Errorf("%d is not reserved for the inspections", uid)
	}
	id := strconv.FormatUint(uint64(uid), 10)
	var account user.UnknownUserIdError
	var group user.UnknownGroupIdError
	if _, err := user.LookupId(id); !errors.As(err, &account) {
		return fmt.Errorf("%d is an account's, or the accounts cannot be read: %v", uid, err)
	}
	if _, err := user.LookupGroupId(id); !errors.As(err, &group) {
		return fmt.Errorf("%d is a group's, or the groups cannot be read: %v", uid, err)
	}
	return nil
}

// rootsOnly: an executable of root's that neither its group nor others can
// write, in a directory of root's that they cannot write either.
func rootsOnly(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("not an absolute path")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for p := real; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		if st.Sys().(*syscall.Stat_t).Uid != 0 || st.Mode().Perm()&0o022 != 0 && st.Mode()&os.ModeSticky == 0 {
			return errors.New(p + " is not root's alone")
		}
		if p == "/" {
			return nil
		}
	}
}

// checkHost refuses to serve on a host where no VM can run (RUN-012): no
// KVM, no cgroup v2 with the processor, memory and task controllers, or
// jails on a file system without devices or execution.
func checkHost(c workerhelper.Config) error {
	var st unix.Stat_t
	if err := unix.Stat("/dev/kvm", &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(st.Rdev) != 10 || unix.Minor(st.Rdev) != 232 {
		return errors.New("/dev/kvm is not the KVM device")
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("/dev/kvm: %w", err)
	}
	kvm.Close()
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return errors.New("/sys/fs/cgroup is not a cgroup v2 hierarchy")
	}
	have := strings.Fields(string(controllers))
	for _, want := range []string{"cpu", "memory", "pids"} {
		found := false
		for _, h := range have {
			found = found || h == want
		}
		if !found {
			return errors.New("the cgroup controller " + want + " is missing")
		}
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(c.Layout.Jails, &fs); err != nil {
		return err
	}
	if fs.Flags&(unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != 0 {
		return errors.New(c.Layout.Jails + " is on a mount without devices or execution, or read-only")
	}
	return nil
}

func main() { os.Exit(run()) }
