//go:build linux

package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// Privileged is what the host driver asks of root (ADR 024): the operations
// on the VMs' cgroups, jails, processes and the files of their UIDs. A
// worker that is not root asks its helper (FirecrackerOptions.Helper); a
// worker that is root, in a laboratory or a KVM suite, does them itself.
// Every operation names the agent and its run as the registry records them.
type Privileged interface {
	// GiveVolume gives the provisioned volume f, at path, to agent's uid.
	GiveVolume(ctx context.Context, f *os.File, path, agent string, uid uint32) error
	// OpenVolume opens a registered agent's volume.
	OpenVolume(ctx context.Context, path string, write bool) (*os.File, error)
	// GiveDrives gives a stopped builder its drives; ReclaimDrives gives its
	// recorded drives back to the worker.
	GiveDrives(ctx context.Context, a *HostAgent, drives []workerhelper.Drive) error
	ReclaimDrives(ctx context.Context, a *HostAgent) error
	// CheckLinkable tells whether each regular file can be hard linked into
	// the jails (ErrCorpusFilesystem otherwise).
	CheckLinkable(ctx context.Context, paths ...string) error
	// Prepare builds the jail and the cgroup of a's starting run; Start
	// starts its jailer, its output to log.
	Prepare(ctx context.Context, a *HostAgent, config []byte, appendix *os.File) error
	Start(ctx context.Context, a *HostAgent, log *os.File) error
	// Observe identifies a's VMM (workerhelper.ErrAbsent when it cannot),
	// and with lock its lock on the volume.
	Observe(ctx context.Context, a *HostAgent, lock bool) (workerhelper.Observation, error)
	// Populated tells whether the cgroup of a's run holds a process.
	Populated(ctx context.Context, a *HostAgent) (bool, error)
	// Cleanup kills the cgroup of agent id's run, then removes it and the
	// run's jail.
	Cleanup(ctx context.Context, id string, run *VMRun) error
	// Dial connects to the control socket of a's VMM; Listen binds the
	// platform socket in its jail, for its UID.
	Dial(ctx context.Context, a *HostAgent) (net.Conn, error)
	Listen(ctx context.Context, a *HostAgent) (*net.UnixListener, error)
}

func (h *FirecrackerHost) privileged() Privileged {
	if h.priv != nil {
		return h.priv
	}
	return localPrivileged{h}
}

// jailBase is the jailer's chroot base for new runs: the helper's, or
// <root>/jails for a worker that is root.
func (h *FirecrackerHost) jailBase() string {
	if h.jails != "" {
		return h.jails
	}
	return filepath.Join(h.root, "jails")
}

// validSocket: run's socket is in its jail, under the jailer's chroot base
// or, for a run a worker that was root started, under <root>/jails.
func (h *FirecrackerHost) validSocket(run *VMRun) bool {
	for _, base := range []string{h.jailBase(), filepath.Join(h.root, "jails")} {
		if run.Socket == filepath.Join(workerhelper.Jail(base, run.ID), "vsock") {
			return true
		}
	}
	return false
}

// jailOf is the chroot of a recorded run: where its socket is.
func (h *FirecrackerHost) jailOf(run *VMRun) string {
	if run.Socket != "" {
		return filepath.Dir(run.Socket)
	}
	return h.jail(run)
}

// helperView is the helper's view of a registered agent.
func helperView(a *HostAgent) *workerhelper.Agent {
	v := &workerhelper.Agent{ID: a.ID, UID: a.UID, Volume: a.Volume, Device: a.Device, Inode: a.Inode, Generation: a.Generation,
		Fenced: a.Fenced, SealID: a.SealID, VolumeRemoved: a.VolumeRemoved, Resources: workerhelper.Resources(a.Resources)}
	if a.SystemImage != nil {
		v.SystemImage = &workerhelper.BootImage{Kernel: a.SystemImage.Kernel, Initrd: a.SystemImage.Initrd}
	}
	if a.Harness != nil {
		v.Harness = &workerhelper.Image{Path: a.Harness.Path}
	}
	for _, c := range a.Corpora {
		v.Corpora = append(v.Corpora, workerhelper.Image{Path: c.Path})
	}
	if b := a.Build; b != nil {
		v.Build = &workerhelper.Build{Enricher: b.Enricher, Source: b.Source, LFS: b.LFS, Output: b.Output}
	}
	if r := a.Run; r != nil {
		v.Run = &workerhelper.Run{ID: r.ID, Generation: r.Generation, Phase: r.Phase, PID: r.PID, StartTicks: r.StartTicks, Socket: r.Socket, FenceOnly: r.FenceOnly}
	}
	return v
}

// crossDevice is ErrCorpusFilesystem for the helper's refusal of a link.
func crossDevice(err error) error {
	if errors.Is(err, workerhelper.ErrCrossDevice) && !errors.Is(err, ErrCorpusFilesystem) {
		return errors.Join(ErrCorpusFilesystem, err)
	}
	return err
}

// cleanupContext bounds a cleanup that runs even when its caller gave up:
// the attempt's cgroup may take ten seconds to empty.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}

// localPrivileged does the operations in this process, which is root.
type localPrivileged struct{ h *FirecrackerHost }

func (localPrivileged) GiveVolume(_ context.Context, f *os.File, _, _ string, uid uint32) error {
	return workerhelper.System{}.Own(f, uid, uid, 0, true)
}

func (localPrivileged) OpenVolume(_ context.Context, path string, write bool) (*os.File, error) {
	flags := syscall.O_RDONLY
	if write {
		flags = syscall.O_RDWR
	}
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (localPrivileged) GiveDrives(_ context.Context, a *HostAgent, drives []workerhelper.Drive) error {
	for _, d := range drives {
		if err := os.Chown(d.Path, int(a.UID), int(a.UID)); err != nil {
			return err
		}
		if err := os.Chmod(d.Path, os.FileMode(d.Mode)); err != nil {
			return err
		}
	}
	return nil
}

// ReclaimDrives: a root worker reads its builders' drives as they are.
func (localPrivileged) ReclaimDrives(context.Context, *HostAgent) error { return nil }

func (p localPrivileged) CheckLinkable(_ context.Context, paths ...string) error {
	return CheckLinkable(p.h.jailBase(), paths...)
}

func (p localPrivileged) layout() workerhelper.Layout {
	return workerhelper.Layout{Root: p.h.root, Jails: p.h.jailBase(), Bin: filepath.Join(p.h.root, "bin"), Cgroup: p.h.cgroup}
}

func (p localPrivileged) Prepare(_ context.Context, a *HostAgent, config []byte, appendix *os.File) error {
	lay, v := p.layout(), helperView(a)
	kernel, initrd, err := lay.BootFiles(v)
	if err != nil {
		return err
	}
	files, err := lay.JailFiles(v)
	if err != nil {
		return err
	}
	var opened []*os.File
	defer func() {
		for _, f := range opened {
			f.Close()
		}
	}()
	open := func(path string) (*os.File, error) {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err == nil {
			opened = append(opened, f)
		}
		return f, err
	}
	plan := workerhelper.JailPlan{Jail: p.h.jail(a.Run), Appendix: appendix, Config: config, Group: p.h.group(a.Run),
		Limits: workerhelper.Limits(workerhelper.Resources(a.resources()))}
	for _, boot := range []string{kernel, initrd} {
		if err = shareBootFile(boot); err != nil {
			return err
		}
	}
	if plan.Initrd, err = open(initrd); err != nil {
		return err
	}
	for _, f := range files {
		o, err := open(f.Source)
		if err != nil {
			return err
		}
		if f.Kind == workerhelper.KindKernel {
			plan.Kernel = o
			continue
		}
		plan.Files = append(plan.Files, workerhelper.PlacedFile{Name: f.Name, Kind: f.Kind, File: o})
	}
	return crossDevice(workerhelper.System{}.PrepareJail(plan))
}

func (p localPrivileged) Start(_ context.Context, a *HostAgent, log *os.File) error {
	bin := filepath.Join(p.h.root, "bin")
	return workerhelper.System{}.Start(workerhelper.StartPlan{Jailer: filepath.Join(bin, "jailer"), Firecracker: filepath.Join(bin, "firecracker"),
		ChrootBase: p.h.jailBase(), RunID: a.Run.ID, UID: a.UID, Cgroup: p.h.cgroup, Group: p.h.group(a.Run), Log: log})
}

// openDir opens a directory as a path descriptor, without following a link.
func openDir(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (p localPrivileged) Observe(_ context.Context, a *HostAgent, lock bool) (workerhelper.Observation, error) {
	jail, err := openDir(p.h.jailOf(a.Run))
	if err != nil {
		return workerhelper.Observation{}, fmt.Errorf("%w: %v", workerhelper.ErrAbsent, err)
	}
	defer jail.Close()
	return workerhelper.System{}.Observe(jail, workerhelper.Target{UID: a.UID, Group: p.h.group(a.Run), PID: a.Run.PID, Ticks: a.Run.StartTicks,
		Volume: a.Volume, Lock: lock})
}

func (p localPrivileged) Populated(_ context.Context, a *HostAgent) (bool, error) {
	return workerhelper.System{}.Populated(p.h.group(a.Run))
}

func (p localPrivileged) Cleanup(_ context.Context, _ string, run *VMRun) error {
	// base/firecracker, which holds the run's directory.
	runs, err := openDir(filepath.Dir(filepath.Dir(p.h.jailOf(run))))
	if errors.Is(err, os.ErrNotExist) {
		runs, err = nil, nil
	}
	if err != nil {
		return err
	}
	if runs != nil {
		defer runs.Close()
	}
	return workerhelper.System{}.Cleanup(runs, run.ID, p.h.group(run))
}

func (p localPrivileged) Dial(ctx context.Context, a *HostAgent) (net.Conn, error) {
	return capsuleprotocol.DialControl(ctx, a.Run.Socket)
}

func (p localPrivileged) Listen(_ context.Context, a *HostAgent) (*net.UnixListener, error) {
	jail, err := openDir(p.h.jailOf(a.Run))
	if err != nil {
		return nil, err
	}
	defer jail.Close()
	return workerhelper.ListenInJail(jail, workerhelper.PlatformSocket, int(a.UID))
}

// remotePrivileged asks the worker's helper.
type remotePrivileged struct{ c *workerhelper.Client }

func (r remotePrivileged) GiveVolume(ctx context.Context, f *os.File, path, agent string, uid uint32) error {
	return r.c.GiveVolume(ctx, f, path, agent, uid)
}

func (r remotePrivileged) OpenVolume(ctx context.Context, path string, write bool) (*os.File, error) {
	return r.c.OpenVolume(ctx, path, write)
}

func (r remotePrivileged) GiveDrives(ctx context.Context, a *HostAgent, drives []workerhelper.Drive) error {
	return r.c.GiveDrives(ctx, a.ID, drives)
}

func (r remotePrivileged) ReclaimDrives(ctx context.Context, a *HostAgent) error {
	return r.c.ReclaimDrives(ctx, a.ID)
}

func (r remotePrivileged) CheckLinkable(ctx context.Context, paths ...string) error {
	return crossDevice(r.c.CheckLinkable(ctx, paths...))
}

func (r remotePrivileged) Prepare(ctx context.Context, a *HostAgent, config []byte, appendix *os.File) error {
	return crossDevice(r.c.Prepare(ctx, a.ID, a.Run.ID, config, appendix))
}

func (r remotePrivileged) Start(ctx context.Context, a *HostAgent, log *os.File) error {
	return r.c.Start(ctx, a.ID, a.Run.ID, log)
}

func (r remotePrivileged) Observe(ctx context.Context, a *HostAgent, lock bool) (workerhelper.Observation, error) {
	return r.c.Observe(ctx, a.ID, a.Run.ID, lock)
}

func (r remotePrivileged) Populated(ctx context.Context, a *HostAgent) (bool, error) {
	return r.c.Populated(ctx, a.ID, a.Run.ID)
}

func (r remotePrivileged) Cleanup(ctx context.Context, id string, run *VMRun) error {
	return r.c.Cleanup(ctx, id, run.ID)
}

func (r remotePrivileged) Dial(ctx context.Context, a *HostAgent) (net.Conn, error) {
	f, err := r.c.Dial(ctx, a.ID, a.Run.ID)
	if err != nil {
		return nil, err
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return connectControl(ctx, conn)
}

func (r remotePrivileged) Listen(ctx context.Context, a *HostAgent) (*net.UnixListener, error) {
	f, err := r.c.Listen(ctx, a.ID, a.Run.ID)
	if err != nil {
		return nil, err
	}
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	u, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		return nil, errors.New("the helper's platform listener is not a Unix socket")
	}
	u.SetUnlinkOnClose(false)
	return u, nil
}

// connectControl asks Firecracker's vsock device for the guest's control
// port on conn, as capsuleprotocol.DialControl does on a socket it dials.
func connectControl(ctx context.Context, conn net.Conn) (net.Conn, error) {
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", capsuleprotocol.ControlPort); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 64)
	line, err := r.ReadSlice('\n')
	if err != nil || !strings.HasPrefix(string(line), "OK ") || r.Buffered() != 0 {
		return nil, capsuleprotocol.ErrTransport
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

// memfile is a sealed-size anonymous file holding b: the appendix a boot
// hands over, never on disk.
func memfile(b []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("agentcapsule-boot", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "agentcapsule-boot")
	if _, err = f.Write(b); err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// offsetBuffer is an in-memory WriteSeeker whose offsets start at base: the
// files a boot appends to an initrd of base bytes, padded as they would be
// in the initrd itself.
type offsetBuffer struct {
	base, pos int64
	buf       []byte
}

func (b *offsetBuffer) Write(p []byte) (int, error) {
	at := b.pos - b.base
	if at < 0 {
		return 0, errors.New("write before the appendix")
	}
	if end := at + int64(len(p)); end > int64(len(b.buf)) {
		b.buf = append(b.buf, make([]byte, end-int64(len(b.buf)))...)
	}
	copy(b.buf[at:], p)
	b.pos += int64(len(p))
	return len(p), nil
}

func (b *offsetBuffer) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += b.pos
	case io.SeekEnd:
		offset += b.base + int64(len(b.buf))
	default:
		return 0, errors.New("invalid whence")
	}
	if offset < b.base {
		return 0, errors.New("seek before the appendix")
	}
	b.pos = offset
	return offset, nil
}
