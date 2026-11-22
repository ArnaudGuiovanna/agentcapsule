//go:build linux

package workerhelper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Config is what the helper holds as true: the root-owned worker
// configuration and its own unit's flags, never the worker's requests.
type Config struct {
	Layout Layout
	// Owner owns the helper's directories, the jails' tree: root.
	Owner uint32
	// WorkerUID is the only account the socket admits; WorkerGID its group;
	// WorkerName its name, which the archive fetch writes as.
	WorkerUID, WorkerGID uint32
	WorkerName           string
	// FirstUID and LastUID are the provisioning range: the only UIDs a file
	// is given to, or a VMM runs as.
	FirstUID, LastUID uint32
	// InspectionUID runs the confined programs; zero: none.
	InspectionUID uint32
	// ImageRoots may hold a jail's boot, harness and corpus images;
	// DriveRoots a builder's drives. Both include the runtime root.
	ImageRoots, DriveRoots []string
	// Jailer and Firecracker are the helper's pinned copies.
	Jailer, Firecracker string
	// Debugfs is the program a confined run may name; Executable the
	// worker's own, whose registered programs a self run runs.
	Debugfs, Executable string
	// ArchiveFetch is the archive shipper's command; nil: no fetch.
	ArchiveFetch []string
}

// Server answers the worker's requests.
type Server struct {
	c   Config
	ops Ops
	mu  sync.Mutex
	reg *Registry
	id  fileID
}

type fileID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime unix.Timespec
}

// NewServer checks the configuration.
func NewServer(c Config, ops Ops) (*Server, error) {
	l := c.Layout
	if !cleanAbs(l.Root) || !cleanAbs(l.Jails) || !cleanAbs(l.Bin) || !cleanAbs(l.Cgroup) || ops == nil ||
		!cleanAbs(c.Jailer) || !cleanAbs(c.Firecracker) || c.FirstUID < 10000 || c.LastUID < c.FirstUID || c.LastUID-c.FirstUID > 1<<20 {
		return nil, errors.New("worker helper: invalid configuration")
	}
	if _, inside := within(l.Root, l.Jails); inside || l.Jails == l.Root {
		return nil, errors.New("worker helper: the jails must lie outside the worker's runtime root")
	}
	for _, roots := range [][]string{c.ImageRoots, c.DriveRoots} {
		for _, r := range roots {
			if !cleanAbs(r) {
				return nil, errors.New("worker helper: invalid image or drive root")
			}
		}
	}
	return &Server{c: c, ops: ops}, nil
}

// Listen creates the socket at path for the worker's group: 0660, root's.
// A leftover socket is replaced; any other file is an error.
func Listen(path string, gid uint32) (*net.UnixListener, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("worker helper: the socket path holds another file")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err = os.Chown(path, -1, int(gid)); err == nil {
		err = os.Chmod(path, 0o660)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve answers on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var t interface{ Temporary() bool }
			if errors.As(err, &t) && t.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveConn(ctx, conn)
		}()
	}
}

// serveConn admits the worker's account only, then answers its requests one
// at a time.
func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	if uid, err := peerUID(conn); err != nil || uid != s.c.WorkerUID {
		return
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	for {
		var req Request
		files, err := receive(conn, &req)
		if errors.Is(err, errMessage) {
			if send(conn, Response{Code: CodeInvalid, Error: "malformed message"}, nil) != nil {
				return
			}
			continue
		}
		if err != nil {
			return
		}
		resp, out := s.Handle(ctx, req, files)
		closeFiles(files)
		err = send(conn, resp, out)
		closeFiles(out)
		if err != nil {
			return
		}
	}
}

// Handle answers one request; files are the request's descriptors, which
// the caller closes, as it closes the answer's once sent.
func (s *Server) Handle(ctx context.Context, req Request, files []*os.File) (Response, []*os.File) {
	if req.V != Version {
		return Response{Code: CodeUnsupported, Error: "protocol version"}, nil
	}
	var resp Response
	var out []*os.File
	var err error
	want := 0
	switch req.Op {
	case OpGiveVolume, OpStart:
		want = 1
	case OpPrepare, OpSandbox:
		want = min(len(files), 1)
	}
	if len(files) != want {
		return failure(invalid("descriptors")), nil
	}
	switch req.Op {
	case OpHello:
		resp = Response{Version: Version, Jails: s.c.Layout.Jails, Cgroup: s.c.Layout.Cgroup}
	case OpGiveVolume:
		err = s.giveVolume(req, files[0])
	case OpOpenVolume:
		out, err = s.openVolume(req)
	case OpGiveDrives:
		err = s.giveDrives(req)
	case OpReclaimDrives:
		err = s.reclaimDrives(req)
	case OpCheckLinkable:
		err = s.checkLinkable(req)
	case OpPrepare:
		err = s.prepare(req, files)
	case OpStart:
		err = s.start(req, files[0])
	case OpObserve:
		var o Observation
		if o, err = s.observe(req); err == nil {
			resp.Observation = &o
		}
	case OpPopulated:
		resp.Populated, err = s.populated(req)
	case OpCleanup:
		err = s.cleanup(req)
	case OpDial, OpListen:
		out, err = s.socket(req)
	case OpSandbox:
		resp.Output, err = s.sandbox(ctx, req, files)
	case OpFetchArchive:
		err = s.fetch(ctx, req)
	default:
		err = &Error{Code: CodeUnsupported, Message: "operation"}
	}
	if err != nil {
		closeFiles(out)
		return failure(err), nil
	}
	resp.OK = true
	return resp, out
}

func failure(err error) Response {
	code, message := codeOf(err), err.Error()
	var e *Error
	if errors.As(err, &e) {
		code, message = e.Code, e.Message
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return Response{Code: code, Error: message}
}

// registry reads the worker's registry.json: reached without a link, the
// worker's (or root's, before the first update), bounded. A file not yet
// written is an empty registry. The last version read is kept while the file
// is the same.
func (s *Server) registry() (*Registry, error) {
	f, err := openUnder([]string{s.c.Layout.Root}, filepath.Join(s.c.Layout.Root, "registry.json"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if errors.Is(err, unix.ENOENT) {
		return &Registry{Version: RegistryVersion, Agents: map[string]*Agent{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := stat(f)
	if err != nil {
		return nil, err
	}
	if !isRegular(st) || (st.Uid != s.c.WorkerUID && st.Uid != s.c.Owner) || st.Size > MaxRegistry {
		return nil, refuse("the worker registry is not the worker's")
	}
	id := fileID{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reg != nil && s.id == id {
		return s.reg, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxRegistry+1))
	if err != nil {
		return nil, err
	}
	r, err := DecodeRegistry(b)
	if err != nil {
		return nil, refuse(err.Error())
	}
	s.reg, s.id = r, id
	return r, nil
}

// uidAllowed: a UID of the provisioning range, neither the worker's nor the
// inspection UID.
func (s *Server) uidAllowed(uid uint32) bool {
	return uid >= 10000 && uid >= s.c.FirstUID && uid <= s.c.LastUID && uid != s.c.WorkerUID && uid != s.c.InspectionUID && uid != s.c.Owner
}

// agent is a registered agent of the request, with a UID of the range.
func (s *Server) agent(id string) (*Agent, error) {
	r, err := s.registry()
	if err != nil {
		return nil, err
	}
	a := r.Agents[id]
	if a == nil || id == "" {
		return nil, &Error{Code: CodeUnknownAgent}
	}
	if !s.uidAllowed(a.UID) {
		return nil, refuse("the agent's UID is outside the provisioning range")
	}
	return a, nil
}

// run is the registered run of the request's agent: the one the registry
// records now, and a socket under the jails.
func (s *Server) run(req Request) (*Agent, *Run, string, error) {
	a, err := s.agent(req.Agent)
	if err != nil {
		return nil, nil, "", err
	}
	if a.Run == nil || a.Run.ID != req.Run || !ValidRunID(req.Run) {
		return nil, nil, "", refuse("not the agent's run")
	}
	base, err := s.c.Layout.JailBase(a.Run)
	if err != nil {
		return nil, nil, "", err
	}
	return a, a.Run, base, nil
}

func (s *Server) volumes() string { return filepath.Join(s.c.Layout.Root, "volumes") }

// directChild: path is a file directly in dir.
func directChild(dir, path string) bool {
	rel, ok := within(dir, path)
	return ok && !strings.Contains(rel, "/")
}

func sameFile(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

// giveVolume gives a provisioned volume to its agent's UID (ADR 024 §3).
func (s *Server) giveVolume(req Request, f *os.File) error {
	if !s.uidAllowed(req.UID) || req.Agent == "" {
		return refuse("a UID outside the provisioning range")
	}
	if !directChild(s.volumes(), req.Path) {
		return refuse("a volume outside the managed volume directory")
	}
	named, err := openUnder([]string{s.c.Layout.Root}, req.Path, unix.O_PATH|unix.O_NOFOLLOW)
	if err != nil {
		return err
	}
	defer named.Close()
	byName, err := stat(named)
	if err != nil {
		return err
	}
	st, err := stat(f)
	if err != nil {
		return err
	}
	if !sameFile(st, byName) || !isRegular(st) || st.Nlink != 1 || perm(st) != 0o600 || (st.Uid != s.c.WorkerUID && st.Uid != req.UID) {
		return refuse("not the worker's volume at that name")
	}
	r, err := s.registry()
	if err != nil {
		return err
	}
	for id, a := range r.Agents {
		if id == req.Agent {
			if a.UID != req.UID {
				return refuse("the agent holds another UID")
			}
			continue
		}
		if a.UID == req.UID || a.Device == st.Dev && a.Inode == st.Ino {
			return refuse("the UID or the volume is another agent's")
		}
	}
	return s.ops.Own(f, req.UID, req.UID, 0, true)
}

// openVolume opens a registered agent's volume for the worker.
func (s *Server) openVolume(req Request) ([]*os.File, error) {
	if !directChild(s.volumes(), req.Path) {
		return nil, refuse("a volume outside the managed volume directory")
	}
	r, err := s.registry()
	if err != nil {
		return nil, err
	}
	var owner *Agent
	for _, a := range r.Agents {
		if a.Volume == req.Path {
			owner = a
		}
	}
	if owner == nil {
		return nil, &Error{Code: CodeUnknownAgent, Message: "no agent has this volume"}
	}
	if !s.uidAllowed(owner.UID) {
		return nil, refuse("the agent's UID is outside the provisioning range")
	}
	flags := unix.O_RDONLY
	if req.Write {
		flags = unix.O_RDWR
	}
	f, err := openUnder([]string{s.c.Layout.Root}, req.Path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	st, err := stat(f)
	if err == nil && (!isRegular(st) || st.Uid != owner.UID || st.Dev != owner.Device || st.Ino != owner.Inode) {
		err = refuse("not the registered volume")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return []*os.File{f}, nil
}

// buildDrive opens a builder's drive: under the drive roots, a regular file
// of whole 4 KiB blocks with one link, owned by one of owners.
func (s *Server) buildDrive(path string, owners ...uint32) (*os.File, error) {
	f, err := openUnder(s.c.DriveRoots, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	st, err := stat(f)
	if err == nil && (!isRegular(st) || st.Nlink != 1 || st.Size < 4096 || st.Size%4096 != 0 || !slices.Contains(owners, st.Uid)) {
		err = refuse("not a build drive of the worker or the agent")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// giveDrives gives a stopped builder its drives.
func (s *Server) giveDrives(req Request) error {
	a, err := s.agent(req.Agent)
	if err != nil {
		return err
	}
	if a.Run != nil {
		return &Error{Code: CodeBusy, Message: "the agent has a run"}
	}
	if len(req.Drives) == 0 || len(req.Drives) > 3 {
		return invalid("drives")
	}
	for _, d := range req.Drives {
		if d.Mode != 0o400 && d.Mode != 0o600 {
			return refuse("a drive mode other than 0400 or 0600")
		}
	}
	for _, d := range req.Drives {
		f, err := s.buildDrive(d.Path, s.c.WorkerUID, a.UID)
		if err != nil {
			return err
		}
		err = s.ops.Own(f, a.UID, a.UID, os.FileMode(d.Mode), false)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// reclaimDrives gives a stopped builder's recorded drives back to the worker.
func (s *Server) reclaimDrives(req Request) error {
	a, err := s.agent(req.Agent)
	if err != nil {
		return err
	}
	if a.Run != nil {
		return &Error{Code: CodeBusy, Message: "the agent has a run"}
	}
	if a.Build == nil {
		return nil
	}
	for _, p := range []string{a.Build.Source, a.Build.LFS, a.Build.Output} {
		if p == "" {
			continue
		}
		f, err := s.buildDrive(p, s.c.WorkerUID, a.UID)
		if errors.Is(err, unix.ENOENT) {
			continue // removed with its build
		}
		if err != nil {
			return err
		}
		err = s.ops.Own(f, s.c.WorkerUID, s.c.WorkerGID, 0o600, false)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// checkLinkable probes whether each file can be hard linked into the jails.
func (s *Server) checkLinkable(req Request) error {
	if len(req.Paths) == 0 || len(req.Paths) > 8 {
		return invalid("paths")
	}
	roots := append(slices.Clone(s.c.ImageRoots), s.c.DriveRoots...)
	for _, p := range req.Paths {
		f, err := openUnder(roots, p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
		if err != nil {
			return err
		}
		st, err := stat(f)
		if err == nil && (!isRegular(st) || (st.Uid != s.c.WorkerUID && st.Uid != s.c.Owner)) {
			err = refuse("not a regular file of the worker")
		}
		if err == nil {
			err = s.ops.LinkProbe(f, s.c.Layout.Jails)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// booting is the request's run while it starts: STARTING, of an agent
// neither fenced, sealed nor removed, in the layout's jails (a new boot never
// goes to the legacy ones).
func (s *Server) booting(req Request) (*Agent, *Run, error) {
	a, run, base, err := s.run(req)
	if err != nil {
		return nil, nil, err
	}
	if run.Phase != "STARTING" || a.Fenced || a.SealID != "" || a.VolumeRemoved || base != s.c.Layout.Jails {
		return nil, nil, refuse("not a run that is starting")
	}
	return a, run, nil
}

// jailFile opens and checks one file a jail gets, by its kind.
func (s *Server) jailFile(a *Agent, f JailFile) (*os.File, error) {
	switch f.Kind {
	case KindVolume:
		if f.Source != a.Volume || !directChild(s.volumes(), f.Source) {
			return nil, refuse("a volume outside the managed volume directory")
		}
		v, err := openUnder([]string{s.c.Layout.Root}, f.Source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
		if err != nil {
			return nil, err
		}
		st, err := stat(v)
		if err == nil && (!isRegular(st) || st.Uid != a.UID || st.Dev != a.Device || st.Ino != a.Inode || st.Nlink != 1 || perm(st) != 0o600) {
			err = refuse("not the agent's registered volume")
		}
		if err != nil {
			v.Close()
			return nil, err
		}
		return v, nil
	case KindBuild:
		return s.buildDrive(f.Source, a.UID)
	}
	roots := s.c.ImageRoots
	if f.Kind == KindKernel {
		roots = []string{filepath.Join(s.c.Layout.Root, "bin")}
	}
	img, err := openUnder(roots, f.Source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	st, err := stat(img)
	if err == nil && (!isRegular(st) || (st.Uid != s.c.WorkerUID && st.Uid != s.c.Owner) || perm(st)&0o004 == 0 || perm(st)&0o022 != 0) {
		err = refuse("an image that is not a write-protected, world-readable file of the worker")
	}
	if err != nil {
		img.Close()
		return nil, err
	}
	return img, nil
}

// prepare builds a starting run's jail and cgroup from the registry: the
// files a jail gets come from the agent's record, never from the request.
func (s *Server) prepare(req Request, files []*os.File) error {
	a, run, err := s.booting(req)
	if err != nil {
		return err
	}
	var config map[string]any
	if len(req.Config) == 0 || len(req.Config) > MaxConfig || json.Unmarshal(req.Config, &config) != nil {
		return invalid("config.json")
	}
	var appendix *os.File
	if len(files) == 1 {
		appendix = files[0]
		if st, err := stat(appendix); err != nil || !isRegular(st) || st.Size > MaxAppendix {
			return invalid("boot appendix")
		}
	}
	plan := JailPlan{Jail: Jail(s.c.Layout.Jails, run.ID), Appendix: appendix, Config: req.Config,
		Group: s.c.Layout.RunCgroup(run.ID), Limits: Limits(a.Resources)}
	kernel, initrd, err := s.c.Layout.BootFiles(a)
	if err != nil {
		return refuse(err.Error())
	}
	var opened []*os.File
	defer func() { closeFiles(opened) }()
	open := func(f JailFile) (*os.File, error) {
		o, err := s.jailFile(a, f)
		if err == nil {
			opened = append(opened, o)
		}
		return o, err
	}
	if plan.Initrd, err = open(JailFile{"initrd", initrd, KindKernel}); err != nil {
		return err
	}
	list, err := s.c.Layout.JailFiles(a)
	if err != nil {
		return refuse(err.Error())
	}
	for _, f := range list {
		o, err := open(f)
		if err != nil {
			return err
		}
		if f.Kind == KindKernel && f.Source == kernel {
			plan.Kernel = o
			continue
		}
		plan.Files = append(plan.Files, PlacedFile{Name: f.Name, Kind: f.Kind, File: o})
	}
	return s.ops.PrepareJail(plan)
}

// start starts a prepared run's jailer, with the worker's VMM log as its
// output.
func (s *Server) start(req Request, log *os.File) error {
	a, run, err := s.booting(req)
	if err != nil {
		return err
	}
	if st, err := stat(log); err != nil || !isRegular(st) || st.Uid != s.c.WorkerUID {
		return invalid("VMM log")
	}
	jail, runs, err := openJail(s.c.Layout.Jails, run.ID, s.c.Owner)
	if err != nil {
		return err
	}
	jail.Close()
	runs.Close()
	return s.ops.Start(StartPlan{Jailer: s.c.Jailer, Firecracker: s.c.Firecracker, ChrootBase: s.c.Layout.Jails, RunID: run.ID,
		UID: a.UID, Cgroup: s.c.Layout.Cgroup, Group: s.c.Layout.RunCgroup(run.ID), Log: log})
}

// jail opens the request's run's chroot: absent when it does not exist.
func (s *Server) jail(base string, run *Run) (*os.File, error) {
	jail, runs, err := openJail(base, run.ID, s.c.Owner)
	if errors.Is(err, unix.ENOENT) {
		return nil, &Error{Code: CodeAbsent, Message: "no jail"}
	}
	if err != nil {
		return nil, err
	}
	runs.Close()
	return jail, nil
}

func (s *Server) observe(req Request) (Observation, error) {
	a, run, base, err := s.run(req)
	if err != nil {
		return Observation{}, err
	}
	jail, err := s.jail(base, run)
	if err != nil {
		return Observation{}, err
	}
	defer jail.Close()
	return s.ops.Observe(jail, Target{UID: a.UID, Group: s.c.Layout.RunCgroup(run.ID), PID: run.PID, Ticks: run.StartTicks, Volume: a.Volume, Lock: req.Lock})
}

func (s *Server) populated(req Request) (bool, error) {
	_, run, _, err := s.run(req)
	if err != nil {
		return false, err
	}
	return s.ops.Populated(s.c.Layout.RunCgroup(run.ID))
}

// cleanup ends a recorded run: its cgroup, then its jail, wherever it is.
func (s *Server) cleanup(req Request) error {
	_, run, base, err := s.run(req)
	if err != nil {
		return err
	}
	var runs *os.File
	b, err := openNoLinks(base, unix.O_PATH|unix.O_DIRECTORY)
	if err == nil {
		err = ownedDir(b, s.c.Owner)
		if err == nil {
			runs, err = openAt(b, "firecracker", unix.O_PATH|unix.O_DIRECTORY)
			if err == nil {
				err = ownedDir(runs, s.c.Owner)
			}
		}
		b.Close()
	}
	if errors.Is(err, unix.ENOENT) {
		err = nil // no jail was ever made there
	}
	if err != nil {
		if runs != nil {
			runs.Close()
		}
		return err
	}
	if runs != nil {
		defer runs.Close()
	}
	return s.ops.Cleanup(runs, run.ID, s.c.Layout.RunCgroup(run.ID))
}

// socket dials the VMM's control socket, or listens on the platform socket
// of a run that may serve one.
func (s *Server) socket(req Request) ([]*os.File, error) {
	a, run, base, err := s.run(req)
	if err != nil {
		return nil, err
	}
	if req.Op == OpListen && (run.FenceOnly || run.Phase != "STARTING" && run.Phase != "RUNNING" || a.Fenced) {
		return nil, refuse("no platform channel for this run")
	}
	jail, err := s.jail(base, run)
	if err != nil {
		return nil, err
	}
	defer jail.Close()
	var f *os.File
	if req.Op == OpDial {
		f, err = s.ops.Dial(jail, a.UID)
	} else {
		f, err = s.ops.Listen(jail, a.UID)
	}
	if err != nil {
		return nil, err
	}
	return []*os.File{f}, nil
}

// SandboxPlan is a confined run as the inspection UID.
type SandboxPlan struct {
	UID              uint32
	Image            *os.File
	ImagePath        string
	Program          string
	Executable, Self string
	Args             []string
	Input            []byte
	Timeout, CPU     time.Duration
}

func (s *Server) sandbox(ctx context.Context, req Request, files []*os.File) ([]byte, error) {
	r := req.Sandbox
	if s.c.InspectionUID == 0 {
		return nil, &Error{Code: CodeUnavailable, Message: "no inspection UID is configured"}
	}
	if r == nil || len(r.Args) > 64 || len(r.Input) > 4096 || r.TimeoutMS <= 0 || r.TimeoutMS > 600_000 || r.CPUMS <= 0 || r.CPUMS > 300_000 {
		return nil, invalid("sandbox run")
	}
	p := SandboxPlan{UID: s.c.InspectionUID, Args: r.Args, Input: r.Input,
		Timeout: time.Duration(r.TimeoutMS) * time.Millisecond, CPU: time.Duration(r.CPUMS) * time.Millisecond}
	switch {
	case r.Self != "" && r.Program == "" && s.c.Executable != "":
		p.Executable, p.Self = s.c.Executable, r.Self
	case r.Self == "" && r.Program != "" && r.Program == s.c.Debugfs:
		p.Program = r.Program
		if len(r.Input) != 0 {
			return nil, invalid("input")
		}
	default:
		return nil, refuse("a program the helper does not run")
	}
	if len(files) == 1 {
		st, err := stat(files[0])
		if err != nil || !isRegular(st) || !cleanAbs(req.Path) {
			return nil, invalid("image")
		}
		p.Image, p.ImagePath = files[0], req.Path
	} else if req.Path != "" {
		return nil, invalid("image")
	}
	return s.ops.Sandbox(ctx, p)
}

// FetchPlan runs the archive shipper's fetch into the worker's archive root,
// writing as the worker's account.
type FetchPlan struct {
	Command        []string
	Root, Owner    string
	Store, Archive string
}

var archiveID = regexp.MustCompile(`^arc_[0-9a-f]{32}$`)

func (s *Server) fetch(ctx context.Context, req Request) error {
	if len(s.c.ArchiveFetch) == 0 || s.c.WorkerName == "" {
		return &Error{Code: CodeUnsupported, Message: "no archive shipper is configured"}
	}
	if req.Store != "standby" && req.Store != "s3" || !archiveID.MatchString(req.Archive) {
		return invalid("store or archive")
	}
	root, err := openNoLinks(req.Path, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	st, err := stat(root)
	root.Close()
	if err != nil {
		return err
	}
	if st.Uid != s.c.WorkerUID || perm(st) != 0o700 {
		return refuse("the archive root is not a private directory of the worker")
	}
	return s.ops.Fetch(ctx, FetchPlan{Command: s.c.ArchiveFetch, Root: req.Path, Owner: s.c.WorkerName, Store: req.Store, Archive: req.Archive})
}
