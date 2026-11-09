//go:build linux

package guestinit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

type ProcessOptions struct {
	Boot       HarnessBoot
	Entrypoint []string
	SocketPath string
	UID, GID   uint32
	// Only the supervisor holds this credential-bearing client. Boot contains
	// the public Unix path, never the platform key or a caller-selected endpoint.
	Platform *capsuleprotocol.PlatformClient
	// Set by capsule-init to its dedicated cgroup-v2 directory. Unit tests can
	// run one nonforking child without a cgroup; product startup always supplies it.
	Cgroup string
	// Root, when set (HarnessRoot), is the harness's own filesystem: the data
	// directory is bound into it and the process runs chrooted there.
	Root string
}

type Process struct {
	cmd    *exec.Cmd
	done   chan struct{}
	mu     sync.Mutex
	err    error
	forced bool
	opts   ProcessOptions
	proxy  http.Handler
}

func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.forced {
		return errors.Join(ErrGuest, p.err)
	}
	return p.err
}
func (p *Process) Proxy() http.Handler { return p.proxy }

func (p *Process) killGroup() error {
	p.mu.Lock()
	p.forced = true
	p.mu.Unlock()
	if p.opts.Cgroup != "" {
		return os.WriteFile(filepath.Join(p.opts.Cgroup, "cgroup.kill"), []byte("1"), 0600)
	}
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func (p *Process) groupEmpty() (bool, error) {
	b, err := os.ReadFile(filepath.Join(p.opts.Cgroup, "cgroup.events"))
	return strings.Contains(string(b), "populated 0\n"), err
}

func (p *Process) drainGroup(ctx context.Context) error {
	if p.opts.Cgroup == "" {
		return nil
	}
	for {
		empty, err := p.groupEmpty()
		if err != nil {
			return err
		}
		if empty {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (p *Process) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return p.Err()
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return p.Err()
	case <-ctx.Done():
		if err := p.killGroup(); err != nil {
			return errors.Join(ctx.Err(), err)
		}
		select {
		case <-p.done:
			return errors.Join(ctx.Err(), p.Err())
		case <-time.After(5 * time.Second):
			return errors.Join(ctx.Err(), ErrGuest)
		}
	}
}

// StartHarness spawns a real independent process. lifetime is the VM lifetime,
// not the bootstrap HTTP request: losing an ACK must not terminate a ready
// harness. readiness bounds startup; failure retires this attempted process.
func StartHarness(lifetime, readiness context.Context, opts ProcessOptions) (*Process, error) {
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	if err := readiness.Err(); err != nil {
		return nil, err
	}
	if len(opts.Entrypoint) == 0 || !filepath.IsAbs(opts.Entrypoint[0]) || !filepath.IsAbs(opts.SocketPath) ||
		opts.UID == 0 || opts.GID == 0 || opts.Boot.SupervisorUID != uint32(os.Geteuid()) {
		return nil, ErrGuest
	}
	config, err := json.Marshal(opts.Boot)
	if err != nil || len(config) > 4096 {
		return nil, ErrGuest
	}
	if _, err = ReadHarnessBoot(strings.NewReader(string(config))); err != nil {
		return nil, err
	}
	bridge, err := startPlatformBridge(lifetime, opts)
	if err != nil {
		return nil, err
	}
	keepBridge := false
	defer func() {
		if !keepBridge {
			_ = bridge.close()
		}
	}()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: opts.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	defer l.Close()
	keepSocket := false
	defer func() {
		if !keepSocket {
			_ = os.Remove(opts.SocketPath)
		}
	}()
	if err = os.Chmod(opts.SocketPath, 0600); err != nil {
		return nil, err
	}
	listenFD, err := l.File()
	if err != nil {
		return nil, err
	}
	defer listenFD.Close()
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	defer w.Close()
	if _, err = w.Write(config); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	dataBind := ""
	if opts.Root != "" {
		dataBind = filepath.Join(opts.Root, opts.Boot.DataDirectory)
		if err = syscall.Mount(opts.Boot.DataDirectory, dataBind, "", syscall.MS_BIND, ""); err != nil {
			return nil, ErrGuest
		}
		if err = syscall.Mount("", dataBind, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
			return nil, errors.Join(ErrGuest, unbind(dataBind))
		}
	}
	keepBind := false
	defer func() {
		if dataBind != "" && !keepBind {
			_ = unbind(dataBind)
		}
	}()
	cmd := exec.Command(opts.Entrypoint[0], opts.Entrypoint[1:]...)
	cmd.ExtraFiles = []*os.File{r, listenFD}
	cmd.Dir = opts.Boot.DataDirectory
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=/tmp"}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Chroot: opts.Root, Credential: &syscall.Credential{Uid: opts.UID, Gid: opts.GID, NoSetGroups: os.Geteuid() != 0}}
	if opts.Cgroup != "" {
		group, err := os.Open(opts.Cgroup)
		if err != nil {
			return nil, err
		}
		defer group.Close()
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(group.Fd())
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	p := &Process{cmd: cmd, done: make(chan struct{}), opts: opts}
	keepSocket = true
	keepBridge = true
	keepBind = true
	go func() {
		err := cmd.Wait()
		err = errors.Join(err, bridge.close())
		if opts.Cgroup != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			empty, observed := p.groupEmpty()
			err = errors.Join(err, observed)
			if observed != nil || !empty {
				// A successful parent exit cannot conceal surviving descendants.
				// Retire them, but preserve the forced-exit classification.
				err = errors.Join(err, p.killGroup())
			}
			err = errors.Join(err, p.drainGroup(ctx))
			cancel()
		}
		_ = os.Remove(opts.SocketPath)
		if dataBind != "" {
			// The encrypted volume can only close once this bind is gone.
			err = errors.Join(err, unbind(dataBind))
		}
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	if bridge != nil {
		go func() {
			select {
			case <-bridge.done:
				if bridge.err != nil && !errors.Is(bridge.err, context.Canceled) {
					_ = p.killGroup()
				}
			case <-p.done:
			}
		}()
	}
	go func() {
		select {
		case <-lifetime.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = p.Stop(ctx)
			cancel()
		case <-p.done:
		}
	}()
	local, err := capsuleprotocol.NewLocalClient(opts.Boot.Identity, opts.SocketPath)
	if err == nil {
		for {
			probe, cancel := context.WithTimeout(readiness, time.Second)
			var health capsuleprotocol.HealthStatus
			health, err = local.HealthStatus(probe)
			if err == nil {
				if health.PreviousShutdown != opts.Boot.PreviousShutdown {
					err = ErrGuest
					cancel()
					goto failed
				}
				err = local.RequireControlContract(probe)
				cancel()
				if err == nil {
					break
				}
				if !errors.Is(err, capsuleprotocol.ErrTransport) {
					goto failed
				}
			} else {
				cancel()
			}
			select {
			case <-p.done:
				err = errors.Join(ErrGuest, p.Err())
				goto failed
			case <-readiness.Done():
				err = readiness.Err()
				goto failed
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
failed:
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, p.Stop(ctx))
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", opts.SocketPath)
		},
	}
	p.proxy = &httputil.ReverseProxy{Transport: transport, Director: func(r *http.Request) { r.URL.Scheme = "http"; r.URL.Host = "harness.local"; r.Host = "harness.local" },
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(struct {
				Protocol string                   `json:"protocol"`
				Identity capsuleprotocol.Identity `json:"identity"`
				Code     string                   `json:"code"`
			}{capsuleprotocol.Version, opts.Boot.Identity, "harness_unavailable"})
		},
	}
	return p, nil
}
