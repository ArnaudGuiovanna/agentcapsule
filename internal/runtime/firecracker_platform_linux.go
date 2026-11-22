//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

type platformService struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (h *FirecrackerHost) platformLockPath(vmID string) string {
	return filepath.Join(h.root, "platform", vmID+".lock")
}

// Close relinquishes this worker's platform listeners without stopping VMMs.
// A replacement worker can reopen the same boot-bound endpoint and credentials.
func (h *FirecrackerHost) Close() {
	h.platformMu.Lock()
	h.platformClosed = true
	services := make([]*platformService, 0, len(h.platform))
	for _, s := range h.platform {
		services = append(services, s)
		s.cancel()
	}
	m := h.monitor
	h.monitor = nil
	clients := h.clients
	h.clients = nil
	h.platformMu.Unlock()
	for _, s := range services {
		<-s.done
	}
	if m != nil {
		close(m.stop)
		<-m.done
	}
	for _, c := range clients {
		c.CloseIdleConnections()
	}
}
func (h *FirecrackerHost) closePlatform(vmID string) {
	h.platformMu.Lock()
	s := h.platform[vmID]
	if s != nil {
		s.cancel()
	}
	h.platformMu.Unlock()
	if s != nil {
		<-s.done
	}
}

type verifiedListener struct {
	net.Listener
	ctx   context.Context
	check func(context.Context, *syscall.Ucred) error
}

func (l *verifiedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		raw, err := u.SyscallConn()
		if err != nil {
			conn.Close()
			continue
		}
		var peer *syscall.Ucred
		var peerErr error
		err = raw.Control(func(fd uintptr) {
			peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if err != nil || peerErr != nil || peer == nil {
			conn.Close()
			continue
		}
		ctx, cancel := context.WithTimeout(l.ctx, 3*time.Second)
		err = l.check(ctx, peer)
		cancel()
		if err != nil {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// platformCheck accepts a connection on the platform channel of boot vmID
// of agentID only from that boot's VMM, while the boot is RUNNING. It reads
// the registry without host.lock: another agent's boot or volume copy, or a
// state change of this one, never makes it wait (S-03). Each call the
// connection carries is admitted again (WithApplication, Control).
func (h *FirecrackerHost) platformCheck(agentID, vmID string, generation uint64) func(context.Context, *syscall.Ucred) error {
	return func(ctx context.Context, peer *syscall.Ucred) error {
		r, err := h.view()
		if err != nil {
			return err
		}
		current := r.Agents[agentID]
		if current == nil || current.Fenced || current.Run == nil || current.Run.ID != vmID || current.Run.Generation != generation || current.Run.FenceOnly || current.Run.Phase != "RUNNING" {
			return ErrGeneration
		}
		if peer.Uid != current.UID || peer.Gid != current.UID || int(peer.Pid) != current.Run.PID {
			return ErrGeneration
		}
		return h.platformPeer(ctx, current.clone(), peer)
	}
}

// platformPeer checks that the peer is the boot's identified VMM, which still
// owns the agent's volume.
func (h *FirecrackerHost) platformPeer(ctx context.Context, a *HostAgent, peer *syscall.Ucred) error {
	if h.peer != nil {
		return h.peer(a, peer)
	}
	return h.ownsVolume(ctx, a)
}

// ensurePlatform runs under the agent's lock. A second kernel lock elects ONE
// listener owner across live worker processes. Worker death releases that
// lock; stale socket files are removed only by its next owner. No secret
// enters the jail log. The socket is bound in the jail, which belongs to the
// VM's user, by root (ADR 024).
func (h *FirecrackerHost) ensurePlatform(ctx context.Context, a *HostAgent) error {
	if h.opts.PlatformHandler == nil || a.Run.FenceOnly {
		return nil
	}
	vmID, agentID, generation := a.Run.ID, a.ID, a.Run.Generation
	h.platformMu.Lock()
	if h.platformClosed {
		h.platformMu.Unlock()
		return errors.New("platform worker is closed")
	}
	if h.platform[vmID] != nil {
		h.platformMu.Unlock()
		return nil
	}
	h.platformMu.Unlock()
	lease, err := os.OpenFile(h.platformLockPath(vmID), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err = syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lease.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil
		}
		return err
	}
	owned := false
	defer func() {
		if !owned {
			lease.Close()
		}
	}()
	b, err := os.ReadFile(h.credentialPath(a.Run))
	if err != nil {
		return err
	}
	var credentials capsuleprotocol.Credentials
	if err = json.Unmarshal(b, &credentials); err != nil {
		return errors.New("invalid platform credential record")
	}
	if credentials.Identity != identity(a) || credentials.Platform == nil || credentials.Platform.Identity != identity(a) || credentials.Platform.Channel != "platform" {
		return capsuleprotocol.ErrIdentity
	}
	handler, err := h.opts.PlatformHandler(agentID, *a.Run)
	if err != nil {
		return err
	}
	// The socket is <jail>/vsock_<port>, beside the VMM's own vsock socket,
	// in the jail its user owns (L-15).
	listener, err := h.privileged().Listen(ctx, a)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	service := &platformService{cancel: cancel, done: make(chan struct{})}
	h.platformMu.Lock()
	if h.platformClosed {
		h.platformMu.Unlock()
		cancel()
		listener.Close()
		return errors.New("platform worker is closed")
	}
	if h.platform == nil {
		h.platform = map[string]*platformService{}
	}
	h.platform[vmID] = service
	h.platformMu.Unlock()
	owned = true
	go func() {
		defer close(service.done)
		defer cancel()
		defer lease.Close()
		defer func() {
			h.platformMu.Lock()
			if h.platform[vmID] == service {
				delete(h.platform, vmID)
			}
			h.platformMu.Unlock()
		}()
		_ = capsuleprotocol.ServeAuthenticated(ctx, &verifiedListener{Listener: listener, ctx: ctx, check: h.platformCheck(agentID, vmID, generation)}, *credentials.Platform, handler)
	}()
	// Another worker may retire the boot and unlink its jail: the host's
	// monitor then relinquishes this process's listener too, rather than keep a
	// deleted socket and its goroutine indefinitely.
	h.watch()
	return nil
}
