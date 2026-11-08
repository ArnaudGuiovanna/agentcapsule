//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	h.platformMu.Unlock()
	for _, s := range services {
		<-s.done
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

// ensurePlatform runs under host.lock. A second kernel lock elects ONE listener
// owner across live worker processes. Worker death releases that lock; stale
// socket files are removed only by its next owner. No secret enters the jail log.
func (h *FirecrackerHost) ensurePlatform(a *HostAgent) error {
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
	socket := fmt.Sprintf("%s_%d", a.Run.Socket, capsuleprotocol.PlatformPort)
	if err = os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	if err = os.Chown(socket, int(a.UID), int(a.UID)); err == nil {
		err = os.Chmod(socket, 0600)
	}
	if err != nil {
		listener.Close()
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
	check := func(ctx context.Context, peer *syscall.Ucred) error {
		return h.locked(ctx, func(r *hostRegistry) error {
			current := r.Agents[agentID]
			if current == nil || current.Fenced || current.Run == nil || current.Run.ID != vmID || current.Run.Generation != generation || current.Run.FenceOnly || current.Run.Phase != "RUNNING" {
				return ErrGeneration
			}
			if peer.Uid != current.UID || peer.Gid != current.UID || int(peer.Pid) != current.Run.PID {
				return ErrGeneration
			}
			if _, _, err := h.identify(current); err != nil {
				return err
			}
			return ownedVolumeLock(current.Run.PID, current.Volume)
		})
	}
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
		_ = capsuleprotocol.ServeAuthenticated(ctx, &verifiedListener{Listener: listener, ctx: ctx, check: check}, *credentials.Platform, handler)
	}()
	// Another worker may retire the boot and unlink its jail. Relinquish this
	// process's listener too; do not keep a deleted socket/goroutine indefinitely.
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				alive := false
				err := h.locked(ctx, func(r *hostRegistry) error {
					a := r.Agents[agentID]
					alive = a != nil && !a.Fenced && a.Run != nil && a.Run.ID == vmID
					return nil
				})
				if err != nil || !alive {
					cancel()
					return
				}
			}
		}
	}()
	return nil
}
