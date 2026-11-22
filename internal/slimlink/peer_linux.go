package slimlink

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

func peerIs(conn net.Conn, uid uint32) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var readErr error
	if err = raw.Control(func(fd uintptr) {
		cred, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return false
	}
	return readErr == nil && cred != nil && cred.Uid == uid
}

// peerListener drops connections from any user but one.
type peerListener struct {
	*net.UnixListener
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.UnixListener.Accept()
		if err != nil {
			return nil, err
		}
		if peerIs(c, l.uid) {
			return c, nil
		}
		c.Close()
	}
}

// Listen creates the socket at path for one peer user, and every
// connection's peer is checked. As root, the file is given to peerUID with
// mode 0600. A worker that is not root (ADR 024) cannot: its socket's
// directory is set-group-ID to the peer's group, so the socket gets that
// group, and mode 0660 lets the peer alone connect. A leftover socket at
// path is replaced; any other file is an error.
func Listen(path string, peerUID uint32) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("slimlink: socket path holds another file")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	switch {
	case os.Geteuid() == 0:
		if err = os.Chown(path, int(peerUID), -1); err == nil {
			err = os.Chmod(path, 0o600)
		}
	case uint32(os.Geteuid()) == peerUID:
		err = os.Chmod(path, 0o600)
	default:
		err = peerGroup(path, peerUID)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return peerListener{l, peerUID}, nil
}

// errPeerGroup: the socket did not get the peer's group from its directory.
var errPeerGroup = errors.New("slimlink: the socket's directory must be set-group-ID to the peer's primary group")

// peerGroup opens the socket at path to the peer's primary group, which its
// directory gave it: mode 0660.
func peerGroup(path string, peerUID uint32) error {
	peer, err := user.LookupId(strconv.FormatUint(uint64(peerUID), 10))
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(peer.Gid, 10, 32)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || uint64(info.Sys().(*syscall.Stat_t).Gid) != gid {
		return errPeerGroup
	}
	return os.Chmod(path, 0o660)
}

// ServeLocal serves h on l until ctx ends, then drains for up to five seconds.
func ServeLocal(ctx context.Context, l net.Listener, h http.Handler) error {
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Shutdown(stop)
			cancel()
		case <-done:
		}
	}()
	err := s.Serve(l)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
