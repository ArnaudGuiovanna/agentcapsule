package main

// The local protocol with the worker, the same as the platform's
// internal/slimlink. This module cannot import the platform's packages (it
// pins an older A2A SDK), so the contract is written twice and pinned by the
// shared examples in internal/slimlink/testdata/contract.json, which both
// sides' tests decode.

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

type Event struct {
	ID       string   `json:"id"`
	Subjects []string `json:"subjects"`
	Body     []byte   `json:"body"`
}

type Receipt struct {
	Result   []byte `json:"result"`
	Replayed bool   `json:"replayed"`
}

const (
	servePath   = "/v1/serve"
	sendPath    = "/v1/send"
	healthPath  = "/v1/health"
	deliverPath = "/v1/deliver"
)

type ServeRequest struct {
	Name string `json:"name"`
}

type SendRequest struct {
	To    string `json:"to"`
	Nonce string `json:"nonce"`
	Event Event  `json:"event"`
}

type DeliverRequest struct {
	To     string `json:"to"`
	Caller string `json:"caller"`
	Nonce  string `json:"nonce"`
	Event  Event  `json:"event"`
}

type Health struct {
	Name string `json:"name"`
}

type Failure struct {
	Error string `json:"error"`
}

const (
	codeUnreachable = "unreachable"
	codeRefused     = "refused"
	codeFailed      = "failed"
	codeInvalid     = "invalid"
	codeUnavailable = "unavailable"
)

const platformNamespace = "agentcapsule/platform/"

const maxBody = 8 << 20

func validComponent(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validName(s string) bool {
	parts := strings.Split(s, "/")
	return len(parts) == 3 && parts[0] == "agentcapsule" && validComponent(parts[1]) && validComponent(parts[2])
}

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

// listen creates the bridge's socket, mode 0600 for its own user (the worker
// runs as root, or as the same user in tests), accepting only workerUID.
func listen(path string, workerUID uint32) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("socket path holds another file")
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
	return peerListener{l, workerUID}, nil
}

// dialWorker connects to the worker's socket and checks the peer is the worker.
func dialWorker(path string, workerUID uint32) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		if !peerIs(c, workerUID) {
			c.Close()
			return nil, errors.New("unexpected peer on the worker's socket")
		}
		return c, nil
	}
}
