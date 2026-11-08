//go:build linux && amd64

package capsuleprotocol

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// DialControl performs the Firecracker host-side vsock handshake, preserving
// buffered bytes. The path belongs to one boot's private jail, never user input.
func DialControl(ctx context.Context, path string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
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
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err = fmt.Fprintf(conn, "CONNECT %d\n", ControlPort); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 64)
	line, err := r.ReadSlice('\n')
	if err != nil || !strings.HasPrefix(string(line), "OK ") {
		return nil, ErrTransport
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return bufferedConn{Conn: conn, reader: r}, nil
}

// Linux x86_64 sockaddr_vm UAPI. RawConn integrates nonblocking accept with Go's
// poller; FileConn/FileListener do not implement AF_VSOCK sockaddr conversion.
type sockaddrVM struct {
	Family, Reserved uint16
	Port, CID        uint32
	Flags            uint8
	Zero             [3]byte
}
type vsockAddr struct{ cid, port uint32 }

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

type vsockConn struct {
	*os.File
	local, remote vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr  { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr { return c.remote }

type vsockListener struct {
	file *os.File
	addr vsockAddr
}

func (l *vsockListener) Close() error   { return l.file.Close() }
func (l *vsockListener) Addr() net.Addr { return l.addr }

func ListenControl() (net.Listener, error) {
	fd, err := syscall.Socket(40, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	addr := sockaddrVM{Family: 40, Port: ControlPort, CID: ^uint32(0)}
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	runtime.KeepAlive(&addr)
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno
	}
	if err = syscall.Listen(fd, 16); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &vsockListener{file: os.NewFile(uintptr(fd), "vsock-listener"), addr: vsockAddr{cid: addr.CID, port: addr.Port}}, nil
}

// DialPlatform connects from the guest to Firecracker's host CID, port 5001.
// The nonblocking connect participates in Go's poller and obeys cancellation.
func DialPlatform(ctx context.Context) (net.Conn, error) {
	fd, err := syscall.Socket(40, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "vsock-platform")
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = f.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	if err = f.SetDeadline(deadline); err != nil {
		return nil, err
	}
	addr := sockaddrVM{Family: 40, Port: PlatformPort, CID: 2}
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	runtime.KeepAlive(&addr)
	if errno != 0 && errno != syscall.EINPROGRESS {
		return nil, errno
	}
	if errno == syscall.EINPROGRESS {
		raw, err := f.SyscallConn()
		if err != nil {
			return nil, err
		}
		var connectErr error
		err = raw.Write(func(fd uintptr) bool {
			code, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
			if e != nil {
				connectErr = e
				return true
			}
			if code != 0 {
				connectErr = syscall.Errno(code)
				return true
			}
			var peer sockaddrVM
			size := uint32(unsafe.Sizeof(peer))
			_, _, e2 := syscall.Syscall(syscall.SYS_GETPEERNAME, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&size)))
			runtime.KeepAlive(&peer)
			runtime.KeepAlive(&size)
			if e2 == syscall.ENOTCONN {
				return false
			}
			if e2 != 0 {
				connectErr = e2
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		if connectErr != nil {
			return nil, connectErr
		}
	}
	if err = f.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ok = true
	return &vsockConn{File: f, local: vsockAddr{}, remote: vsockAddr{cid: 2, port: PlatformPort}}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.file.SyscallConn()
		if err != nil {
			return nil, err
		}
		var peer sockaddrVM
		size := uint32(unsafe.Sizeof(peer))
		var accepted uintptr
		var acceptErr syscall.Errno
		err = raw.Read(func(fd uintptr) bool {
			accepted, _, acceptErr = syscall.Syscall6(syscall.SYS_ACCEPT4, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&size)), syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0, 0)
			return acceptErr != syscall.EAGAIN && acceptErr != syscall.EINTR
		})
		runtime.KeepAlive(&peer)
		runtime.KeepAlive(&size)
		if err != nil {
			return nil, err
		}
		if acceptErr != 0 {
			return nil, acceptErr
		}
		if peer.CID != 2 {
			syscall.Close(int(accepted))
			continue
		} // control accepts only host CID
		return &vsockConn{File: os.NewFile(accepted, "vsock-control"), local: l.addr, remote: vsockAddr{cid: peer.CID, port: peer.Port}}, nil
	}
}
