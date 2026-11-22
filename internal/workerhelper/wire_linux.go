//go:build linux

package workerhelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// errMessage: a message that is too long, truncated, carries too many
// descriptors, or is not one JSON object of the protocol.
var errMessage = errors.New("worker helper: malformed message")

// send writes v as one message, with files as its descriptors.
func send(c *net.UnixConn, v any, files []*os.File) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage || len(files) > MaxFiles {
		return errMessage
	}
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	n, oobn, err := c.WriteMsgUnix(b, oob, nil)
	if err == nil && (n != len(b) || oobn != len(oob)) {
		err = io.ErrShortWrite
	}
	return err
}

// receive reads one message into v, and its descriptors, close-on-exec from
// the start: a program the helper starts never inherits one. A message with
// too many descriptors, a truncated one, or one that is not a single JSON
// object of v's fields is refused, its descriptors closed. io.EOF: the peer
// closed the connection.
func receive(c *net.UnixConn, v any) ([]*os.File, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, MaxMessage+1)
	oob := make([]byte, unix.CmsgSpace(4*(MaxFiles+1)))
	var n, oobn, flags int
	var recvErr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobn, flags, _, recvErr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC)
		return recvErr != unix.EAGAIN
	})
	if err == nil {
		err = recvErr
	}
	if err != nil {
		return nil, err
	}
	files, fdErr := parseRights(oob[:oobn])
	if fdErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > MaxMessage || len(files) > MaxFiles {
		closeFiles(files)
		return nil, errMessage
	}
	if n == 0 && oobn == 0 {
		return nil, io.EOF
	}
	d := json.NewDecoder(bytes.NewReader(buf[:n]))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil || d.More() {
		closeFiles(files)
		return nil, errMessage
	}
	return files, nil
}

func parseRights(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	var bad error
	for _, m := range messages {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			bad = err
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "received"))
		}
	}
	if bad != nil {
		closeFiles(files)
		return nil, bad
	}
	return files, nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}

// peerUID is the account of the process at the other end (SO_PEERCRED).
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
