//go:build linux

package workerhelper

import (
	"net"

	"golang.org/x/sys/unix"
)

// sendRaw sends b with the descriptors fds, past send's own bounds.
func sendRaw(c *net.UnixConn, b []byte, fds []int) error {
	_, _, err := c.WriteMsgUnix(b, unix.UnixRights(fds...), nil)
	return err
}
