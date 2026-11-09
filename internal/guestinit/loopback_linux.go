//go:build linux

package guestinit

import (
	"syscall"
	"unsafe"
)

// BringLoopbackUp sets the guest's loopback interface up; the kernel then gives
// it 127.0.0.1. The VM has no other interface: this opens no route out of it,
// only lets processes inside reach each other over TCP (the model endpoint of
// an adapted agent).
func BringLoopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	// struct ifreq: the interface name, then (among others) short ifr_flags.
	var req struct {
		name  [syscall.IFNAMSIZ]byte
		flags uint16
		_     [22]byte
	}
	copy(req.name[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	req.flags |= syscall.IFF_UP
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	return nil
}
