//go:build linux

package guestinit

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// HarnessRoot is where capsule-init mounts a harness filesystem from the
// registry. The harness process runs with this directory as its root.
const HarnessRoot = "/harness"

// MountHarnessRoot mounts the read-only harness drive and exposes the guest
// runtime the harness needs at the same paths as a built-in harness: devices,
// /proc, /run (platform socket) and /tmp. The data directory is bound per
// process start, so the encrypted volume can always be closed after it.
func MountHarnessRoot() error {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return ErrGuest
	}
	if err := os.MkdirAll(HarnessRoot, 0o755); err != nil {
		return ErrGuest
	}
	if err := syscall.Mount(capsuleprotocol.HarnessDevice, HarnessRoot, "ext4",
		syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOATIME, ""); err != nil {
		return ErrGuest
	}
	for _, dir := range capsuleprotocol.HarnessMountPoints {
		st, err := os.Lstat(filepath.Join(HarnessRoot, dir))
		if err != nil || !st.IsDir() {
			return ErrGuest
		}
	}
	for _, b := range []struct {
		source string
		flags  uintptr
	}{
		{"/dev", syscall.MS_NOSUID | syscall.MS_NOEXEC},
		{"/run", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"/tmp", syscall.MS_NOSUID | syscall.MS_NODEV},
	} {
		if err := bindInto(b.source, b.flags); err != nil {
			return err
		}
	}
	if err := syscall.Mount("proc", filepath.Join(HarnessRoot, "proc"), "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return ErrGuest
	}
	return nil
}

// bindInto makes source visible at the same path under HarnessRoot, with flags.
func bindInto(source string, flags uintptr) error {
	target := filepath.Join(HarnessRoot, source)
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return ErrGuest
	}
	if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|flags, ""); err != nil {
		return ErrGuest
	}
	return nil
}

// unbind detaches a per-process bind; a lazy detach still releases the
// volume once nothing uses it.
func unbind(target string) error {
	if err := syscall.Unmount(target, 0); err != nil {
		if err = syscall.Unmount(target, syscall.MNT_DETACH); err != nil {
			return err
		}
	}
	return nil
}
