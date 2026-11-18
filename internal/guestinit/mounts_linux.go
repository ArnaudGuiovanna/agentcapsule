//go:build linux

package guestinit

import "syscall"

// Mount is one filesystem capsule-init mounts at boot, before anything else.
type Mount struct {
	Source, Target, Kind, Data string
	Flags                      uintptr
}

// Sizes of the memory-backed directories. Without one, each tmpfs may grow to
// half of the guest's memory. /tmp takes a quarter of the guest's memory,
// which is the agent's memory_mib (64 MiB for 256 MiB). /run holds only the
// supervisor's sockets and lock files: the harness cannot write there.
const (
	TmpSize = "25%"
	RunSize = "8m"
)

// BootMounts is the guest's runtime layout under the read-only base: kernel
// interfaces, devices, and the two memory-backed directories.
func BootMounts() []Mount {
	return []Mount{
		{"proc", "/proc", "proc", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"sysfs", "/sys", "sysfs", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", syscall.MS_NOSUID},
		{"tmpfs", "/run", "tmpfs", "mode=0711,size=" + RunSize, syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777,size=" + TmpSize, syscall.MS_NOSUID | syscall.MS_NODEV},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
	}
}
