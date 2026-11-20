//go:build linux

package guestinit

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// CorpusRoot is where capsule-init mounts the VM's corpora, one directory
// each (ADR 023 §5.3). It is a read-only tmpfs, empty when the VM has no
// corpus, and the harness sees it at the same path.
const CorpusRoot = capsuleprotocol.CorpusMountPoint

// BuildDevices is the directory of the builder's raw drives: source, lfs
// and output, usable by the harness user only.
const BuildDevices = "/dev/corpus"

// corpusFlags: a corpus is data, never code. It cannot be written, carry a
// device or a setuid file, or be executed.
const corpusFlags = syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOATIME

// MountCorpora prepares /corpus before the harness starts. For each corpus
// of c, in order, it checks the UUID of the drive's ext4 superblock against
// c, then mounts it read-only at /corpus/<mount>. Any mismatch, missing
// device or unreadable superblock refuses the boot: a shift in the drive
// order never mounts the wrong corpus. /corpus is then made read-only and,
// for a harness from the registry (harnessRoot), bound at its /corpus; a
// harness of base 1 has no such directory, and cannot be given corpora.
// For the builder (c.Build), each build drive must have its size; it then
// appears under BuildDevices for uid and gid only. c is nil when the VM has
// neither corpora nor build drives: /corpus stays an empty read-only
// directory.
func MountCorpora(c *capsuleprotocol.GuestCorpora, harnessRoot string, uid, gid int) error {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return ErrGuest
	}
	if err := os.MkdirAll(CorpusRoot, 0o755); err != nil {
		return ErrGuest
	}
	if err := syscall.Mount("corpus", CorpusRoot, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=0755,size=4k,nr_inodes=16"); err != nil {
		return ErrGuest
	}
	var corpora []capsuleprotocol.CorpusMount
	if c != nil {
		corpora = c.Corpora
	}
	for _, m := range corpora {
		device, err := capsuleprotocol.DriveDevice(m.Index)
		if err != nil {
			return ErrGuest
		}
		if err = checkDriveUUID(device, m.UUID, true); err != nil {
			return err
		}
		target := filepath.Join(CorpusRoot, m.Mount)
		// capsule-init runs with umask 0077: set the mode explicitly.
		if err = os.Mkdir(target, 0o755); err != nil || os.Chmod(target, 0o755) != nil {
			return ErrGuest
		}
		if err = syscall.Mount(device, target, "ext4", corpusFlags, ""); err != nil {
			return ErrGuest
		}
	}
	if err := syscall.Mount("", CorpusRoot, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return ErrGuest
	}
	if harnessRoot != "" {
		target := filepath.Join(harnessRoot, CorpusRoot)
		st, err := os.Lstat(target)
		switch {
		case err == nil && st.IsDir():
			if err = syscall.Mount(CorpusRoot, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				return ErrGuest
			}
			if err = syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
				return ErrGuest
			}
		case len(corpora) > 0:
			return ErrGuest // base 1: no mount point for corpora
		}
	}
	if c != nil && c.Build != nil {
		return exposeBuildDrives(*c.Build, uid, gid)
	}
	return nil
}

// exposeBuildDrives checks each build drive's size, then gives the harness
// user a device node of its own for it: source and lfs read-only, output
// read-write. The /dev/vd* nodes stay root's.
func exposeBuildDrives(b capsuleprotocol.GuestBuildDrives, uid, gid int) error {
	if err := os.Mkdir(BuildDevices, 0o755); err != nil || os.Chmod(BuildDevices, 0o755) != nil {
		return ErrGuest
	}
	drives := []struct {
		name  string
		drive *capsuleprotocol.BuildDrive
		mode  uint32
	}{{"source", &b.Source, 0o400}, {"lfs", b.LFS, 0o400}, {"output", &b.Output, 0o600}}
	for _, d := range drives {
		if d.drive == nil {
			continue
		}
		device, err := capsuleprotocol.DriveDevice(d.drive.Index)
		if err != nil {
			return ErrGuest
		}
		rdev, err := checkDriveSize(device, d.drive.Bytes, true)
		if err != nil {
			return err
		}
		node := filepath.Join(BuildDevices, d.name)
		if err = syscall.Mknod(node, syscall.S_IFBLK|d.mode, int(rdev)); err != nil {
			return ErrGuest
		}
		if err = os.Lchown(node, uid, gid); err != nil || os.Chmod(node, os.FileMode(d.mode)) != nil {
			return ErrGuest
		}
	}
	return nil
}

// openDrive opens path read-only; block requires a block device, as every
// drive is in the guest (tests read regular files).
func openDrive(path string, block bool) (*os.File, uint64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, ErrGuest
	}
	st, err := f.Stat()
	if err != nil || (block && st.Mode()&os.ModeDevice == 0) || (block && st.Mode()&os.ModeCharDevice != 0) || (!block && !st.Mode().IsRegular()) {
		f.Close()
		return nil, 0, ErrGuest
	}
	return f, st.Sys().(*syscall.Stat_t).Rdev, nil
}

// checkDriveUUID reads the ext4 superblock of path and compares its UUID.
func checkDriveUUID(path, uuid string, block bool) error {
	f, _, err := openDrive(path, block)
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := capsuleprotocol.Ext4UUID(f)
	if err != nil || got != uuid {
		return ErrGuest
	}
	return nil
}

// checkDriveSize compares the size of path with bytes and returns its
// device number.
func checkDriveSize(path string, bytes int64, block bool) (uint64, error) {
	f, rdev, err := openDrive(path, block)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil || size != bytes {
		return 0, ErrGuest
	}
	return rdev, nil
}
