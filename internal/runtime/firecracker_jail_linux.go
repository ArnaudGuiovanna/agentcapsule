//go:build linux

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// A jail's root directory belongs to its VMM's user, who can put a link, a
// FIFO or a large file under any name in it. Root works there without
// following a link and without waiting on what it opens (L-15).

// readPIDFile reads the PID the jailer wrote, at most 32 bytes of a regular
// file opened without following a link or blocking.
func readPIDFile(dir, name string) (int, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, errors.New("PID file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return 0, err
	}
	if len(b) > 32 {
		return 0, errors.New("PID file too long")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid PID file")
	}
	return pid, nil
}

// listenInJail binds the Unix socket name in dir for uid, and gives it to
// uid. The directory is opened without following a link, the socket bound
// through that descriptor, and its owner and mode set through a descriptor of
// the node itself, opened without following a link: a node the VMM swapped
// in is refused, never followed. The listener does not unlink on close: the
// jail goes with its run.
func listenInJail(dir, name string, uid int) (*net.UnixListener, error) {
	d, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(d)
	if err = unix.Unlinkat(d, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", d, name), Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	if err = ownSocket(d, name, uid); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// afterBind runs between the bind and the change of owner: tests only.
var afterBind func()

func ownSocket(dir int, name string, uid int) error {
	if afterBind != nil {
		afterBind()
	}
	fd, err := unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("platform socket replaced in the jail")
	}
	if err = unix.Fchownat(fd, "", uid, uid, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	// The descriptor pins the socket node: its /proc link reaches that node
	// and nothing else.
	return os.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), 0600)
}

// shareBootFile makes a cached kernel or initrd readable by the VMMs, which
// reach it only through a jail's hard link: the bin directory stays private.
func shareBootFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("boot image is not a regular file")
	}
	if st.Mode().Perm() == 0444 {
		return nil
	}
	return os.Chmod(path, 0444)
}

// bootImage names the cached kernel or initrd of a.
func (h *FirecrackerHost) bootImage(a *HostAgent, name string) (string, error) {
	artifact := name
	if a.SystemImage != nil {
		digest := a.SystemImage.Kernel
		if name == "initrd" {
			digest = a.SystemImage.Initrd
		}
		if raw, err := hex.DecodeString(digest); err != nil || len(raw) != sha256.Size {
			return "", errors.New("invalid system image digest")
		}
		artifact += "-" + digest
	}
	return filepath.Join(h.root, "bin", artifact), nil
}

// placeBootImages puts a's kernel and initrd into the jail root (P-12). The
// kernel is a hard link to the cached image, which no VMM can write (0444,
// root's). The initrd gets the boot's own files appended, so it is a clone
// of the cached image where the file system can (FICLONE), a copy otherwise.
// Neither is synced: a jail does not survive a crash.
func (h *FirecrackerHost) placeBootImages(a *HostAgent, root string, appendix func(*os.File) error) error {
	kernel, err := h.bootImage(a, "kernel")
	if err != nil {
		return err
	}
	if err = shareBootFile(kernel); err != nil {
		return err
	}
	if err = os.Link(kernel, filepath.Join(root, "kernel")); errors.Is(err, syscall.EXDEV) {
		err = copyBootFile(kernel, filepath.Join(root, "kernel"), nil)
	}
	if err != nil {
		return err
	}
	initrd, err := h.bootImage(a, "initrd")
	if err != nil {
		return err
	}
	return copyBootFile(initrd, filepath.Join(root, "initrd"), appendix)
}

func copyBootFile(source, destination string, appendix func(*os.File) error) error {
	in, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0444)
	if err != nil {
		return err
	}
	if unix.IoctlFileClone(int(out.Fd()), int(in.Fd())) == nil {
		_, err = out.Seek(0, io.SeekEnd)
	} else {
		_, err = io.Copy(out, in)
	}
	if err == nil && appendix != nil {
		err = appendix(out)
	}
	// The worker runs with UMask=0077. The jailer drops privileges before
	// Firecracker reads these files inside its per-run private directory.
	if err == nil {
		err = out.Chmod(0444)
	}
	return errors.Join(err, out.Close())
}
