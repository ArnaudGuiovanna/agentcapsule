//go:build linux

package workerhelper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The helper resolves every path the worker could influence without
// following a symbolic link, and checks each file through its own
// descriptor: the worker owns the runtime root, and could swap any of its
// entries between a check and a use.

const noLinks = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// cleanAbs: an absolute clean path.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// within tells whether path lies strictly under root, and gives its path
// relative to root.
func within(root, path string) (string, bool) {
	if !cleanAbs(root) || !cleanAbs(path) {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// openNoLinks opens path, absolute, with flags, following no symbolic link
// on the way.
func openNoLinks(path string, flags int) (*os.File, error) {
	if !cleanAbs(path) {
		return nil, errors.New("not an absolute clean path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: noLinks})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openAt opens rel under the directory dir, without leaving it and without
// following a symbolic link.
func openAt(dir *os.File, rel string, flags int) (*os.File, error) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, errors.New("not a relative clean path")
	}
	fd, err := unix.Openat2(int(dir.Fd()), rel, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: noLinks | unix.RESOLVE_BENEATH})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: filepath.Join(dir.Name(), rel), Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), rel)), nil
}

// openUnder opens path, which must lie under one of roots, without following
// a symbolic link anywhere: neither to the root nor below it.
func openUnder(roots []string, path string, flags int) (*os.File, error) {
	for _, root := range roots {
		rel, ok := within(root, path)
		if !ok {
			continue
		}
		dir, err := openNoLinks(root, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		return openAt(dir, rel, flags)
	}
	return nil, refuse("a path outside the helper's roots")
}

// stat is the Stat_t of an open file.
func stat(f *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &st)
	return st, err
}

func isDir(st unix.Stat_t) bool     { return st.Mode&unix.S_IFMT == unix.S_IFDIR }
func isRegular(st unix.Stat_t) bool { return st.Mode&unix.S_IFMT == unix.S_IFREG }
func perm(st unix.Stat_t) uint32    { return st.Mode & 0o7777 }

// ownedDir checks that a directory belongs to owner and that neither its
// group nor others can write it.
func ownedDir(f *os.File, owner uint32) error {
	st, err := stat(f)
	if err != nil {
		return err
	}
	if !isDir(st) || st.Uid != owner || perm(st)&0o022 != 0 {
		return refuse("a directory of the jails is not the helper's")
	}
	return nil
}

// openJail opens run runID's chroot under base, a directory of owner (root),
// as the run's directory under base/firecracker: every component is reached
// without a link, and every one but the chroot itself, which the jailer gives
// the VM's user, must be owner's. It returns the chroot and the directory
// holding the run's directory (base/firecracker).
func openJail(base, runID string, owner uint32) (jail, runs *os.File, err error) {
	if !ValidRunID(runID) {
		return nil, nil, refuse("not a run")
	}
	b, err := openNoLinks(base, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, nil, err
	}
	defer b.Close()
	if err = ownedDir(b, owner); err != nil {
		return nil, nil, err
	}
	runs, err = openAt(b, "firecracker", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (*os.File, *os.File, error) { runs.Close(); return nil, nil, e }
	if err = ownedDir(runs, owner); err != nil {
		return fail(err)
	}
	dir, err := openAt(runs, runID, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return fail(err)
	}
	defer dir.Close()
	if err = ownedDir(dir, owner); err != nil {
		return fail(err)
	}
	jail, err = openAt(dir, "root", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return fail(err)
	}
	return jail, runs, nil
}

// fdPath names an open file through this process's descriptor table: a path
// that reaches that file and nothing else, whatever is renamed meanwhile.
func fdPath(f *os.File) string { return "/proc/self/fd/" + itoa(int(f.Fd())) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
