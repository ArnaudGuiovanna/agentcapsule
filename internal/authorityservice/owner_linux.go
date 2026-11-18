//go:build linux && cgo

package authorityservice

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// ErrInUse means that another process owns an authority directory: the
// authority service, or a command that opened it.
var ErrInUse = errors.New("authority directory in use by another process")

// OwnerLock is the lock file that each process opening an authority
// directory holds, exclusively, while it runs (ADR 006 §1).
const OwnerLock = "owner.lock"

// Owner holds the lock of one or more authority directories.
type Owner struct{ files []*os.File }

// Own takes the exclusive lock of each existing directory, without waiting:
// ErrInUse when another process holds one. A missing directory is skipped,
// since nothing runs on it; a command that creates it takes its lock on
// its next run. The service and every command that opens an authority
// directory take it: snapshot, promote, init-replica, and the
// administrator's init commands. restoreauthority.Open does not: the
// package's tests open two handles in one process to stand for two
// processes.
func Own(dirs ...string) (*Owner, error) {
	o := &Owner{}
	for _, dir := range dirs {
		st, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && !st.IsDir() {
			err = errors.New("authority path is not a directory")
		}
		if err != nil {
			o.Release()
			return nil, err
		}
		f, err := os.OpenFile(filepath.Join(dir, OwnerLock), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
		if err == nil {
			if st, e := f.Stat(); e != nil || !st.Mode().IsRegular() {
				f.Close()
				err = errors.Join(errors.New("owner lock is not a regular file"), e)
			}
		}
		if err != nil {
			o.Release()
			return nil, err
		}
		if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			f.Close()
			o.Release()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, ErrInUse
			}
			return nil, err
		}
		o.files = append(o.files, f)
	}
	return o, nil
}

// Release gives the locks back.
func (o *Owner) Release() {
	if o == nil {
		return
	}
	for _, f := range o.files {
		f.Close()
	}
	o.files = nil
}
