//go:build linux

// Package operatorconfig reads bounded private configuration without following
// the final path component. Its errors never contain secret file contents.
package operatorconfig

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrPrivateFile = errors.New("configuration requires a private regular file owned by this user or root")

// ReadPrivate reads a private file of exactly size bytes.
func ReadPrivate(path string, size int) ([]byte, error) { return readPrivate(path, size, size) }

// ReadPrivateUpTo reads a private file of 1 to max bytes.
func ReadPrivateUpTo(path string, max int) ([]byte, error) { return readPrivate(path, 1, max) }

func readPrivate(path string, min, max int) ([]byte, error) {
	if min < 1 || max < min || max > 65536 {
		return nil, ErrPrivateFile
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	uid := st.Sys().(*syscall.Stat_t).Uid
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || (uid != 0 && uid != uint32(os.Geteuid())) ||
		st.Size() < int64(min) || st.Size() > int64(max) {
		return nil, ErrPrivateFile
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) < min || len(data) > max {
		clear(data)
		return nil, ErrPrivateFile
	}
	return data, nil
}

// EnsurePrivate creates exclusively, fsyncs the data and parent directory, and
// preserves an existing file. A partial prior creation fails closed on reread.
func EnsurePrivate(path string, size int, generate func() []byte) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		return ReadPrivate(path, size)
	}
	if err != nil {
		return nil, err
	}
	data := generate()
	if len(data) != size {
		f.Close()
		return nil, ErrPrivateFile
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return nil, err
	}
	return data, nil
}
