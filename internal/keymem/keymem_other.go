//go:build !linux

// Package keymem keeps key bytes out of the Go heap on Linux
// (keymem_linux.go). Elsewhere a buffer is ordinary memory that Release
// clears: no product process runs there.
package keymem

import "errors"

var (
	// ErrSize refuses a buffer of no byte, or of more than a page.
	ErrSize = errors.New("keymem: a buffer holds 1 byte to a page")
	// ErrUnavailable means that no page could be mapped.
	ErrUnavailable = errors.New("keymem: no page for a key buffer")
)

const pageSize = 4096

// Buffer returns n zero bytes, at most a page.
func Buffer(n int) ([]byte, error) {
	if n < 1 || n > pageSize {
		return nil, ErrSize
	}
	return make([]byte, n), nil
}

// Release clears b.
func Release(b []byte) { clear(b) }

// Copy returns a copy of b in a buffer of its own.
func Copy(b []byte) ([]byte, error) {
	c, err := Buffer(len(b))
	if err == nil {
		copy(c, b)
	}
	return c, err
}

// InUse is the number of buffers handed out and not released yet: none is
// counted here.
func InUse() int { return 0 }
