//go:build linux

package keyauthority

import (
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
)

// The key buffers of this package (L-18): a record read from disk, a record
// it writes, and a key it makes or hands to the journal live in buffers of
// package keymem: a page of their own, outside the Go heap, locked in RAM
// while in use, left out of core dumps, and cleared at their release.

// lockedBuffer returns n zero bytes, at most a page, at the start of a page
// of their own. release gives it back.
func lockedBuffer(n int) ([]byte, error) {
	b, err := keymem.Buffer(n)
	switch {
	case errors.Is(err, keymem.ErrSize):
		return nil, ErrInput
	case err != nil:
		return nil, ErrUnavailable
	}
	return b, nil
}

// release clears the page of a buffer that lockedBuffer returned, unlocks
// it and keeps it. It does nothing for a nil buffer, a buffer released
// already, or any other slice: each buffer is released once, by whoever
// holds it last.
func release(b []byte) { keymem.Release(b) }

// lockedCopy returns a copy of b in a buffer of its own.
func lockedCopy(b []byte) ([]byte, error) {
	c, err := lockedBuffer(len(b))
	if err == nil {
		copy(c, b)
	}
	return c, err
}
