//go:build linux

// Package keymem keeps key bytes out of the Go heap (finding L-18 of the
// v0.1.0 audit). A buffer lives in a page of its own, mapped outside the
// heap (which the collector copies nowhere, but never clears), locked in RAM
// while in use (mlock), so that the kernel never writes it to swap, and left
// out of core dumps (MADV_DONTDUMP). Released, a page is cleared, unlocked
// and kept for the next buffer: a reference kept by mistake reads zeros or a
// later buffer, never a freed mapping. Locking needs room under
// RLIMIT_MEMLOCK (one page per buffer in use); without it, a page is still
// cleared and left out of dumps.
//
// The key authority, the authority service and its client hold volume keys
// and receipt keys in these buffers.
package keymem

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	// ErrSize refuses a buffer of no byte, or of more than a page.
	ErrSize = errors.New("keymem: a buffer holds 1 byte to a page")
	// ErrUnavailable means that no page could be mapped.
	ErrUnavailable = errors.New("keymem: no page for a key buffer")
)

var pages struct {
	sync.Mutex
	// live are the pages handed out, by their first byte; free the pages
	// released, at most maxFreePages.
	live map[*byte][]byte
	free [][]byte
}

const maxFreePages = 64

// Buffer returns n zero bytes, at most a page, at the start of a page of
// their own. Release gives it back.
func Buffer(n int) ([]byte, error) {
	if n < 1 || n > os.Getpagesize() {
		return nil, ErrSize
	}
	pages.Lock()
	defer pages.Unlock()
	var page []byte
	if k := len(pages.free); k > 0 {
		page, pages.free = pages.free[k-1], pages.free[:k-1]
	} else {
		p, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
		if err != nil {
			return nil, ErrUnavailable
		}
		_ = unix.Madvise(p, unix.MADV_DONTDUMP)
		page = p
	}
	_ = unix.Mlock(page)
	if pages.live == nil {
		pages.live = map[*byte][]byte{}
	}
	pages.live[&page[0]] = page
	return page[:n:n], nil
}

// Release clears the page of a buffer that Buffer returned, unlocks it and
// keeps it. It does nothing for a nil buffer, a buffer released already, or
// any other slice: each buffer is released once, by whoever holds it last.
func Release(b []byte) {
	if cap(b) == 0 {
		return
	}
	pages.Lock()
	defer pages.Unlock()
	page, ok := pages.live[&b[:1][0]]
	if !ok {
		return
	}
	delete(pages.live, &page[0])
	clear(page)
	_ = unix.Munlock(page)
	if len(pages.free) < maxFreePages {
		pages.free = append(pages.free, page)
		return
	}
	_ = unix.Munmap(page)
}

// Copy returns a copy of b in a buffer of its own.
func Copy(b []byte) ([]byte, error) {
	c, err := Buffer(len(b))
	if err == nil {
		copy(c, b)
	}
	return c, err
}

// InUse is the number of buffers handed out and not released yet.
func InUse() int {
	pages.Lock()
	defer pages.Unlock()
	return len(pages.live)
}
