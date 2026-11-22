//go:build linux

package keyauthority

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The key buffers of this package (L-18): a record read from disk, a record
// it writes, and a key it makes or hands to the journal live in a page of
// their own, outside the Go heap (which the collector copies nowhere, but
// never clears), locked in RAM while in use (mlock), so that the kernel
// never writes them to swap, and left out of core dumps (MADV_DONTDUMP).
// Released, a page is cleared, unlocked and kept for the next buffer: a
// reference kept by mistake reads zeros, never a freed mapping. Locking
// needs room under RLIMIT_MEMLOCK (one page per buffer in use); without it,
// a page is still cleared and left out of dumps.
var pages struct {
	sync.Mutex
	// live are the pages handed out, by their first byte; free the pages
	// released, at most maxFreePages.
	live map[*byte][]byte
	free [][]byte
}

const maxFreePages = 64

// lockedBuffer returns n zero bytes, at most a page, at the start of a page
// of their own. release gives it back.
func lockedBuffer(n int) ([]byte, error) {
	if n < 1 || n > os.Getpagesize() {
		return nil, ErrInput
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

// release clears the page of a buffer that lockedBuffer returned, unlocks
// it and keeps it. It does nothing for a nil buffer, a buffer released
// already, or any other slice: each buffer is released once, by whoever
// holds it last.
func release(b []byte) {
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

// lockedCopy returns a copy of b in a buffer of its own.
func lockedCopy(b []byte) ([]byte, error) {
	c, err := lockedBuffer(len(b))
	if err == nil {
		copy(c, b)
	}
	return c, err
}
