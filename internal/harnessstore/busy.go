//go:build cgo

package harnessstore

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

// Busy reports whether err is the store refusing a transaction because
// another one holds it past the busy timeout (5 s): a delivery's handler
// that is slow, or never returns. It is transient. A harness's background
// work waits it out and tries again; it must not end the harness, which
// would end its guest and count a crash (ADR 012, question 6).
func Busy(err error) bool {
	var e sqlite3.Error
	return errors.As(err, &e) && (e.Code == sqlite3.ErrBusy || e.Code == sqlite3.ErrLocked)
}
