//go:build !cgo

package harnessstore

// Busy reports whether err is the store refusing a transaction because
// another one holds it past the busy timeout. Without cgo the SQLite driver
// opens no database, so no error is that refusal. This file only lets the
// packages that import harnessstore build without cgo (internal/directory in
// the interoperability job); harnesses are built with cgo and use busy.go.
func Busy(error) bool { return false }
