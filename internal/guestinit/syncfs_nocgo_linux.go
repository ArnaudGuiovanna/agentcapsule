//go:build linux && !cgo

package guestinit

import "os"

// Product guests require cgo (SQLite and syncfs). A reduced build cannot attest
// filesystem writeback; do not silently replace syncfs with error-blind sync.
func syncFilesystem(*os.File) error { return ErrGuest }
