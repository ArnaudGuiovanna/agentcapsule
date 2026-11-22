// Package persistence defines the identifiers and errors shared by the control plane records.
package persistence

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var ErrNotFound = errors.New("resource not found")
var ErrInput = errors.New("invalid input")

var ErrTransition = errors.New("request transition is not permitted")

var ErrConflict = errors.New("idempotency key reused with a different request")

var ErrExpired = errors.New("request deadline has elapsed")

// ID gives a new row its prefixed, random identifier.
func ID(prefix string) string {
	var id [16]byte
	_, _ = rand.Read(id[:]) // crypto/rand.Read is guaranteed to fill or terminate on Go 1.25+.
	return prefix + "_" + hex.EncodeToString(id[:])
}
