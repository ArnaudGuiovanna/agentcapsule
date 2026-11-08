//go:build linux

package main

import (
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// definiteRefusal reports errors that are decided by the database state or the
// input. Repeating the same command cannot change them, unlike a failure whose
// commit result is unknown. Operators are told which case they are in.
func definiteRefusal(err error) (string, bool) {
	switch {
	case errors.Is(err, controlplane.ErrInput):
		return "invalid_input", true
	case errors.Is(err, controlplane.ErrForbidden):
		return "forbidden", true
	case errors.Is(err, controlplane.ErrNotFound):
		return "not_found", true
	case errors.Is(err, controlplane.ErrConflict), errors.Is(err, controlplane.ErrTransition):
		return "conflict", true
	}
	return "", false
}
