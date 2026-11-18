//go:build linux

package main

import "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"

// definiteRefusal reports errors that are decided by the database state or the
// input. Repeating the same command cannot change them, unlike a failure whose
// commit result is unknown. Operators are told which case they are in.
func definiteRefusal(err error) (string, bool) {
	return controlplane.RefusalReason(err)
}
