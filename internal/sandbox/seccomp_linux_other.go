//go:build linux && !amd64

package sandbox

import (
	"errors"

	"golang.org/x/sys/unix"
)

// policy: the filter is written for x86_64, the platform's only
// architecture; elsewhere the sandbox is unavailable.
type policy struct{}

func strict() policy     { return policy{} }
func testTools() policy  { return policy{} }
func selfPolicy() policy { return policy{} }
func noExec() policy     { return policy{} }

func filterProgram(policy) ([]unix.SockFilter, error) {
	return nil, errors.New("no seccomp filter for this architecture")
}
