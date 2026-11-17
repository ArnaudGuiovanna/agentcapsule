//go:build linux && !amd64

package sandbox

import "errors"

// policy: the filter is written for x86_64, the platform's only
// architecture; elsewhere the sandbox is unavailable.
type policy struct{}

func strict() policy    { return policy{} }
func testTools() policy { return policy{} }

func installFilter(policy) error {
	return errors.New("no seccomp filter for this architecture")
}
