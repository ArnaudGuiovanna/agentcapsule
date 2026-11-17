//go:build linux && !amd64

package sandbox

import "errors"

// installFilter: the filter is written for x86_64, the platform's only
// architecture; elsewhere the sandbox is unavailable.
func installFilter() error {
	return errors.New("no seccomp filter for this architecture")
}
