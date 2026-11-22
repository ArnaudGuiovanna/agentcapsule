//go:build !linux

package sandbox

import "context"

// AsRoot: the sandbox exists on Linux only.
func AsRoot() bool { return false }

// Run: the sandbox needs Linux namespaces; elsewhere it is unavailable.
func (o Options) Run(ctx context.Context, image, program string, args ...string) ([]byte, error) {
	return nil, ErrUnavailable
}

// RunSelf: as Run.
func (o Options) RunSelf(ctx context.Context, image string, input []byte, name string, args ...string) ([]byte, error) {
	return nil, ErrUnavailable
}

// Self: no program of this executable runs confined here.
func Self(name string) bool { return false }
