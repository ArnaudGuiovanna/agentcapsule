// Package oidclifecycle supplies the controller for the bundled identity
// service: container.py, which agentcapsule-oidc.service runs to prepare, stop
// and clean up its Podman container. internal/hostops embeds it in the
// installer; the server bundle ships it as oidc/container.py for manual
// systemd installations (deploy/oidc/README.md).
package oidclifecycle

import _ "embed"

// ContainerLifecycle is container.py.
//
//go:embed container.py
var ContainerLifecycle []byte
