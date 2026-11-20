// Package oidc supplies the controller for the bundled identity service.
package oidc

import _ "embed"

// ContainerLifecycle also accompanies manual systemd installations.
//
//go:embed container.py
var ContainerLifecycle []byte
