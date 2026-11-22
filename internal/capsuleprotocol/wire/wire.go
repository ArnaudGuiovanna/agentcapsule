// Package wire defines the stored payloads shared by the control plane and the guest protocol.
package wire

import (
	"errors"
)

const MaxContentBytes = 512 << 10

var ErrProtocol = errors.New("invalid capsule control message")
