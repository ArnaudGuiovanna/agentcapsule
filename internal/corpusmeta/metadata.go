// Package corpusmeta defines the published corpus layout and validates its JSON metadata.
// Readers can use it without linking the source decoders or image tooling.
package corpusmeta

import (
	"errors"
	"fmt"
)

// Schema names the published layout and the host package's manifest.
const Schema = "agentcapsule.corpus/v1"

// ErrInvalid: an image, a package or a document of the layout is malformed
// or tampered with. The message names the failed check, never a file's
// contents or a path the image chose.
var ErrInvalid = errors.New("invalid corpus")

// Invalid reports a failed corpus validation check.
func Invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
