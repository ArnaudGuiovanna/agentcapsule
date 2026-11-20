// Package individualidentity describes a single signer's delegated identity.
// The issuer encodes the holder's public key. Its sole subject is the key's
// fingerprint. The API still requires an explicitly registered organization,
// trust, principal and active membership for every signed request.
package individualidentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

const Prefix = "urn:agentcapsule:individual:"
const KeyID = "individual"
const Lifetime = 5 * time.Minute

func Issuer(pub ed25519.PublicKey) string { return Prefix + base64.RawURLEncoding.EncodeToString(pub) }
func Key(issuer string) (ed25519.PublicKey, bool) {
	raw, ok := strings.CutPrefix(issuer, Prefix)
	if !ok {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return ed25519.PublicKey(b), err == nil && len(b) == ed25519.PublicKeySize && base64.RawURLEncoding.EncodeToString(b) == raw
}
func Subject(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}
func Scopes() []string {
	return append(slices.Clone(authorization.DelegableScopes), authorization.ScopeIdentityManage)
}
