// Package delegatedidentity authenticates short-lived delegations issued by
// explicitly configured clients. Signature and JWT validation use golang-jwt;
// tenant selection and scope limits come exclusively from server configuration.
//
// Authentication does not authorize a request. The caller must resolve the
// (tenant, issuer, subject) to a current database principal, check organization,
// membership, credential revocation and permissions, and keep those checks
// authoritative through the consuming transaction, including receipt replay.
// This package neither provisions principals nor reads roles from a token.
package delegatedidentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrConfiguration = errors.New("invalid delegated identity configuration")
	ErrInvalidToken  = errors.New("invalid delegated identity token")
)

const (
	DefaultMaxTokenBytes = 8192
	MaximumTokenBytes    = 65536
	maxIdentifierBytes   = 1024
	maxScopeCount        = 64
)

// Trust binds one issuer/audience pair to exactly one tenant. Multiple key IDs
// support a controlled rotation; a token cannot supply a key or a key URL.
// AllowedScopes are an upper bound, never scopes automatically granted to a
// token. MaxTTL is the maximum exp-iat duration and must be explicitly positive.
type Trust struct {
	Issuer        string
	Audience      string
	TenantID      string
	Keys          map[string]ed25519.PublicKey
	AllowedScopes []string
	MaxTTL        time.Duration
}

type Config struct {
	Trusts        []Trust
	MaxTokenBytes int
	// Clock defaults to time.Now. An injected clock must be safe for concurrent
	// calls. Each verification takes a single time snapshot; no leeway is used.
	Clock func() time.Time
}

// VerifiedIdentity contains authenticated claims, not authorization decisions.
// TokenID is the issuer's jti. Revocation keys must include TenantID and Issuer;
// jti alone is not globally unique, and this verifier does not prevent replay.
// TrustFingerprint identifies the complete configured trust used to verify the
// token. The caller must compare it with the current trusted reference while
// authorizing its transaction. A fingerprint alone is not proof of authority.
type VerifiedIdentity struct {
	TenantID         string
	Issuer           string
	Audience         string
	Subject          string
	TokenID          string
	KeyID            string
	TrustFingerprint [32]byte
	TrustGeneration  int64
	IssuedAt         time.Time
	NotBefore        time.Time
	ExpiresAt        time.Time
	Scopes           []string
}

type trustID struct{ issuer, audience string }

type configuredTrust struct {
	tenantID    string
	keys        map[string]ed25519.PublicKey
	scopes      map[string]struct{}
	maxTTL      time.Duration
	fingerprint [32]byte
}

// Verifier owns immutable copies of its trust configuration and supports
// concurrent Verify calls. Replace the verifier to rotate or remove trust;
// callers must serialize current trust/revocation with their authorization path.
type Verifier struct {
	trusts        map[trustID]configuredTrust
	maxTokenBytes int
	clock         func() time.Time
}

func NewVerifier(config Config) (*Verifier, error) {
	if len(config.Trusts) == 0 {
		return nil, fmt.Errorf("%w: at least one trust is required", ErrConfiguration)
	}
	if config.MaxTokenBytes == 0 {
		config.MaxTokenBytes = DefaultMaxTokenBytes
	}
	if config.MaxTokenBytes < 1 || config.MaxTokenBytes > MaximumTokenBytes {
		return nil, fmt.Errorf("%w: token size limit", ErrConfiguration)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	v := &Verifier{trusts: make(map[trustID]configuredTrust), maxTokenBytes: config.MaxTokenBytes, clock: config.Clock}
	for _, trust := range config.Trusts {
		if !validIdentifier(trust.Issuer) || !validIdentifier(trust.Audience) || !validIdentifier(trust.TenantID) || trust.MaxTTL <= 0 || len(trust.Keys) == 0 || len(trust.AllowedScopes) > maxScopeCount {
			return nil, fmt.Errorf("%w: incomplete trust", ErrConfiguration)
		}
		id := trustID{trust.Issuer, trust.Audience}
		if _, duplicate := v.trusts[id]; duplicate {
			return nil, fmt.Errorf("%w: ambiguous issuer and audience", ErrConfiguration)
		}
		copy := configuredTrust{tenantID: trust.TenantID, keys: make(map[string]ed25519.PublicKey), scopes: make(map[string]struct{}), maxTTL: trust.MaxTTL}
		for kid, key := range trust.Keys {
			if !validIdentifier(kid) || len(key) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: invalid key ID or Ed25519 public key", ErrConfiguration)
			}
			copy.keys[kid] = slices.Clone(key)
		}
		for _, scope := range trust.AllowedScopes {
			if !validScope(scope) {
				return nil, fmt.Errorf("%w: invalid allowed scope", ErrConfiguration)
			}
			if _, duplicate := copy.scopes[scope]; duplicate {
				return nil, fmt.Errorf("%w: duplicate allowed scope", ErrConfiguration)
			}
			copy.scopes[scope] = struct{}{}
		}
		var err error
		copy.fingerprint, err = fingerprint(id, copy)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot encode trust", ErrConfiguration)
		}
		v.trusts[id] = copy
	}
	return v, nil
}

// TrustFingerprint returns the immutable reference for a configured trust. It
// is configuration metadata, not authentication. The current trusted reference
// must be stored/loaded by the caller independently of an incoming identity and
// checked in the transaction that consumes that identity. An old verifier will
// intentionally retain its old reference until the caller replaces it.
func (v *Verifier) TrustFingerprint(issuer, audience string) ([32]byte, bool) {
	if v == nil {
		return [32]byte{}, false
	}
	trust, found := v.trusts[trustID{issuer, audience}]
	return trust.fingerprint, found
}

func fingerprint(id trustID, trust configuredTrust) ([32]byte, error) {
	type publicKey struct {
		ID    string `json:"kid"`
		Bytes []byte `json:"public_key"`
	}
	// This versioned struct fixes JSON field order; no maps enter the encoding.
	// Public keys use encoding/json's standard padded base64 representation,
	// strings its normal escaping, and TTL an exact integer nanosecond count.
	canonical := struct {
		Domain            string      `json:"domain"`
		Issuer            string      `json:"issuer"`
		Audience          string      `json:"audience"`
		Tenant            string      `json:"tenant"`
		Keys              []publicKey `json:"keys"`
		Scopes            []string    `json:"scopes"`
		MaxTTLNanoseconds int64       `json:"max_ttl_nanoseconds"`
	}{
		Domain: "agentcapsule.delegatedidentity.trust.v1", Issuer: id.issuer, Audience: id.audience,
		Tenant: trust.tenantID, Keys: make([]publicKey, 0, len(trust.keys)),
		Scopes: make([]string, 0, len(trust.scopes)), MaxTTLNanoseconds: int64(trust.maxTTL),
	}
	kids := make([]string, 0, len(trust.keys))
	for kid := range trust.keys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	for _, kid := range kids {
		canonical.Keys = append(canonical.Keys, publicKey{ID: kid, Bytes: trust.keys[kid]})
	}
	for scope := range trust.scopes {
		canonical.Scopes = append(canonical.Scopes, scope)
	}
	slices.Sort(canonical.Scopes)
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// Verify accepts the compact JWT itself, without a Bearer prefix. The delegation
// profile requires EdDSA, kid, iss, a single aud, sub, jti, trust_generation,
// exp and iat. trust_generation is an exact positive signed 64-bit integer.
// Its CURRENT value is authorized by the caller's database, not this verifier. Numeric
// dates are integer Unix seconds; nbf is optional and validated when present.
// scope is an optional space-separated string; omitted/empty grants no scopes.
// An optional tenant_id must match server trust, but can never select a tenant.
// role/roles and other non-authoritative claims are ignored.
//
// All token failures return the same error and no partial identity. Unverified
// claims are used only to select configured verification parameters, never to
// return an identity, fetch keys or authorize a request.
func (v *Verifier) Verify(raw string) (VerifiedIdentity, error) {
	if v == nil || v.clock == nil || len(raw) == 0 || len(raw) > v.maxTokenBytes {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	claims := jwt.MapClaims{}
	preparser := jwt.NewParser(jwt.WithJSONNumber(), jwt.WithStrictDecoding())
	unverified, _, err := preparser.ParseUnverified(raw, claims)
	if err != nil || !validHeader(unverified) {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	issuer, ok := claims["iss"].(string)
	audiences, audienceErr := claims.GetAudience()
	if !ok || !validIdentifier(issuer) || audienceErr != nil || len(audiences) != 1 || !validIdentifier(audiences[0]) {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	id := trustID{issuer, audiences[0]}
	trust, found := v.trusts[id]
	kid, _ := unverified.Header["kid"].(string)
	key, foundKey := trust.keys[kid]
	if !found || !foundKey {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	// Validate the stricter delegation claim profile before the library converts
	// dates to floating point. This also rejects malformed/overflowing dates.
	issuedAt, issuedOK := numericDate(claims, "iat")
	expiresAt, expiresOK := numericDate(claims, "exp")
	subject, subjectOK := claims["sub"].(string)
	jti, jtiOK := claims["jti"].(string)
	generationNumber, generationOK := claims["trust_generation"].(json.Number)
	generation, generationErr := generationNumber.Int64()
	if !generationOK || generationErr != nil || generation <= 0 || !issuedOK || !expiresOK || !expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(trust.maxTTL)) || !subjectOK || !validIdentifier(subject) || !jtiOK || !validIdentifier(jti) {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	var notBefore time.Time
	if _, present := claims["nbf"]; present {
		var valid bool
		notBefore, valid = numericDate(claims, "nbf")
		if !valid || !notBefore.Before(expiresAt) {
			return VerifiedIdentity{}, ErrInvalidToken
		}
	}
	if value, present := claims["tenant_id"]; present {
		if tenant, valid := value.(string); !valid || tenant != trust.tenantID {
			return VerifiedIdentity{}, ErrInvalidToken
		}
	}
	scopes, valid := tokenScopes(claims, trust.scopes)
	if !valid {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	now := v.clock()
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithJSONNumber(), jwt.WithStrictDecoding(),
		jwt.WithIssuer(id.issuer), jwt.WithAudience(id.audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	verified, err := parser.ParseWithClaims(raw, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		if !validHeader(token) || token.Header["kid"] != kid {
			return nil, ErrInvalidToken
		}
		return key, nil
	})
	if err != nil || !verified.Valid {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	return VerifiedIdentity{
		TenantID: trust.tenantID, Issuer: issuer, Audience: id.audience, Subject: subject,
		TokenID: jti, KeyID: kid, TrustFingerprint: trust.fingerprint, TrustGeneration: generation, IssuedAt: issuedAt, NotBefore: notBefore, ExpiresAt: expiresAt, Scopes: scopes,
	}, nil
}

func validHeader(token *jwt.Token) bool {
	if token == nil || token.Method != jwt.SigningMethodEdDSA || token.Header["alg"] != "EdDSA" {
		return false
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || !validIdentifier(kid) {
		return false
	}
	if typ, present := token.Header["typ"]; present && typ != "JWT" {
		return false
	}
	// No critical extensions or token-provided key material are supported. In
	// particular, no jku/x5u lookup can turn verification into a network request.
	for _, name := range []string{"crit", "b64", "jku", "jwk", "x5u", "x5c"} {
		if _, present := token.Header[name]; present {
			return false
		}
	}
	return true
}

func numericDate(claims jwt.MapClaims, name string) (time.Time, bool) {
	value, ok := claims[name].(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, err := value.Int64()
	// Integer dates through year 9999 are exactly representable by the library's
	// float conversion and remain within the supported profile's time range.
	if err != nil || seconds < 0 || seconds > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

func tokenScopes(claims jwt.MapClaims, allowed map[string]struct{}) ([]string, bool) {
	if _, ambiguous := claims["scopes"]; ambiguous {
		return nil, false
	}
	value, present := claims["scope"]
	if !present {
		return nil, true
	}
	scope, ok := value.(string)
	if !ok {
		return nil, false
	}
	if scope == "" {
		return nil, true
	}
	scopes := strings.Split(scope, " ")
	if len(scopes) > maxScopeCount {
		return nil, false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !validScope(scope) {
			return nil, false
		}
		if _, exists := allowed[scope]; !exists {
			return nil, false
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, false
		}
		seen[scope] = struct{}{}
	}
	slices.Sort(scopes)
	return scopes, true
}

func validScope(scope string) bool {
	if len(scope) == 0 || len(scope) > 128 {
		return false
	}
	for _, char := range scope {
		if char < 0x21 || char > 0x7e || char == '"' || char == '\\' {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= maxIdentifierBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
