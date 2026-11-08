package delegatedidentity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
)

var referenceTime = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T) (delegatedidentity.Config, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return delegatedidentity.Config{
		Clock: func() time.Time { return referenceTime },
		Trusts: []delegatedidentity.Trust{{
			Issuer: "https://client.example", Audience: "agentcapsule:tenant-a", TenantID: "tenant-a",
			Keys:          map[string]ed25519.PublicKey{"key-1": public},
			AllowedScopes: []string{"org:read", "agent:read", "agent:invoke"}, MaxTTL: 5 * time.Minute,
		}},
	}, private
}

func claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://client.example", "aud": "agentcapsule:tenant-a", "sub": "employee-123", "jti": "delegation-1",
		"iat": referenceTime.Add(-time.Minute).Unix(), "exp": referenceTime.Add(time.Minute).Unix(),
		"scope":            "org:read agent:invoke",
		"trust_generation": int64(1),
	}
}

func sign(t *testing.T, values jwt.MapClaims, method jwt.SigningMethod, key any, header func(map[string]any)) string {
	t.Helper()
	token := jwt.NewWithClaims(method, values)
	token.Header["kid"] = "key-1"
	if header != nil {
		header(token.Header)
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func verifier(t *testing.T, config delegatedidentity.Config) *delegatedidentity.Verifier {
	t.Helper()
	v, err := delegatedidentity.NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func rejected(t *testing.T, v *delegatedidentity.Verifier, raw string) {
	t.Helper()
	identity, err := v.Verify(raw)
	if !errors.Is(err, delegatedidentity.ErrInvalidToken) || !reflect.DeepEqual(identity, delegatedidentity.VerifiedIdentity{}) {
		t.Fatalf("invalid token returned identity %+v or unexpected error %v", identity, err)
	}
}

func TestVerifiedIdentityComesFromConfiguredTrust(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	values := claims()
	// Unknown role claims never become authorization. A matching optional tenant
	// claim is only a consistency check, not a source of tenant selection.
	values["role"], values["roles"] = "org_owner", []string{"platform:admin"}
	values["tenant_id"] = "tenant-a"
	identity, err := v.Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	fingerprint, found := v.TrustFingerprint("https://client.example", "agentcapsule:tenant-a")
	if !found || fingerprint == [32]byte{} {
		t.Fatal("configured trust reference missing")
	}
	want := delegatedidentity.VerifiedIdentity{
		TenantID: "tenant-a", Issuer: "https://client.example", Audience: "agentcapsule:tenant-a",
		Subject: "employee-123", TokenID: "delegation-1", KeyID: "key-1", TrustFingerprint: fingerprint, TrustGeneration: 1,
		IssuedAt: referenceTime.Add(-time.Minute), ExpiresAt: referenceTime.Add(time.Minute), Scopes: []string{"agent:invoke", "org:read"},
	}
	if err != nil || !reflect.DeepEqual(identity, want) {
		t.Fatal("verified identity", identity, err)
	}
	delete(values, "tenant_id")
	values["aud"] = []string{"agentcapsule:tenant-a"}
	identity, err = v.Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	if err != nil || identity.TenantID != "tenant-a" {
		t.Fatal("tenant must come from trust without a tenant claim", identity, err)
	}
	delete(values, "scope")
	identity, err = v.Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	if err != nil || len(identity.Scopes) != 0 {
		t.Fatal("trust maximum or token role implicitly granted scopes", identity, err)
	}
}

func TestSignaturesAndAlgorithmConfusionAreRejected(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	_, foreign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"foreign-signature": sign(t, claims(), jwt.SigningMethodEdDSA, foreign, nil),
		"unsigned":          sign(t, claims(), jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, nil),
		"hmac-public-key":   sign(t, claims(), jwt.SigningMethodHS256, []byte(config.Trusts[0].Keys["key-1"]), nil),
		"false-alg-header":  sign(t, claims(), jwt.SigningMethodEdDSA, private, func(h map[string]any) { h["alg"] = "HS256" }),
	}
	valid := sign(t, claims(), jwt.SigningMethodEdDSA, private, nil)
	parts := strings.Split(valid, ".")
	tests["missing-signature"] = parts[0] + "." + parts[1] + "."
	// Change signed claims while retaining the first token's signature.
	changed := claims()
	changed["sub"] = "another-employee"
	otherParts := strings.Split(sign(t, changed, jwt.SigningMethodEdDSA, private, nil), ".")
	tests["tampered-payload"] = parts[0] + "." + otherParts[1] + "." + parts[2]
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) { rejected(t, v, raw) })
	}
}

func TestHeaderCannotChooseKeysOrExtensions(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	tests := map[string]func(map[string]any){
		"missing-kid":    func(h map[string]any) { delete(h, "kid") },
		"unknown-kid":    func(h map[string]any) { h["kid"] = "other-key" },
		"wrong-type-kid": func(h map[string]any) { h["kid"] = 1 },
		"empty-kid":      func(h map[string]any) { h["kid"] = "" },
		"wrong-type":     func(h map[string]any) { h["typ"] = "something-else" },
		"unknown-crit":   func(h map[string]any) { h["crit"], h["future"] = []string{"future"}, true },
		"empty-crit":     func(h map[string]any) { h["crit"] = []string{} },
		"bad-crit-type":  func(h map[string]any) { h["crit"] = "future" },
		"unencoded":      func(h map[string]any) { h["b64"] = false },
		"key-url":        func(h map[string]any) { h["jku"] = "http://127.0.0.1/key" },
		"inline-key":     func(h map[string]any) { h["jwk"] = map[string]string{"kty": "OKP"} },
		"cert-url":       func(h map[string]any) { h["x5u"] = "http://127.0.0.1/cert" },
		"inline-cert":    func(h map[string]any) { h["x5c"] = []string{"certificate"} },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) { rejected(t, v, sign(t, claims(), jwt.SigningMethodEdDSA, private, change)) })
	}
	if _, err := v.Verify(sign(t, claims(), jwt.SigningMethodEdDSA, private, func(h map[string]any) { delete(h, "typ") })); err != nil {
		t.Fatal("optional typ absent", err)
	}
}

func TestRequiredClaimsAndTrustBoundaries(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	for _, field := range []string{"iss", "aud", "sub", "jti", "iat", "exp", "trust_generation"} {
		t.Run("missing-"+field, func(t *testing.T) {
			values := claims()
			delete(values, field)
			rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, private, nil))
		})
	}
	tests := map[string]struct {
		field string
		value any
	}{
		"unknown-issuer":       {"iss", "https://foreign.example"},
		"numeric-issuer":       {"iss", 10},
		"wrong-audience":       {"aud", "agentcapsule:tenant-b"},
		"multiple-audiences":   {"aud", []string{"agentcapsule:tenant-a", "another-service"}},
		"numeric-audience":     {"aud", 10},
		"empty-audience-array": {"aud", []string{}},
		"foreign-tenant":       {"tenant_id", "tenant-b"},
		"numeric-tenant":       {"tenant_id", 10},
		"null-tenant":          {"tenant_id", nil},
		"empty-subject":        {"sub", ""},
		"trimmed-subject":      {"sub", " employee-123"},
		"subject-control":      {"sub", "employee\n123"},
		"numeric-subject":      {"sub", 10},
		"oversized-subject":    {"sub", strings.Repeat("a", 1025)},
		"empty-token-id":       {"jti", ""},
		"numeric-token-id":     {"jti", 10},
		"string-date":          {"exp", "1794052860"},
		"null-date":            {"iat", nil},
		"fractional-date":      {"exp", float64(referenceTime.Unix()) + 60.5},
		"huge-date":            {"exp", json.Number("9999999999999999999999999")},
		"range-date":           {"exp", int64(253402300800)},
		"negative-date":        {"iat", -10},
		"string-generation":    {"trust_generation", "1"},
		"zero-generation":      {"trust_generation", 0},
		"negative-generation":  {"trust_generation", -1},
		"null-generation":      {"trust_generation", nil},
		"fraction-generation":  {"trust_generation", json.Number("1.5")},
		"decimal-generation":   {"trust_generation", json.Number("1.0")},
		"exponent-generation":  {"trust_generation", json.Number("1e0")},
		"overflow-generation":  {"trust_generation", json.Number("9223372036854775808")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			values := claims()
			values[test.field] = test.value
			rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, private, nil))
		})
	}
}

func TestGenerationIsExactThroughMaximumSignedInteger(t *testing.T) {
	config, key := fixture(t)
	v := verifier(t, config)
	values := claims()
	values["trust_generation"] = json.Number("9223372036854775807")
	identity, err := v.Verify(sign(t, values, jwt.SigningMethodEdDSA, key, nil))
	if err != nil || identity.TrustGeneration != int64(9223372036854775807) {
		t.Fatal("generation lost integer precision", err)
	}
}

func TestTimeValidationAndMaximumLifetime(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	tests := map[string]func(jwt.MapClaims){
		"expired":           func(c jwt.MapClaims) { c["exp"] = referenceTime.Add(-time.Second).Unix() },
		"expires-now":       func(c jwt.MapClaims) { c["exp"] = referenceTime.Unix() },
		"future-issued":     func(c jwt.MapClaims) { c["iat"] = referenceTime.Add(time.Second).Unix() },
		"future-not-before": func(c jwt.MapClaims) { c["nbf"] = referenceTime.Add(time.Second).Unix() },
		"invalid-not-before": func(c jwt.MapClaims) {
			c["nbf"] = "not-a-date"
		},
		"nbf-after-exp": func(c jwt.MapClaims) { c["nbf"] = referenceTime.Add(2 * time.Minute).Unix() },
		"too-long":      func(c jwt.MapClaims) { c["exp"] = referenceTime.Add(5 * time.Minute).Unix() },
		"inverted":      func(c jwt.MapClaims) { c["exp"] = referenceTime.Add(-2 * time.Minute).Unix() },
		"empty-life":    func(c jwt.MapClaims) { c["exp"] = c["iat"] },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			values := claims()
			change(values)
			rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, private, nil))
		})
	}
	values := claims()
	values["iat"], values["nbf"], values["exp"] = referenceTime.Unix(), referenceTime.Unix(), referenceTime.Add(5*time.Minute).Unix()
	if _, err := v.Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil)); err != nil {
		t.Fatal("exactly maximum TTL and nbf boundary must be valid", err)
	}
	config.Clock = func() time.Time { return referenceTime.Add(time.Minute) }
	rejected(t, verifier(t, config), sign(t, claims(), jwt.SigningMethodEdDSA, private, nil))
}

func TestMaximumLifetimeDoesNotSaturate(t *testing.T) {
	config, private := fixture(t)
	config.Trusts[0].MaxTTL = time.Duration(1<<63 - 1)
	values := claims()
	values["iat"], values["exp"] = int64(0), int64(253402300799)
	// time.Sub saturates at MaxInt64 for this interval. Comparing that duration
	// to the configured maximum would mistakenly admit an almost 8,000-year JWT.
	rejected(t, verifier(t, config), sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	values["exp"] = time.Unix(0, 0).Add(config.Trusts[0].MaxTTL).Unix()
	if _, err := verifier(t, config).Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil)); err != nil {
		t.Fatal("representable lifetime inside the configured maximum rejected", err)
	}
}

func TestScopesCannotExceedConfiguredMaximum(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	for _, scope := range []any{"agent:delete", "agent:invoke platform:admin", "*", "agent:*", "agent:invoke agent:invoke", " agent:invoke", "agent:invoke ", "agent:invoke  org:read", "agent:invoke\torg:read", "agent:invoke\norg:read", []string{"agent:invoke"}, nil} {
		values := claims()
		values["scope"] = scope
		rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	}
	values := claims()
	values["scopes"] = []string{"platform:admin"}
	rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	values = claims()
	values["scope"] = ""
	identity, err := v.Verify(sign(t, values, jwt.SigningMethodEdDSA, private, nil))
	if err != nil || len(identity.Scopes) != 0 {
		t.Fatal("empty scopes must not inherit trust maximum", identity, err)
	}
}

func TestRotatingKeysAndDistinctTrusts(t *testing.T) {
	config, first := fixture(t)
	public, second, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config.Trusts[0].Keys["key-2"] = public
	config.Trusts = append(config.Trusts, delegatedidentity.Trust{
		Issuer: "https://client.example", Audience: "agentcapsule:tenant-b", TenantID: "tenant-b",
		Keys: map[string]ed25519.PublicKey{"key-1": public}, AllowedScopes: []string{"org:read"}, MaxTTL: time.Minute,
	})
	v := verifier(t, config)
	if _, err := v.Verify(sign(t, claims(), jwt.SigningMethodEdDSA, first, nil)); err != nil {
		t.Fatal("first rotation key denied", err)
	}
	rotated, err := v.Verify(sign(t, claims(), jwt.SigningMethodEdDSA, second, func(h map[string]any) { h["kid"] = "key-2" }))
	expectedFingerprint, _ := v.TrustFingerprint("https://client.example", "agentcapsule:tenant-a")
	if err != nil || rotated.KeyID != "key-2" || rotated.TrustFingerprint != expectedFingerprint {
		t.Fatal("second rotation key or trust reference incorrect", rotated, err)
	}
	values := claims()
	values["aud"], values["iat"], values["scope"] = "agentcapsule:tenant-b", referenceTime.Unix(), "org:read"
	identity, err := v.Verify(sign(t, values, jwt.SigningMethodEdDSA, second, nil))
	if err != nil || identity.TenantID != "tenant-b" {
		t.Fatal("distinct configured trust", identity, err)
	}
	rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, first, nil))
	values["scope"] = "agent:invoke"
	rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, second, nil))
	values["scope"], values["iat"] = "org:read", referenceTime.Add(-time.Minute).Unix()
	rejected(t, v, sign(t, values, jwt.SigningMethodEdDSA, second, nil))
}

func TestConfigurationIsCopiedAndVerificationIsConcurrent(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	raw := sign(t, claims(), jwt.SigningMethodEdDSA, private, nil)
	config.Trusts[0].Keys["key-1"][0] ^= 1
	delete(config.Trusts[0].Keys, "key-1")
	config.Trusts[0].AllowedScopes[0] = "platform:admin"
	config.Trusts[0].TenantID = "tenant-changed"
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				identity, err := v.Verify(raw)
				if err != nil || identity.TenantID != "tenant-a" || !reflect.DeepEqual(identity.Scopes, []string{"agent:invoke", "org:read"}) {
					t.Error("configuration or result aliases mutable caller state", identity, err)
					return
				}
				identity.Scopes[0] = "platform:admin"
			}
		}()
	}
	wg.Wait()
}

func configuredFingerprint(t *testing.T, config delegatedidentity.Config) [32]byte {
	t.Helper()
	trust := config.Trusts[0]
	fingerprint, found := verifier(t, config).TrustFingerprint(trust.Issuer, trust.Audience)
	if !found || fingerprint == [32]byte{} {
		t.Fatal("configured trust fingerprint missing")
	}
	return fingerprint
}

func TestTrustFingerprintIsIndependentOfMapAndScopeOrder(t *testing.T) {
	config, _ := fixture(t)
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config.Trusts[0].Keys["key-2"] = otherPublic
	before := configuredFingerprint(t, config)
	keys := config.Trusts[0].Keys
	config.Trusts[0].Keys = map[string]ed25519.PublicKey{"key-2": keys["key-2"], "key-1": keys["key-1"]}
	slices.Reverse(config.Trusts[0].AllowedScopes)
	for range 20 {
		if after := configuredFingerprint(t, config); after != before {
			t.Fatal("map/scope iteration order changed trust fingerprint")
		}
	}
	config.Trusts[0].AllowedScopes = nil
	empty := configuredFingerprint(t, config)
	config.Trusts[0].AllowedScopes = []string{}
	if configuredFingerprint(t, config) != empty {
		t.Fatal("nil and empty scope sets have different fingerprints")
	}
}

func TestTrustFingerprintChangesWithAuthority(t *testing.T) {
	tests := map[string]func(*delegatedidentity.Trust){
		"issuer":    func(t *delegatedidentity.Trust) { t.Issuer = "https://other-client.example" },
		"audience":  func(t *delegatedidentity.Trust) { t.Audience = "agentcapsule:other-audience" },
		"tenant":    func(t *delegatedidentity.Trust) { t.TenantID = "tenant-b" },
		"ttl":       func(t *delegatedidentity.Trust) { t.MaxTTL += time.Nanosecond },
		"scope-add": func(t *delegatedidentity.Trust) { t.AllowedScopes = append(t.AllowedScopes, "agent:delete") },
		"scope-remove": func(t *delegatedidentity.Trust) {
			t.AllowedScopes = t.AllowedScopes[:len(t.AllowedScopes)-1]
		},
		"key-remove": func(t *delegatedidentity.Trust) { delete(t.Keys, "key-2") },
		"key-add":    func(t *delegatedidentity.Trust) { t.Keys["key-3"] = slices.Clone(t.Keys["key-1"]) },
		"key-change": func(t *delegatedidentity.Trust) { t.Keys["key-1"] = slices.Clone(t.Keys["key-2"]) },
		"kid-change": func(t *delegatedidentity.Trust) {
			t.Keys["renamed"] = t.Keys["key-1"]
			delete(t.Keys, "key-1")
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config, _ := fixture(t)
			otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			config.Trusts[0].Keys["key-2"] = otherPublic
			before := configuredFingerprint(t, config)
			change(&config.Trusts[0])
			if configuredFingerprint(t, config) == before {
				t.Fatal("authority changed without changing trust fingerprint")
			}
		})
	}
}

func TestTrustFingerprintEncodingIsVersionedAndCanonical(t *testing.T) {
	config := delegatedidentity.Config{Trusts: []delegatedidentity.Trust{{
		Issuer: "issuer", Audience: "audience", TenantID: "tenant", MaxTTL: time.Minute,
		Keys:          map[string]ed25519.PublicKey{"first": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		AllowedScopes: []string{"org:read", "agent:invoke"},
	}}}
	// A fixed vector makes any encoding/version change explicit during review.
	canonical := `{"domain":"agentcapsule.delegatedidentity.trust.v1","issuer":"issuer","audience":"audience","tenant":"tenant","keys":[{"kid":"first","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}],"scopes":["agent:invoke","org:read"],"max_ttl_nanoseconds":60000000000}`
	if configuredFingerprint(t, config) != sha256.Sum256([]byte(canonical)) {
		t.Fatal("trust fingerprint no longer matches the documented encoding")
	}
	v := verifier(t, config)
	if got, found := v.TrustFingerprint("issuer", "foreign-audience"); found || got != [32]byte{} {
		t.Fatal("unknown trust obtained a configured reference")
	}
	var absent *delegatedidentity.Verifier
	if got, found := absent.TrustFingerprint("issuer", "audience"); found || got != [32]byte{} {
		t.Fatal("nil verifier returned a trust reference")
	}
}

func TestConfigurationRejectsAmbiguousOrIncompleteTrust(t *testing.T) {
	tests := map[string]func(*delegatedidentity.Config){
		"no-trusts":       func(c *delegatedidentity.Config) { c.Trusts = nil },
		"negative-size":   func(c *delegatedidentity.Config) { c.MaxTokenBytes = -1 },
		"unbounded-size":  func(c *delegatedidentity.Config) { c.MaxTokenBytes = delegatedidentity.MaximumTokenBytes + 1 },
		"empty-issuer":    func(c *delegatedidentity.Config) { c.Trusts[0].Issuer = "" },
		"empty-audience":  func(c *delegatedidentity.Config) { c.Trusts[0].Audience = "" },
		"empty-tenant":    func(c *delegatedidentity.Config) { c.Trusts[0].TenantID = "" },
		"no-ttl":          func(c *delegatedidentity.Config) { c.Trusts[0].MaxTTL = 0 },
		"negative-ttl":    func(c *delegatedidentity.Config) { c.Trusts[0].MaxTTL = -time.Minute },
		"no-keys":         func(c *delegatedidentity.Config) { c.Trusts[0].Keys = nil },
		"bad-key":         func(c *delegatedidentity.Config) { c.Trusts[0].Keys["key-1"] = []byte{1} },
		"empty-kid":       func(c *delegatedidentity.Config) { c.Trusts[0].Keys[""] = c.Trusts[0].Keys["key-1"] },
		"malformed-scope": func(c *delegatedidentity.Config) { c.Trusts[0].AllowedScopes = []string{"agent:invoke org:read"} },
		"duplicate-scope": func(c *delegatedidentity.Config) {
			c.Trusts[0].AllowedScopes = []string{"agent:invoke", "agent:invoke"}
		},
		"ambiguous-tenant": func(c *delegatedidentity.Config) {
			other := c.Trusts[0]
			other.TenantID = "tenant-b"
			c.Trusts = append(c.Trusts, other)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config, _ := fixture(t)
			change(&config)
			if v, err := delegatedidentity.NewVerifier(config); v != nil || !errors.Is(err, delegatedidentity.ErrConfiguration) {
				t.Fatal("invalid trust accepted", err)
			}
		})
	}
}

func TestMalformedAndOversizedTokensFailWithoutIdentity(t *testing.T) {
	config, private := fixture(t)
	v := verifier(t, config)
	for _, raw := range []string{"", "not-a-token", "a.b.c", "e30.e30.", "a.b.c.d", strings.Repeat("a", delegatedidentity.DefaultMaxTokenBytes+1)} {
		rejected(t, v, raw)
	}
	raw := sign(t, claims(), jwt.SigningMethodEdDSA, private, nil)
	rejected(t, v, "Bearer "+raw)
	rejected(t, v, " "+raw)
	rejected(t, v, raw+" ")
	config.MaxTokenBytes = len(raw) - 1
	rejected(t, verifier(t, config), raw)
	config.MaxTokenBytes = len(raw)
	if _, err := verifier(t, config).Verify(raw); err != nil {
		t.Fatal("exact size limit rejected", err)
	}
	var absent *delegatedidentity.Verifier
	rejected(t, absent, raw)
	rejected(t, &delegatedidentity.Verifier{}, raw)
}
