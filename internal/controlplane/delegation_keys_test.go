package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signWith signs the lab owner's token with any key, under any key ID.
func (l *tenantLab) signWith(t *testing.T, kid string, key ed25519.PrivateKey, id string, at time.Time, edit func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": organizationInput().InitialOwner.Subject, "jti": id,
		"iat": at.Unix(), "exp": at.Add(5 * time.Minute).Unix(), "scope": "org:read", "trust_generation": int64(1)}
	if edit != nil {
		edit(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (l *tenantLab) keyChange(t *testing.T, action, op, kid string, key ed25519.PublicKey, overlap time.Duration) (DelegationChangeResult, error) {
	t.Helper()
	return l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: op, Actor: "test-operator", Action: action,
		TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, KeyID: kid, PublicKey: key, Overlap: overlap})
}

// The API verifies with the keys registered in PostgreSQL (nil verifier).
func (l *tenantLab) accepted(t *testing.T, raw string) bool {
	t.Helper()
	_, err := l.s.AuthenticateDelegation(t.Context(), nil, raw)
	if err != nil && !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	return err == nil
}

// A routine key rotation: the new key is added, both sign valid tokens during
// the overlap, then the old one is refused. Neither the generation nor the
// issuance threshold moves, so no token signed with the new key is refused.
func TestDelegationKeysRotateWithOverlap(t *testing.T) {
	l := newTenantLab(t, true)
	pub2, key2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !l.accepted(t, l.sign(t, "before", l.cutoff, nil)) {
		t.Fatal("registered key refused")
	}
	if l.accepted(t, l.signWith(t, "key-2", key2, "early", l.cutoff, nil)) {
		t.Fatal("a key not yet added was accepted")
	}
	added, err := l.keyChange(t, "add-key", "add-key-2", "key-2", pub2, 0)
	if err != nil || added.Generation != 1 || !added.MinimumIAT.Equal(l.cutoff) || added.KeyID != "key-2" {
		t.Fatal("add-key moved the trust's epoch", added, err)
	}
	if replay, err := l.keyChange(t, "add-key", "add-key-2", "key-2", pub2, 0); err != nil || !replay.Replayed || replay.Fingerprint != added.Fingerprint {
		t.Fatal("add-key replay", err)
	}
	if again, err := l.keyChange(t, "add-key", "add-key-2-again", "key-2", pub2, 0); err != nil || again.Fingerprint != added.Fingerprint {
		t.Fatal("adding the same key again changed the trust", err)
	}
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := l.keyChange(t, "add-key", "rebind-key-2", "key-2", pub3, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("a key ID was rebound to another key", err)
	}
	if !l.accepted(t, l.sign(t, "old-key", l.cutoff, nil)) || !l.accepted(t, l.signWith(t, "key-2", key2, "new-key", l.cutoff, nil)) {
		t.Fatal("both keys must sign during the overlap")
	}
	// A principal authenticated before the retirement is consumed after it.
	inFlight, err := l.s.AuthenticateDelegation(t.Context(), nil, l.sign(t, "in-flight", l.cutoff, nil))
	if err != nil {
		t.Fatal(err)
	}
	retired, err := l.keyChange(t, "retire-key", "retire-key-1", "key-1", nil, 2*time.Second)
	if err != nil || retired.KeyExpiresAt == nil || retired.Generation != 1 || !retired.MinimumIAT.Equal(l.cutoff) {
		t.Fatal("retire-key", retired, err)
	}
	if !l.accepted(t, l.sign(t, "overlap", l.cutoff, nil)) {
		t.Fatal("the old key was refused during its overlap")
	}
	if _, err := l.a.CurrentOrganization(t.Context(), inFlight); err != nil {
		t.Fatal("a scheduled retirement refused a valid principal", err)
	}
	// Retiring later than already scheduled never extends the overlap.
	if later, err := l.keyChange(t, "retire-key", "retire-key-1-later", "key-1", nil, time.Hour); err != nil || !later.KeyExpiresAt.Equal(*retired.KeyExpiresAt) {
		t.Fatal("a retirement was pushed back", err)
	}
	waitTenantClock(t, l.s, retired.KeyExpiresAt.Add(time.Millisecond))
	if l.accepted(t, l.sign(t, "after-overlap", l.cutoff, nil)) {
		t.Fatal("the old key signed after its overlap")
	}
	if _, err := l.a.CurrentOrganization(t.Context(), inFlight); !errors.Is(err, ErrAuthentication) {
		t.Fatal("a principal of a retired key survived its overlap", err)
	}
	if !l.accepted(t, l.signWith(t, "key-2", key2, "after", l.cutoff, nil)) {
		t.Fatal("the new key was refused after the overlap")
	}
	// The trust always keeps a key without an end: revoke-trust stops all.
	if _, err := l.keyChange(t, "retire-key", "retire-key-2", "key-2", nil, 0); !errors.Is(err, ErrTransition) {
		t.Fatal("the last key was retired", err)
	}
	// A retired key never returns, by add-key or by rotate.
	if _, err := l.keyChange(t, "add-key", "readd-key-1", "key-1", l.trust.Keys["key-1"], 0); !errors.Is(err, ErrConflict) {
		t.Fatal("a retired key returned", err)
	}
	if _, err := l.keyChange(t, "retire-key", "retire-unknown", "key-9", nil, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown key", err)
	}
	if _, err := l.keyChange(t, "retire-key", "retire-too-late", "key-2", nil, MaxKeyOverlap+time.Second); !errors.Is(err, ErrInput) {
		t.Fatal("an overlap beyond the maximum was accepted", err)
	}
	var actions []string
	rows, err := l.s.pool.Query(t.Context(), "SELECT action||':'||key_id||':'||changed FROM delegation_audit WHERE action IN ('add-key','retire-key') ORDER BY created_at,id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		if err = rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	rows.Close()
	if strings.Join(actions, " ") != "add-key:key-2:true add-key:key-2:false retire-key:key-1:true retire-key:key-1:false" {
		t.Fatal("key changes are not audited as made", actions)
	}
}

// Rotate replaces the key set: a key absent from the new trust is refused at
// once, together with every token of the previous generation.
func TestDelegationRotateRetiresKeysAbsentFromItsTrust(t *testing.T) {
	l := newTenantLab(t, true)
	pub2, key2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next := l.trust
	next.Keys = map[string]ed25519.PublicKey{"key-2": pub2}
	r := l.change(t, "rotate", "rotate-to-key-2", "", &next)
	waitTenantClock(t, l.s, r.MinimumIAT)
	generation := func(c jwt.MapClaims) { c["trust_generation"] = r.Generation }
	if l.accepted(t, l.sign(t, "key-1", r.MinimumIAT, generation)) {
		t.Fatal("a key absent from the rotated trust was accepted")
	}
	if !l.accepted(t, l.signWith(t, "key-2", key2, "key-2", r.MinimumIAT, generation)) {
		t.Fatal("the rotated key was refused")
	}
	back := l.trust
	if _, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "rotate-back", Actor: "test-operator", Action: "rotate",
		TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &back}); !errors.Is(err, ErrConflict) {
		t.Fatal("rotate brought back a retired key", err)
	}
}

// The registered trust is enough: no local configuration. A token naming an
// unknown trust or key is refused, and an issuer and audience serve one
// organization only.
func TestDelegationRegisteredTrustNeedsNoLocalVerifier(t *testing.T) {
	l := newTenantLab(t, false)
	raw := l.sign(t, "registered", time.Now().Add(-time.Second), nil)
	if l.accepted(t, raw) {
		t.Fatal("a token was accepted before its trust was registered")
	}
	r := l.change(t, "install", "install", "", &l.trust)
	waitTenantClock(t, l.s, r.MinimumIAT)
	if !l.accepted(t, l.sign(t, "registered", r.MinimumIAT, nil)) {
		t.Fatal("the registered trust did not verify its own key")
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, raw := range map[string]string{
		"unknown-kid":      l.signWith(t, "key-9", stranger, "x", r.MinimumIAT, nil),
		"wrong-key":        l.signWith(t, "key-1", stranger, "x", r.MinimumIAT, nil),
		"unknown-audience": l.sign(t, "x", r.MinimumIAT, func(c jwt.MapClaims) { c["aud"] = "other" }),
		"unknown-issuer":   l.sign(t, "x", r.MinimumIAT, func(c jwt.MapClaims) { c["iss"] = "https://other.example" }),
	} {
		if l.accepted(t, raw) {
			t.Fatal("accepted:", name)
		}
	}
	other := createTestOrganization(t, l.a, l.platform, "other-tenant")
	shared := l.trust
	shared.TenantID = other.ID
	if _, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "shared", Actor: "test-operator", Action: "install",
		TenantID: other.ID, Issuer: shared.Issuer, Audience: shared.Audience, Trust: &shared}); !errors.Is(err, ErrConflict) {
		t.Fatal("one issuer and audience served two organizations", err)
	}
}

// TEN-008: an end user is who a registered trust's signature says, nothing
// else. A user ID written by the caller is refused in every form.
func TestFreeFormUserIDsAreRefused(t *testing.T) {
	l := newTenantLab(t, true)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": organizationInput().InitialOwner.Subject,
		"jti": "none", "iat": l.cutoff.Unix(), "exp": l.cutoff.Add(time.Minute).Unix(), "trust_generation": 1})
	unsigned.Header["kid"] = "key-1"
	none, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	other := createTestOrganization(t, l.a, l.platform, "other")
	for name, raw := range map[string]string{
		"bare-subject":        organizationInput().InitialOwner.Subject,
		"principal-id":        l.org.OwnerPrincipalID,
		"unsigned":            none,
		"self-signed":         l.signWith(t, "key-1", stranger, "self", l.cutoff, nil),
		"unregistered-member": l.sign(t, "mallory", l.cutoff, func(c jwt.MapClaims) { c["sub"] = "mallory" }),
		"chosen-tenant":       l.sign(t, "tenant", l.cutoff, func(c jwt.MapClaims) { c["tenant_id"] = other.ID }),
		"role-claim-only":     l.sign(t, "role", l.cutoff, func(c jwt.MapClaims) { c["sub"] = "nobody"; c["role"] = "org_owner" }),
	} {
		if l.accepted(t, raw) {
			t.Fatal("a free-form identity was accepted:", name)
		}
		if _, err := l.s.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("an opaque-token path accepted a free-form identity:", name, err)
		}
	}
	if !l.accepted(t, l.sign(t, "genuine", l.cutoff, nil)) {
		t.Fatal("the registered member was refused")
	}
}
