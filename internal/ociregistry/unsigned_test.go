package ociregistry

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"testing"
)

// L-16: in production (SignaturesByDefault), every rule trusts publisher
// keys, or says allow_unsigned: an explicit opt-out, per rule. Strict mode
// (RequireSignatures) allows no opt-out, and an opt-out beside publisher
// keys is refused as contradictory. In development, a rule without keys
// imports unsigned packages, as before. The opt-out comes from the rule's
// JSON.
func TestProductionRulesRequireSignaturesUnlessTheyOptOut(t *testing.T) {
	unsigned := Rule{Host: "ghcr.io", Repositories: []string{"acme/"}}
	signed := unsigned
	signed.Keys = []PublisherKey{publisher(t, ecdsaKey(t, elliptic.P256()))}
	optedOut := unsigned
	optedOut.AllowUnsigned = true
	both := signed
	both.AllowUnsigned = true
	for _, c := range []struct {
		name   string
		policy Policy
		want   error
	}{
		{"production, signed", Policy{Rules: []Rule{signed}, SignaturesByDefault: true}, nil},
		{"production, unsigned", Policy{Rules: []Rule{unsigned}, SignaturesByDefault: true}, ErrUnsigned},
		{"production, opted out", Policy{Rules: []Rule{optedOut}, SignaturesByDefault: true}, nil},
		{"production, one of two unsigned", Policy{Rules: []Rule{signed, func() Rule { r := unsigned; r.Host = "registry.example"; return r }()},
			SignaturesByDefault: true}, ErrUnsigned},
		{"strict, opted out", Policy{Rules: []Rule{optedOut}, RequireSignatures: true}, ErrPolicy},
		{"strict, unsigned", Policy{Rules: []Rule{unsigned}, RequireSignatures: true}, ErrPolicy},
		{"an opt-out beside keys", Policy{Rules: []Rule{both}}, ErrPolicy},
		{"an opt-out beside keys, production", Policy{Rules: []Rule{both}, SignaturesByDefault: true}, ErrPolicy},
		{"development, unsigned", Policy{Rules: []Rule{unsigned}}, nil},
		{"development, opted out", Policy{Rules: []Rule{optedOut}}, nil},
	} {
		err := c.policy.Validate()
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, not %v", c.name, err, c.want)
		}
		if c.want != nil && !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: %v is not a policy error", c.name, err)
		}
	}
	var r Rule
	if err := json.Unmarshal([]byte(`{"host":"ghcr.io","repositories":["acme/"],"allow_unsigned":true}`), &r); err != nil || !r.AllowUnsigned {
		t.Fatal("allow_unsigned:", r, err)
	}
	if b, err := json.Marshal(unsigned); err != nil || string(b) != `{"host":"ghcr.io","repositories":["acme/"]}` {
		t.Fatalf("a rule without the opt-out: %s %v", b, err)
	}
}
