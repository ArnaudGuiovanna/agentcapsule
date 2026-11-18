package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The platform credential's creation and revocation are audited with the
// operator's name; a confirmed retry is not a new action.
func TestPlatformCredentialIsAudited(t *testing.T) {
	s, _, _ := accountLab(t)
	ctx := WithOperator(t.Context(), "local-uid:1000")
	secret := "acpp_" + tokenSecret()[4:]
	for range 2 {
		if err := s.BootstrapPlatformToken(ctx, "platform-operator", secret, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.RevokeOperatorCredential(ctx, OperatorCommand{Actor: "local-uid:1000"}, "platform", p.TokenID); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ListOperatorAudit(t.Context(), 10)
	if err != nil || len(events) != 3 {
		t.Fatal("operator audit", events, err)
	}
	// The revocation is a guarded command (ADR 014), audited with its outcome.
	want := []string{"credential.revoked:false", "credential.revoked:true", "platform_credential.created:true"}
	for i, e := range events {
		got := e.Action + ":" + map[bool]string{true: "true", false: "false"}[e.Changed]
		if got != want[i] || e.Actor != "local-uid:1000" || e.Target != p.TokenID || strings.Contains(e.Reference+e.Target, secret) {
			t.Fatal("operator audit event", i, e)
		}
	}
	if _, err := s.ListOperatorAudit(t.Context(), 0); !errors.Is(err, ErrInput) {
		t.Fatal("unbounded audit listing", err)
	}
}

// Once closed, the legacy owner domain's acp_ tokens authenticate nothing;
// the platform credential still does.
func TestLegacyOwnerDomainClosed(t *testing.T) {
	s, _ := freshStore(t, "manual", 2)
	legacy, err := s.BootstrapService(t.Context(), "legacy-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	platform := "acpp_" + tokenSecret()[4:]
	if err = s.BootstrapPlatformToken(t.Context(), "platform-operator", platform, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(t.Context(), legacy); err != nil {
		t.Fatal("lab: the legacy token must work before the domain is closed", err)
	}
	s.CloseLegacyOwnerDomain()
	if _, err = s.Authenticate(t.Context(), legacy); !errors.Is(err, ErrAuthentication) {
		t.Fatal("a legacy token authenticated after the domain was closed", err)
	}
	if p, err := s.Authenticate(t.Context(), platform); err != nil || p.Kind != "platform" {
		t.Fatal("the platform credential was refused", err)
	}
}

// Creating an organization twice by mistake, with another idempotency key,
// fails while the first is active; the same key still replays.
func TestOrganizationNameIsUniqueAmongActiveOrganizations(t *testing.T) {
	_, a, p, _, _ := organizationLab(t)
	first, err := a.CreateOrganization(t.Context(), p, "first", organizationInput())
	if err != nil || first.Status != 201 {
		t.Fatal(err)
	}
	if replay, err := a.CreateOrganization(t.Context(), p, "first", organizationInput()); err != nil || !replay.Replayed {
		t.Fatal("replay", err)
	}
	same := organizationInput()
	same.Name = strings.ToUpper(same.Name)
	if _, err := a.CreateOrganization(t.Context(), p, "second", same); !errors.Is(err, ErrOrganizationNameTaken) {
		t.Fatal("a second active organization took the same name", err)
	}
	var created CreateOrganizationResponse
	if err := json.Unmarshal(first.Body, &created); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DisableOrganization(t.Context(), p, created.ID, "disable"); err != nil {
		t.Fatal(err)
	}
	if r, err := a.CreateOrganization(t.Context(), p, "third", same); err != nil || r.Status != 201 {
		t.Fatal("the name of a disabled organization stays taken", err)
	}
}
