package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

const sourceSecret = "github_pat_corpus-0123456789abcdef" // gitleaks:allow test fixture, not a credential

func createSourceCredential(t *testing.T, l *tenantLab, p Principal, key, name string) SourceCredential {
	t.Helper()
	r, err := l.a.CreateSourceCredential(t.Context(), p, key, CreateSourceCredentialInput{Name: name, Kind: "gitlab", Host: "gitlab.example.org", Secret: sourceSecret})
	var v SourceCredential
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create source credential", err, r.Status)
	}
	return v
}

// ADR 023 §3.1: a source credential is sealed under its own purpose key,
// bound to its organization, identifier and generation; no answer, receipt
// or audit event carries the secret; only the worker opens it.
func TestSourceCredentialsAreSealedAndWriteOnly(t *testing.T) {
	l, _, owner := agentLab(t)
	ctx := t.Context()
	v := createSourceCredential(t, l, owner, "s1", "school-gitlab")
	if !strings.HasPrefix(v.ID, "scr_") || v.Generation != 1 || v.Status != "active" || v.Kind != "gitlab" || v.Host != "gitlab.example.org" {
		t.Fatal("created", v)
	}
	r, err := l.a.CreateSourceCredential(ctx, owner, "s1", CreateSourceCredentialInput{Name: "school-gitlab", Kind: "gitlab", Host: "gitlab.example.org", Secret: sourceSecret})
	if err != nil || !r.Replayed || bytes.Contains(r.Body, []byte(sourceSecret)) {
		t.Fatal("replay failed or leaks", err, r.Replayed)
	}
	if _, err = l.a.CreateSourceCredential(ctx, owner, "s1", CreateSourceCredentialInput{Name: "school-gitlab", Kind: "gitlab", Host: "gitlab.example.org", Secret: sourceSecret + "x"}); !errors.Is(err, ErrConflict) {
		t.Fatal("the same key with another secret was accepted", err)
	}
	if _, err = l.a.CreateSourceCredential(ctx, owner, "s2", CreateSourceCredentialInput{Name: "school-gitlab", Kind: "github", Host: "github.com", Secret: sourceSecret}); !errors.Is(err, ErrSourceCredentialNameTaken) {
		t.Fatal("a second credential of the same name", err)
	}
	items, err := l.a.ListSourceCredentials(ctx, owner, "", 50)
	if err != nil || len(items) != 1 || items[0] != v {
		t.Fatal("list", err, items)
	}
	if encoded, _ := json.Marshal(items); bytes.Contains(encoded, []byte(sourceSecret)) {
		t.Fatal("the list carries the secret")
	}
	var sealed []byte
	if err = l.s.pool.QueryRow(ctx, `SELECT sealed FROM source_credentials WHERE id=$1`, v.ID).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte(sourceSecret)) || len(sealed) < 28 {
		t.Fatal("the secret is stored in clear", err)
	}
	// The worker opens it; the ciphertext opens only for its own row and
	// generation, and not under the provider credentials' key.
	if s, err := l.a.OpenSourceCredential(ctx, owner.TenantID, v.ID); err != nil || s.Secret != sourceSecret || s.Kind != "gitlab" || s.Host != "gitlab.example.org" {
		t.Fatal("open", err, s.Kind, s.Host)
	}
	if _, err = l.a.openSourceSecret(owner.TenantID, v.ID, 2, sealed); err == nil {
		t.Fatal("a ciphertext opened under another generation")
	}
	other := createSourceCredential(t, l, owner, "s3", "other")
	if _, err = l.a.openSourceSecret(owner.TenantID, other.ID, 1, sealed); err == nil {
		t.Fatal("a ciphertext opened for another credential")
	}
	if _, err = l.a.openProviderSecret(owner.TenantID, v.ID, 1, sealed); err == nil {
		t.Fatal("a source credential opened under the provider credentials' key")
	}
	if _, err = l.a.OpenSourceCredential(ctx, "org_"+strings.Repeat("0", 32), v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("another organization opened the credential", err)
	}

	// Rotation: a new generation, the old ciphertext gone.
	r, err = l.a.RotateSourceCredential(ctx, owner, v.ID, "rotate-1", sourceSecret+"-2")
	var rotated SourceCredential
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &rotated) != nil || rotated.Generation != 2 || rotated.RotatedAt == nil {
		t.Fatal("rotate", err, rotated)
	}
	if s, err := l.a.OpenSourceCredential(ctx, owner.TenantID, v.ID); err != nil || s.Secret != sourceSecret+"-2" {
		t.Fatal("the rotated secret", err)
	}
	if _, err = l.a.openSourceSecret(owner.TenantID, v.ID, 1, sealed); err != nil {
		t.Fatal("the first ciphertext should still open under its own generation", err)
	}
	var now []byte
	if err = l.s.pool.QueryRow(ctx, `SELECT sealed FROM source_credentials WHERE id=$1`, v.ID).Scan(&now); err != nil || bytes.Equal(now, sealed) {
		t.Fatal("the rotation kept the old ciphertext", err)
	}

	// Disabling erases the ciphertext, for good, and is idempotent.
	for _, key := range []string{"disable-1", "disable-2"} {
		r, err = l.a.DisableSourceCredential(ctx, owner, v.ID, key)
		var disabled SourceCredential
		if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &disabled) != nil || disabled.Status != "disabled" || disabled.DisabledAt == nil {
			t.Fatal("disable", key, err, disabled)
		}
	}
	if err = l.s.pool.QueryRow(ctx, `SELECT sealed FROM source_credentials WHERE id=$1`, v.ID).Scan(&now); err != nil || now != nil {
		t.Fatal("a disabled credential kept its ciphertext", err)
	}
	if _, err = l.a.OpenSourceCredential(ctx, owner.TenantID, v.ID); !errors.Is(err, ErrSourceCredentialDisabled) {
		t.Fatal("a disabled credential opened", err)
	}
	if _, err = l.a.RotateSourceCredential(ctx, owner, v.ID, "rotate-2", sourceSecret); !errors.Is(err, ErrTransition) {
		t.Fatal("a disabled credential was rotated", err)
	}

	// The trail: each action once, by its actor and credential, and never
	// the secret; the receipts hold no secret either.
	var events int
	var dump string
	if err = l.s.pool.QueryRow(ctx, `SELECT count(*), coalesce(string_agg(a::text,' '),'') FROM corpus_audit a
        WHERE tenant_id=$1 AND actor_principal_id=$2 AND credential_id=$3`, owner.TenantID, owner.ID, owner.TokenID).Scan(&events, &dump); err != nil || events != 4 {
		t.Fatal("the trail", err, events)
	}
	for _, action := range []string{"source_credential.created", "source_credential.rotated", "source_credential.disabled"} {
		if !strings.Contains(dump, action) {
			t.Fatal("the trail lacks", action)
		}
	}
	page, err := l.a.ListAudit(ctx, owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range page.Items {
		if strings.HasPrefix(e.Action, "source_credential.") {
			seen++
			if e.Target != v.ID && e.Target != other.ID {
				t.Fatal("an event's target", e)
			}
		}
	}
	if seen != 4 {
		t.Fatal("GET /v1/audit shows", seen, "source credential events")
	}
	rows, err := l.s.pool.Query(ctx, `SELECT response_ciphertext FROM tenant_http_receipts WHERE tenant_id=$1 AND operation LIKE 'source_credential.%'`, owner.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var receipt []byte
		if err = rows.Scan(&receipt); err != nil || bytes.Contains(receipt, []byte(sourceSecret)) {
			t.Fatal("a receipt carries the secret", err)
		}
	}
	if strings.Contains(dump, sourceSecret) {
		t.Fatal("the trail carries the secret")
	}
}

// Only owners and administrators with corpus:manage manage source
// credentials; another organization's answers as if it did not exist;
// invalid inputs are refused before anything is stored.
func TestSourceCredentialRightsAndInputs(t *testing.T) {
	l, _, owner := agentLab(t)
	ctx := t.Context()
	v := createSourceCredential(t, l, owner, "s1", "school")
	addMember(t, l, owner, "admin", authorization.OrgAdmin)
	addMember(t, l, owner, "operator", authorization.AgentOperator)
	addMember(t, l, owner, "auditor", authorization.Auditor)
	admin := agentPrincipal(t, l, "admin", agentScopes)
	if _, err := l.a.RotateSourceCredential(ctx, admin, v.ID, "admin-rotate", sourceSecret); err != nil {
		t.Fatal("an administrator could not rotate", err)
	}
	for name, p := range map[string]Principal{
		"operator":   agentPrincipal(t, l, "operator", agentScopes),
		"auditor":    agentPrincipal(t, l, "auditor", agentScopes),
		"no scope":   agentPrincipal(t, l, "admin", strings.ReplaceAll(agentScopes, " corpus:manage", "")),
		"read scope": agentPrincipal(t, l, "admin", "org:read corpus:read"),
	} {
		if _, err := l.a.ListSourceCredentials(ctx, p, "", 10); !errors.Is(err, ErrForbidden) {
			t.Error(name, "listed source credentials:", err)
		}
		if _, err := l.a.CreateSourceCredential(ctx, p, "x-"+name, CreateSourceCredentialInput{Name: "x", Kind: "github", Host: "github.com", Secret: sourceSecret}); !errors.Is(err, ErrForbidden) {
			t.Error(name, "created a source credential:", err)
		}
		if _, err := l.a.DisableSourceCredential(ctx, p, v.ID, "x-"+name); !errors.Is(err, ErrForbidden) {
			t.Error(name, "disabled a source credential:", err)
		}
	}
	if _, err := l.a.RotateSourceCredential(ctx, owner, "scr_"+strings.Repeat("0", 32), "missing", sourceSecret); !errors.Is(err, ErrNotFound) {
		t.Fatal("rotating an unknown credential", err)
	}
	for _, bad := range []CreateSourceCredentialInput{
		{Name: "Upper", Kind: "github", Host: "github.com", Secret: sourceSecret},
		{Name: "-x", Kind: "github", Host: "github.com", Secret: sourceSecret},
		{Name: "x", Kind: "bitbucket", Host: "bitbucket.org", Secret: sourceSecret},
		{Name: "x", Kind: "github", Host: "https://github.com", Secret: sourceSecret},
		{Name: "x", Kind: "github", Host: "GitHub.com", Secret: sourceSecret},
		{Name: "x", Kind: "github", Host: "github.com/acme", Secret: sourceSecret},
		{Name: "x", Kind: "github", Host: "github.com", Secret: ""},
		{Name: "x", Kind: "github", Host: "github.com", Secret: "with space"},
		{Name: "x", Kind: "github", Host: "github.com", Secret: "line\nbreak"},
		{Name: "x", Kind: "github", Host: "github.com", Secret: strings.Repeat("a", 4097)},
	} {
		if _, err := l.a.CreateSourceCredential(ctx, owner, newID("k"), bad); !errors.Is(err, ErrInput) {
			t.Error("accepted", bad.Name, bad.Kind, bad.Host, len(bad.Secret), err)
		}
	}
	if _, err := l.a.CreateSourceCredential(ctx, owner, "port", CreateSourceCredentialInput{Name: "internal", Kind: "gitlab", Host: "gitlab.example.org:8443", Secret: strings.Repeat("a", 4096)}); err != nil {
		t.Fatal("a host with a port, a secret of 4,096 bytes:", err)
	}
}
