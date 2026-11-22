package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5/pgxpool"
)

func platformSecret(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Platform sessions form chains (finding L-01): a session records the
// credential that issued it, revoking a credential revokes every session
// descended from it, a credential has one live child unless the child
// replaces it, and no session outlives the chain's lifetime.
func TestPlatformSessionChains(t *testing.T) {
	server, store, _, dsn := apiLab(t)
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n := 0
	issue := func(bearer string, replace bool) (int, controlplane.OperatorCredential, string) {
		t.Helper()
		token := platformSecret("acpp_")
		sum := sha256.Sum256([]byte(token))
		body, _ := json.Marshal(controlplane.PlatformSessionRequest{TokenSHA256: hex.EncodeToString(sum[:]), ReplaceCurrent: replace})
		n++
		r := call(t, server, "POST", "/v1/platform/sessions", bearer, "chain-"+strings.Repeat("x", n), string(body))
		var out controlplane.OperatorCredential
		_ = json.Unmarshal(r.Body.Bytes(), &out)
		return r.Code, out, token
	}
	alive := func(bearer string) bool {
		t.Helper()
		r := call(t, server, "GET", "/v1/platform/session", bearer, "", "")
		if r.Code != 200 && r.Code != 401 {
			t.Fatal("session", r.Code, r.Body.String())
		}
		return r.Code == 200
	}
	id := func(bearer string) string {
		t.Helper()
		var out controlplane.OperatorCredential
		r := call(t, server, "GET", "/v1/platform/session", bearer, "", "")
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil {
			t.Fatal("session", r.Code, r.Body.String())
		}
		return out.ID
	}

	// A credential issues one live child; a second is refused.
	root := platformForAPI(t, store)
	code, child, childToken := issue(root, false)
	if code != 201 {
		t.Fatal("first child", code)
	}
	if code, _, _ = issue(root, false); code != 409 {
		t.Fatal("a second concurrent child", code)
	}
	code, _, grandchild := issue(childToken, false)
	if code != 201 {
		t.Fatal("grandchild", code)
	}
	var parent string
	if err = db.QueryRow(t.Context(), "SELECT parent_id FROM platform_credentials WHERE id=$1", child.ID).Scan(&parent); err != nil || parent != id(root) {
		t.Fatal("the child names its parent", parent, err)
	}
	// Revoking the root revokes its descendants, here with the grandchild's
	// own credential.
	rootID := id(root)
	r := call(t, server, "POST", "/v1/platform/sessions/"+rootID+"/revoke", grandchild, "revoke-root", "{}")
	if r.Code != 200 {
		t.Fatal("revoke the root", r.Code, r.Body.String())
	}
	for name, bearer := range map[string]string{"root": root, "child": childToken, "grandchild": grandchild} {
		if alive(bearer) {
			t.Error("the", name, "outlived the revocation of the chain's root")
		}
	}

	// An enrollment starts a chain; a replacement revokes the session it
	// replaces and that session's other descendants.
	proof := platformSecret("acpe_")
	if err = store.IssuePlatformEnrollment(t.Context(), "api-platform", proof, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	code, _, first := issue(proof, false)
	if code != 201 {
		t.Fatal("enrollment exchange", code)
	}
	if code, _, _ = issue(proof, false); code != 401 {
		t.Fatal("an enrollment proof used twice", code)
	}
	code, _, side := issue(first, false)
	if code != 201 {
		t.Fatal("side child", code)
	}
	code, _, second := issue(first, true)
	if code != 201 || alive(first) || alive(side) || !alive(second) {
		t.Fatal("replacement", code, alive(first), alive(side), alive(second))
	}

	// The chain's lifetime: a renewal near its end is cut to it, one past
	// it is refused.
	if _, err = db.Exec(t.Context(), `UPDATE platform_credentials SET chain_started_at=clock_timestamp()-$2::bigint*interval '1 microsecond'+interval '2 hours' WHERE id=$1`,
		id(second), controlplane.PlatformSessionChainLifetime.Microseconds()); err != nil {
		t.Fatal(err)
	}
	code, cut, third := issue(second, true)
	if code != 201 || time.Until(cut.ExpiresAt) > 2*time.Hour || time.Until(cut.ExpiresAt) < time.Hour {
		t.Fatal("a renewal near the chain's end", code, cut.ExpiresAt)
	}
	if _, err = db.Exec(t.Context(), `UPDATE platform_credentials SET chain_started_at=clock_timestamp()-$2::bigint*interval '1 microsecond' WHERE id=$1`,
		id(third), controlplane.PlatformSessionChainLifetime.Microseconds()); err != nil {
		t.Fatal(err)
	}
	if code, _, _ = issue(third, true); code != 409 {
		t.Fatal("a renewal past the chain's end", code)
	}
	if !alive(third) {
		t.Fatal("a refused renewal consumed its session")
	}
}

// A bearer that is no enrollment proof is refused without waiting for the
// platform credentials' lock (finding L-02).
func TestForgedEnrollmentDoesNotWaitForThePlatformLock(t *testing.T) {
	server, _, _, dsn := apiLab(t)
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	holder, err := db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if _, err = holder.Exec(t.Context(), "SELECT pg_advisory_xact_lock(756610045)"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("forged"))
	body := `{"token_sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	done := make(chan int, 1)
	go func() {
		done <- call(t, server, "POST", "/v1/platform/sessions", platformSecret("acpe_"), "forged", body).Code
	}()
	select {
	case code := <-done:
		if code != 401 {
			t.Fatal("a forged enrollment proof", code)
		}
	case <-time.After(time.Second):
		_ = holder.Rollback(context.Background())
		<-done
		t.Fatal("a forged enrollment proof waited for the platform lock")
	}
}
