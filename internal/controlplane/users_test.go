package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func accountLab(t *testing.T) (*Store, *Accounts, Principal) {
	t.Helper()
	s, _ := freshStore(t, "manual", 2)
	a, err := NewAccounts(s, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "test-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	return s, a, p
}
func createAccount(t *testing.T, a *Accounts, p Principal, key, name string) User {
	t.Helper()
	r, err := a.CreateUser(t.Context(), p, key, CreateUserInput{DisplayName: name})
	if err != nil {
		t.Fatal(err)
	}
	var u User
	if err = json.Unmarshal(r.Body, &u); err != nil {
		t.Fatal(err)
	}
	return u
}
func issueAccountToken(t *testing.T, a *Accounts, p Principal, u User, key string) TokenResponse {
	t.Helper()
	r, err := a.IssueUserToken(t.Context(), p, u.ID, key, IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var token TokenResponse
	if err = json.Unmarshal(r.Body, &token); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAccountsIdempotentCreationAndConcurrentRetry(t *testing.T) {
	s, a, p := accountLab(t)
	var wg sync.WaitGroup
	results := make(chan APIReceipt, 16)
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			r, err := a.CreateUser(t.Context(), p, "same", CreateUserInput{"Arnaud"})
			if err != nil {
				errs <- err
			} else {
				results <- r
			}
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrInProgress) {
			t.Fatal(err)
		}
	}
	var original []byte
	for r := range results {
		if original == nil {
			original = r.Body
		}
		if r.Status != 201 || !bytes.Equal(original, r.Body) {
			t.Fatal("non-identical concurrent receipts")
		}
	}
	if original == nil {
		t.Fatal("no request completed")
	}
	if n := count(t, s, "users"); n != 1 {
		t.Fatalf("created %d users", n)
	}
	r, err := a.CreateUser(t.Context(), p, "same", CreateUserInput{"Arnaud"})
	if err != nil || !r.Replayed || !bytes.Equal(r.Body, original) {
		t.Fatalf("retry differs: %v", err)
	}
	if _, err = a.CreateUser(t.Context(), p, "same", CreateUserInput{"Marc"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("different body: %v", err)
	}
	if n := count(t, s, "users"); n != 1 {
		t.Fatal("conflict mutated users")
	}
}

func TestAccountsTokenReplayAuthorityAndSecretStorage(t *testing.T) {
	s, a, p := accountLab(t)
	u := createAccount(t, a, p, "a", "Arnaud")
	in := IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	r, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in)
	if err != nil {
		t.Fatal(err)
	}
	var token TokenResponse
	if err = json.Unmarshal(r.Body, &token); err != nil {
		t.Fatal(err)
	}
	again, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in)
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, r.Body) {
		t.Fatal("token response not exactly replayed", err)
	}
	member, err := s.Authenticate(t.Context(), token.Token)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := a.Me(t.Context(), member)
	if err != nil || profile.ID != u.ID {
		t.Fatal("wrong owner profile", err)
	}
	if _, err = a.Me(t.Context(), p); !errors.Is(err, ErrForbidden) {
		t.Fatalf("service read owner profile: %v", err)
	}
	if _, err = a.CreateUser(t.Context(), member, "escalate", CreateUserInput{"Admin"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member escalated: %v", err)
	}
	var hash, ciphertext []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT token_hash FROM api_tokens WHERE id=$1", token.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(token.Token))
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("incorrect stored hash")
	}
	if err = s.pool.QueryRow(t.Context(), "SELECT response_ciphertext FROM http_receipts WHERE key='token'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(token.Token)) {
		t.Fatal("plaintext token in receipt")
	}
	if err = s.RevokeToken(t.Context(), member, member.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(t.Context(), token.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked token authenticates", err)
	}
	if _, err = a.Me(t.Context(), member); !errors.Is(err, ErrAuthentication) {
		t.Fatal("cached principal accepted", err)
	}
	// Even the original issuance receipt must not bypass current service authority.
	if _, err = s.pool.Exec(t.Context(), "UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE id=$1", p.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err = a.IssueUserToken(t.Context(), p, u.ID, "token", in); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked administrator replayed secret", err)
	}
}

func TestAccountsReceiptRollbackAndInProgress(t *testing.T) {
	s, a, p := accountLab(t)
	// A failed receipt write must roll back the account mutation too.
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_api_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure'; END $$;
        CREATE TRIGGER reject_receipt BEFORE INSERT ON http_receipts FOR EACH ROW EXECUTE FUNCTION reject_api_receipt()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.CreateUser(t.Context(), p, "rollback", CreateUserInput{"Arnaud"}); err == nil {
		t.Fatal("failure injection ignored")
	}
	if count(t, s, "users") != 0 || count(t, s, "http_receipts") != 0 {
		t.Fatal("partial account transaction")
	}
	if _, err = s.pool.Exec(t.Context(), "DROP TRIGGER reject_receipt ON http_receipts"); err != nil {
		t.Fatal(err)
	}
	// The independent connection holds exactly the receipt's transaction lock.
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	b, _ := json.Marshal(scope(p, "POST", "/v1/users", "rollback"))
	hash := sha256.Sum256(b)
	if _, err = tx.Exec(t.Context(), "SELECT pg_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(hash[:8]))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err = a.CreateUser(ctx, p, "rollback", CreateUserInput{"Arnaud"}); !errors.Is(err, ErrInProgress) {
		t.Fatal("did not report concurrent in-progress operation", err)
	}
	rollback(tx)
	createAccount(t, a, p, "rollback", "Arnaud")
}

func TestAccountsReceiptTamperExpiryAndDisabledUser(t *testing.T) {
	s, a, p := accountLab(t)
	var err error
	u := createAccount(t, a, p, "a", "Arnaud")
	if _, err = s.pool.Exec(t.Context(), "UPDATE http_receipts SET response_ciphertext=decode('00','hex') WHERE key='a'"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.CreateUser(t.Context(), p, "a", CreateUserInput{"Arnaud"}); err == nil {
		t.Fatal("corrupt receipt accepted")
	}
	if count(t, s, "users") != 1 {
		t.Fatal("corruption generated another user")
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE http_receipts SET expires_at=clock_timestamp()-interval '1 second' WHERE key='a'"); err != nil {
		t.Fatal(err)
	}
	createAccount(t, a, p, "a", "New account after retention")
	token := issueAccountToken(t, a, p, u, "token")
	if _, err = s.pool.Exec(t.Context(), "UPDATE users SET status='disabled' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(t.Context(), token.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatal("disabled user authenticated", err)
	}
	if _, err = a.IssueUserToken(t.Context(), p, u.ID, "second", IssueTokenInput{time.Now().Add(time.Hour)}); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled user received token", err)
	}
	if _, err = s.BootstrapService(t.Context(), "another", time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap repeated", err)
	}
	if _, err = a.CreateUser(t.Context(), p, "long", CreateUserInput{strings.Repeat("é", 101)}); !errors.Is(err, ErrInput) {
		t.Fatal("oversized name accepted")
	}
}

func TestBootstrapPersistedSecretRetryDoesNotExtendAuthority(t *testing.T) {
	s, _ := freshStore(t, "manual", 1)
	secret := tokenSecret()
	if err := s.BootstrapServiceToken(t.Context(), "installation", secret, time.Hour); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT expires_at FROM api_tokens").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapServiceToken(t.Context(), "installation", secret, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(t.Context(), "SELECT expires_at FROM api_tokens").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) || count(t, s, "api_tokens") != 1 {
		t.Fatal("bootstrap replay changed authority")
	}
	if err := s.BootstrapServiceToken(t.Context(), "another", secret, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("changed service identity accepted", err)
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE api_tokens SET revoked_at=clock_timestamp()"); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapServiceToken(t.Context(), "installation", secret, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap revived revoked token", err)
	}
}

func TestReceiptKeyCannotBeReplacedOnExistingInstallation(t *testing.T) {
	s, _ := freshStore(t, "manual", 1)
	a, err := NewAccounts(s, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.CheckReceiptKey(t.Context()); !errors.Is(err, ErrReceiptKey) {
		t.Fatal("uninitialized key accepted", err)
	}
	if err = a.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = a.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal("same key not idempotent", err)
	}
	b, err := NewAccounts(s, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.CheckReceiptKey(t.Context()); !errors.Is(err, ErrReceiptKey) {
		t.Fatal("different key accepted", err)
	}
	if err = b.InitializeReceiptKey(t.Context()); !errors.Is(err, ErrReceiptKey) {
		t.Fatal("new key rebound installation", err)
	}
	if err = a.CheckReceiptKey(t.Context()); err != nil {
		t.Fatal("original binding changed", err)
	}
}

// A service that mints a user token can read that user's private content, so the
// issuing credential must be recorded with the token.
func TestIssuedUserTokenRecordsIssuingCredential(t *testing.T) {
	s, a, p := accountLab(t)
	u := createAccount(t, a, p, "issuer", "Arnaud")
	r, err := a.IssueUserToken(t.Context(), p, u.ID, "issued", IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var token TokenResponse
	if err = json.Unmarshal(r.Body, &token); err != nil {
		t.Fatal(err)
	}
	var issuer *string
	if err = s.pool.QueryRow(t.Context(), "SELECT issued_by_token_id FROM api_tokens WHERE id=$1", token.ID).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	if issuer == nil || *issuer != p.TokenID || p.TokenID == "" {
		t.Fatal("user token does not record the credential that issued it", issuer, p.TokenID)
	}
}

func TestServiceTokenCanBeReplacedAfterRevocationButNotWhileActive(t *testing.T) {
	s, _, p := accountLab(t)
	fresh := func() string { return tokenSecret() }
	if err := s.BootstrapServiceToken(t.Context(), "installation", fresh(), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("second active service token accepted", err)
	}
	if err := s.RevokeOperatorCredential(t.Context(), "service", p.TokenID); err != nil {
		t.Fatal(err)
	}
	replacement := fresh()
	if err := s.BootstrapServiceToken(t.Context(), "installation", replacement, time.Hour); err != nil {
		t.Fatal("operator locked out after revocation:", err)
	}
	if q, err := s.Authenticate(t.Context(), replacement); err != nil || q.Kind != "service" {
		t.Fatal("replacement service token does not authenticate", err)
	}
}

func TestExpiredReceiptsArePurgedAndLiveOnesKept(t *testing.T) {
	s, a, p := accountLab(t)
	u := createAccount(t, a, p, "purge", "Arnaud")
	in := IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	if _, err := a.IssueUserToken(t.Context(), p, u.ID, "live", in); err != nil {
		t.Fatal(err)
	}
	if _, err := a.IssueUserToken(t.Context(), p, u.ID, "old", in); err != nil {
		t.Fatal(err)
	}
	before, keysBefore := count(t, s, "http_receipts"), count(t, s, "api_receipt_key")
	if _, err := s.pool.Exec(t.Context(), "UPDATE http_receipts SET expires_at=clock_timestamp()-interval '1 second' WHERE key='old'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PurgeExpiredReceipts(t.Context(), 0); !errors.Is(err, ErrInput) {
		t.Fatal("invalid limit accepted", err)
	}
	n, err := s.PurgeExpiredReceipts(t.Context(), 10)
	if err != nil || n != 1 {
		t.Fatal("expected exactly the expired receipt to be purged", n, err)
	}
	if got := count(t, s, "http_receipts"); got != before-1 {
		t.Fatal("purge removed a live receipt or none", before, got)
	}
	r, err := a.IssueUserToken(t.Context(), p, u.ID, "live", in)
	if err != nil || !r.Replayed {
		t.Fatal("live receipt no longer replays", err)
	}
	if count(t, s, "api_receipt_key") != keysBefore {
		t.Fatal("purge touched the receipt key binding")
	}
}
