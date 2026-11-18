package controlplane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

func linkAccounts(t *testing.T, fill byte) *Accounts {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &Accounts{links: aead}
}

// A link opens until it expires, only with the key of its installation, and
// stands for its principal narrowed to reading content.
func TestDownloadLinksExpireAndStaySealed(t *testing.T) {
	a := linkAccounts(t, 1)
	v := delegatedidentity.VerifiedIdentity{TenantID: "org", Issuer: "https://idp", Subject: "bob", TokenID: "jti",
		Scopes: []string{"agent:invoke", authorization.ScopeAgentContentRead, "agent:manage"}}
	p := Principal{Kind: "tenant", ID: "prn_bob", TenantID: "org", TokenID: "jti", delegation: &v}
	now := time.Now()
	link, err := a.seal(p, "attachment", "att_1", time.Minute, now)
	if err != nil || !link.ExpiresAt.Equal(time.Unix(now.Add(time.Minute).Unix(), 0)) {
		t.Fatal(link, err)
	}
	token := strings.TrimPrefix(link.URL, "/v1/downloads/")
	for _, secret := range []string{"bob", "https://idp", "jti", "att_1", "org"} {
		if strings.Contains(token, secret) {
			t.Fatal("the link shows", secret)
		}
	}
	got, claims, err := a.open(token, now.Add(59*time.Second))
	if err != nil || got.ID != "prn_bob" || claims.Resource != "att_1" || claims.Purpose != "attachment" ||
		len(tenantScopes(got)) != 1 || tenantScopes(got)[0] != authorization.ScopeAgentContentRead || !tenantBound(got) {
		t.Fatal(got, claims, err)
	}
	if _, _, err = a.open(token, now.Add(61*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatal("an expired link opened", err)
	}
	if _, _, err = linkAccounts(t, 2).open(token, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("another installation's link opened", err)
	}
	if _, _, err = a.open(strings.TrimPrefix(token, "dl_"), now); !errors.Is(err, ErrNotFound) {
		t.Fatal("a link without its prefix opened", err)
	}
	for _, seconds := range []int{-1, 29, 901} {
		if _, err = linkTTL(seconds); !errors.Is(err, ErrInput) {
			t.Fatal("ttl", seconds)
		}
	}
	if ttl, err := linkTTL(0); err != nil || ttl != DefaultLinkTTL {
		t.Fatal(ttl, err)
	}
}
