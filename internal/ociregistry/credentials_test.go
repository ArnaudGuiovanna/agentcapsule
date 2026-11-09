package ociregistry

import (
	"errors"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
)

// Fake credentials of the in-process test registry, not secrets.
const (
	testUser     = "ci-bot"
	testPassword = "test-password-not-a-secret" // gitleaks:allow
)

func withCredentials(rule Rule, user, password string) Rule {
	rule.Username, rule.Password = user, password
	return rule
}

func TestPrivateRegistryBehindATokenService(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	reg.Token, reg.Username, reg.Password = "pull-token", testUser, testPassword
	rule := localRule(reg, "acme/")
	rule.BlobHosts = []string{reg.RedirectBlobs()}
	if _, err := Push(t.Context(), rule, "acme/echo", "", buildPackage(t, manifestFor("echo", "1.0.0"))); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous push to a private registry", err)
	}
	authorized := withCredentials(rule, testUser, testPassword)
	ref, err := Push(t.Context(), authorized, "acme/echo", "1.0.0", buildPackage(t, manifestFor("echo", "1.0.0")))
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(r Rule) error {
		f, err := NewFetcher(Policy{Rules: []Rule{r}}, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Fetch(t.Context(), ref, t.TempDir())
		return err
	}
	if err = fetch(authorized); err != nil {
		t.Fatal("authorized pull", err)
	}
	if err = fetch(rule); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous pull of a private package", err)
	}
	if err = fetch(withCredentials(rule, testUser, "wrong-password")); !errors.Is(err, ErrDenied) {
		t.Fatal("pull with refused credentials", err)
	}
	// The password went only to the token service: never to the registry API,
	// never to the blob host.
	if reg.BasicSeen.Load() != 0 || reg.BlobAuth.Load() != 0 {
		t.Fatal("credentials leaked", reg.BasicSeen.Load(), reg.BlobAuth.Load())
	}
}

func TestBasicRegistryGetsCredentialsOnlyAfterAChallenge(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	reg.Basic, reg.Username, reg.Password = true, testUser, testPassword
	rule := localRule(reg, "acme/")
	// Same address, other port: Go would forward the header; the client must not.
	rule.BlobHosts = []string{reg.RedirectBlobs()}
	authorized := withCredentials(rule, testUser, testPassword)
	ref, err := Push(t.Context(), authorized, "acme/echo", "", buildPackage(t, manifestFor("echo", "1.0.0")))
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFetcher(Policy{Rules: []Rule{authorized}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	before := reg.Challenges.Load()
	if _, err = f.Fetch(t.Context(), ref, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// One challenge: the first request went out anonymously, later ones reused
	// the credentials for that repository.
	if n := reg.Challenges.Load() - before; n != 1 || reg.BlobAuth.Load() != 0 {
		t.Fatal("credentials sent before a challenge or to the blob host", n, reg.BlobAuth.Load())
	}
	for _, r := range []Rule{rule, withCredentials(rule, testUser, "wrong-password")} {
		f, _ := NewFetcher(Policy{Rules: []Rule{r}}, 64<<20)
		if _, err = f.Fetch(t.Context(), ref, t.TempDir()); !errors.Is(err, ErrDenied) {
			t.Fatal("pull without valid credentials", err)
		}
	}
}

func TestCredentialsCannotBreakHeaders(t *testing.T) {
	for _, c := range [][2]string{
		{"user:name", "p"},            // ':' ends a Basic username
		{"user", "pass\r\nX-Evil: 1"}, // header injection
		{"user name", "p"},            // spaces
		{"user", ""},                  // half credentials
	} {
		p := Policy{Rules: []Rule{{Host: "ghcr.io", Repositories: []string{"acme/"}, Username: c[0], Password: c[1]}}}
		if p.Validate() == nil {
			t.Fatal("unsafe credentials accepted", c[0])
		}
	}
}
