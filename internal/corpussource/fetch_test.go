package corpussource_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/forgetest"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
	secret  = "glpat-forge-token-0123456789" // gitleaks:allow test fixture, not a credential
)

var limits = corpussource.Limits{ArchiveBytes: 1 << 20, LFSBytes: 64 << 20, LFSObjects: 1000}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type lab struct {
	forge   *forgetest.Forge
	fetcher *corpussource.Fetcher
	dir     string
}

func newLab(t *testing.T, l corpussource.Limits, rules ...corpussource.Rule) *lab {
	t.Helper()
	f := forgetest.New(t)
	if rules == nil {
		rules = forgetest.Rules()
	}
	fetcher, err := corpussource.NewForTests(corpussource.Policy{Rules: rules}, l, f.Network())
	if err != nil {
		t.Fatal(err)
	}
	return &lab{forge: f, fetcher: fetcher, dir: t.TempDir()}
}

func source(kind, repo string) corpussource.Source {
	host := forgetest.GitHubHost
	if kind == corpussource.GitLab {
		host = forgetest.GitLabHost
	}
	return corpussource.Source{Kind: kind, Host: host, Repository: repo}
}

// checkStored: the file holds the bytes as sent, then zeros to a whole
// block, and the archive's record is their size and sha256.
func checkStored(t *testing.T, path string, want []byte, a corpussource.Archive) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(want)
	if a.Bytes != int64(len(want)) || a.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("the archive's record is not its bytes':", a)
	}
	if int64(len(got)) != corpussource.Padded(int64(len(want))) || len(got)%corpussource.Block != 0 || !bytes.Equal(got[:len(want)], want) ||
		!bytes.Equal(got[len(want):], make([]byte, len(got)-len(want))) {
		t.Fatal("the stored archive is not the forge's bytes padded with zeros:", len(got), len(want))
	}
	if err = corpussource.VerifyArchive(path, a); err != nil {
		t.Fatal("a stored archive does not verify:", err)
	}
}

// Lot 3's exit criterion, on fake forges: the archive of a public and of a
// private repository, on GitHub and on GitLab, pinned on the commit its ref
// names. The credential goes to the forge's API only, never to the archive
// host, which takes the signed URL the forge redirected to.
func TestArchivesOfPublicAndPrivateRepositoriesPinnedOnACommit(t *testing.T) {
	for _, kind := range []string{corpussource.GitHub, corpussource.GitLab} {
		for _, private := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/private=%v", kind, private), func(t *testing.T) {
				l := newLab(t, limits)
				repo := "acme/handbook"
				if kind == corpussource.GitLab {
					repo = "school/finance/l3"
				}
				body := randomBytes(t, 10_000)
				r := &forgetest.Repo{Kind: kind, Path: repo, Private: private, Token: secret,
					Refs:     map[string]string{"main": commitA, "release/2026": commitB, commitA: commitA},
					Archives: map[string][]byte{commitA: body, commitB: randomBytes(t, 5000)}}
				l.forge.Add(r)
				src := source(kind, repo)
				token := corpussource.Token("")
				if private {
					token = secret
					// Without the credential, a private repository does not exist.
					if _, err := l.fetcher.Resolve(t.Context(), src, "main", ""); !errors.Is(err, corpussource.ErrNotFound) {
						t.Fatal("a private repository answered without its credential:", err)
					}
					if _, err := l.fetcher.Resolve(t.Context(), src, "main", "wrong-token"); !errors.Is(err, corpussource.ErrNotFound) {
						t.Fatal("a private repository answered a wrong credential:", err)
					}
				}
				commit, err := l.fetcher.Resolve(t.Context(), src, "main", token)
				if err != nil || commit != commitA {
					t.Fatal("resolve main:", commit, err)
				}
				if commit, err = l.fetcher.Resolve(t.Context(), src, "release/2026", token); err != nil || commit != commitB {
					t.Fatal("resolve a ref with a slash:", commit, err)
				}
				if _, err = l.fetcher.Resolve(t.Context(), src, "missing", token); !errors.Is(err, corpussource.ErrNotFound) {
					t.Fatal("an unknown ref:", err)
				}
				l.forge.Reset()
				path := filepath.Join(l.dir, "source.bin")
				a, err := l.fetcher.Archive(t.Context(), src, commitA, token, path)
				if err != nil {
					t.Fatal("archive:", err)
				}
				checkStored(t, path, body, a)
				for _, req := range l.forge.Requests() {
					forge := req.Host == forgetest.GitHubAPI || req.Host == forgetest.GitLabHost
					if (req.Authorization != "") != (private && forge) {
						t.Errorf("Authorization %v at %s %s", req.Authorization != "", req.Host, req.Path)
					}
					if strings.Contains(req.Query, secret) {
						t.Error("the credential is in a URL")
					}
				}
				if kind == corpussource.GitHub && len(l.forge.Requests()) != 2 {
					t.Fatal("GitHub's archive is the API's redirect to its archive host:", l.forge.Requests())
				}
				if _, err = l.fetcher.Archive(t.Context(), src, commitB[:39]+"3", token, path); !errors.Is(err, corpussource.ErrNotFound) {
					t.Fatal("an unknown commit's archive:", err)
				}
			})
		}
	}
}

// A redirect to a host the rule does not declare is refused before anything
// is sent there, and leaves no file.
func TestRedirectToAnUndeclaredHostIsRefused(t *testing.T) {
	l := newLab(t, limits)
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitHub, Path: "acme/handbook", Archives: map[string][]byte{commitA: randomBytes(t, 100)}})
	l.forge.ArchiveRedirect = forgetest.Elsewhere
	path := filepath.Join(l.dir, "source.bin")
	if _, err := l.fetcher.Archive(t.Context(), source(corpussource.GitHub, "acme/handbook"), commitA, "", path); !errors.Is(err, corpussource.ErrPolicy) {
		t.Fatal("a redirect to an undeclared host:", err)
	}
	for _, req := range l.forge.Requests() {
		if req.Host == forgetest.Elsewhere {
			t.Fatal("the undeclared host was reached")
		}
	}
	if entries, _ := os.ReadDir(l.dir); len(entries) != 0 {
		t.Fatal("a refused archive left files:", entries)
	}
}

// An archive past the limit is refused, whether the forge announces its
// size or streams it; one at the limit is taken.
func TestOversizedArchiveIsRefused(t *testing.T) {
	small := corpussource.Limits{ArchiveBytes: 3000, LFSBytes: 1, LFSObjects: 1}
	for _, chunked := range []bool{false, true} {
		l := newLab(t, small)
		l.forge.Chunked = chunked
		l.forge.Add(&forgetest.Repo{Kind: corpussource.GitLab, Path: "school/big",
			Archives: map[string][]byte{commitA: randomBytes(t, 3001), commitB: randomBytes(t, 3000)}})
		src := source(corpussource.GitLab, "school/big")
		path := filepath.Join(l.dir, "source.bin")
		if _, err := l.fetcher.Archive(t.Context(), src, commitA, "", path); !errors.Is(err, corpussource.ErrTooLarge) {
			t.Fatal("chunked", chunked, ": an archive past the limit:", err)
		}
		if entries, _ := os.ReadDir(l.dir); len(entries) != 0 {
			t.Fatal("a refused archive left files:", entries)
		}
		if a, err := l.fetcher.Archive(t.Context(), src, commitB, "", path); err != nil || a.Bytes != 3000 {
			t.Fatal("chunked", chunked, ": an archive at the limit:", a, err)
		}
	}
}

// The host never decodes: an archive sent with a content encoding (which
// Go's client would otherwise undo) is refused, and nothing is stored.
func TestEncodedArchiveIsRefused(t *testing.T) {
	l := newLab(t, limits)
	l.forge.ArchiveEncoding = "gzip"
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitLab, Path: "school/x", Archives: map[string][]byte{commitA: randomBytes(t, 100)}})
	path := filepath.Join(l.dir, "source.bin")
	if _, err := l.fetcher.Archive(t.Context(), source(corpussource.GitLab, "school/x"), commitA, "", path); !errors.Is(err, corpussource.ErrIntegrity) {
		t.Fatal("an encoded archive:", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an encoded archive was stored")
	}
}

// A repository or a forge no rule approves is refused before any
// connection, as is a source whose kind is not its forge's.
func TestUnapprovedSourcesAreRefusedBeforeAnyConnection(t *testing.T) {
	l := newLab(t, limits)
	for _, src := range []corpussource.Source{
		{Kind: corpussource.GitHub, Host: forgetest.GitHubHost, Repository: "other/handbook"},
		{Kind: corpussource.GitHub, Host: forgetest.GitHubHost, Repository: "acmeish/handbook"},
		{Kind: corpussource.GitLab, Host: forgetest.GitHubHost, Repository: "acme/handbook"},
		{Kind: corpussource.GitHub, Host: "unknown.test", Repository: "acme/handbook"},
		{Kind: corpussource.GitHub, Host: forgetest.GitHubHost, Repository: "acme/../secret"},
		{Kind: corpussource.GitHub, Host: forgetest.GitHubHost, Repository: "acme/a/b"},
	} {
		if _, err := l.fetcher.Resolve(t.Context(), src, "main", ""); !errors.Is(err, corpussource.ErrPolicy) {
			t.Error(src, ": not refused by policy:", err)
		}
		if _, err := l.fetcher.Archive(t.Context(), src, commitA, "", filepath.Join(l.dir, "x")); !errors.Is(err, corpussource.ErrPolicy) {
			t.Error(src, ": archive not refused by policy:", err)
		}
	}
	if len(l.forge.Dialed) != 0 {
		t.Fatal("a refused source was dialed:", l.forge.Dialed)
	}
	// Case does not matter on the forges, nor in the rules.
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitHub, Path: "Acme/Handbook", Refs: map[string]string{"main": commitA}})
	if c, err := l.fetcher.Resolve(t.Context(), source(corpussource.GitHub, "Acme/Handbook"), "main", ""); err != nil || c != commitA {
		t.Fatal("a repository in another case:", c, err)
	}
}

// Addresses are checked after DNS resolution: a forge whose name resolves to
// an internal address is refused unless the operator allows it, over
// HTTPS, and a metadata or link-local address never.
func TestInternalForgesNeedTheOperatorsConsent(t *testing.T) {
	internal := corpussource.Rule{Host: "gitlab.internal", Kind: corpussource.GitLab, Repositories: []string{"school/"}}
	src := corpussource.Source{Kind: corpussource.GitLab, Host: "gitlab.internal", Repository: "school/x"}
	f := forgetest.New(t)
	try := func(allowed []string, addr string) error {
		f.Resolve("gitlab.internal", addr)
		fetcher, err := corpussource.NewForTests(corpussource.Policy{Rules: []corpussource.Rule{internal}, AllowedInternalHosts: allowed}, limits, f.Network())
		if err != nil {
			t.Fatal(err)
		}
		_, err = fetcher.Resolve(t.Context(), src, "main", "")
		return err
	}
	if err := try(nil, "10.0.0.5"); !errors.Is(err, corpussource.ErrPolicy) {
		t.Fatal("an internal forge without consent:", err)
	}
	if len(f.Dialed) != 0 {
		t.Fatal("a refused address was dialed:", f.Dialed)
	}
	// Allowed by name or by prefix, the forge is reached (it knows no such
	// project: 404).
	for _, allowed := range [][]string{{"gitlab.internal:443"}, {"10.0.0.0/24"}} {
		if err := try(allowed, "10.0.0.5"); !errors.Is(err, corpussource.ErrNotFound) {
			t.Fatal("an allowed internal forge:", allowed, err)
		}
	}
	f.Dialed = nil
	for _, addr := range []string{"169.254.169.254", "0.0.0.0", "fe80::1", "168.63.129.16"} {
		if err := try([]string{"gitlab.internal:443"}, addr); !errors.Is(err, corpussource.ErrPolicy) {
			t.Error("an address never allowed:", addr, err)
		}
	}
	if len(f.Dialed) != 0 {
		t.Fatal("a never-allowed address was dialed:", f.Dialed)
	}
	if _, err := corpussource.New(corpussource.Policy{Rules: []corpussource.Rule{internal}, AllowedInternalHosts: []string{"169.254.169.254:80"}}, limits); err == nil {
		t.Fatal("a metadata address was accepted in allowed_internal_hosts")
	}
}

// The rules are checked as the registry's are: no duplicate host, a known
// kind, repository prefixes, host names (no address unless local).
func TestPolicyValidation(t *testing.T) {
	ok := forgetest.Rules()
	if err := (corpussource.Policy{Rules: ok}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corpussource.Rule){
		"kind":            func(r *corpussource.Rule) { r.Kind = "bitbucket" },
		"no repositories": func(r *corpussource.Rule) { r.Repositories = nil },
		"repository":      func(r *corpussource.Rule) { r.Repositories = []string{"../x"} },
		"host":            func(r *corpussource.Rule) { r.Host = "GitHub.com" },
		"address":         func(r *corpussource.Rule) { r.Host = "10.0.0.1" },
		"archive host":    func(r *corpussource.Rule) { r.ArchiveHosts = []string{"https://codeload.github.com"} },
		"lfs host":        func(r *corpussource.Rule) { r.LFSHosts = []string{"1.2.3.4"} },
	} {
		rules := forgetest.Rules()
		mutate(&rules[0])
		if err := (corpussource.Policy{Rules: rules}).Validate(); !errors.Is(err, corpussource.ErrPolicy) {
			t.Error(name, ": accepted")
		}
	}
	twice := append(forgetest.Rules(), forgetest.Rules()[0])
	if err := (corpussource.Policy{Rules: twice}).Validate(); err == nil {
		t.Error("a host named twice was accepted")
	}
	local := corpussource.Rule{Host: "127.0.0.1:3000", Kind: corpussource.GitLab, Repositories: []string{"dev/"}, Local: true}
	if err := (corpussource.Policy{Rules: []corpussource.Rule{local}}).Validate(); err != nil {
		t.Error("a local rule on an address:", err)
	}
	for _, raw := range []string{"https://github.com/acme/handbook", "https://gitlab.example.org/school/finance/l3"} {
		kind := corpussource.GitHub
		if strings.Contains(raw, "gitlab") {
			kind = corpussource.GitLab
		}
		if _, err := corpussource.ParseURL(kind, raw); err != nil {
			t.Error(raw, err)
		}
	}
	for _, raw := range []string{"http://github.com/acme/x", "https://user@github.com/acme/x", "https://github.com/acme/x?y", "https://github.com/acme/x#y",
		"https://github.com/acme", "https://github.com/acme/x.git", "https://github.com/acme/%2e%2e", "https://github.com/a/b/c"} {
		if _, err := corpussource.ParseURL(corpussource.GitHub, raw); err == nil {
			t.Error("accepted", raw)
		}
	}
}

func TestTokensNeverFormat(t *testing.T) {
	tok := corpussource.Token(secret)
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %s %q %#v %+v", tok, tok, tok, tok, tok), fmt.Sprint(struct{ T corpussource.Token }{tok})} {
		if strings.Contains(s, secret) {
			t.Fatal("a token formatted as itself:", s)
		}
	}
}
