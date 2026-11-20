//go:build corpuslive

package corpussource_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
)

// liveEnv reads a setting of the live test, or its default.
func liveEnv(name, def string) string {
	if v := os.Getenv("AGENTCAPSULE_CORPUS_LIVE_" + name); v != "" {
		return v
	}
	return def
}

// liveToken reads a token from the file a variable names, if any. The
// token is never printed.
func liveToken(t *testing.T, name string) corpussource.Token {
	t.Helper()
	path := os.Getenv("AGENTCAPSULE_CORPUS_LIVE_" + name + "_TOKEN_FILE")
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("the token file of", name, "cannot be read")
	}
	return corpussource.Token(strings.TrimSpace(string(raw)))
}

func hosts(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// Lot 3's exit criterion on real forges, run by hand, never by the
// campaigns: the archive of a GitHub and of a GitLab repository, pinned on
// the commit its ref names, and an LFS object of each when one is named.
// By default it reads small public repositories anonymously, read-only,
// over HTTPS:
//
//	go test -tags corpuslive -count=1 ./internal/corpussource -run TestLiveForges -v
//
// A private repository takes its owner's read-only token from a file
// (docs/registry.md#corpus-sources):
//
//	AGENTCAPSULE_CORPUS_LIVE_GITHUB=acme/private AGENTCAPSULE_CORPUS_LIVE_GITHUB_TOKEN_FILE=/path/to/token
//	AGENTCAPSULE_CORPUS_LIVE_GITLAB=group/private AGENTCAPSULE_CORPUS_LIVE_GITLAB_TOKEN_FILE=/path/to/token
//
// Each forge's ref, LFS object ("oid:size") and extra hosts can be set too:
// see the variables below.
func TestLiveForges(t *testing.T) {
	limits := corpussource.Limits{ArchiveBytes: 256 << 20, LFSBytes: 256 << 20, LFSObjects: 100}
	gitlabHost := liveEnv("GITLAB_HOST", "gitlab.com")
	policy := corpussource.Policy{Rules: []corpussource.Rule{
		{Host: "github.com", Kind: corpussource.GitHub, Repositories: []string{strings.Split(liveEnv("GITHUB", "octocat/Hello-World"), "/")[0] + "/"},
			ArchiveHosts: hosts(liveEnv("GITHUB_ARCHIVE_HOSTS", "codeload.github.com")),
			LFSHosts:     hosts(liveEnv("GITHUB_LFS_HOSTS", "github-cloud.githubusercontent.com,media.githubusercontent.com"))},
		{Host: gitlabHost, Kind: corpussource.GitLab, Repositories: []string{strings.Split(liveEnv("GITLAB", "gitlab-org/gitlab-test"), "/")[0] + "/"},
			ArchiveHosts: hosts(liveEnv("GITLAB_ARCHIVE_HOSTS", "")), LFSHosts: hosts(liveEnv("GITLAB_LFS_HOSTS", ""))},
	}}
	f, err := corpussource.New(policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, kind, host, repo, ref, lfs string }{
		{"GITHUB", corpussource.GitHub, "github.com", liveEnv("GITHUB", "octocat/Hello-World"), liveEnv("GITHUB_REF", "master"), liveEnv("GITHUB_LFS", "")},
		{"GITLAB", corpussource.GitLab, gitlabHost, liveEnv("GITLAB", "gitlab-org/gitlab-test"), liveEnv("GITLAB_REF", "master"),
			liveEnv("GITLAB_LFS", "91eff75a492a3ed0dfcb544d7f31326bc4014c8551849c192fd1e48d4dd2c897:1575078")},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := corpussource.Source{Kind: c.kind, Host: c.host, Repository: c.repo}
			token := liveToken(t, c.name)
			dir := t.TempDir()
			if keep := os.Getenv("AGENTCAPSULE_CORPUS_LIVE_DIR"); keep != "" {
				dir = filepath.Join(keep, strings.ToLower(c.name))
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			commit, err := f.Resolve(t.Context(), src, c.ref, token)
			if err != nil {
				t.Fatal("resolve", c.ref, err)
			}
			again, err := f.Resolve(t.Context(), src, commit, token)
			if err != nil || again != commit {
				t.Fatal("the commit does not resolve to itself:", again, err)
			}
			path := filepath.Join(dir, "source.bin")
			a, err := f.Archive(t.Context(), src, commit, token, path)
			if err != nil {
				t.Fatal("archive", err)
			}
			if err = corpussource.VerifyArchive(path, a); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil || raw[0] != 0x1f || raw[1] != 0x8b {
				t.Fatal("the archive is not the forge's gzip bytes", err)
			}
			t.Logf("%s %s@%s: commit %s, archive %d bytes, sha256 %s, private=%v", c.name, c.repo, c.ref, commit, a.Bytes, a.SHA256, token != "")
			if c.lfs == "" {
				return
			}
			oid, size, _ := strings.Cut(c.lfs, ":")
			n, err := strconv.ParseInt(size, 10, 64)
			if err != nil {
				t.Fatal("LFS object", c.lfs)
			}
			d, err := f.LFS(t.Context(), src, token, []corpussource.Pointer{{OID: oid, Size: n}}, dir, corpussource.LFSOptions{})
			if err != nil {
				t.Fatal("LFS", err)
			}
			t.Logf("%s LFS: %d object of %d bytes checked against its oid; drive %d bytes, sha256 %s", c.name, d.Objects, d.ObjectBytes, d.Bytes, d.SHA256)
		})
	}
}
