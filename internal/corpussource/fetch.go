package corpussource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// Block is the alignment of the build drives: an archive is padded with
// zeros to a multiple of it, and each LFS object starts at a multiple of it.
const Block = 4096

// Limits bound what one build fetches (corpus.max_archive_mib,
// corpus.max_lfs_mib, corpus.max_lfs_objects).
type Limits struct {
	ArchiveBytes int64
	LFSBytes     int64
	LFSObjects   int
}

// Fetcher fetches corpus sources under a policy.
type Fetcher struct {
	policy  Policy
	limits  Limits
	clients map[string]*client
}

// New returns a fetcher for the policy and limits, both validated.
func New(p Policy, l Limits) (*Fetcher, error) {
	return newFetcher(p, l, TestNetwork{})
}

// NewForTests is New on a test network. It panics outside a test binary
// built by go test, so that no production path can reach it.
func NewForTests(p Policy, l Limits, n TestNetwork) (*Fetcher, error) {
	if !testing.Testing() {
		panic("corpussource: NewForTests outside a test binary")
	}
	return newFetcher(p, l, n)
}

func newFetcher(p Policy, l Limits, n TestNetwork) (*Fetcher, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if l.ArchiveBytes < 1 || l.LFSBytes < 0 || l.LFSObjects < 0 || l.LFSObjects > 1_000_000 {
		return nil, fmt.Errorf("%w: limits", ErrPolicy)
	}
	allow, err := llmgateway.ParseAllowlist(p.AllowedInternalHosts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	f := &Fetcher{policy: p, limits: l, clients: map[string]*client{}}
	for _, r := range p.Rules {
		f.clients[r.Host] = newClient(r, allow, n)
	}
	return f, nil
}

// Policy returns the fetcher's policy.
func (f *Fetcher) Policy() Policy { return f.policy }

func (f *Fetcher) client(s Source) (*client, error) {
	rule, err := f.policy.Allow(s)
	if err != nil {
		return nil, err
	}
	return f.clients[rule.Host], nil
}

func ValidCommit(s string) bool { return repository.ValidCommit(s) }
func ValidRef(s string) bool    { return repository.ValidRef(s) }

// pathEscape escapes each segment of a slash-separated name.
func pathEscape(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// project is a GitLab project's identifier in an API path: its URL-encoded
// path.
func project(repository string) string { return url.PathEscape(repository) }

// Resolve asks the forge which commit ref names: GitHub
// GET /repos/{repository}/commits/{ref}, GitLab
// GET /projects/{repository}/repository/commits/{ref}.
func (f *Fetcher) Resolve(ctx context.Context, s Source, ref string, token Token) (string, error) {
	c, err := f.client(s)
	if err != nil {
		return "", err
	}
	if !ValidRef(ref) {
		return "", fmt.Errorf("%w: the ref is not one the forge can be asked about", ErrNotFound)
	}
	var raw string
	header := map[string]string{"Accept": "application/json"}
	if s.Kind == GitHub {
		// The bare SHA, not the commit with its files and patches.
		raw = c.api() + "/repos/" + pathEscape(s.Repository) + "/commits/" + pathEscape(ref)
		header = map[string]string{"Accept": "application/vnd.github.sha", "X-GitHub-Api-Version": "2022-11-28"}
	} else {
		raw = c.api() + "/projects/" + project(s.Repository) + "/repository/commits/" + url.PathEscape(ref)
	}
	resp, err := c.do(ctx, http.MethodGet, raw, nil, bearer(token), header)
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", statusError(resp, "the ref")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnavailable, redact(err))
	}
	if sha := string(bytes.TrimSpace(body)); s.Kind == GitHub && ValidCommit(sha) {
		return sha, nil
	}
	var commit struct {
		ID  string `json:"id"`
		SHA string `json:"sha"`
	}
	if err = json.Unmarshal(body, &commit); err != nil {
		return "", fmt.Errorf("%w: the forge's answer for the ref", ErrUnavailable)
	}
	sha := commit.ID
	if s.Kind == GitHub {
		sha = commit.SHA
	}
	if !ValidCommit(sha) {
		return "", fmt.Errorf("%w: the forge named no commit for the ref", ErrIntegrity)
	}
	return sha, nil
}

// Archive is a downloaded archive: its exact size before padding and the
// sha256 of those bytes, in hexadecimal.
type Archive struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Padded is the size of a file holding n bytes padded to a whole block.
func Padded(n int64) int64 { return (n + Block - 1) / Block * Block }

// Archive streams the commit's archive to path, at most the archive limit,
// hashing it as it arrives, then pads it with zeros to a whole block: GitHub
// GET /repos/{repository}/tarball/{commit}, which redirects to its archive
// host, GitLab GET /projects/{repository}/repository/archive.tar.gz?sha=.
// The bytes are written as they come; nothing reads them back but the hash.
func (f *Fetcher) Archive(ctx context.Context, s Source, commit string, token Token, path string) (Archive, error) {
	c, err := f.client(s)
	if err != nil {
		return Archive{}, err
	}
	if !ValidCommit(commit) {
		return Archive{}, fmt.Errorf("%w: commit", ErrNotFound)
	}
	raw := c.api() + "/projects/" + project(s.Repository) + "/repository/archive.tar.gz?sha=" + commit
	if s.Kind == GitHub {
		raw = c.api() + "/repos/" + pathEscape(s.Repository) + "/tarball/" + commit
	}
	resp, err := c.do(ctx, http.MethodGet, raw, nil, bearer(token), nil)
	if err != nil {
		return Archive{}, err
	}
	defer drain(resp)
	switch {
	case resp.StatusCode != http.StatusOK:
		return Archive{}, statusError(resp, "the archive")
	case encoded(resp):
		return Archive{}, fmt.Errorf("%w: the archive came with a content encoding", ErrIntegrity)
	case resp.ContentLength > f.limits.ArchiveBytes:
		return Archive{}, fmt.Errorf("%w: the archive is past %d bytes", ErrTooLarge, f.limits.ArchiveBytes)
	}
	partial := path + ".partial"
	out, err := os.OpenFile(partial, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return Archive{}, err
	}
	defer func() {
		out.Close()
		_ = os.Remove(partial)
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, f.limits.ArchiveBytes+1))
	switch {
	case err != nil && isLocal(err):
		return Archive{}, err
	case err != nil:
		return Archive{}, fmt.Errorf("%w: archive download: %s", ErrUnavailable, redact(err))
	case n > f.limits.ArchiveBytes:
		return Archive{}, fmt.Errorf("%w: the archive is past %d bytes", ErrTooLarge, f.limits.ArchiveBytes)
	case n == 0:
		return Archive{}, fmt.Errorf("%w: an empty archive", ErrIntegrity)
	case resp.ContentLength >= 0 && n != resp.ContentLength:
		return Archive{}, fmt.Errorf("%w: the archive ended early", ErrUnavailable)
	}
	if err = finish(out, Padded(n)); err != nil {
		return Archive{}, err
	}
	if err = os.Rename(partial, path); err != nil {
		return Archive{}, err
	}
	return Archive{Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, syncDir(filepath.Dir(path))
}

// localError marks a failure of the host's own disk, not of the forge.
type localError struct{ error }

func (e localError) Unwrap() error { return e.error }

func isLocal(err error) bool {
	var p *os.PathError
	return errors.As(err, &p) || errors.As(err, new(localError))
}

// finish pads the file with zeros to size, then writes it to disk.
func finish(f *os.File, size int64) error {
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Sync()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// VerifyArchive checks that path holds the archive a: its padded size, the
// sha256 of its first a.Bytes bytes, and zeros after them. A retry reuses a
// recorded archive only if it passes: the forge may build another archive of
// the same commit, with other bytes.
func VerifyArchive(path string, a Archive) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() != Padded(a.Bytes) {
		return fmt.Errorf("%w: the archive's size", ErrIntegrity)
	}
	h := sha256.New()
	if _, err = io.CopyN(h, f, a.Bytes); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%w: the archive's digest", ErrIntegrity)
	}
	return zeros(f, st.Size()-a.Bytes)
}

// zeros checks that the next n bytes of r are zeros.
func zeros(r io.Reader, n int64) error {
	buf := make([]byte, Block)
	for n > 0 {
		k, err := io.ReadFull(r, buf[:min(n, Block)])
		if err != nil {
			return err
		}
		for _, b := range buf[:k] {
			if b != 0 {
				return fmt.Errorf("%w: the padding", ErrIntegrity)
			}
		}
		n -= int64(k)
	}
	return nil
}
