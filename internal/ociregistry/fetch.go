package ociregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

const (
	emptyMediaType = "application/vnd.oci.empty.v1+json"
	emptyDigest    = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type imageManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Subject       *descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Package is a verified harness package written to a staging directory.
type Package struct {
	Reference      Reference
	ManifestDigest string
	Manifest       harnesspkg.HarnessManifest
	RootfsDigest   string
	RootfsSize     int64
	// Dir holds harness.yaml, checksums.json and harness.ext4, each verified.
	Dir string
	// Signer is the ID of the publisher key whose signature was verified, or
	// empty when the rule trusts no key.
	Signer string
}

// Fetcher imports packages under a policy.
type Fetcher struct {
	policy    Policy
	maxRootfs int64
	clients   map[string]*client
}

func NewFetcher(policy Policy, maxRootfs int64) (*Fetcher, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if maxRootfs < harnesspkg.MinRootfsBytes || maxRootfs > 64<<30 {
		return nil, fmt.Errorf("%w: maximum harness size", ErrPolicy)
	}
	f := &Fetcher{policy: policy, maxRootfs: maxRootfs, clients: map[string]*client{}}
	for _, r := range policy.Rules {
		f.clients[r.Host] = newClient(r, 0)
	}
	return f, nil
}

// Fetch downloads and verifies the package pinned by ref into dir, which must
// exist and be empty. On error, dir may hold partial files the caller removes.
func (f *Fetcher) Fetch(ctx context.Context, ref Reference, dir string) (Package, error) {
	rule, err := f.policy.Allow(ref)
	if err != nil {
		return Package{}, err
	}
	c := f.clients[rule.Host]
	scope := "repository:" + ref.Repository + ":pull"
	resp, err := c.do(ctx, ref.Repository, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, c.base()+"/v2/"+ref.Repository+"/manifests/"+ref.Digest, nil)
		if err == nil {
			req.Header.Set("Accept", ociManifestType)
		}
		return req, err
	})
	if err != nil {
		return Package{}, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return Package{}, statusError(resp, "manifest")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return Package{}, fmt.Errorf("%w: manifest read", ErrUnavailable)
	}
	if len(raw) > maxManifest || sha256Hex(raw) != ref.Digest {
		return Package{}, fmt.Errorf("%w: manifest digest", ErrIntegrity)
	}
	layers, err := checkManifest(raw, f.maxRootfs)
	if err != nil {
		return Package{}, err
	}
	// A rule that trusts publisher keys requires a signature from one of them,
	// checked before any large download.
	signer := ""
	if len(rule.Keys) > 0 {
		if signer, err = c.trustedSigner(ctx, ref, scope, rule.Keys); err != nil {
			return Package{}, err
		}
	}
	files := []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile}
	for i, l := range layers {
		if err = f.blob(ctx, c, ref.Repository, scope, l, filepath.Join(dir, files[i])); err != nil {
			return Package{}, err
		}
	}
	pkg, err := verifyFiles(ctx, ref, dir, layers, f.maxRootfs)
	pkg.Signer = signer
	return pkg, err
}

// checkManifest accepts exactly the package layout: OCI image manifest, the
// harness artifact type, an empty config and the three layers in order.
func checkManifest(raw []byte, maxRootfs int64) ([]descriptor, error) {
	var m imageManifest
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: manifest does not parse", ErrIntegrity)
	}
	want := []struct {
		media string
		max   int64
	}{{harnesspkg.ManifestMediaType, harnesspkg.MaxManifestBytes}, {harnesspkg.ChecksumsMediaType, harnesspkg.MaxChecksumsBytes},
		{harnesspkg.RootfsMediaType, maxRootfs}}
	switch {
	case m.SchemaVersion != 2 || m.MediaType != ociManifestType:
		return nil, fmt.Errorf("%w: not an OCI image manifest", ErrIntegrity)
	case m.ArtifactType != harnesspkg.ArtifactType:
		return nil, fmt.Errorf("%w: not a harness package", ErrIntegrity)
	case m.Config.MediaType != emptyMediaType || m.Config.Digest != emptyDigest || m.Config.Size != 2:
		return nil, fmt.Errorf("%w: unexpected config", ErrIntegrity)
	case len(m.Layers) != len(want):
		return nil, fmt.Errorf("%w: unexpected layer count", ErrIntegrity)
	}
	for i, w := range want {
		l := m.Layers[i]
		if l.MediaType != w.media || !validDigest(l.Digest) || l.Size < 1 || l.Size > w.max {
			return nil, fmt.Errorf("%w: layer %d", ErrIntegrity, i)
		}
	}
	return m.Layers, nil
}

// blob streams one blob to path, refusing more bytes than declared and any
// digest mismatch. The file is created exclusively and made read-only.
func (f *Fetcher) blob(ctx context.Context, c *client, repo, scope string, l descriptor, path string) (err error) {
	resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, c.base()+"/v2/"+repo+"/blobs/"+l.Digest, nil)
	})
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return statusError(resp, "blob")
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, l.Size+1))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("%w: blob download interrupted", ErrUnavailable)
	}
	if n != l.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != l.Digest {
		return fmt.Errorf("%w: blob size or digest", ErrIntegrity)
	}
	if err = out.Sync(); err != nil {
		return err
	}
	// World-readable, never writable: each agent's VMM, running as its own
	// unprivileged user, reads the shared harness image.
	return os.Chmod(path, 0o444)
}

// verifyFiles checks the package content after every blob matched its digest.
func verifyFiles(ctx context.Context, ref Reference, dir string, layers []descriptor, maxRootfs int64) (Package, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(dir, harnesspkg.ManifestFile))
	if err != nil {
		return Package{}, err
	}
	m, err := harnesspkg.ParseManifest(manifestBytes)
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	checksumBytes, err := os.ReadFile(filepath.Join(dir, harnesspkg.ChecksumsFile))
	if err != nil {
		return Package{}, err
	}
	sums, err := harnesspkg.ParseChecksums(checksumBytes)
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if sums.Files[harnesspkg.ManifestFile] != layers[0].Digest || sums.Files[harnesspkg.RootfsFile] != layers[2].Digest {
		return Package{}, fmt.Errorf("%w: checksums.json disagrees with the package", ErrIntegrity)
	}
	rootfs, err := os.Open(filepath.Join(dir, harnesspkg.RootfsFile))
	if err != nil {
		return Package{}, err
	}
	defer rootfs.Close()
	if err = harnesspkg.CheckRootfs(rootfs, layers[2].Size, maxRootfs); err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if err = harnesspkg.InspectRootfs(ctx, filepath.Join(dir, harnesspkg.RootfsFile), m); err != nil {
		if errors.Is(err, harnesspkg.ErrInvalid) {
			return Package{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		return Package{}, err
	}
	return Package{Reference: ref, ManifestDigest: ref.Digest, Manifest: m, RootfsDigest: layers[2].Digest, RootfsSize: layers[2].Size, Dir: dir}, nil
}
