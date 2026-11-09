package ociregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

// Push publishes the package files in dir (harness.yaml, checksums.json,
// harness.ext4, as written by harnesspkg.WriteChecksums) to repository on the
// rule's registry and returns the reference pinned by digest. tag may be empty.
func Push(ctx context.Context, rule Rule, repository, tag, dir string) (Reference, error) {
	if err := (Policy{Rules: []Rule{rule}}).Validate(); err != nil {
		return Reference{}, err
	}
	if !validRepository(repository) || tag != "" && !tagPattern.MatchString(tag) {
		return Reference{}, fmt.Errorf("%w: repository or tag", ErrPolicy)
	}
	c := newClient(rule, 0)
	scope := "repository:" + repository + ":pull,push"
	media := []string{harnesspkg.ManifestMediaType, harnesspkg.ChecksumsMediaType, harnesspkg.RootfsMediaType}
	names := []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile}
	m := imageManifest{SchemaVersion: 2, MediaType: ociManifestType, ArtifactType: harnesspkg.ArtifactType,
		Config: descriptor{MediaType: emptyMediaType, Digest: emptyDigest, Size: 2}}
	if err := c.pushBlob(ctx, repository, scope, emptyDigest, []byte("{}")); err != nil {
		return Reference{}, err
	}
	for i, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Reference{}, err
		}
		d := harnesspkg.Digest(b)
		if err = c.pushBlob(ctx, repository, scope, d, b); err != nil {
			return Reference{}, err
		}
		m.Layers = append(m.Layers, descriptor{MediaType: media[i], Digest: d, Size: int64(len(b)),
			Annotations: map[string]string{"org.opencontainers.image.title": name}})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Reference{}, err
	}
	digest := sha256Hex(raw)
	target := digest
	if tag != "" {
		target = tag
	}
	resp, err := c.do(ctx, repository, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPut, c.base()+"/v2/"+repository+"/manifests/"+target, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", ociManifestType)
		}
		return req, err
	})
	if err != nil {
		return Reference{}, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Reference{}, statusError(resp, "manifest upload")
	}
	return Reference{Registry: rule.Host, Repository: repository, Tag: tag, Digest: digest}, nil
}

// pushBlob uploads one blob monolithically unless the registry already has it.
func (c *client) pushBlob(ctx context.Context, repo, scope, digest string, b []byte) error {
	head, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		return http.NewRequest(http.MethodHead, c.base()+"/v2/"+repo+"/blobs/"+digest, nil)
	})
	if err != nil {
		return err
	}
	drain(head)
	if head.StatusCode == http.StatusOK {
		return nil
	}
	start, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, c.base()+"/v2/"+repo+"/blobs/uploads/", nil)
	})
	if err != nil {
		return err
	}
	drain(start)
	if start.StatusCode != http.StatusAccepted {
		return statusError(start, "upload start")
	}
	loc, err := url.Parse(start.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("%w: upload location", ErrUnavailable)
	}
	base, _ := url.Parse(c.base() + "/")
	loc = base.ResolveReference(loc)
	if !c.allowedURL(loc, nil) {
		return fmt.Errorf("%w: upload location on another host", ErrPolicy)
	}
	q := loc.Query()
	q.Set("digest", digest)
	loc.RawQuery = q.Encode()
	put, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPut, loc.String(), bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = int64(len(b))
		}
		return req, err
	})
	if err != nil {
		return err
	}
	defer drain(put)
	if put.StatusCode != http.StatusCreated {
		return statusError(put, "blob upload")
	}
	_, _ = io.Copy(io.Discard, put.Body)
	return nil
}
