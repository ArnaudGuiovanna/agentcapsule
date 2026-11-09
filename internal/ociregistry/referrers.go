package ociregistry

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

type ociIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}

func mediaType(h string) string {
	t, _, err := mime.ParseMediaType(h)
	if err != nil {
		return ""
	}
	return t
}

// getManifest fetches a manifest or an index by digest or tag, bounded.
func (c *client) getManifest(ctx context.Context, repo, scope, reference, accept string) ([]byte, string, error) {
	resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, c.base()+"/v2/"+repo+"/manifests/"+reference, nil)
		if err == nil {
			req.Header.Set("Accept", accept)
		}
		return req, err
	})
	if err != nil {
		return nil, "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, "", statusError(resp, "manifest")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: manifest read", ErrUnavailable)
	}
	if len(raw) > maxManifest {
		return nil, "", fmt.Errorf("%w: manifest too large", ErrIntegrity)
	}
	return raw, mediaType(resp.Header.Get("Content-Type")), nil
}

// referrers lists what is attached to digest: through the referrers API, or
// the referrers tag schema ("sha256-<hex>") on registries without it.
func (c *client) referrers(ctx context.Context, repo, scope, digest string) ([]descriptor, error) {
	resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, c.base()+"/v2/"+repo+"/referrers/"+digest, nil)
		if err == nil {
			req.Header.Set("Accept", ociIndexType)
		}
		return req, err
	})
	if err != nil {
		return nil, err
	}
	var raw []byte
	if resp.StatusCode == http.StatusOK && mediaType(resp.Header.Get("Content-Type")) == ociIndexType {
		raw, err = io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
		drain(resp)
		if err != nil {
			return nil, fmt.Errorf("%w: referrers read", ErrUnavailable)
		}
	} else {
		status := resp.StatusCode
		drain(resp)
		switch status {
		case http.StatusOK, http.StatusNotFound, http.StatusBadRequest, http.StatusNotAcceptable:
		default:
			return nil, fmt.Errorf("%w: referrers answered %d", ErrUnavailable, status)
		}
		raw, _, err = c.getManifest(ctx, repo, scope, strings.Replace(digest, ":", "-", 1), ociIndexType)
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	var idx ociIndex
	if len(raw) > maxManifest || json.Unmarshal(raw, &idx) != nil {
		return nil, fmt.Errorf("%w: referrers index", ErrIntegrity)
	}
	return idx.Manifests, nil
}

// blobBytes reads a small blob into memory, checking size and digest.
func (c *client) blobBytes(ctx context.Context, repo, scope string, d descriptor, max int64) ([]byte, error) {
	if !validDigest(d.Digest) || d.Size < 1 || d.Size > max {
		return nil, fmt.Errorf("%w: blob descriptor", ErrIntegrity)
	}
	resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, c.base()+"/v2/"+repo+"/blobs/"+d.Digest, nil)
	})
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, "blob")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, d.Size+1))
	if err != nil {
		return nil, fmt.Errorf("%w: blob read", ErrUnavailable)
	}
	if int64(len(b)) != d.Size || sha256Hex(b) != d.Digest {
		return nil, fmt.Errorf("%w: blob size or digest", ErrIntegrity)
	}
	return b, nil
}

// trustedSigner finds a signature of ref by one of keys among the bundles
// attached to it, and returns the signing key's ID. A registry that cannot be
// read is ErrUnavailable (retried); no valid signature is ErrSignature.
func (c *client) trustedSigner(ctx context.Context, ref Reference, scope string, keys []PublisherKey) (string, error) {
	descs, err := c.referrers(ctx, ref.Repository, scope, ref.Digest)
	if err != nil {
		return "", err
	}
	last := fmt.Errorf("%w: the package has no signature", ErrSignature)
	seen := 0
	for _, d := range descs {
		if d.ArtifactType != BundleMediaType || !validDigest(d.Digest) {
			continue
		}
		if seen++; seen > maxReferrers {
			break
		}
		raw, _, err := c.getManifest(ctx, ref.Repository, scope, d.Digest, ociManifestType)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrIntegrity) || errors.Is(err, ErrDenied) {
			continue
		}
		if err != nil {
			return "", err
		}
		var m imageManifest
		if sha256Hex(raw) != d.Digest || json.Unmarshal(raw, &m) != nil || m.Subject == nil || m.Subject.Digest != ref.Digest {
			continue
		}
		for _, l := range m.Layers {
			if l.MediaType != BundleMediaType {
				continue
			}
			b, err := c.blobBytes(ctx, ref.Repository, scope, l, maxBundle)
			if errors.Is(err, ErrUnavailable) || ctx.Err() != nil {
				return "", errors.Join(err, ctx.Err())
			}
			if err != nil {
				continue
			}
			signer, err := VerifyBundle(b, ref.Digest, keys)
			if err == nil {
				return signer, nil
			}
			last = err
		}
	}
	return "", last
}

// Sign signs the package pinned by ref with key and attaches the signature as
// cosign v3 does ("cosign sign --key"): a Sigstore bundle in an OCI referrer
// whose subject is the package manifest. On a registry without the referrers
// API, the referrers tag index is updated too. It returns the referrer digest.
func Sign(ctx context.Context, rule Rule, ref Reference, key crypto.Signer) (string, error) {
	if err := (Policy{Rules: []Rule{rule}}).Validate(); err != nil {
		return "", err
	}
	if ref.Registry != rule.Host || !validRepository(ref.Repository) || !validDigest(ref.Digest) {
		return "", fmt.Errorf("%w: reference", ErrPolicy)
	}
	c := newClient(rule, 0)
	repo := ref.Repository
	scope := "repository:" + repo + ":pull,push"
	subject, subjectType, err := c.getManifest(ctx, repo, scope, ref.Digest, ociManifestType)
	if err != nil {
		return "", err
	}
	if sha256Hex(subject) != ref.Digest {
		return "", fmt.Errorf("%w: manifest digest", ErrIntegrity)
	}
	if subjectType == "" {
		subjectType = ociManifestType
	}
	bundle, err := SignBundle(ref.Digest, key)
	if err != nil {
		return "", err
	}
	if err = c.pushBlob(ctx, repo, scope, emptyDigest, []byte("{}")); err != nil {
		return "", err
	}
	bundleDigest := harnesspkg.Digest(bundle)
	if err = c.pushBlob(ctx, repo, scope, bundleDigest, bundle); err != nil {
		return "", err
	}
	annotations := map[string]string{"dev.sigstore.bundle.content": "dsse-envelope", bundlePredicateHeader: CosignSignPredicate}
	m := imageManifest{SchemaVersion: 2, MediaType: ociManifestType, ArtifactType: BundleMediaType,
		Config:      descriptor{MediaType: emptyMediaType, ArtifactType: BundleMediaType, Digest: emptyDigest, Size: 2},
		Layers:      []descriptor{{MediaType: BundleMediaType, Digest: bundleDigest, Size: int64(len(bundle))}},
		Subject:     &descriptor{MediaType: subjectType, Digest: ref.Digest, Size: int64(len(subject))},
		Annotations: annotations}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	digest := sha256Hex(raw)
	referrersAPI, err := c.putManifest(ctx, repo, scope, digest, ociManifestType, raw)
	if err != nil || referrersAPI {
		return digest, err
	}
	// Referrers tag schema: add this referrer to the index tagged sha256-<hex>.
	tag := strings.Replace(ref.Digest, ":", "-", 1)
	idx := ociIndex{SchemaVersion: 2, MediaType: ociIndexType}
	old, _, err := c.getManifest(ctx, repo, scope, tag, ociIndexType)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return "", err
	case json.Unmarshal(old, &idx) != nil:
		return "", fmt.Errorf("%w: referrers index", ErrIntegrity)
	}
	idx.Manifests = append(idx.Manifests, descriptor{MediaType: ociManifestType, ArtifactType: BundleMediaType,
		Digest: digest, Size: int64(len(raw)), Annotations: annotations})
	b, err := json.Marshal(idx)
	if err != nil {
		return "", err
	}
	_, err = c.putManifest(ctx, repo, scope, tag, ociIndexType, b)
	return digest, err
}

// putManifest uploads a manifest or index and reports whether the registry
// indexed its subject itself (OCI-Subject header, referrers API).
func (c *client) putManifest(ctx context.Context, repo, scope, reference, contentType string, raw []byte) (bool, error) {
	resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPut, c.base()+"/v2/"+repo+"/manifests/"+reference, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", contentType)
		}
		return req, err
	})
	if err != nil {
		return false, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return false, statusError(resp, "manifest upload")
	}
	return resp.Header.Get("OCI-Subject") != "", nil
}
