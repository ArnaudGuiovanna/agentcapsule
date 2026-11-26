package ociregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
)

// Push publishes the package files in dir (harness.yaml, checksums.json,
// harness.ext4, as written by harnesspkg.WriteChecksums) to repository on the
// rule's registry and returns the reference pinned by digest. tag may be empty.
func Push(ctx context.Context, rule Rule, repository, tag, dir string) (Reference, error) {
	if err := (Policy{Rules: []Rule{rule}}).Validate(); err != nil {
		return Reference{}, err
	}
	if !validRepository(repository) || tag != "" && !reference.ValidTag(tag) {
		return Reference{}, fmt.Errorf("%w: repository or tag", ErrPolicy)
	}
	c := newClient(rule, 0)
	scope := "repository:" + repository + ":pull,push"
	m, raw, err := packageManifest(dir)
	if err != nil {
		return Reference{}, err
	}
	if err = c.pushBlob(ctx, repository, scope, emptyDigest, []byte("{}")); err != nil {
		return Reference{}, err
	}
	for _, d := range m.Layers {
		file, err := os.Open(filepath.Join(dir, d.Annotations["org.opencontainers.image.title"]))
		if err != nil {
			return Reference{}, err
		}
		err = c.upload(ctx, repository, scope, d.Digest, file, d.Size)
		closeErr := file.Close()
		if err != nil {
			return Reference{}, err
		}
		if closeErr != nil {
			return Reference{}, closeErr
		}
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

// PackageDigest calculates the exact manifest digest used by Push without a registry.
func PackageDigest(dir string) (string, error) {
	_, raw, err := packageManifest(dir)
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func packageManifest(dir string) (imageManifest, []byte, error) {
	m := imageManifest{SchemaVersion: 2, MediaType: ociManifestType, ArtifactType: harnesspkg.ArtifactType,
		Config: descriptor{MediaType: emptyMediaType, Digest: emptyDigest, Size: 2}}
	for _, layer := range []struct{ name, media string }{
		{harnesspkg.ManifestFile, harnesspkg.ManifestMediaType},
		{harnesspkg.ChecksumsFile, harnesspkg.ChecksumsMediaType},
		{harnesspkg.RootfsFile, harnesspkg.RootfsMediaType},
	} {
		f, err := os.Open(filepath.Join(dir, layer.name))
		if err != nil {
			return m, nil, err
		}
		h := sha256.New()
		size, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return m, nil, err
		}
		m.Layers = append(m.Layers, descriptor{MediaType: layer.media, Digest: fmt.Sprintf("sha256:%x", h.Sum(nil)), Size: size,
			Annotations: map[string]string{"org.opencontainers.image.title": layer.name}})
	}
	raw, err := json.Marshal(m)
	return m, raw, err
}

func (c *client) pushBlob(ctx context.Context, repo, scope, digest string, b []byte) error {
	return c.upload(ctx, repo, scope, digest, bytes.NewReader(b), int64(len(b)))
}

const uploadChunk = 4 << 20

func (c *client) upload(ctx context.Context, repo, scope, digest string, source io.ReaderAt, size int64) error {
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
	if head.StatusCode != http.StatusNotFound && head.StatusCode != http.StatusMethodNotAllowed {
		return statusError(head, "blob existence check")
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
	loc, err := c.uploadLocation(start)
	if err != nil {
		return err
	}
	var offset int64
	// Chunk large layers and use each returned upload URL (registries can
	// rotate its token after every PATCH). A fresh reader replays an auth challenge.
	chunkSize := int64(uploadChunk)
	if value := start.Header.Get("OCI-Chunk-Min-Length"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("%w: invalid minimum upload chunk", ErrUnavailable)
		}
		chunkSize = max(chunkSize, n)
	}
	for size > chunkSize && offset < size {
		loc, offset, err = c.sendChunk(ctx, repo, scope, loc, source, offset, min(chunkSize, size-offset))
		if err != nil {
			return err
		}
	}
	q := loc.Query()
	q.Set("digest", digest)
	loc.RawQuery = q.Encode()
	put, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		// A zero-length SectionReader is an unknown-length Body to net/http,
		// which would send a chunked transfer instead of Content-Length: 0.
		var body io.Reader
		if offset < size {
			body = io.NewSectionReader(source, offset, size-offset)
		}
		req, err := http.NewRequest(http.MethodPut, loc.String(), body)
		if err == nil {
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = size - offset
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

// A PATCH may reach the registry even when its reply never reaches the
// publisher. Read the session offset before retrying, and resume partial
// chunks from the first unconfirmed byte. A retry never assumes acceptance.
func (c *client) sendChunk(ctx context.Context, repo, scope string, loc *url.URL, source io.ReaderAt, start, length int64) (*url.URL, int64, error) {
	end := start + length
	for attempt := 0; ; attempt++ {
		resp, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodPatch, loc.String(), io.NewSectionReader(source, start, length))
			if err == nil {
				req.ContentLength = length
				req.Header.Set("Content-Type", "application/octet-stream")
				req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", start, end-1))
			}
			return req, err
		})
		if err == nil {
			drain(resp)
			if resp.StatusCode == http.StatusAccepted {
				if confirmed := resp.Header.Get("Range"); confirmed != "" && strings.TrimPrefix(confirmed, "bytes=") != fmt.Sprintf("0-%d", end-1) {
					return nil, start, fmt.Errorf("%w: blob upload offset", ErrIntegrity)
				}
				next, err := c.uploadLocation(resp)
				return next, end, err
			}
			err = statusError(resp, "blob chunk")
			if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable && resp.StatusCode != http.StatusRequestTimeout &&
				resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return nil, start, err
			}
		}
		if !errors.Is(err, ErrUnavailable) || attempt == 3 {
			return nil, start, fmt.Errorf("upload bytes %d-%d: %w", start, end-1, err)
		}
		select {
		case <-ctx.Done():
			return nil, start, ctx.Err()
		case <-time.After(time.Second << attempt):
		}
		next, confirmed, err := c.uploadStatus(ctx, repo, scope, loc, start, end)
		if err != nil || confirmed > start {
			return next, confirmed, err
		}
		loc = next
	}
}

func (c *client) uploadStatus(ctx context.Context, repo, scope string, loc *url.URL, start, end int64) (*url.URL, int64, error) {
	status, err := c.do(ctx, repo, scope, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, loc.String(), nil)
	})
	if err != nil {
		// GHCR redirects the status GET to a web page. Keep credentials on the
		// registry and replay the same inclusive range until it is acknowledged.
		if errors.Is(err, ErrPolicy) || errors.Is(err, ErrUnavailable) {
			return loc, start, nil
		}
		return nil, start, err
	}
	drain(status)
	switch status.StatusCode {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return loc, start, nil
	case http.StatusNoContent, http.StatusAccepted:
	default:
		if status.StatusCode >= 500 {
			return loc, start, nil
		}
		return nil, start, statusError(status, "blob upload status")
	}
	if status.Header.Get("Location") != "" {
		loc, err = c.uploadLocation(status)
		if err != nil {
			return nil, start, err
		}
	}
	confirmed, ok := strings.CutPrefix(strings.TrimPrefix(status.Header.Get("Range"), "bytes="), "0-")
	last, err := strconv.ParseInt(confirmed, 10, 64)
	if !ok || err != nil || last < 0 || last < start-1 || last >= end {
		return nil, start, fmt.Errorf("%w: blob upload status offset", ErrIntegrity)
	}
	// Registries also use 0-0 for a new session with zero bytes.
	if start == 0 && last == 0 {
		return loc, 0, nil
	}
	return loc, last + 1, nil
}

func (c *client) uploadLocation(resp *http.Response) (*url.URL, error) {
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("%w: missing upload location", ErrUnavailable)
	}
	loc, err := resp.Request.URL.Parse(location)
	if err != nil || !c.allowedURL(loc, nil) {
		return nil, fmt.Errorf("%w: invalid upload location", ErrPolicy)
	}
	return loc, nil
}
