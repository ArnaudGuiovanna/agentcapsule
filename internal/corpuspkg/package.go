// Package corpuspkg handles corpus images (ADR 023 §2): the reproducible
// image a builder makes from a corpusmeta layout, the checks the host
// makes on an image without mounting it, and the host package the worker
// keeps in its cache.
//
// The host package mirrors a harness package, in <corpus.cache>/sha256/<hex>/
// where <hex> is the sha256 of corpus.ext4:
//
//	corpus.yaml    PackageManifest: the corpus, build, commit, builder, UUID and size
//	checksums.json sha256 of corpus.yaml and corpus.ext4
//	corpus.ext4    the image, read-only
//
// The worker writes it; it never comes from outside. The source side, the
// manifest an author keeps in the repository, is package source.
package corpuspkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

const (
	// GuestBase is the guest ABI that mounts corpora under /corpus.
	GuestBase = "agentcapsule-guest/2"

	ManifestFile  = "corpus.yaml"
	ChecksumsFile = "checksums.json"
	ImageFile     = "corpus.ext4"

	MaxManifestBytes  = 16 << 10
	MaxChecksumsBytes = 16 << 10
)

// Builder names the builder release that made an image.
type Builder struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	Digest  string `yaml:"digest" json:"digest"`
}

// PackageManifest is corpus.yaml. It carries no release version: the worker
// writes it before any publication, and one image may be published under
// several versions (ADR 023, C13).
type PackageManifest struct {
	Schema  string  `yaml:"schema" json:"schema"`
	Name    string  `yaml:"name" json:"name"`
	BuildID string  `yaml:"build_id" json:"build_id"`
	Commit  string  `yaml:"commit" json:"commit"`
	Builder Builder `yaml:"builder" json:"builder"`
	Base    string  `yaml:"base" json:"base"`
	UUID    string  `yaml:"uuid" json:"uuid"`
	Bytes   int64   `yaml:"bytes" json:"bytes"`
}

func (m PackageManifest) Validate() error {
	switch {
	case m.Schema != corpusmeta.Schema:
		return corpusmeta.Invalid("corpus.yaml schema must be %s", corpusmeta.Schema)
	case !corpusmeta.ValidName(m.Name):
		return corpusmeta.Invalid("corpus.yaml name")
	case !corpusmeta.ValidID("cbd", m.BuildID):
		return corpusmeta.Invalid("corpus.yaml build_id")
	case !corpusmeta.ValidCommit(m.Commit):
		return corpusmeta.Invalid("corpus.yaml commit")
	case !harnesspkg.CatalogName(m.Builder.Name) || !harnesspkg.CatalogName(m.Builder.Version) || !harnesspkg.ValidDigest(m.Builder.Digest):
		return corpusmeta.Invalid("corpus.yaml builder")
	case m.Base != GuestBase:
		return corpusmeta.Invalid("corpus.yaml base must be %s", GuestBase)
	case !corpusmeta.ValidUUID(m.UUID):
		return corpusmeta.Invalid("corpus.yaml uuid")
	case m.Bytes < MinImageBytes || m.Bytes%4096 != 0:
		return corpusmeta.Invalid("corpus.yaml bytes")
	}
	return nil
}

// ParsePackageManifest decodes corpus.yaml strictly: unknown fields,
// duplicate keys, several documents or an oversized file are refused.
func ParsePackageManifest(b []byte) (PackageManifest, error) {
	var m PackageManifest
	if len(b) == 0 || len(b) > MaxManifestBytes || !utf8.Valid(b) {
		return m, corpusmeta.Invalid("corpus.yaml size or encoding")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&m); err != nil {
		return PackageManifest{}, corpusmeta.Invalid("corpus.yaml does not parse")
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return PackageManifest{}, corpusmeta.Invalid("corpus.yaml has more than one document")
	}
	return m, m.Validate()
}

// Checksums is checksums.json: the sha256 of corpus.yaml and corpus.ext4.
type Checksums struct {
	Files map[string]string `json:"files"`
}

func ParseChecksums(b []byte) (Checksums, error) {
	var c Checksums
	if len(b) == 0 || len(b) > MaxChecksumsBytes {
		return c, corpusmeta.Invalid("checksums.json size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Checksums{}, corpusmeta.Invalid("checksums.json does not parse")
	}
	if d.More() {
		return Checksums{}, corpusmeta.Invalid("checksums.json has trailing data")
	}
	if len(c.Files) != 2 || !harnesspkg.ValidDigest(c.Files[ManifestFile]) || !harnesspkg.ValidDigest(c.Files[ImageFile]) {
		return Checksums{}, corpusmeta.Invalid("checksums.json must list corpus.yaml and corpus.ext4")
	}
	return c, nil
}

// WritePackage writes corpus.yaml and checksums.json next to dir/corpus.ext4,
// whose sha256 it returns: the image's digest, the name of the cache
// directory. m.Bytes must be the image's size, and the image must pass
// CheckImage with m.UUID. The image is made read-only (0444).
func WritePackage(dir string, m PackageManifest, maxBytes int64) (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	image := filepath.Join(dir, ImageFile)
	f, err := os.Open(image)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() != m.Bytes {
		return "", corpusmeta.Invalid("corpus.yaml bytes differ from corpus.ext4")
	}
	if err = CheckImage(f, st.Size(), maxBytes, m.UUID); err != nil {
		return "", err
	}
	digest, err := digestOf(f)
	if err != nil {
		return "", err
	}
	manifest, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}
	sums, err := json.MarshalIndent(Checksums{Files: map[string]string{ManifestFile: harnesspkg.Digest(manifest), ImageFile: digest}}, "", "  ")
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(dir, ManifestFile), manifest, 0o444); err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(dir, ChecksumsFile), append(sums, '\n'), 0o444); err != nil {
		return "", err
	}
	return digest, os.Chmod(image, 0o444)
}

// ReadPackage reads the package in dir and checks it: corpus.yaml and
// checksums.json parse, the digests match the files, and the image's size,
// superblock and UUID are corpus.yaml's. It returns the manifest and the
// image's digest. It reads the whole image, to hash it.
func ReadPackage(dir string, maxBytes int64) (PackageManifest, string, error) {
	read := func(name string, max int64) ([]byte, error) {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, max+1))
		if err == nil && int64(len(b)) > max {
			err = corpusmeta.Invalid("%s size", name)
		}
		return b, err
	}
	raw, err := read(ManifestFile, MaxManifestBytes)
	if err != nil {
		return PackageManifest{}, "", err
	}
	m, err := ParsePackageManifest(raw)
	if err != nil {
		return PackageManifest{}, "", err
	}
	rawSums, err := read(ChecksumsFile, MaxChecksumsBytes)
	if err != nil {
		return PackageManifest{}, "", err
	}
	sums, err := ParseChecksums(rawSums)
	if err != nil {
		return PackageManifest{}, "", err
	}
	if sums.Files[ManifestFile] != harnesspkg.Digest(raw) {
		return PackageManifest{}, "", corpusmeta.Invalid("corpus.yaml does not match checksums.json")
	}
	f, err := os.Open(filepath.Join(dir, ImageFile))
	if err != nil {
		return PackageManifest{}, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return PackageManifest{}, "", err
	}
	if !st.Mode().IsRegular() || st.Size() != m.Bytes {
		return PackageManifest{}, "", corpusmeta.Invalid("corpus.ext4 is not the size corpus.yaml gives")
	}
	if err = CheckImage(f, st.Size(), maxBytes, m.UUID); err != nil {
		return PackageManifest{}, "", err
	}
	digest, err := digestOf(f)
	if err != nil {
		return PackageManifest{}, "", err
	}
	if digest != sums.Files[ImageFile] {
		return PackageManifest{}, "", corpusmeta.Invalid("corpus.ext4 does not match checksums.json")
	}
	return m, digest, nil
}
