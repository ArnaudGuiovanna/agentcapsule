// Package harnesspkg defines the harness package format: what a published
// harness contains, how it is identified, and the checks that run before the
// platform accepts it. It never mounts or executes anything.
//
// A package is an OCI artifact (artifactType ArtifactType) whose config is the
// OCI empty descriptor and whose three layers are, in this order:
//
//	harness.yaml   ManifestMediaType   the HarnessManifest below
//	checksums.json ChecksumsMediaType  sha256 of the two other files
//	harness.ext4   RootfsMediaType     read-only root filesystem of the harness
package harnesspkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	ArtifactType       = "application/vnd.agentcapsule.harness.v1"
	ManifestMediaType  = "application/vnd.agentcapsule.harness.manifest.v1+yaml"
	ChecksumsMediaType = "application/vnd.agentcapsule.harness.checksums.v1+json"
	RootfsMediaType    = "application/vnd.agentcapsule.harness.rootfs.v1+ext4"

	ManifestFile  = "harness.yaml"
	ChecksumsFile = "checksums.json"
	RootfsFile    = "harness.ext4"

	Schema       = "agentcapsule.harness/v1"
	Protocol     = "capsule.v1"
	Architecture = "x86_64"
	// GuestBase names the guest ABI (kernel, capsule-init, mount layout) a
	// harness is built against. A platform runs only the bases it supports.
	GuestBase = "agentcapsule-guest/1"

	MaxManifestBytes  = 64 << 10
	MaxChecksumsBytes = 16 << 10
	MinRootfsBytes    = 64 << 10
)

// ErrInvalid: the package is malformed, tampered with or incompatible. The
// message names the failed check, never file contents.
var ErrInvalid = errors.New("invalid harness package")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// HarnessManifest is harness.yaml.
type HarnessManifest struct {
	Schema       string   `yaml:"schema" json:"schema"`
	Name         string   `yaml:"name" json:"name"`
	Version      string   `yaml:"version" json:"version"`
	Protocol     string   `yaml:"protocol" json:"protocol"`
	Architecture string   `yaml:"architecture" json:"architecture"`
	Base         string   `yaml:"base" json:"base"`
	Entrypoint   []string `yaml:"entrypoint" json:"entrypoint"`
	Description  string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// CatalogName is the rule shared with the control plane for harness names and
// versions: 1 to 100 ASCII letters, digits, '-', '_' or '.', not "." or "..".
func CatalogName(v string) bool {
	if len(v) < 1 || len(v) > 100 || v == "." || v == ".." {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// ParseManifest decodes harness.yaml strictly: unknown fields, duplicate keys,
// several documents or an oversized file are refused.
func ParseManifest(b []byte) (HarnessManifest, error) {
	var m HarnessManifest
	if len(b) == 0 || len(b) > MaxManifestBytes || !utf8.Valid(b) {
		return m, invalid("harness.yaml size or encoding")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&m); err != nil {
		return HarnessManifest{}, invalid("harness.yaml does not parse")
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return HarnessManifest{}, invalid("harness.yaml has more than one document")
	}
	return m, m.Validate()
}

func (m HarnessManifest) Validate() error {
	switch {
	case m.Schema != Schema:
		return invalid("schema must be %s", Schema)
	case !CatalogName(m.Name) || !CatalogName(m.Version):
		return invalid("name or version")
	case m.Protocol != Protocol:
		return invalid("protocol must be %s", Protocol)
	case m.Architecture != Architecture:
		return invalid("architecture must be %s", Architecture)
	case m.Base != GuestBase:
		return invalid("unsupported base")
	case len(m.Entrypoint) < 1 || len(m.Entrypoint) > 32:
		return invalid("entrypoint")
	case len(m.Description) > 300 || strings.ContainsAny(m.Description, "\x00\r"):
		return invalid("description")
	}
	exe := m.Entrypoint[0]
	if !strings.HasPrefix(exe, "/") || path.Clean(exe) != exe || exe == "/" {
		return invalid("entrypoint must be a clean absolute path")
	}
	for _, a := range m.Entrypoint {
		if a == "" || len(a) > 256 || !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
			return invalid("entrypoint argument")
		}
	}
	return nil
}

// Checksums is checksums.json: the sha256 of harness.yaml and harness.ext4, so
// a package copied outside a registry can still be verified.
type Checksums struct {
	Files map[string]string `json:"files"`
}

func ParseChecksums(b []byte) (Checksums, error) {
	var c Checksums
	if len(b) == 0 || len(b) > MaxChecksumsBytes {
		return c, invalid("checksums.json size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Checksums{}, invalid("checksums.json does not parse")
	}
	if len(c.Files) != 2 || !ValidDigest(c.Files[ManifestFile]) || !ValidDigest(c.Files[RootfsFile]) {
		return Checksums{}, invalid("checksums.json must list harness.yaml and harness.ext4")
	}
	return c, nil
}

// ValidDigest accepts only lowercase "sha256:" followed by 64 hex digits.
func ValidDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") || strings.ToLower(d) != d {
		return false
	}
	_, err := hex.DecodeString(d[7:])
	return err == nil
}

func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CheckRootfs reads only the ext4 superblock of an image file: magic, block
// size and the filesystem fitting in the file. The image is never mounted on
// the host; the guest kernel mounts it read-only.
func CheckRootfs(f *os.File, size, max int64) error {
	if size < MinRootfsBytes || size > max || size%4096 != 0 {
		return invalid("harness.ext4 size")
	}
	sb := make([]byte, 1024)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		return invalid("harness.ext4 superblock unreadable")
	}
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xEF53 {
		return invalid("harness.ext4 is not an ext4 filesystem")
	}
	logBlock := binary.LittleEndian.Uint32(sb[0x18:])
	if logBlock > 6 {
		return invalid("harness.ext4 block size")
	}
	blockSize := int64(1024) << logBlock
	blocks := int64(binary.LittleEndian.Uint32(sb[0x04:]))
	if binary.LittleEndian.Uint32(sb[0x60:])&0x80 != 0 { // INCOMPAT_64BIT: high half is meaningful
		blocks |= int64(binary.LittleEndian.Uint32(sb[0x150:])) << 32
	}
	if blocks < 1 || blocks > size/blockSize {
		return invalid("harness.ext4 is larger than its file")
	}
	return nil
}
