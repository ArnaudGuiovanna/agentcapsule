//go:build linux

package corpuspkg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

func manifestFor(size int64) PackageManifest {
	return PackageManifest{Schema: corpusmeta.Schema, Name: "finance-l3", BuildID: "cbd_" + strings.Repeat("1f", 16),
		Commit: strings.Repeat("ab", 20), Builder: Builder{Name: "agentcapsule-corpus-builder", Version: "1.0.0",
			Digest: "sha256:" + strings.Repeat("cd", 32)}, Base: GuestBase, UUID: testUUID, Bytes: size}
}

// The worker writes the host package next to a checked image, and reads it
// back only when every digest, the size and the UUID agree.
func TestPackageRoundTripAndTampering(t *testing.T) {
	image, size := built(t)
	dir := t.TempDir()
	b, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, ImageFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := WritePackage(dir, manifestFor(size), 64<<20)
	if err != nil || digest != harnesspkg.Digest(b) {
		t.Fatal(digest, err)
	}
	m, again, err := ReadPackage(dir, 64<<20)
	if err != nil || again != digest || m != manifestFor(size) {
		t.Fatal(m, again, err)
	}
	if st, err := os.Stat(filepath.Join(dir, ImageFile)); err != nil || st.Mode().Perm() != 0o444 {
		t.Fatal("the image is not read-only", st.Mode(), err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil || strings.Contains("\n"+string(raw), "\nversion:") {
		t.Fatal("corpus.yaml names a release version", string(raw), err)
	}
	tamper := func(name string, change func([]byte) []byte) string {
		t.Helper()
		copyDir := t.TempDir()
		for _, f := range []string{ManifestFile, ChecksumsFile, ImageFile} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Fatal(err)
			}
			if f == name {
				b = change(b)
			}
			if err = os.WriteFile(filepath.Join(copyDir, f), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return copyDir
	}
	for name, dir := range map[string]string{
		"a byte of the image": tamper(ImageFile, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
		"the manifest":        tamper(ManifestFile, func(b []byte) []byte { return []byte(strings.Replace(string(b), "finance-l3", "finance-l4", 1)) }),
		"a version added":     tamper(ManifestFile, func(b []byte) []byte { return append(b, "version: 3\n"...) }),
		"the checksums":       tamper(ChecksumsFile, func(b []byte) []byte { return []byte(strings.Replace(string(b), "sha256:", "sha256:0", 1)) }),
		"an image cut":        tamper(ImageFile, func(b []byte) []byte { return b[:len(b)-4096] }),
	} {
		if _, _, err := ReadPackage(dir, 64<<20); !errors.Is(err, corpusmeta.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// WritePackage checks the image against the manifest it writes.
	wrong := manifestFor(size)
	wrong.UUID = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
	if _, err := WritePackage(tamper("", nil), wrong, 64<<20); !errors.Is(err, corpusmeta.ErrInvalid) {
		t.Error("another UUID:", err)
	}
	wrong = manifestFor(size + 4096)
	if _, err := WritePackage(tamper("", nil), wrong, 64<<20); !errors.Is(err, corpusmeta.ErrInvalid) {
		t.Error("another size:", err)
	}
}

func TestPackageManifestIsStrict(t *testing.T) {
	good := manifestFor(4 << 20)
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PackageManifest){
		"schema":   func(m *PackageManifest) { m.Schema = "agentcapsule.corpus/v2" },
		"name":     func(m *PackageManifest) { m.Name = "Finance" },
		"build":    func(m *PackageManifest) { m.BuildID = "cor_" + strings.Repeat("1f", 16) },
		"commit":   func(m *PackageManifest) { m.Commit = "main" },
		"builder":  func(m *PackageManifest) { m.Builder.Digest = "sha256:x" },
		"base":     func(m *PackageManifest) { m.Base = "agentcapsule-guest/1" },
		"uuid":     func(m *PackageManifest) { m.UUID = strings.ToUpper(testUUID) },
		"bytes":    func(m *PackageManifest) { m.Bytes = 4<<20 + 1 },
		"no bytes": func(m *PackageManifest) { m.Bytes = 0 },
	} {
		m := good
		change(&m)
		if !errors.Is(m.Validate(), corpusmeta.ErrInvalid) {
			t.Error("accepted", name)
		}
	}
	for name, doc := range map[string]string{
		"unknown field":   "schema: agentcapsule.corpus/v1\nversion: 3\n",
		"second document": "schema: agentcapsule.corpus/v1\n---\nname: x\n",
		"duplicate key":   "schema: agentcapsule.corpus/v1\nschema: agentcapsule.corpus/v1\n",
	} {
		if _, err := ParsePackageManifest([]byte(doc)); !errors.Is(err, corpusmeta.ErrInvalid) {
			t.Error("accepted", name)
		}
	}
	d := harnesspkg.Digest([]byte("x"))
	if _, err := ParseChecksums([]byte(`{"files":{"corpus.yaml":"` + d + `","corpus.ext4":"` + d + `"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"files":{"corpus.yaml":"` + d + `"}}`,
		`{"files":{"corpus.yaml":"` + d + `","harness.ext4":"` + d + `"}}`,
		`{"files":{"corpus.yaml":"` + d + `","corpus.ext4":"` + d + `"},"extra":1}`,
		`{"files":{"corpus.yaml":"` + d + `","corpus.ext4":"` + d + `"}} {}`,
	} {
		if _, err := ParseChecksums([]byte(bad)); err == nil {
			t.Error("accepted", bad)
		}
	}
}
