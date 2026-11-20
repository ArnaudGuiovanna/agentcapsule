//go:build linux

package corpuspkg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

func manifestFor(size int64) PackageManifest {
	return PackageManifest{Schema: Schema, Name: "finance-l3", BuildID: "cbd_" + strings.Repeat("1f", 16),
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
		if _, _, err := ReadPackage(dir, 64<<20); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// WritePackage checks the image against the manifest it writes.
	wrong := manifestFor(size)
	wrong.UUID = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
	if _, err := WritePackage(tamper("", nil), wrong, 64<<20); !errors.Is(err, ErrInvalid) {
		t.Error("another UUID:", err)
	}
	wrong = manifestFor(size + 4096)
	if _, err := WritePackage(tamper("", nil), wrong, 64<<20); !errors.Is(err, ErrInvalid) {
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
		if !errors.Is(m.Validate(), ErrInvalid) {
			t.Error("accepted", name)
		}
	}
	for name, doc := range map[string]string{
		"unknown field":   "schema: agentcapsule.corpus/v1\nversion: 3\n",
		"second document": "schema: agentcapsule.corpus/v1\n---\nname: x\n",
		"duplicate key":   "schema: agentcapsule.corpus/v1\nschema: agentcapsule.corpus/v1\n",
	} {
		if _, err := ParsePackageManifest([]byte(doc)); !errors.Is(err, ErrInvalid) {
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

// The report of ADR 023 §2.4 decodes strictly, and its totals are its files'.
func TestReportIsStrict(t *testing.T) {
	r := Report{Schema: ReportSchema, BuildID: "cbd_" + strings.Repeat("1f", 16), Commit: strings.Repeat("ab", 20),
		Files: []ReportEntry{
			{Path: "courses/chap1.pdf", Kind: "pdf", Status: StatusConverted, DocID: DocumentID("courses/chap1.pdf"), Bytes: 182340, Tokens: 5120, Warnings: []string{"ocr_low_confidence"}},
			{Path: "courses/chap2.pdf", Kind: "pdf", Status: StatusCached, DocID: DocumentID("courses/chap2.pdf"), Bytes: 1000, Tokens: 80, Warnings: []string{}},
			{Path: "audio/a.mp3", Kind: "audio", Status: StatusSkipped, Bytes: 10, Warnings: []string{}, Error: FileStepDisabled},
			{Path: "scan.pdf", Kind: "pdf", Status: StatusFailed, Bytes: 10, Warnings: []string{}, Error: FileMalformed},
		},
		Totals: ReportTotals{Files: 4, Converted: 1, Cached: 1, Skipped: 1, Failed: 1, Tokens: 5200}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseReport(b); err != nil || len(got.Files) != 4 {
		t.Fatal(got, err)
	}
	for name, change := range map[string]func(*Report){
		"totals":            func(r *Report) { r.Totals.Tokens++ },
		"status":            func(r *Report) { r.Files[0].Status = "done" },
		"kind":              func(r *Report) { r.Files[0].Kind = "html" },
		"converted, no doc": func(r *Report) { r.Files[0].DocID = "" },
		"converted, error":  func(r *Report) { r.Files[0].Error = FileTimeout },
		"skipped, doc":      func(r *Report) { r.Files[2].DocID = "d1" },
		"skipped, failure":  func(r *Report) { r.Files[2].Error = FileTimeout },
		"failed, no error":  func(r *Report) { r.Files[3].Error = "" },
		"warning":           func(r *Report) { r.Files[0].Warnings = []string{"looks_odd"} },
		"warning twice":     func(r *Report) { r.Files[0].Warnings = []string{"no_text", "no_text"} },
		"path twice":        func(r *Report) { r.Files[1].Path = r.Files[0].Path },
		"path":              func(r *Report) { r.Files[0].Path = "../chap1.pdf" },
		"commit":            func(r *Report) { r.Commit = "HEAD" },
		"no warnings list":  func(r *Report) { r.Files[0].Warnings = nil },
	} {
		bad := r
		bad.Files = append([]ReportEntry(nil), r.Files...)
		change(&bad)
		if b, _ := json.Marshal(bad); !errorsIsInvalid(ParseReport(b)) {
			t.Error("accepted", name)
		}
	}
	if _, err := ParseReport(append(b[:len(b)-1], []byte(`,"costs":{}}`)...)); !errors.Is(err, ErrInvalid) {
		t.Error("an unknown field:", err)
	}
}

func errorsIsInvalid(_ Report, err error) bool { return errors.Is(err, ErrInvalid) }

func TestInfoAndDocumentRecordsValidate(t *testing.T) {
	info := Info{Schema: Schema, Name: "finance-l3", Title: "Finance", BuildID: "cbd_" + strings.Repeat("1f", 16),
		Commit: strings.Repeat("ab", 20), SourcePath: "cours", Builder: "agentcapsule-corpus-builder@1.0.0",
		Languages: []string{"fr"}, Modalities: []string{ModalityText, ModalityVideo}, Tokens: 5200,
		Embeddings: &Embeddings{Alias: "embed", Model: "nomic-embed-text", Dimensions: 768},
		Documents: []InfoEntry{{ID: DocumentID("a.pdf"), Path: "a.pdf", Kind: "pdf", Title: "A", Tokens: 5000},
			{ID: DocumentID("b.mp4"), Path: "b.mp4", Kind: "video", Title: "B", Tokens: 200}}}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseInfo(b); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Info){
		"tokens":    func(i *Info) { i.Tokens = 1 },
		"id twice":  func(i *Info) { i.Documents[1].ID = i.Documents[0].ID },
		"modality":  func(i *Info) { i.Modalities = []string{"smell"} },
		"embedding": func(i *Info) { i.Embeddings.Dimensions = 0 },
		"no lang":   func(i *Info) { i.Languages = nil },
		"other":     func(i *Info) { i.Documents[0].Kind = "other" },
	} {
		bad := info
		bad.Documents = append([]InfoEntry(nil), info.Documents...)
		e := *info.Embeddings
		bad.Embeddings = &e
		change(&bad)
		if !errors.Is(bad.Validate(), ErrInvalid) {
			t.Error("accepted", name)
		}
	}
	start, end, low := 1.5, 3.0, 0.4
	doc := DocumentRecord{Schema: DocumentSchema, ID: DocumentID("b.mp4"), Path: "b.mp4", Kind: "video", Title: "B", Seconds: 60,
		Elements: []Element{
			{ID: "e0001", Type: "heading", Level: 1, Text: "Session 2", Source: "native", Part: PartName(1)},
			{ID: "e0002", Type: "transcript", Text: "Hello", Start: &start, End: &end, Source: "transcription", Confidence: &low, Part: PartName(1)},
			{ID: "e0003", Type: "figure", Text: "A chart", Page: 2, Box: &[4]float64{0.1, 0.2, 0.5, 0.6}, Source: "vision", Part: PartName(12)},
		}}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Element){
		"type":       func(e *Element) { e.Type = "banner" },
		"source":     func(e *Element) { e.Source = "guess" },
		"part":       func(e *Element) { e.Part = "part-1.md" },
		"box":        func(e *Element) { e.Box = &[4]float64{0.5, 0.2, 0.1, 0.6} },
		"box, page":  func(e *Element) { e.Page = 0 },
		"confidence": func(e *Element) { c := 1.5; e.Confidence = &c },
		"level":      func(e *Element) { e.Level = 2; e.Type = "paragraph" },
	} {
		bad := doc
		bad.Elements = append([]Element(nil), doc.Elements...)
		change(&bad.Elements[2])
		if !errors.Is(bad.Validate(), ErrInvalid) {
			t.Error("accepted", name)
		}
	}
}
