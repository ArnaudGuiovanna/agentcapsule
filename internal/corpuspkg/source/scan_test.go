package source

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const lintManifest = `schema: agentcapsule.corpus-source/v1
title: Finance
language: fr
include: [courses, "videos/**", "data/**", notes.md, readme.txt, images, "audio/**", "lfs/**", "tools/**", "nomatch/**"]
exclude: ["**/drafts/**", "never/**"]
processing:
  transcription: {alias: transcribe}
documents:
  - path: courses/chap1.pdf
    title: Chapter 1
corrections:
  - path: videos/session2.mp4
    markdown: corrections/session2.md
`

// writeTree writes files (path to content) under dir; a content starting
// with "->" makes a symbolic link to the rest.
func writeTree(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if target, ok := strings.CutPrefix(string(data), "->"); ok {
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The exit criterion of the corpus plan's lot 1: lint recognizes each kind,
// says which files it ignores and why, and estimates the volumes.
func TestScanKeepsIgnoresAndMeasures(t *testing.T) {
	dir := t.TempDir()
	oid := strings.Repeat("c", 64)
	writeTree(t, dir, map[string][]byte{
		ManifestFile:              []byte(lintManifest),
		"courses/chap1.pdf":       samplePDF(3),
		"courses/chap2.pdf":       samplePDFObjectStreams(t, 7),
		"courses/slides.pptx":     sampleZip(t, map[string]string{"ppt/slides/slide1.xml": "", "ppt/slides/slide2.xml": ""}),
		"courses/report.docx":     sampleZip(t, map[string]string{"docProps/app.xml": "<Pages>4</Pages>"}),
		"courses/thesis.odt":      sampleZip(t, map[string]string{"meta.xml": `meta:page-count="2"`}),
		"courses/drafts/d.md":     []byte("draft"),
		"courses/fake.pdf":        []byte("not a pdf at all"),
		"data/table.xlsx":         sampleZip(t, map[string]string{"xl/worksheets/sheet1.xml": ""}),
		"data/values.csv":         []byte("a,b\n1,2\n"),
		"notes.md":                []byte(strings.Repeat("n", 400)),
		"readme.txt":              []byte("read me"),
		"images/figure.png":       []byte("\x89PNG\r\n\x1a\n..."),
		"audio/talk.mp3":          sampleMP3(100, true),
		"audio/talk.wav":          sampleWAV(2),
		"videos/session1.webm":    sampleMKV(30),
		"videos/session2.mp4":     sampleMP4(0, 1000, 60000),
		"corrections/session2.md": []byte("# Session 2\n"),
		"lfs/big.pdf":             []byte(lfsVersion + "\noid sha256:" + oid + "\nsize 5000000\n"),
		"lfs/copy.pdf":            []byte(lfsVersion + "\noid sha256:" + oid + "\nsize 5000000\n"),
		"tools/build.sh":          []byte("#!/bin/sh\n"),
		"outside/other.md":        []byte("x"),
		".hidden.md":              []byte("x"),
		".git/objects/ab/cdef":    []byte("x"),
		"courses/link.pdf":        []byte("->chap1.pdf"),
		"courses/bad\x01name.md":  []byte("x"),
	})
	r, err := Scan(os.DirFS(dir), Options{Measure: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid() || r.Manifest == nil || r.Manifest.Title != "Finance" {
		t.Fatal(r.Errors)
	}
	kept := map[string]File{}
	for _, f := range r.Files {
		kept[f.Path] = f
	}
	for path, kind := range map[string]Kind{"courses/chap1.pdf": KindPDF, "courses/chap2.pdf": KindPDF, "courses/slides.pptx": KindPPTX,
		"courses/report.docx": KindDOCX, "courses/thesis.odt": KindODT, "courses/fake.pdf": KindPDF, "data/table.xlsx": KindXLSX,
		"data/values.csv": KindCSV, "notes.md": KindMarkdown, "readme.txt": KindText, "audio/talk.mp3": KindAudio,
		"audio/talk.wav": KindAudio, "videos/session1.webm": KindVideo, "videos/session2.mp4": KindVideo,
		"lfs/big.pdf": KindPDF, "lfs/copy.pdf": KindPDF} {
		if kept[path].Kind != kind {
			t.Errorf("%s: kept as %q, want %s", path, kept[path].Kind, kind)
		}
	}
	if len(kept) != 16 {
		t.Errorf("%d files kept: %v", len(kept), r.Files)
	}
	ignored := map[string]Ignored{}
	for _, i := range r.Ignored {
		ignored[i.Path] = i
	}
	for path, reason := range map[string]string{ManifestFile: ReasonManifest, "corrections/session2.md": ReasonCorrection,
		".hidden.md": ReasonHidden, ".git/": ReasonHidden, "courses/link.pdf": ReasonSymlink, "courses/bad\x01name.md": ReasonInvalidName,
		"outside/other.md": ReasonNotIncluded, "courses/drafts/d.md": ReasonExcluded, "tools/build.sh": ReasonUnsupported,
		"images/figure.png": ReasonStepDisabled} {
		if ignored[path].Reason != reason {
			t.Errorf("%s: ignored for %q, want %s", path, ignored[path].Reason, reason)
		}
	}
	if ignored["images/figure.png"].Step != StepVision || len(ignored) != 10 {
		t.Error(r.Ignored)
	}
	if r.Totals.Kept != 16 || r.Totals.Ignored != 10 || r.Totals.Seen != 26 {
		t.Errorf("%+v", r.Totals)
	}
	e := r.Totals.Estimate
	// 3 + 7 + 4 + 2 pages; fake.pdf and the LFS pointers are unmeasured.
	if e.Pages != 16 || e.Slides != 2 || e.Sheets != 1 || e.Images != 0 || e.AudioSeconds != 5 || e.VideoSeconds != 90 ||
		e.TextTokens != 100+2+2 || e.Unmeasured != 3 {
		t.Errorf("%+v", e)
	}
	if r.Totals.Kinds[KindPDF] != 5 || r.Totals.Kinds[KindAudio] != 2 || r.Totals.Kinds[KindImage] != 0 {
		t.Error(r.Totals.Kinds)
	}
	if kept["lfs/big.pdf"].LFS == nil || kept["lfs/big.pdf"].Bytes != 5000000 || len(r.LFS) != 1 ||
		r.LFS[0].OID != oid || r.Totals.LFSObjects != 1 || r.Totals.LFSBytes != 5000000 {
		t.Error(r.LFS, r.Totals)
	}
	var warnings []string
	for _, w := range r.Warnings {
		warnings = append(warnings, w.Code+" "+w.Path)
	}
	slices.Sort(warnings)
	want := []string{WarnContentMismatch + " courses/fake.pdf", WarnLFSPointer + " lfs/big.pdf", WarnLFSPointer + " lfs/copy.pdf",
		WarnPatternUnused + " never/**", WarnPatternUnused + " nomatch/**"}
	if !slices.Equal(warnings, want) {
		t.Errorf("warnings %v, want %v", warnings, want)
	}
	// The scan is deterministic: the same tree gives the same result.
	again, err := Scan(os.DirFS(dir), Options{Measure: true})
	if err != nil || !slices.EqualFunc(again.Files, r.Files, func(a, b File) bool { return a.Path == b.Path && a.Measures == b.Measures }) ||
		!slices.Equal(again.Ignored, r.Ignored) {
		t.Error("another scan of the same tree differs")
	}
}

// A build refuses what lint refuses: metadata or a correction of a file it
// does not keep, a missing correction, a corpus with no file, a missing
// manifest.
func TestScanRefusesWhatABuildWouldRefuse(t *testing.T) {
	scan := func(files map[string][]byte) Result {
		t.Helper()
		dir := t.TempDir()
		writeTree(t, dir, files)
		r, err := Scan(os.DirFS(dir), Options{})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := scan(map[string][]byte{ManifestFile: []byte(lintManifest), "courses/chap2.pdf": samplePDF(1),
		"videos/session2.mp4": []byte("x"), "courses/drafts/chap1.pdf": samplePDF(1)})
	if !slices.Equal(r.Errors.Codes(), []string{CodeDocumentMissing, CodeCorrectionMissing}) || r.Valid() {
		t.Fatal(r.Errors)
	}
	r = scan(map[string][]byte{ManifestFile: []byte(strings.Replace(lintManifest, "  transcription: {alias: transcribe}\n", "", 1)),
		"courses/chap1.pdf": samplePDF(1), "videos/session2.mp4": []byte("x"), "corrections/session2.md": []byte("x")})
	if !slices.Equal(r.Errors.Codes(), []string{CodeDocumentMissing}) || r.Errors[0].Field != "corrections[0].path" {
		t.Fatal("a correction of a video whose transcription is off:", r.Errors)
	}
	r = scan(map[string][]byte{ManifestFile: []byte("schema: agentcapsule.corpus-source/v1\ntitle: T\nlanguage: en\n"), "a.sh": []byte("x")})
	if !slices.Equal(r.Errors.Codes(), []string{CodeNoDocuments}) {
		t.Fatal(r.Errors)
	}
	r = scan(map[string][]byte{"a.md": []byte("x"), "b.mp3": sampleMP3(1, false)})
	if !slices.Equal(r.Errors.Codes(), []string{CodeManifestMissing}) || r.Manifest != nil || len(r.Files) != 1 ||
		r.Warnings[0].Code != WarnDefaultManifest {
		t.Fatal(r.Errors, r.Files, r.Warnings)
	}
	r = scan(map[string][]byte{ManifestFile: []byte("title: [unclosed\n"), "a.md": []byte("x")})
	if !slices.Equal(r.Errors.Codes(), []string{CodeManifestInvalid}) || r.Manifest != nil {
		t.Fatal(r.Errors)
	}
	// Invalid fields are reported, and the valid ones still select.
	r = scan(map[string][]byte{ManifestFile: []byte(strings.Replace(lintManifest, "language: fr", "language: '?'", 1)),
		"courses/chap1.pdf": samplePDF(1), "videos/session2.mp4": []byte("x"), "corrections/session2.md": []byte("x"), "outside/a.md": []byte("x")})
	if !slices.Equal(r.Errors.Codes(), []string{CodeLanguage}) || r.Manifest == nil || len(r.Files) != 2 {
		t.Fatal(r.Errors, r.Files)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string][]byte{"real.yaml": []byte(lintManifest), ManifestFile: []byte("->real.yaml"), "notes.md": []byte("x")})
	if r, err := Scan(os.DirFS(dir), Options{}); err != nil || !slices.Equal(r.Errors.Codes(), []string{CodeManifestInvalid}) {
		t.Fatal("a manifest that is a symbolic link:", r.Errors, err)
	}
	if _, err := Scan(os.DirFS(filepath.Join(dir, "absent")), Options{}); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a missing directory:", err)
	}
}
