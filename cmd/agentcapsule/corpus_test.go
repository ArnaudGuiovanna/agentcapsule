package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// lintOutput is the part of corpus lint's report the tests read.
type lintOutput struct {
	Version int `json:"version"`
	Data    struct {
		Directory string   `json:"directory"`
		Valid     bool     `json:"valid"`
		Title     string   `json:"title"`
		Language  string   `json:"language"`
		Aliases   []string `json:"aliases"`
		Errors    []struct {
			Code  string `json:"code"`
			Field string `json:"field"`
		} `json:"errors"`
		Files []struct {
			Path  string `json:"path"`
			Kind  string `json:"kind"`
			Bytes int64  `json:"bytes"`
			Pages int    `json:"pages"`
		} `json:"files"`
		Ignored []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
			Step   string `json:"step"`
		} `json:"ignored"`
		Warnings []struct {
			Code string `json:"code"`
			Path string `json:"path"`
		} `json:"warnings"`
		Totals struct {
			Seen       int            `json:"seen"`
			Kept       int            `json:"kept"`
			Ignored    int            `json:"ignored"`
			Kinds      map[string]int `json:"kinds"`
			Pages      int64          `json:"pages"`
			TextTokens int64          `json:"text_tokens"`
		} `json:"totals"`
	} `json:"data"`
}

// The CLI reads a corpus's sources with the source package only: it links
// neither the image build, which runs e2fsprogs, nor the sandbox, whose
// helper a linked binary becomes when started under its name.
func TestCLILinksNoImageCode(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal("go list", err)
	}
	linked := strings.Fields(string(out))
	if !slices.ContainsFunc(linked, func(p string) bool { return strings.HasSuffix(p, "/internal/corpuspkg/source") }) {
		t.Fatal("go list does not see the corpus source package", linked)
	}
	for _, p := range linked {
		for _, denied := range []string{"/internal/corpuspkg", "/internal/ext4image", "/internal/sandbox", "/internal/harnesspkg"} {
			if strings.HasSuffix(p, denied) {
				t.Error("the CLI links", p)
			}
		}
	}
}

// corpus init and corpus lint are local, as identity is: they need no
// context and call no API. init writes a manifest lint accepts, and never
// replaces one; lint says what a build keeps, ignores and why, and exits 1
// with its report when a build would refuse the source.
func TestCorpusInitAndLintAreLocal(t *testing.T) {
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(t.TempDir(), "no context"))
	dir := filepath.Join(t.TempDir(), "finance-l3")
	cmd := func(args ...string) (string, error) {
		var out, errout bytes.Buffer
		err := run(t.Context(), args, strings.NewReader(""), &out, &errout)
		return out.String(), err
	}
	out, err := cmd("corpus", "init", dir, "--language", "fr")
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Data map[string]string `json:"data"`
	}
	if err = json.Unmarshal([]byte(out), &created); err != nil || created.Data["title"] != "finance-l3" ||
		created.Data["manifest"] != filepath.Join(dir, "agentcapsule-corpus.yaml") {
		t.Fatal(out, err)
	}
	if _, err = cmd("corpus", "init", dir); err == nil {
		t.Fatal("init replaced an existing manifest")
	}
	files := map[string]string{
		"courses/chap1.pdf": "%PDF-1.4\n2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj\n%%EOF\n",
		"notes.md":          strings.Repeat("n", 40),
		"talk.mp3":          "ID3\x04\x00\x00\x00\x00\x00\x00",
		"tools/build.sh":    "#!/bin/sh\n",
		".notes.md":         "hidden",
	}
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err = cmd("corpus", "lint", dir)
	if err != nil {
		t.Fatal(err, out)
	}
	var lint lintOutput
	if err = json.Unmarshal([]byte(out), &lint); err != nil {
		t.Fatal(err)
	}
	d := lint.Data
	if lint.Version != 1 || !d.Valid || d.Title != "finance-l3" || d.Language != "fr" || len(d.Aliases) != 0 || len(d.Errors) != 0 ||
		d.Totals.Kept != 2 || d.Totals.Ignored != 4 || d.Totals.Seen != 6 || d.Totals.Kinds["pdf"] != 1 || d.Totals.Pages != 2 ||
		d.Totals.TextTokens != 10 {
		t.Fatalf("%+v", d)
	}
	reasons := map[string]string{}
	for _, i := range d.Ignored {
		reasons[i.Path] = i.Reason + " " + i.Step
	}
	if reasons["talk.mp3"] != "step_disabled transcription" || reasons["tools/build.sh"] != "unsupported_type " ||
		reasons[".notes.md"] != "hidden " || reasons["agentcapsule-corpus.yaml"] != "manifest " {
		t.Fatal(reasons)
	}
	// A manifest naming a file the build would not keep: the report, then exit 1.
	manifest := filepath.Join(dir, "agentcapsule-corpus.yaml")
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, "documents:\n  - path: talk.mp3\n    title: Talk\n"...)
	if err = os.WriteFile(manifest, b, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = cmd("corpus", "lint", dir)
	var invalid corpusSourceInvalid
	if !errors.As(err, &invalid) || invalid.codes[0] != "document_missing" {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(out), &lint); err != nil || lint.Data.Valid || lint.Data.Errors[0].Field != "documents[0].path" {
		t.Fatal(out, err)
	}
	for _, args := range [][]string{{"corpus", "lint"}, {"corpus", "lint", dir, "--title", "x"}, {"corpus", "init", dir, "--language", "français"}} {
		var usage usageError
		if _, err = cmd(args...); !errors.As(err, &usage) {
			t.Error(args, err)
		}
	}
	if _, err = cmd("corpus", "lint", filepath.Join(dir, "absent")); err == nil {
		t.Error("lint of a missing directory")
	}
}
