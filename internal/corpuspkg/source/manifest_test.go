package source

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// The example of ADR 023 §2.1, with OCR through an alias (C14).
const example = `schema: agentcapsule.corpus-source/v1
title: "Corporate finance, year 3"
language: fr
include: ["courses/**", "videos/**", "data/**"]
exclude: ["**/drafts/**"]
processing:
  ocr: {alias: ocr, mode: auto}
  transcription: {alias: transcribe-fr}
  vision: {alias: vision, describe_figures: true}
  summaries: {alias: summary}
  embeddings: {alias: embed}
documents:
  - path: courses/chap1.pdf
    title: "Chapter 1: time value of money"
    tags: [discounting, NPV]
corrections:
  - path: videos/session2.mp4
    markdown: corrections/session2.md
`

func TestManifestOfTheADRParses(t *testing.T) {
	m, err := ParseManifest([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if m.Title != "Corporate finance, year 3" || m.Language != "fr" || len(m.Include) != 3 || m.Processing.OCR.Mode != "auto" ||
		!m.Processing.Vision.DescribeFigures || m.Documents[0].Tags[1] != "NPV" || m.Corrections[0].Markdown != "corrections/session2.md" {
		t.Fatalf("%+v", m)
	}
	if got := m.Aliases(); !slices.Equal(got, []string{"embed", "ocr", "summary", "transcribe-fr", "vision"}) {
		t.Fatal(got)
	}
	minimal, err := ParseManifest([]byte("schema: agentcapsule.corpus-source/v1\ntitle: Handbook\nlanguage: en-GB\n"))
	if err != nil || !slices.Equal(minimal.Patterns(), []string{"**"}) || len(minimal.Processing.Steps()) != 0 || len(minimal.Aliases()) != 0 {
		t.Fatal(minimal, err)
	}
}

// The manifest is strict YAML: unknown fields, duplicate keys and extra
// documents are refused, as are an oversized file, invalid UTF-8 and a
// value of the wrong type.
func TestManifestIsStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field":      example + "privileged: true\n",
		"unknown step":       strings.Replace(example, "  summaries:", "  translation: {alias: x}\n  summaries:", 1),
		"unknown step field": strings.Replace(example, "{alias: summary}", "{alias: summary, model: gpt}", 1),
		"duplicate key":      example + "title: again\n",
		"second document":    example + "---\ntitle: other\n",
		"too large":          example + "# " + strings.Repeat("x", MaxManifestBytes) + "\n",
		"invalid UTF-8":      strings.Replace(example, "year 3", "year \xff", 1),
		"include as string":  strings.Replace(example, `include: ["courses/**", "videos/**", "data/**"]`, `include: "courses/**"`, 1),
		"tags as string":     strings.Replace(example, "tags: [discounting, NPV]", "tags: NPV", 1),
		"empty":              "",
		"not a mapping":      "- a\n- b\n",
	} {
		_, err := ParseManifest([]byte(doc))
		var errs Errors
		if !errors.As(err, &errs) || !slices.Equal(errs.Codes(), []string{CodeManifestInvalid}) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each field's rule has its closed code, and every problem is reported at
// once, sorted by field.
func TestManifestNamesEachProblem(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(example, old) {
			t.Fatal("not in the example:", old)
		}
		return strings.Replace(example, old, new, 1)
	}
	for name, c := range map[string]struct {
		doc   string
		code  string
		field string
	}{
		"schema":              {replace("corpus-source/v1", "corpus-source/v2"), CodeSchema, "schema"},
		"empty title":         {replace(`"Corporate finance, year 3"`, `" "`), CodeTitle, "title"},
		"long title":          {replace(`"Corporate finance, year 3"`, strings.Repeat("é", 201)), CodeTitle, "title"},
		"title control":       {replace(`"Corporate finance, year 3"`, `"a\tb"`), CodeTitle, "title"},
		"language":            {replace("language: fr", "language: french!"), CodeLanguage, "language"},
		"no language":         {replace("language: fr\n", ""), CodeLanguage, "language"},
		"absolute glob":       {replace(`"courses/**"`, `"/courses/**"`), CodePattern, "include[0]"},
		"parent glob":         {replace(`"courses/**"`, `"../courses/**"`), CodePattern, "include[0]"},
		"backslash glob":      {replace(`"courses/**"`, `"courses\\**"`), CodePattern, "include[0]"},
		"empty element":       {replace(`"courses/**"`, `"courses//x"`), CodePattern, "include[0]"},
		"malformed glob":      {replace(`"**/drafts/**"`, `"[a-"`), CodePattern, "exclude[0]"},
		"empty include":       {replace(`include: ["courses/**", "videos/**", "data/**"]`, "include: []"), CodePattern, "include"},
		"alias with a space":  {replace("{alias: summary}", "{alias: my summary}"), CodeProcessing, "processing.summaries.alias"},
		"missing alias":       {replace("{alias: embed}", "{}"), CodeProcessing, "processing.embeddings.alias"},
		"ocr never":           {replace("mode: auto", "mode: never"), CodeProcessing, "processing.ocr.mode"},
		"document path":       {replace("- path: courses/chap1.pdf", "- path: courses/../chap1.pdf"), CodeDocument, "documents[0].path"},
		"document dot":        {replace("- path: courses/chap1.pdf", "- path: ./chap1.pdf"), CodeDocument, "documents[0].path"},
		"document tag twice":  {replace("[discounting, NPV]", "[NPV, NPV]"), CodeDocument, "documents[0].tags[1]"},
		"document long tag":   {replace("[discounting, NPV]", "[\""+strings.Repeat("t", 51)+"\"]"), CodeDocument, "documents[0].tags[0]"},
		"correction absolute": {replace("- path: videos/session2.mp4", "- path: /videos/session2.mp4"), CodeCorrection, "corrections[0].path"},
		"correction not md":   {replace("corrections/session2.md", "corrections/session2.txt"), CodeCorrection, "corrections[0].markdown"},
		"correction self":     {replace("markdown: corrections/session2.md", "markdown: videos/session2.mp4.md\n  - path: a.md\n    markdown: a.md"), CodeCorrection, "corrections[1].markdown"},
	} {
		_, err := ParseManifest([]byte(c.doc))
		var errs Errors
		if !errors.As(err, &errs) || len(errs) != 1 || errs[0].Code != c.code || errs[0].Field != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	twice := example + "  - path: courses/chap1.pdf\n    markdown: corrections/session2.md\n"
	twice = strings.Replace(twice, "documents:\n", "documents:\n  - path: courses/chap1.pdf\n", 1)
	_, err := ParseManifest([]byte(twice))
	var errs Errors
	if !errors.As(err, &errs) || len(errs) != 2 || errs[0].Field != "corrections[1].markdown" || errs[1].Field != "documents[1].path" {
		t.Fatal(err)
	}
	several := strings.Replace(strings.Replace(example, "language: fr", "language: x", 1), "corpus-source/v1", "v0", 1)
	_, err = ParseManifest([]byte(several))
	if !errors.As(err, &errs) || !slices.Equal(errs.Codes(), []string{CodeLanguage, CodeSchema}) {
		t.Fatal(err)
	}
}

func TestTemplateIsAValidCommentedManifest(t *testing.T) {
	b, err := Template(`Finance "L3": cours`, "fr")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(b)
	if err != nil || m.Title != `Finance "L3": cours` || m.Language != "fr" || len(m.Processing.Steps()) != 0 ||
		!strings.Contains(string(b), "# corrections:") || !strings.Contains(string(b), "# exclude:") {
		t.Fatal(string(b), err)
	}
	// Uncommenting the examples gives a valid manifest too.
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#   ") || strings.HasPrefix(line, "  # ") || strings.HasPrefix(line, "# exclude") ||
			strings.HasPrefix(line, "# documents") || strings.HasPrefix(line, "# corrections") {
			line = strings.Replace(line, "# ", "", 1)
			line, _, _ = strings.Cut(line, "  #")
		}
		lines = append(lines, line)
	}
	if m, err = ParseManifest([]byte(strings.Join(lines, "\n"))); err != nil || len(m.Processing.Steps()) != 5 ||
		len(m.Documents) != 1 || len(m.Corrections) != 1 || len(m.Exclude) != 1 {
		t.Fatal(strings.Join(lines, "\n"), err)
	}
	if _, err = Template("", "fr"); err == nil {
		t.Fatal("an empty title")
	}
	if _, err = Template("x", "français"); err == nil {
		t.Fatal("a language that is not a tag")
	}
}

func TestGlobs(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"**", "a.pdf", true},
		{"**", "a/b/c.pdf", true},
		{"courses/**", "courses/chap1.pdf", true},
		{"courses/**", "courses/x/y.pdf", true},
		{"courses/**", "other/courses/x.pdf", false},
		{"courses", "courses/x/y.pdf", true},
		{"courses", "courses.pdf", false},
		{"**/drafts/**", "drafts/a.md", true},
		{"**/drafts/**", "a/b/drafts/c.md", true},
		{"**/drafts", "a/drafts/c.md", true},
		{"**/drafts/**", "a/drafts-old/c.md", false},
		{"*.pdf", "a.pdf", true},
		{"*.pdf", "x/a.pdf", false},
		{"**/*.pdf", "x/y/a.pdf", true},
		{"**/*.pdf", "x/y/a.pdfx", false},
		{"data/202?/*.csv", "data/2024/a.csv", true},
		{"data/[0-9]*/a.csv", "data/9z/a.csv", true},
		{"data/[0-9]*/a.csv", "data/z9/a.csv", false},
		{"videos/**/session*.mp4", "videos/session2.mp4", true},
		{"a/**/b/**/c", "a/x/b/y/z/c", true},
		{"a/**/b/**/c", "a/x/c", false},
	} {
		if err := ValidPattern(c.pattern); err != nil {
			t.Fatal(c.pattern, err)
		}
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("%s on %s: %v", c.pattern, c.name, got)
		}
	}
	// A glob of many "**" on a deep path decides in linear time per element.
	deep := strings.Repeat("a/", 500) + "b"
	start := time.Now()
	if Match(strings.Repeat("**/a/", 40)+"**/c", deep) || !Match(strings.Repeat("**/a/", 40)+"**/b", deep) {
		t.Fatal("deep match")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("matching took", time.Since(start))
	}
}

func TestLFSPointers(t *testing.T) {
	oid := strings.Repeat("ab", 32)
	p, ok := ParsePointer([]byte(lfsVersion + "\noid sha256:" + oid + "\nsize 1048576\n"))
	if !ok || p.OID != oid || p.Size != 1048576 {
		t.Fatal(p, ok)
	}
	for name, b := range map[string]string{
		"no final newline": lfsVersion + "\noid sha256:" + oid + "\nsize 1",
		"upper-case oid":   lfsVersion + "\noid sha256:" + strings.ToUpper(oid) + "\nsize 1\n",
		"short oid":        lfsVersion + "\noid sha256:" + oid[:62] + "\nsize 1\n",
		"other version":    "version https://example.org/spec/v1\noid sha256:" + oid + "\nsize 1\n",
		"extra line":       lfsVersion + "\next-0-foo sha256:" + oid + "\noid sha256:" + oid + "\nsize 1\n",
		"leading zero":     lfsVersion + "\noid sha256:" + oid + "\nsize 01\n",
		"negative size":    lfsVersion + "\noid sha256:" + oid + "\nsize -1\n",
		"markdown":         "# Title\n\nText.\n",
	} {
		if _, ok := ParsePointer([]byte(b)); ok {
			t.Error("a pointer:", name)
		}
	}
}
