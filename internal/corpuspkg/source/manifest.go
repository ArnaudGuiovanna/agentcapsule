// Package source defines the source side of a corpus: the manifest
// agentcapsule-corpus.yaml (schema agentcapsule.corpus-source/v1) that an
// author keeps in the repository next to the documents, which files a build
// keeps and why it ignores the others, and the volumes it will process.
//
// The corpus builder reads it in its VM; the CLI's corpus init and corpus
// lint read it on the author's own machine. The platform host never does:
// it neither parses a manifest nor opens a source file (ADR 023, REG-007).
// The package runs no program, and decodes no media.
package source

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
)

const (
	// Schema is the manifest's schema.
	Schema = "agentcapsule.corpus-source/v1"
	// ManifestFile is the manifest's name, at the corpus's path in the
	// repository.
	ManifestFile = "agentcapsule-corpus.yaml"
	// MaxManifestBytes bounds the manifest.
	MaxManifestBytes = 64 << 10

	maxPatterns = 64
	maxTags     = 32
)

// Error codes: the closed list of reasons a build refuses a source (the scan
// phase's errors, ADR 023 §6.3). Field and Message say more to the author.
const (
	CodeManifestMissing   = "manifest_missing"   // no agentcapsule-corpus.yaml at the corpus's path
	CodeManifestInvalid   = "manifest_invalid"   // size, encoding, YAML, unknown field, duplicate key, extra document, type
	CodeSchema            = "schema_unsupported" // schema is not agentcapsule.corpus-source/v1
	CodeTitle             = "title_invalid"
	CodeLanguage          = "language_invalid"
	CodePattern           = "pattern_invalid"    // an include or exclude glob
	CodeProcessing        = "processing_invalid" // an alias or an OCR mode
	CodeDocument          = "document_invalid"   // a documents entry
	CodeDocumentMissing   = "document_missing"   // documents or corrections names no kept file
	CodeCorrection        = "correction_invalid" // a corrections entry
	CodeCorrectionMissing = "correction_missing" // a correction's Markdown file is absent
	CodeNoDocuments       = "no_documents"       // the build would keep no file
)

// Codes lists every error code.
var Codes = []string{CodeManifestMissing, CodeManifestInvalid, CodeSchema, CodeTitle, CodeLanguage, CodePattern,
	CodeProcessing, CodeDocument, CodeDocumentMissing, CodeCorrection, CodeCorrectionMissing, CodeNoDocuments}

// Error is one reason a source is refused.
type Error struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Field == "" {
		return e.Code + ": " + e.Message
	}
	return e.Code + ": " + e.Field + ": " + e.Message
}

// Errors is every reason a source is refused, in the order found.
type Errors []*Error

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, err := range e {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

// Codes returns the distinct codes of e, in the order found.
func (e Errors) Codes() []string {
	var codes []string
	for _, err := range e {
		if !slices.Contains(codes, err.Code) {
			codes = append(codes, err.Code)
		}
	}
	return codes
}

// Manifest is agentcapsule-corpus.yaml.
type Manifest struct {
	Schema   string `yaml:"schema"`
	Title    string `yaml:"title"`
	Language string `yaml:"language"`
	// Include and Exclude are globs relative to the corpus's path; Include
	// defaults to ["**"].
	Include     []string     `yaml:"include,omitempty"`
	Exclude     []string     `yaml:"exclude,omitempty"`
	Processing  Processing   `yaml:"processing,omitempty"`
	Documents   []Document   `yaml:"documents,omitempty"`
	Corrections []Correction `yaml:"corrections,omitempty"`
}

// Processing names the steps a build runs and the LLM alias of each. A step
// left out is off.
type Processing struct {
	OCR           *OCR    `yaml:"ocr,omitempty"`
	Transcription *Step   `yaml:"transcription,omitempty"`
	Vision        *Vision `yaml:"vision,omitempty"`
	Summaries     *Step   `yaml:"summaries,omitempty"`
	Embeddings    *Step   `yaml:"embeddings,omitempty"`
}

// Step is a processing step served by an LLM alias of the organization.
type Step struct {
	Alias string `yaml:"alias"`
}

// OCR reads pages that have no native text (mode auto, the default) or every
// page (mode always).
type OCR struct {
	Alias string `yaml:"alias"`
	Mode  string `yaml:"mode,omitempty"`
}

// Vision describes images, and figures in documents when DescribeFigures.
type Vision struct {
	Alias           string `yaml:"alias"`
	DescribeFigures bool   `yaml:"describe_figures,omitempty"`
}

// Document is optional metadata of one source file.
type Document struct {
	Path  string   `yaml:"path"`
	Title string   `yaml:"title,omitempty"`
	Tags  []string `yaml:"tags,omitempty"`
}

// Correction replaces the generated Markdown view of the document at Path
// with the Markdown file at Markdown.
type Correction struct {
	Path     string `yaml:"path"`
	Markdown string `yaml:"markdown"`
}

// ParseManifest decodes agentcapsule-corpus.yaml strictly (unknown fields,
// duplicate keys, several documents or an oversized file are refused) and
// validates it. A non-nil error is Errors.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) == 0 || len(b) > MaxManifestBytes || !utf8.Valid(b) {
		return Manifest{}, Errors{{CodeManifestInvalid, "", fmt.Sprintf("the manifest must be UTF-8, 1 to %d bytes", MaxManifestBytes)}}
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&m); err != nil {
		return Manifest{}, Errors{{CodeManifestInvalid, "", yamlMessage(err)}}
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Manifest{}, Errors{{CodeManifestInvalid, "", "the manifest holds more than one YAML document"}}
	}
	if err := m.Validate(); err != nil {
		return m, err
	}
	return m, nil
}

// yamlMessage keeps yaml.v3's line and reason, which name the author's
// field, never more than the first line.
func yamlMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

var language = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$`)

// Validate checks every field and returns every problem found, as Errors.
func (m Manifest) Validate() error {
	var errs Errors
	add := func(code, field, format string, args ...any) {
		errs = append(errs, &Error{code, field, fmt.Sprintf(format, args...)})
	}
	if m.Schema != Schema {
		add(CodeSchema, "schema", "must be %s", Schema)
	}
	if !corpusmeta.Text(m.Title, 200) {
		add(CodeTitle, "title", "1 to 200 characters, without control characters")
	}
	if len(m.Language) > 35 || !language.MatchString(m.Language) {
		add(CodeLanguage, "language", "a BCP 47 language tag, such as fr or en-GB")
	}
	for name, patterns := range map[string][]string{"include": m.Include, "exclude": m.Exclude} {
		if len(patterns) > maxPatterns {
			add(CodePattern, name, "at most %d patterns", maxPatterns)
		}
		for i, p := range patterns {
			if err := ValidPattern(p); err != nil {
				add(CodePattern, fmt.Sprintf("%s[%d]", name, i), "%v", err)
			}
		}
	}
	if m.Include != nil && len(m.Include) == 0 {
		add(CodePattern, "include", "an empty list keeps no file; leave include out to keep every file")
	}
	p := m.Processing
	for step, alias := range p.Steps() {
		if !corpusmeta.ValidAlias(alias) {
			add(CodeProcessing, "processing."+step+".alias", "an LLM alias of the organization: 1 to 100 bytes, without spaces")
		}
	}
	if p.OCR != nil && p.OCR.Mode != "" && p.OCR.Mode != "auto" && p.OCR.Mode != "always" {
		add(CodeProcessing, "processing.ocr.mode", "auto (pages without native text) or always")
	}
	paths := map[string]bool{}
	for i, d := range m.Documents {
		field := fmt.Sprintf("documents[%d]", i)
		switch {
		case !corpusmeta.ValidPath(d.Path):
			add(CodeDocument, field+".path", "a clean relative path inside the corpus")
		case paths[d.Path]:
			add(CodeDocument, field+".path", "%s is listed twice", d.Path)
		}
		paths[d.Path] = true
		if d.Title != "" && !corpusmeta.Text(d.Title, 200) {
			add(CodeDocument, field+".title", "1 to 200 characters, without control characters")
		}
		if len(d.Tags) > maxTags {
			add(CodeDocument, field+".tags", "at most %d tags", maxTags)
		}
		for j, tag := range d.Tags {
			if !corpusmeta.Text(tag, 50) || slices.Index(d.Tags, tag) != j {
				add(CodeDocument, fmt.Sprintf("%s.tags[%d]", field, j), "1 to 50 characters, each tag once")
			}
		}
	}
	corrected, markdown := map[string]bool{}, map[string]bool{}
	for i, c := range m.Corrections {
		field := fmt.Sprintf("corrections[%d]", i)
		switch {
		case !corpusmeta.ValidPath(c.Path):
			add(CodeCorrection, field+".path", "a clean relative path inside the corpus")
		case corrected[c.Path]:
			add(CodeCorrection, field+".path", "%s is corrected twice", c.Path)
		}
		corrected[c.Path] = true
		switch {
		case !corpusmeta.ValidPath(c.Markdown) || !strings.HasSuffix(strings.ToLower(c.Markdown), ".md"):
			add(CodeCorrection, field+".markdown", "a clean relative path to a .md file inside the corpus")
		case markdown[c.Markdown]:
			add(CodeCorrection, field+".markdown", "%s corrects two documents", c.Markdown)
		case c.Markdown == c.Path:
			add(CodeCorrection, field+".markdown", "a document cannot correct itself")
		}
		markdown[c.Markdown] = true
	}
	if len(errs) > 0 {
		slices.SortStableFunc(errs, func(a, b *Error) int { return strings.Compare(a.Field, b.Field) })
		return errs
	}
	return nil
}

// Step names, as Processing's fields.
const (
	StepOCR           = "ocr"
	StepTranscription = "transcription"
	StepVision        = "vision"
	StepSummaries     = "summaries"
	StepEmbeddings    = "embeddings"
)

// Steps maps each step that is on to its alias.
func (p Processing) Steps() map[string]string {
	steps := map[string]string{}
	if p.OCR != nil {
		steps[StepOCR] = p.OCR.Alias
	}
	if p.Transcription != nil {
		steps[StepTranscription] = p.Transcription.Alias
	}
	if p.Vision != nil {
		steps[StepVision] = p.Vision.Alias
	}
	if p.Summaries != nil {
		steps[StepSummaries] = p.Summaries.Alias
	}
	if p.Embeddings != nil {
		steps[StepEmbeddings] = p.Embeddings.Alias
	}
	return steps
}

// Patterns returns the include globs, ["**"] by default.
func (m Manifest) Patterns() []string {
	if len(m.Include) == 0 {
		return []string{"**"}
	}
	return m.Include
}

// Aliases returns the LLM aliases the manifest names, sorted, each once.
func (m Manifest) Aliases() []string {
	var out []string
	for _, a := range m.Processing.Steps() {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}
