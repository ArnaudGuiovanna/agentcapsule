package corpusmeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// Paths of the published layout agentcapsule.corpus/v1, at the image's root
// (/corpus/<mount>/ in a VM).
const (
	InfoFile     = "corpus.json"       // Info
	IndexFile    = "INDEX.md"          // the global summary
	TopicsDir    = "topics"            // topics/*.md
	GlossaryFile = "glossary.md"       // terms with a sourced definition
	DocsDir      = "docs"              // docs/<id>/
	SearchFile   = "search/fts.sqlite" // FTS5 passages
	ReportFile   = "report.json"       // Report
	ExtDir       = "ext"               // reserved for enrichers: empty in this version

	// In docs/<id>/:
	DocumentFile = "doc.json"  // DocumentRecord
	ReadmeFile   = "README.md" // summary, outline, metadata, source path

	// MaxIndexBytes bounds INDEX.md (a target of 8,000 tokens).
	MaxIndexBytes = 64 << 10
	// MaxReportBytes bounds report.json: the review bundle's total.
	MaxReportBytes = 8 << 20
	// MaxInfoBytes bounds corpus.json.
	MaxInfoBytes = 32 << 20
)

// RequiredFiles are the regular files every image holds; the worker refuses
// an image without them.
var RequiredFiles = []string{InfoFile, IndexFile, SearchFile}

// Modalities of a corpus: what its documents came from.
const (
	ModalityText  = "text"
	ModalityImage = "image"
	ModalityAudio = "audio"
	ModalityVideo = "video"
)

// Info is corpus.json: what the image holds. It names no release version,
// which the image cannot know: one image may be published under several.
type Info struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Title  string `json:"title"`
	// BuildID, Commit and SourcePath say where the documents come from:
	// SourcePath is the corpus's path in the repository ("" for its root),
	// and each document's path is relative to it.
	BuildID    string `json:"build_id"`
	Commit     string `json:"commit"`
	SourcePath string `json:"source_path"`
	// Builder is the builder release, name@version.
	Builder    string      `json:"builder"`
	Languages  []string    `json:"languages"`
	Modalities []string    `json:"modalities"`
	Tokens     int64       `json:"tokens"`
	Embeddings *Embeddings `json:"embeddings,omitempty"`
	Documents  []InfoEntry `json:"documents"`
}

// Embeddings describes search/vectors.*, present only with it: a harness
// embeds its queries with the same alias, and checks the model.
type Embeddings struct {
	Alias      string `json:"alias"`
	Model      string `json:"model,omitempty"`
	Dimensions int    `json:"dimensions"`
}

// InfoEntry is one document of corpus.json.
type InfoEntry struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Kind   Kind   `json:"kind"`
	Title  string `json:"title"`
	Tokens int64  `json:"tokens"`
}

// ParseInfo decodes corpus.json strictly and validates it.
func ParseInfo(b []byte) (Info, error) {
	var i Info
	if err := strictJSON(b, MaxInfoBytes, &i); err != nil {
		return Info{}, Invalid("corpus.json: %v", err)
	}
	return i, i.Validate()
}

func (i Info) Validate() error {
	switch {
	case i.Schema != Schema:
		return Invalid("corpus.json schema must be %s", Schema)
	case !ValidName(i.Name) || !Text(i.Title, 200):
		return Invalid("corpus.json name or title")
	case !ValidID("cbd", i.BuildID) || !ValidCommit(i.Commit) || i.SourcePath != "" && !ValidPath(i.SourcePath):
		return Invalid("corpus.json build_id, commit or source_path")
	case !Text(i.Builder, 201):
		return Invalid("corpus.json builder")
	case len(i.Languages) < 1 || i.Tokens < 0:
		return Invalid("corpus.json languages or tokens")
	}
	for _, m := range i.Modalities {
		if !slices.Contains([]string{ModalityText, ModalityImage, ModalityAudio, ModalityVideo}, m) {
			return Invalid("corpus.json modality")
		}
	}
	if e := i.Embeddings; e != nil && (!ValidAlias(e.Alias) || e.Dimensions < 1 || e.Model != "" && !Text(e.Model, 200)) {
		return Invalid("corpus.json embeddings")
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	var total int64
	for _, d := range i.Documents {
		if !ValidMount(d.ID) || ids[d.ID] || !ValidPath(d.Path) || paths[d.Path] || !slices.Contains(Kinds, d.Kind) ||
			d.Kind == KindOther || !Text(d.Title, 200) || d.Tokens < 0 {
			return Invalid("corpus.json document")
		}
		ids[d.ID], paths[d.Path] = true, true
		total += d.Tokens
	}
	if total != i.Tokens {
		return Invalid("corpus.json tokens are not the documents' sum")
	}
	return nil
}

// DocumentRecord is docs/<id>/doc.json: a document in canonical form, its
// elements in reading order. Its Markdown view, part-001.md and following,
// holds the same elements, each after an anchor <a id="ELEMENT_ID"></a>.
type DocumentRecord struct {
	Schema    string    `json:"schema"`
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Kind      Kind      `json:"kind"`
	Title     string    `json:"title"`
	Language  string    `json:"language,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Pages     int       `json:"pages,omitempty"`
	Seconds   float64   `json:"seconds,omitempty"`
	Corrected bool      `json:"corrected,omitempty"`
	Elements  []Element `json:"elements"`
}

// DocumentSchema is doc.json's schema.
const DocumentSchema = "agentcapsule.corpus-document/v1"

// Element types and sources.
var (
	ElementTypes   = []string{"heading", "paragraph", "list", "table", "figure", "caption", "code", "formula", "quote", "note", "transcript"}
	ElementSources = []string{"native", "ocr", "transcription", "vision", "correction"}
)

// Element is one typed part of a document, with its locator: a page (or
// slide) and a box on it, a sheet and cell range, or a time range.
type Element struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Text string `json:"text"`
	// Level is a heading's level, 1 to 6.
	Level int `json:"level,omitempty"`
	// Page is the page or slide, from 1; Box is x0, y0, x1, y1 as fractions
	// of the page's width and height, from its top left corner.
	Page int         `json:"page,omitempty"`
	Box  *[4]float64 `json:"box,omitempty"`
	// Sheet and Range locate a spreadsheet's cells ("B2:F40").
	Sheet string `json:"sheet,omitempty"`
	Range string `json:"range,omitempty"`
	// Start and End are seconds from the start of audio or video.
	Start *float64 `json:"start,omitempty"`
	End   *float64 `json:"end,omitempty"`
	// Source says how the text was obtained; Confidence, 0 to 1, how sure
	// the step that produced it was, when it says.
	Source     string   `json:"source"`
	Confidence *float64 `json:"confidence,omitempty"`
	// Part is the Markdown part that holds the element: "part-001.md".
	Part string `json:"part"`
}

func (d DocumentRecord) Validate() error {
	if d.Schema != DocumentSchema || !ValidMount(d.ID) || !ValidPath(d.Path) || !slices.Contains(Kinds, d.Kind) ||
		!Text(d.Title, 200) || d.Pages < 0 || d.Seconds < 0 {
		return Invalid("doc.json header")
	}
	ids := map[string]bool{}
	for _, e := range d.Elements {
		ok := ValidMount(e.ID) && !ids[e.ID] && slices.Contains(ElementTypes, e.Type) && slices.Contains(ElementSources, e.Source) &&
			(e.Level == 0 || e.Type == "heading" && e.Level <= 6) && e.Page >= 0 && validPart(e.Part) &&
			(e.Confidence == nil || *e.Confidence >= 0 && *e.Confidence <= 1) &&
			(e.Start == nil || *e.Start >= 0) && (e.End == nil || e.Start != nil && *e.End >= *e.Start)
		if e.Box != nil {
			b := *e.Box
			ok = ok && e.Page > 0 && 0 <= b[0] && b[0] <= b[2] && b[2] <= 1 && 0 <= b[1] && b[1] <= b[3] && b[3] <= 1
		}
		if !ok {
			return Invalid("doc.json element")
		}
		ids[e.ID] = true
	}
	return nil
}

// PartName is the name of a document's n-th Markdown part, from 1:
// part-001.md.
func PartName(n int) string { return fmt.Sprintf("part-%03d.md", n) }

func validPart(p string) bool {
	var n int
	_, err := fmt.Sscanf(p, "part-%03d.md", &n)
	return err == nil && n >= 1 && PartName(n) == p
}

// strictJSON decodes one JSON value of at most max bytes into v: unknown
// fields and trailing data are refused.
func strictJSON(b []byte, max int, v any) error {
	if len(b) == 0 || len(b) > max {
		return fmt.Errorf("size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("does not decode")
	}
	if d.More() {
		return fmt.Errorf("trailing data")
	}
	var rest any
	if err := d.Decode(&rest); err == nil {
		return fmt.Errorf("trailing data")
	}
	return nil
}
