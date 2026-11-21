package corpusmeta

import (
	"slices"
)

// ReportSchema is report.json's schema.
const ReportSchema = "agentcapsule.corpus-report/v1"

// Statuses of a file in the report.
const (
	StatusConverted = "converted" // converted by this build
	StatusCached    = "cached"    // taken from the builder's conversion cache
	StatusSkipped   = "skipped"   // an unsupported type, or a processing step that is off
	StatusFailed    = "failed"
)

// Report error codes (closed): a skipped file's reason, or a failed file's.
const (
	FileUnsupportedType = "unsupported_type"
	FileStepDisabled    = "step_disabled"
	FileTooLarge        = "too_large"
	FileMalformed       = "malformed"
	FileInferenceFailed = "inference_failed"
	FileTimeout         = "timeout"
)

// FileWarnings is the closed list of a file's warnings.
var FileWarnings = []string{
	"ocr_low_confidence",           // OCR said it was unsure of some text
	"transcription_low_confidence", // the transcription said it was unsure
	"no_text",                      // nothing was extracted
	"truncated",                    // the document was cut to fit a limit
	"corrected",                    // a correction of the manifest replaced its Markdown view
	"figures_not_described",        // figures were found, vision is off or failed
}

// Report is report.json: what a build did with each file it selected. Its
// costs are the platform ledger's, not the report's.
type Report struct {
	Schema  string        `json:"schema"`
	BuildID string        `json:"build_id"`
	Commit  string        `json:"commit"`
	Files   []ReportEntry `json:"files"`
	Totals  ReportTotals  `json:"totals"`
}

// ReportEntry is one file: DocID is its document's, for a converted or
// cached file, and "" otherwise; Error is "" for those, and a closed code
// for a skipped or failed one.
type ReportEntry struct {
	Path     string   `json:"path"`
	Kind     Kind     `json:"kind"`
	Status   string   `json:"status"`
	DocID    string   `json:"doc_id"`
	Bytes    int64    `json:"bytes"`
	Tokens   int64    `json:"tokens"`
	Warnings []string `json:"warnings"`
	Error    string   `json:"error"`
}

type ReportTotals struct {
	Files     int   `json:"files"`
	Converted int   `json:"converted"`
	Cached    int   `json:"cached"`
	Skipped   int   `json:"skipped"`
	Failed    int   `json:"failed"`
	Tokens    int64 `json:"tokens"`
}

// ParseReport decodes report.json strictly (unknown fields refused) and
// validates it, as the worker does when it reads the review bundle.
func ParseReport(b []byte) (Report, error) {
	var r Report
	if err := strictJSON(b, MaxReportBytes, &r); err != nil {
		return Report{}, Invalid("report.json: %v", err)
	}
	return r, r.Validate()
}

func (r Report) Validate() error {
	if r.Schema != ReportSchema || !ValidID("cbd", r.BuildID) || !ValidCommit(r.Commit) || r.Files == nil {
		return Invalid("report.json schema, build_id or commit")
	}
	var t ReportTotals
	paths := map[string]bool{}
	for _, f := range r.Files {
		var ok bool
		switch f.Status {
		case StatusConverted, StatusCached:
			ok = ValidMount(f.DocID) && f.Error == "" && f.Kind != KindOther
		case StatusSkipped:
			ok = f.DocID == "" && (f.Error == FileUnsupportedType || f.Error == FileStepDisabled)
		case StatusFailed:
			ok = f.DocID == "" && slices.Contains([]string{FileUnsupportedType, FileTooLarge, FileMalformed, FileInferenceFailed, FileTimeout}, f.Error)
		}
		ok = ok && ValidPath(f.Path) && !paths[f.Path] && slices.Contains(Kinds, f.Kind) && f.Bytes >= 0 && f.Tokens >= 0 &&
			f.Warnings != nil && len(f.Warnings) <= len(FileWarnings)
		for i, w := range f.Warnings {
			ok = ok && slices.Contains(FileWarnings, w) && slices.Index(f.Warnings, w) == i
		}
		if !ok {
			return Invalid("report.json file entry")
		}
		paths[f.Path] = true
		t.Files++
		t.Tokens += f.Tokens
		switch f.Status {
		case StatusConverted:
			t.Converted++
		case StatusCached:
			t.Cached++
		case StatusSkipped:
			t.Skipped++
		case StatusFailed:
			t.Failed++
		}
	}
	if t != r.Totals {
		return Invalid("report.json totals are not the files' sums")
	}
	return nil
}
