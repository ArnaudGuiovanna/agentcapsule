package source

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"slices"
	"strings"
)

// Reasons a file is not kept.
const (
	ReasonManifest     = "manifest"         // agentcapsule-corpus.yaml itself
	ReasonCorrection   = "correction"       // a correction's Markdown, read with its document
	ReasonHidden       = "hidden"           // a name starting with '.', or inside such a directory
	ReasonSymlink      = "symlink"          // never followed
	ReasonSpecial      = "special_file"     // not a regular file
	ReasonInvalidName  = "invalid_name"     // not printable UTF-8, or a backslash
	ReasonNotIncluded  = "not_included"     // matches no include glob
	ReasonExcluded     = "excluded"         // matches an exclude glob
	ReasonUnsupported  = "unsupported_type" // an extension no build converts
	ReasonStepDisabled = "step_disabled"    // its kind needs a processing step that is off
)

// Warning codes: what a build accepts but the author may not mean.
const (
	WarnPatternUnused   = "pattern_unused"   // an include or exclude glob matches no file
	WarnContentMismatch = "content_mismatch" // the content does not start as its extension says
	WarnLFSPointer      = "lfs_pointer"      // a Git LFS pointer, not its object: not measured here
	WarnLFSLimit        = "lfs_limit"        // past the default limits of LFS objects per build
	WarnDefaultManifest = "default_manifest" // no usable manifest: the defaults select the files
)

// Default limits of a worker (ADR 023 §13), which an operator may change.
const (
	DefaultMaxLFSObjects = 10000
	DefaultMaxLFSBytes   = 20 << 30
)

// File is a file a build keeps.
type File struct {
	Path  string `json:"path"`
	Kind  Kind   `json:"kind"`
	Bytes int64  `json:"bytes"`
	// LFS is the object a Git LFS pointer stands for; Bytes is then its
	// size.
	LFS *Pointer `json:"lfs,omitempty"`
	Measures
}

// Ignored is a file, or a hidden directory ("name/"), a build does not
// keep, and why. Step names the step a ReasonStepDisabled file needs.
type Ignored struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Step   string `json:"step,omitempty"`
}

// Warning is something a build accepts but the author may not mean. Path is
// the file or the glob it is about.
type Warning struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Totals sum the kept files.
type Totals struct {
	Seen    int          `json:"seen"`
	Kept    int          `json:"kept"`
	Ignored int          `json:"ignored"`
	Bytes   int64        `json:"bytes"`
	Kinds   map[Kind]int `json:"kinds"`
	Estimate
	LFSObjects int   `json:"lfs_objects"`
	LFSBytes   int64 `json:"lfs_bytes"`
}

// Estimate is the volume a build will process, from the files' headers:
// Unmeasured counts the files whose measure could not be read cheaply.
type Estimate struct {
	Pages        int64 `json:"pages"`
	Slides       int64 `json:"slides"`
	Sheets       int64 `json:"sheets"`
	Images       int64 `json:"images"`
	AudioSeconds int64 `json:"audio_seconds"`
	VideoSeconds int64 `json:"video_seconds"`
	TextTokens   int64 `json:"text_tokens"`
	Unmeasured   int64 `json:"unmeasured"`
}

// Result is what Scan found.
type Result struct {
	// Manifest is the manifest Scan read, nil when missing or unreadable;
	// Errors says why.
	Manifest *Manifest `json:"-"`
	Errors   Errors    `json:"errors"`
	Files    []File    `json:"files"`
	Ignored  []Ignored `json:"ignored"`
	Warnings []Warning `json:"warnings"`
	Totals   Totals    `json:"totals"`
	// LFS lists each object the kept files point to once, by OID.
	LFS []Pointer `json:"lfs"`
}

// Valid reports whether a build would accept the source.
func (r Result) Valid() bool { return len(r.Errors) == 0 }

// Options of a scan.
type Options struct {
	// Measure reads the pages, slides, sheets and durations of the kept
	// files from their headers (Measure).
	Measure bool
}

type candidate struct {
	path string
	size int64
}

// Scan reads the manifest at the root of fsys, then walks fsys and sorts
// every file into kept and ignored, as a build would. Symbolic links are
// never followed. A missing or unreadable manifest is an error of the
// result, and the defaults (every file, no processing step) select the
// files. The error is an I/O failure only.
func Scan(fsys fs.FS, o Options) (Result, error) {
	r := Result{Errors: Errors{}, Files: []File{}, Ignored: []Ignored{}, Warnings: []Warning{}, LFS: []Pointer{},
		Totals: Totals{Kinds: map[Kind]int{}}}
	m, err := readManifest(fsys)
	var errs Errors
	switch {
	case errors.As(err, &errs):
		r.Errors = append(r.Errors, errs...)
		decoded := !slices.ContainsFunc(errs, func(e *Error) bool {
			return e.Code == CodeManifestMissing || e.Code == CodeManifestInvalid
		})
		if decoded { // its invalid fields are left out below
			r.Manifest = &m
		}
	case err != nil:
		return Result{}, err
	default:
		r.Manifest = &m
	}
	if r.Manifest == nil {
		m = Manifest{}
		r.Warnings = append(r.Warnings, Warning{WarnDefaultManifest, "", "no usable manifest: every file is selected, no processing step is on"})
	}
	var files []candidate
	ignore := func(p, reason, step string) { r.Ignored = append(r.Ignored, Ignored{p, reason, step}) }
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		switch {
		case strings.HasPrefix(d.Name(), ".") && d.IsDir():
			ignore(p+"/", ReasonHidden, "")
			return fs.SkipDir
		case d.IsDir():
			return nil
		case p == ManifestFile:
			ignore(p, ReasonManifest, "")
		case strings.HasPrefix(d.Name(), "."):
			ignore(p, ReasonHidden, "")
		case d.Type()&fs.ModeSymlink != 0:
			ignore(p, ReasonSymlink, "")
		case !d.Type().IsRegular():
			ignore(p, ReasonSpecial, "")
		case !ValidPath(p):
			ignore(p, ReasonInvalidName, "")
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}
			files = append(files, candidate{p, info.Size()})
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	include, exclude := validPatterns(m.Patterns()), validPatterns(m.Exclude)
	includeUsed, excludeUsed := make([]bool, len(include)), make([]bool, len(exclude))
	corrections := map[string]bool{}
	for _, c := range m.Corrections {
		corrections[c.Markdown] = false
	}
	steps := m.Processing.Steps()
	kept := map[string]bool{}
	objects := map[string]int64{}
	for _, c := range files {
		if _, ok := corrections[c.path]; ok {
			corrections[c.path] = true
			ignore(c.path, ReasonCorrection, "")
			continue
		}
		in, out := firstMatch(include, c.path), firstMatch(exclude, c.path)
		if in >= 0 {
			includeUsed[in] = true
		}
		if in >= 0 && out >= 0 {
			excludeUsed[out] = true
		}
		kind := KindOf(c.path)
		_, stepOn := steps[NeededStep(kind)]
		switch {
		case in < 0:
			ignore(c.path, ReasonNotIncluded, "")
			continue
		case out >= 0:
			ignore(c.path, ReasonExcluded, "")
			continue
		case kind == KindOther:
			ignore(c.path, ReasonUnsupported, "")
			continue
		case NeededStep(kind) != "" && !stepOn:
			ignore(c.path, ReasonStepDisabled, NeededStep(kind))
			continue
		}
		f, warn, err := examine(fsys, c, kind, o.Measure)
		if err != nil {
			return Result{}, err
		}
		if warn != nil {
			r.Warnings = append(r.Warnings, *warn)
		}
		f.Tokens = TextTokens(kind, f.Bytes)
		kept[c.path] = true
		r.Files = append(r.Files, f)
		r.Totals.add(f)
		if f.LFS != nil {
			objects[f.LFS.OID] = f.LFS.Size
		}
	}
	for i, used := range includeUsed {
		if !used {
			r.Warnings = append(r.Warnings, Warning{WarnPatternUnused, include[i], "this include glob matches no file"})
		}
	}
	for i, used := range excludeUsed {
		if !used {
			r.Warnings = append(r.Warnings, Warning{WarnPatternUnused, exclude[i], "this exclude glob removes no included file"})
		}
	}
	for i, d := range m.Documents {
		if ValidPath(d.Path) && !kept[d.Path] {
			r.Errors = append(r.Errors, &Error{CodeDocumentMissing, fmt.Sprintf("documents[%d].path", i), d.Path + " is not a file this build keeps"})
		}
	}
	for i, c := range m.Corrections {
		if ValidPath(c.Path) && !kept[c.Path] {
			r.Errors = append(r.Errors, &Error{CodeDocumentMissing, fmt.Sprintf("corrections[%d].path", i), c.Path + " is not a file this build keeps"})
		}
		if found, listed := corrections[c.Markdown]; listed && !found && ValidPath(c.Markdown) {
			r.Errors = append(r.Errors, &Error{CodeCorrectionMissing, fmt.Sprintf("corrections[%d].markdown", i), c.Markdown + " is not a regular file of the corpus"})
		}
	}
	if len(r.Files) == 0 {
		r.Errors = append(r.Errors, &Error{CodeNoDocuments, "", "the build would keep no file"})
	}
	for oid, size := range objects {
		r.LFS = append(r.LFS, Pointer{oid, size})
		r.Totals.LFSBytes += size
	}
	r.Totals.LFSObjects = len(r.LFS)
	slices.SortFunc(r.LFS, func(a, b Pointer) int { return strings.Compare(a.OID, b.OID) })
	if r.Totals.LFSObjects > DefaultMaxLFSObjects || r.Totals.LFSBytes > DefaultMaxLFSBytes {
		r.Warnings = append(r.Warnings, Warning{WarnLFSLimit, "", fmt.Sprintf(
			"%d LFS objects of %d bytes: past a worker's default limits (%d objects, %d bytes)",
			r.Totals.LFSObjects, r.Totals.LFSBytes, DefaultMaxLFSObjects, int64(DefaultMaxLFSBytes))})
	}
	slices.SortFunc(r.Ignored, func(a, b Ignored) int { return strings.Compare(a.Path, b.Path) })
	r.Totals.Kept, r.Totals.Ignored = len(r.Files), len(r.Ignored)
	r.Totals.Seen = r.Totals.Kept + r.Totals.Ignored
	return r, nil
}

func readManifest(fsys fs.FS) (Manifest, error) {
	info, err := fs.Lstat(fsys, ManifestFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Manifest{}, Errors{{CodeManifestMissing, "", ManifestFile + " is missing"}}
	case err != nil:
		return Manifest{}, err
	case !info.Mode().IsRegular():
		return Manifest{}, Errors{{CodeManifestInvalid, "", ManifestFile + " must be a regular file"}}
	case info.Size() > MaxManifestBytes:
		return Manifest{}, Errors{{CodeManifestInvalid, "", fmt.Sprintf("the manifest must be 1 to %d bytes", MaxManifestBytes)}}
	}
	f, err := fsys.Open(ManifestFile)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(b)
}

func validPatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if ValidPattern(p) == nil {
			out = append(out, p)
		}
	}
	return out
}

func firstMatch(patterns []string, name string) int {
	for i, p := range patterns {
		if Match(p, name) {
			return i
		}
	}
	return -1
}

// examine reads a kept file's head: a Git LFS pointer stands for its object;
// otherwise the head should match the extension, and the file is measured
// when measure is set.
func examine(fsys fs.FS, c candidate, kind Kind, measure bool) (File, *Warning, error) {
	f := File{Path: c.path, Kind: kind, Bytes: c.size}
	file, err := fsys.Open(c.path)
	if err != nil {
		return File{}, nil, err
	}
	defer file.Close()
	head := make([]byte, 4096)
	n, err := io.ReadFull(file, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return File{}, nil, err
	}
	head = head[:n]
	if c.size < MaxPointerBytes {
		if p, ok := ParsePointer(head); ok {
			f.LFS, f.Bytes = &p, p.Size
			f.Unmeasured = measurable(kind)
			return f, &Warning{WarnLFSPointer, c.path, "a Git LFS pointer: install Git LFS and pull the object to measure it"}, nil
		}
	}
	var warn *Warning
	if !looksLike(strings.ToLower(path.Ext(c.path)), head) {
		warn = &Warning{WarnContentMismatch, c.path, "the content does not start as a " + string(kind) + " file does"}
	}
	if measure {
		ra, ok := file.(io.ReaderAt)
		if !ok {
			// A file system without random access: measure what the head holds.
			ra = readerAt(head)
		}
		f.Measures = Measure(ra, c.size, c.path)
	}
	return f, warn, nil
}

func (t *Totals) add(f File) {
	t.Bytes += f.Bytes
	t.Kinds[f.Kind]++
	t.Pages += int64(f.Pages)
	t.Slides += int64(f.Slides)
	t.Sheets += int64(f.Sheets)
	t.TextTokens += f.Tokens
	if f.Kind == KindImage {
		t.Images++
	}
	seconds := int64(math.Ceil(f.Seconds))
	if f.Kind == KindAudio {
		t.AudioSeconds += seconds
	}
	if f.Kind == KindVideo {
		t.VideoSeconds += seconds
	}
	if f.Unmeasured {
		t.Unmeasured++
	}
}

type readerAt []byte

func (b readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
