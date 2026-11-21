// Package corpusbuilder runs inside the per-organization builder guest.
package corpusbuilder

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg/source"
)

const Schema = "agentcapsule.corpus-builder/v1"

type Drive struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ScanRequest is the first invocation. Subsequent pages use the same
// request and its previous answer's cursor.
type ScanRequest struct {
	Schema  string `json:"schema"`
	Phase   string `json:"phase"`
	BuildID string `json:"build_id"`
	Name    string `json:"name"`
	Builder string `json:"builder"`
	Commit  string `json:"commit"`
	Path    string `json:"path"`
	Source  Drive  `json:"source"`
	Cursor  string `json:"cursor,omitempty"`
}

type FileCount struct {
	Total    int `json:"total"`
	Included int `json:"included"`
	Skipped  int `json:"skipped"`
}

type Estimate struct {
	LLMCalls     int64 `json:"llm_calls"`
	InputTokens  int64 `json:"input_tokens"`
	AudioSeconds int64 `json:"audio_seconds"`
	Pages        int64 `json:"pages"`
}

type ScanReply struct {
	Schema     string              `json:"schema"`
	Phase      string              `json:"phase"`
	Manifest   string              `json:"manifest"`
	Errors     []string            `json:"errors,omitempty"`
	Files      FileCount           `json:"files"`
	Bytes      int64               `json:"bytes"`
	Kinds      map[source.Kind]int `json:"kinds"`
	Estimate   Estimate            `json:"estimate"`
	Aliases    []string            `json:"aliases"`
	LFS        []source.Pointer    `json:"lfs"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

func (d Drive) valid() bool {
	digest, err := hex.DecodeString(d.SHA256)
	return d.Bytes > 0 && err == nil && len(digest) == sha256.Size && strings.ToLower(d.SHA256) == d.SHA256
}

func (r ScanRequest) validate() error {
	if r.Schema != Schema || r.Phase != "scan" || !corpusmeta.ValidID("cbd", r.BuildID) ||
		!corpusmeta.ValidCommit(r.Commit) || !corpusmeta.ValidName(r.Name) || !corpusmeta.Text(r.Builder, 201) ||
		(r.Path != "" && !corpusmeta.ValidPath(r.Path)) || !r.Source.valid() {
		return errors.New("invalid builder scan request")
	}
	return nil
}

// extractSource reads exactly the authenticated, unpadded bytes. All
// repository members share one forge-provided top directory. Only regular
// files and directories are materialized in the guest's private workspace.
func extractSource(ctx context.Context, device io.ReaderAt, spec Drive, dir, subdir string, maxExpanded int64) error {
	if !spec.valid() || maxExpanded <= 0 || (subdir != "" && !corpusmeta.ValidPath(subdir)) {
		return errors.New("invalid source drive")
	}
	region := io.NewSectionReader(device, 0, spec.Bytes)
	sum := sha256.New()
	reader := io.TeeReader(region, sum)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gz.Close()
	// Charge tar headers and padding as well as file bodies against the limit.
	unpacked := &io.LimitedReader{R: gz, N: maxExpanded}
	tr := tar.NewReader(unpacked)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	wrapper := ""
	for n := 0; ; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n >= 100000 || h.Size < 0 {
			return errors.New("source exceeds entry limit")
		}
		// Git forge archives may start with a POSIX global metadata record.
		// It is not a filesystem entry and does not name the wrapper directory.
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		member := strings.TrimSuffix(h.Name, "/")
		if !fs.ValidPath(member) || member == "." || strings.ContainsRune(member, '\\') || len(member) > 4096 {
			return errors.New("invalid archive path")
		}
		top, rel, hasPath := strings.Cut(member, "/")
		if wrapper == "" {
			wrapper = top
		}
		if top != wrapper || (!hasPath && h.Typeflag != tar.TypeDir) {
			return errors.New("invalid forge archive root")
		}
		if !hasPath {
			continue
		}
		if subdir != "" {
			var keep bool
			rel, keep = strings.CutPrefix(rel, subdir+"/")
			if !keep {
				continue
			}
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = root.MkdirAll(rel, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err = root.MkdirAll(path.Dir(rel), 0700); err != nil {
				return err
			}
			f, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, h.Size)
			if err = errors.Join(copyErr, f.Close()); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Neither target is part of the corpus.
		default:
			return errors.New("unsupported archive entry")
		}
	}
	if _, err = io.Copy(io.Discard, unpacked); err != nil {
		return err
	}
	if unpacked.N == 0 || wrapper == "" {
		return errors.New("empty or oversized source")
	}
	// A short physical drive must fail even if its prefix is valid gzip.
	if _, err = io.Copy(io.Discard, reader); err != nil {
		return err
	}
	pos, err := region.Seek(0, io.SeekCurrent)
	if err != nil || pos != spec.Bytes || hex.EncodeToString(sum.Sum(nil)) != spec.SHA256 {
		return errors.New("source drive digest mismatch")
	}
	return nil
}

func scanPage(s source.Result, cursor string) (ScanReply, error) {
	out := ScanReply{Schema: Schema, Phase: "scan", Manifest: "valid", Files: FileCount{s.Totals.Seen, s.Totals.Kept, s.Totals.Ignored}, Bytes: s.Totals.Bytes, Kinds: s.Totals.Kinds, Aliases: []string{}, LFS: []source.Pointer{}}
	if !s.Valid() {
		out.Manifest = "invalid"
		codes := s.Errors.Codes()
		out.Errors = codes[:min(16, len(codes))]
		return out, nil
	}
	if a := s.Manifest.Aliases(); len(a) > 0 {
		out.Aliases = a
	}
	p := s.Manifest.Processing
	out.Estimate.InputTokens = s.Totals.TextTokens
	out.Estimate.AudioSeconds = s.Totals.AudioSeconds + s.Totals.VideoSeconds
	out.Estimate.Pages = s.Totals.Pages + s.Totals.Slides
	if p.OCR != nil && p.OCR.Mode != "never" {
		out.Estimate.LLMCalls += out.Estimate.Pages
	}
	if p.Transcription != nil {
		out.Estimate.LLMCalls += int64(s.Totals.Kinds[source.KindAudio] + s.Totals.Kinds[source.KindVideo])
	}
	if p.Vision != nil {
		out.Estimate.LLMCalls += s.Totals.Images
	}
	if p.Summaries != nil {
		out.Estimate.LLMCalls += int64(s.Totals.Kept)
	}
	if p.Embeddings != nil {
		out.Estimate.LLMCalls += int64(s.Totals.Kept)
	}
	offset := 0
	if cursor != "" {
		var err error
		offset, err = strconv.Atoi(cursor)
		if err != nil || offset <= 0 || offset%256 != 0 || offset >= len(s.LFS) || strconv.Itoa(offset) != cursor {
			return ScanReply{}, errors.New("invalid scan cursor")
		}
	}
	end := min(offset+256, len(s.LFS))
	out.LFS = append(out.LFS, s.LFS[offset:end]...)
	if end < len(s.LFS) {
		out.NextCursor = strconv.Itoa(end)
	}
	return out, nil
}
