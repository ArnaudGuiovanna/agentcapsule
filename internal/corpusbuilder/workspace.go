package corpusbuilder

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg/source"
)

// Guest uses the encrypted data directory for phase checkpoints. Its device
// directory is /dev/corpus in the product guest. Keeping these explicit also
// allows a phase to run against a regular-file image in conformance tests.
type Guest struct {
	DataDir          string
	DeviceDir        string
	MaxExpandedBytes int64
}

type scanState struct {
	Request  ScanRequest
	Result   source.Result
	Manifest *source.Manifest
}

func readScan(dir string) (scanState, error) {
	var s scanState
	data, err := os.ReadFile(filepath.Join(dir, "scan.json"))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	s.Result.Manifest = s.Manifest
	return s, err
}

func (g Guest) Scan(ctx context.Context, r ScanRequest) (ScanReply, error) {
	if err := r.validate(); err != nil {
		return ScanReply{}, err
	}
	cursor := r.Cursor
	r.Cursor = ""
	parent := filepath.Join(g.DataDir, "builds")
	build := filepath.Join(parent, r.BuildID)
	state, err := readScan(build)
	if errors.Is(err, fs.ErrNotExist) {
		state, err = g.stageScan(ctx, r, parent, build)
	}
	if err != nil {
		return ScanReply{}, err
	}
	if state.Request != r {
		return ScanReply{}, errors.New("build source changed")
	}
	return scanPage(state.Result, cursor)
}

func (g Guest) stageScan(ctx context.Context, r ScanRequest, parent, build string) (scanState, error) {
	if err := os.MkdirAll(parent, 0700); err != nil {
		return scanState{}, err
	}
	tmp, err := os.MkdirTemp(parent, ".scan-")
	if err != nil {
		return scanState{}, err
	}
	defer os.RemoveAll(tmp)
	tree := filepath.Join(tmp, "source")
	if err = os.Mkdir(tree, 0700); err != nil {
		return scanState{}, err
	}
	drive, err := os.Open(filepath.Join(g.DeviceDir, "source"))
	if err != nil {
		return scanState{}, err
	}
	defer drive.Close()
	limit := g.MaxExpandedBytes
	if limit == 0 {
		limit = 16 << 30
	}
	if err = extractSource(ctx, drive, r.Source, tree, r.Path, limit); err != nil {
		return scanState{}, err
	}
	result, err := source.Scan(os.DirFS(tree), source.Options{Measure: true})
	if err != nil {
		return scanState{}, err
	}
	state := scanState{r, result, result.Manifest}
	data, err := json.Marshal(state)
	if err != nil {
		return scanState{}, err
	}
	if err = os.WriteFile(filepath.Join(tmp, "scan.json"), data, 0600); err != nil {
		return scanState{}, err
	}
	if err = os.Rename(tmp, build); err != nil {
		// Another caller may have committed this build while we read it.
		if existing, e := readScan(build); e == nil {
			return existing, nil
		}
		return scanState{}, err
	}
	return state, nil
}
