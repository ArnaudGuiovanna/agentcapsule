package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
)

const schema = "agentcapsule.corpus-enricher/v1"

type request struct {
	Schema  string `json:"schema"`
	BuildID string `json:"build_id"`
	Name    string `json:"name"`
	Mount   string `json:"mount"`
	UUID    string `json:"uuid"`
	Output  struct {
		Bytes int64 `json:"bytes"`
	} `json:"output"`
}
type response struct {
	Schema     string `json:"schema"`
	ImageBytes int64  `json:"image_bytes"`
}
type notion struct {
	Title  string `json:"title"`
	Source string `json:"source"`
}
type exercise struct {
	Prompt string `json:"prompt"`
	Source string `json:"source"`
}

// enrich reads the filesystem mounted by capsule-init. Each exercise cites a
// document in that immutable base. Data-specific choices live in this harness.
func enrich(ctx context.Context, raw []byte, base, output, work string) (response, error) {
	var q request
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		return response{}, err
	}
	if d.Decode(&struct{}{}) != io.EOF || q.Schema != schema || q.Mount != "/corpus/base" || !capsuleprotocol.ValidCorpusMount(q.Name) || !corpusmeta.ValidID("cbd", q.BuildID) || !capsuleprotocol.ValidUUID(q.UUID) || q.Output.Bytes < corpuspkg.MinImageBytes || q.Output.Bytes > capsuleprotocol.MaxBuildDriveBytes {
		return response{}, errors.New("invalid enrichment instruction")
	}
	f, err := os.Open(filepath.Join(base, corpusmeta.InfoFile))
	if err != nil {
		return response{}, err
	}
	metadata, err := io.ReadAll(io.LimitReader(f, corpusmeta.MaxInfoBytes+1))
	f.Close()
	if err != nil {
		return response{}, err
	}
	info, err := corpusmeta.ParseInfo(metadata)
	if err != nil {
		return response{}, err
	}
	notions := []notion{}
	exercises := []exercise{}
	for _, doc := range info.Documents {
		cite := "docs/" + doc.ID + "/README.md"
		notions = append(notions, notion{doc.Title, cite})
		exercises = append(exercises, exercise{fmt.Sprintf("Expliquez « %s » à partir du document et citez un exemple.", doc.Title), cite})
	}
	scratch, err := os.MkdirTemp(work, ".course-")
	if err != nil {
		return response{}, err
	}
	defer os.RemoveAll(scratch)
	layout := filepath.Join(scratch, "layout")
	if err = os.Mkdir(layout, 0700); err != nil {
		return response{}, err
	}
	for name, items := range map[string]any{"notions.json": notions, "exercices.json": exercises} {
		b, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return response{}, err
		}
		if err = os.WriteFile(filepath.Join(layout, name), append(b, '\n'), 0600); err != nil {
			return response{}, err
		}
	}
	image := filepath.Join(scratch, "course.ext4")
	size, err := corpuspkg.BuildExtensionImage(ctx, layout, image, q.UUID, q.Output.Bytes)
	if err != nil {
		return response{}, err
	}
	src, err := os.Open(image)
	if err != nil {
		return response{}, err
	}
	defer src.Close()
	out, err := os.OpenFile(output, os.O_WRONLY, 0)
	if err != nil {
		return response{}, err
	}
	defer out.Close()
	if _, err = io.CopyN(out, src, size); err != nil {
		return response{}, err
	}
	if err = out.Sync(); err != nil {
		return response{}, err
	}
	return response{schema, size}, nil
}
