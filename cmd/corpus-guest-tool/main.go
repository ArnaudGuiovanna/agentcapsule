// corpus-guest-tool runs inside a corpus builder release. The harness passes
// the phase input on stdin and reads one JSON reply from stdout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusbuilder"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
)

type packageRequest struct {
	Schema  string `json:"schema"`
	Phase   string `json:"phase"`
	BuildID string `json:"build_id"`
	UUID    string `json:"uuid"`
	Output  struct {
		Bytes int64 `json:"bytes"`
	} `json:"output"`
}

func decode(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}

func run(ctx context.Context, args []string, input io.Reader) (any, error) {
	if len(args) != 3 || !filepath.IsAbs(args[1]) || !filepath.IsAbs(args[2]) {
		return nil, errors.New("expected phase, data directory, device directory")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 32*1024+1))
	if err != nil || len(raw) > 32*1024 {
		return nil, errors.New("invalid input size")
	}
	g := corpusbuilder.Guest{DataDir: args[1], DeviceDir: args[2]}
	switch args[0] {
	case "scan":
		var req corpusbuilder.ScanRequest
		if err = decode(raw, &req); err != nil {
			return nil, err
		}
		return g.Scan(ctx, req)
	case "package":
		var req packageRequest
		if err = decode(raw, &req); err != nil {
			return nil, err
		}
		if req.Schema != corpusbuilder.Schema || req.Phase != "package" || !corpusmeta.ValidID("cbd", req.BuildID) || !corpusmeta.ValidUUID(req.UUID) || req.Output.Bytes <= 0 {
			return nil, errors.New("invalid package request")
		}
		dir := filepath.Join(g.DataDir, "builds", req.BuildID)
		layout := filepath.Join(dir, "layout")
		raw, err = os.ReadFile(filepath.Join(dir, "execution.json"))
		if err != nil {
			return nil, err
		}
		report, err := corpusmeta.ParseReport(raw)
		if err != nil || report.BuildID != req.BuildID {
			return nil, errors.New("invalid execution report")
		}
		encoded, err := os.ReadFile(filepath.Join(layout, corpusmeta.InfoFile))
		if err != nil {
			return nil, err
		}
		info, err := corpusmeta.ParseInfo(encoded)
		if err != nil || info.Commit != report.Commit || info.Tokens != report.Totals.Tokens {
			return nil, errors.New("invalid corpus info")
		}
		index, err := os.ReadFile(filepath.Join(layout, corpusmeta.IndexFile))
		if err != nil {
			return nil, err
		}
		// Use a fresh sparse file for mkfs, including on replay: a retried
		// request can arrive with an already formatted output block device.
		image, err := os.CreateTemp(dir, ".image-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(image.Name())
		defer image.Close()
		size, err := corpuspkg.BuildImage(ctx, layout, image.Name(), req.UUID, req.Output.Bytes-int64(len(raw))-48)
		if err != nil {
			return nil, err
		}
		disk, err := os.OpenFile(filepath.Join(g.DeviceDir, "output"), os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		defer disk.Close()
		if _, err = io.CopyN(disk, image, size); err != nil {
			return nil, err
		}
		if err = corpuspkg.WriteExecutionReport(disk, req.Output.Bytes, size, raw); err != nil {
			return nil, err
		}
		if err = disk.Sync(); err != nil {
			return nil, err
		}
		return map[string]any{"schema": req.Schema, "phase": req.Phase, "image_bytes": size, "documents": len(info.Documents), "tokens": info.Tokens, "index_tokens": (len(index) + 3) / 4}, nil
	}
	return nil, errors.New("unknown guest tool phase")
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := run(ctx, os.Args[1:], os.Stdin)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
