//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// The probe-corpus behaviour (ADR 023 §5): an event whose body is
// corpusProbeBody is answered with what the harness sees of /corpus instead
// of its echo, so that a KVM test checks the mounts from inside the
// harness. Other events are handled as usual.
const corpusProbeBody = "probe-corpus"

// corpusMarker is the file a test corpus carries at its root, read back by
// the probe; bin/tool is an executable it tries to run.
const corpusMarker = "marker.txt"

type corpusView struct {
	// Present: /corpus is a directory.
	Present bool     `json:"present"`
	Options []string `json:"options"`
	// Write is the outcome of creating a file in /corpus.
	Write  string            `json:"write"`
	Mounts []corpusMountView `json:"mounts"`
}

type corpusMountView struct {
	Name string `json:"name"`
	// Options are the mount's own options, from /proc/self/mountinfo.
	Options []string `json:"options"`
	// Marker is the start of the corpus's marker file.
	Marker string `json:"marker"`
	// Write and Exec are the outcomes of creating a file and of running
	// bin/tool: ok, or the errno that refused it (EROFS, EACCES), or other.
	Write string `json:"write"`
	Exec  string `json:"exec"`
}

func probeCorpusOf(handle mutation, root, mountinfo string) mutation {
	return func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if string(e.Body) != corpusProbeBody {
			return handle(ctx, e, tx)
		}
		return json.Marshal(probeCorpus(ctx, root, mountinfo))
	}
}

func probeCorpus(ctx context.Context, root, mountinfo string) corpusView {
	v := corpusView{Mounts: []corpusMountView{}}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return v
	}
	options := mountOptions(mountinfo)
	v.Present, v.Options, v.Write = true, options[root], tryWrite(root)
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		m := corpusMountView{Name: entry.Name(), Options: options[dir], Write: tryWrite(dir)}
		if f, err := os.Open(filepath.Join(dir, corpusMarker)); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 256))
			f.Close()
			m.Marker = string(b)
		}
		m.Exec = outcome(exec.CommandContext(ctx, filepath.Join(dir, "bin", "tool")).Run())
		v.Mounts = append(v.Mounts, m)
	}
	return v
}

// mountOptions maps each mount point of a mountinfo file to its own
// options (the sixth field).
func mountOptions(path string) map[string][]string {
	out := map[string][]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 6 {
			out[f[4]] = strings.Split(f[5], ",")
		}
	}
	return out
}

func tryWrite(dir string) string {
	f, err := os.CreateTemp(dir, "probe-")
	if err == nil {
		f.Close()
		os.Remove(f.Name())
	}
	return outcome(err)
}

func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, syscall.EROFS):
		return "EROFS"
	case errors.Is(err, syscall.EACCES):
		return "EACCES"
	}
	return "other"
}
