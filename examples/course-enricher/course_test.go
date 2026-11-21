//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
)

func TestDemoGeneratesNotionsAndExercisesFromTheReviewedCourse(t *testing.T) {
	dir := t.TempDir()
	q := request{Schema: schema, Name: "tutor", Mount: "/corpus/base", BuildID: "cbd_" + strings.Repeat("a", 32), UUID: "11111111-1111-1111-1111-111111111111"}
	q.Output.Bytes = 16 << 20
	info := corpusmeta.Info{Schema: corpusmeta.Schema, Name: "maths", Title: "Mathématiques", BuildID: q.BuildID, Commit: strings.Repeat("a", 40), Builder: "builder@1", Languages: []string{"fr"}, Modalities: []string{"text"}, Tokens: 3, Documents: []corpusmeta.InfoEntry{{ID: "d1", Path: "fractions.md", Title: "Les fractions", Kind: corpusmeta.KindText, Tokens: 3}}}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "corpus.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "output")
	f, err := os.Create(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(q.Output.Bytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	raw, _ = json.Marshal(q)
	out, err := enrich(t.Context(), raw, dir, disk, t.TempDir())
	if err != nil || out.ImageBytes > q.Output.Bytes || out.Schema != schema {
		t.Fatal(out, err)
	}
	for _, file := range []string{"notions.json", "exercices.json"} {
		b, err := exec.Command("debugfs", "-R", "cat /"+file, disk).Output()
		if err != nil || !bytes.Contains(b, []byte("Les fractions")) || !bytes.Contains(b, []byte("docs/d1/README.md")) {
			t.Fatal(file, err, string(b))
		}
	}
	before, _ := os.ReadFile(disk)
	out, err = enrich(t.Context(), raw, dir, disk, t.TempDir())
	after, _ := os.ReadFile(disk)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("non-reproducible extension", out, err)
	}
	q.Mount = "/tmp"
	raw, _ = json.Marshal(q)
	if _, err = enrich(t.Context(), raw, dir, disk, t.TempDir()); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("untrusted source mount accepted", err)
	}
}
