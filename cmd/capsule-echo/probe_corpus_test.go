//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func TestProbeCorpusIsATestBehaviour(t *testing.T) {
	if b, err := parseBehaviour([]string{"probe-corpus"}); err != nil || b != (behaviour{probeCorpus: true}) {
		t.Fatal(b, err)
	}
	if _, err := parseBehaviour([]string{"probe-corpus", "now"}); err == nil {
		t.Fatal("accepted an argument")
	}
}

// The probe reports what the harness sees of /corpus: the mount options of
// each corpus, from the kernel's mount table, its marker, and whether a
// write or an execution there succeeds. Only an event whose body is the
// probe's is answered so; others are echoed.
func TestProbeCorpusReportsTheMountsItSees(t *testing.T) {
	root := filepath.Join(t.TempDir(), "corpus")
	if err := os.MkdirAll(filepath.Join(root, "finance", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "finance", corpusMarker), []byte("finance corpus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	table := "22 1 0:21 / / rw,relatime - tmpfs rootfs rw\n" +
		"40 22 0:30 / " + root + " ro,nosuid,nodev,noexec - tmpfs corpus ro,size=4k\n" +
		"41 40 254:2 / " + root + "/finance ro,nosuid,nodev,noexec,noatime - ext4 /dev/vdc ro\n"
	if err := os.WriteFile(mountinfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	echoed := false
	handle := probeCorpusOf(func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		echoed = true
		return []byte(`{"echo":""}`), nil
	}, root, mountinfo)
	if _, err := handle(t.Context(), harnessstore.Event{Body: []byte("hello")}, nil); err != nil || !echoed {
		t.Fatal("another event was not echoed", err)
	}
	out, err := handle(t.Context(), harnessstore.Event{Body: []byte(corpusProbeBody)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var v corpusView
	if err = json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if !v.Present || !slices.Equal(v.Options, []string{"ro", "nosuid", "nodev", "noexec"}) || len(v.Mounts) != 1 {
		t.Fatal("view of /corpus", v)
	}
	m := v.Mounts[0]
	if m.Name != "finance" || m.Marker != "finance corpus\n" || !slices.Equal(m.Options, []string{"ro", "nosuid", "nodev", "noexec", "noatime"}) {
		t.Fatal("view of a corpus", m)
	}
	// On this writable test directory the write succeeds; the tool is
	// missing, so the execution fails otherwise than by noexec.
	if m.Write != "ok" || m.Exec == "EACCES" || m.Exec == "ok" {
		t.Fatal("write and execution", m)
	}
	missing, err := probeCorpusOf(nil, filepath.Join(t.TempDir(), "absent"), mountinfo)(t.Context(), harnessstore.Event{Body: []byte(corpusProbeBody)}, nil)
	var none corpusView
	if err != nil || json.Unmarshal(missing, &none) != nil || none.Present || len(none.Mounts) != 0 {
		t.Fatal("a harness without /corpus", string(missing), err)
	}
}
