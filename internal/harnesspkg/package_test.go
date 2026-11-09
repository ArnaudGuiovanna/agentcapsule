package harnesspkg

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

const goodManifest = `schema: agentcapsule.harness/v1
name: echo
version: 1.0.0
protocol: capsule.v1
architecture: x86_64
base: agentcapsule-guest/1
entrypoint: [/bin/harness, --serve]
description: Reference echo harness
`

func TestManifestIsStrict(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil || m.Name != "echo" || len(m.Entrypoint) != 2 {
		t.Fatal(m, err)
	}
	for name, doc := range map[string]string{
		"unknown field":   goodManifest + "privileged: true\n",
		"second document": goodManifest + "---\nname: other\n",
		"bad schema":      strings.Replace(goodManifest, "harness/v1", "harness/v9", 1),
		"bad protocol":    strings.Replace(goodManifest, "capsule.v1", "capsule.v2", 1),
		"bad arch":        strings.Replace(goodManifest, "x86_64", "aarch64", 1),
		"bad base":        strings.Replace(goodManifest, "guest/1", "guest/9", 1),
		"bad name":        strings.Replace(goodManifest, "name: echo", "name: ../echo", 1),
		"relative entry":  strings.Replace(goodManifest, "/bin/harness", "bin/harness", 1),
		"unclean entry":   strings.Replace(goodManifest, "/bin/harness", "/bin/../harness", 1),
		"no entrypoint":   strings.Replace(goodManifest, "entrypoint: [/bin/harness, --serve]", "entrypoint: []", 1),
		"duplicate key":   goodManifest + "name: again\n",
		"too large":       goodManifest + "description2: " + strings.Repeat("x", MaxManifestBytes),
	} {
		if _, err := ParseManifest([]byte(doc)); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

func TestChecksumsListExactlyTheTwoFiles(t *testing.T) {
	d := Digest([]byte("x"))
	if _, err := ParseChecksums([]byte(`{"files":{"harness.yaml":"` + d + `","harness.ext4":"` + d + `"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"files":{"harness.yaml":"` + d + `"}}`,
		`{"files":{"harness.yaml":"` + d + `","harness.ext4":"` + strings.ToUpper(d) + `"}}`,
		`{"files":{"harness.yaml":"` + d + `","harness.ext4":"` + d + `","extra":"` + d + `"}}`,
		`{"files":{},"unknown":1}`,
	} {
		if _, err := ParseChecksums([]byte(bad)); err == nil {
			t.Fatal("accepted:", bad)
		}
	}
}

func TestRootfsSuperblockChecks(t *testing.T) {
	write := func(size int64, mutate func([]byte)) *os.File {
		t.Helper()
		b := make([]byte, size)
		sb := b[1024:2048]
		binary.LittleEndian.PutUint16(sb[0x38:], 0xEF53)
		binary.LittleEndian.PutUint32(sb[0x18:], 2) // 4 KiB blocks
		binary.LittleEndian.PutUint32(sb[0x04:], uint32(size/4096))
		if mutate != nil {
			mutate(sb)
		}
		p := filepath.Join(t.TempDir(), "fs")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	if err := CheckRootfs(write(1<<20, nil), 1<<20, 2<<20); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		size   int64
		max    int64
		mutate func([]byte)
	}{
		"magic":          {1 << 20, 2 << 20, func(sb []byte) { sb[0x38] = 0 }},
		"over maximum":   {1 << 20, 512 << 10, nil},
		"too small":      {32 << 10, 2 << 20, nil},
		"blocks overrun": {1 << 20, 2 << 20, func(sb []byte) { binary.LittleEndian.PutUint32(sb[0x04:], 1<<20) }},
		"block size":     {1 << 20, 2 << 20, func(sb []byte) { binary.LittleEndian.PutUint32(sb[0x18:], 9) }},
	} {
		if err := CheckRootfs(write(c.size, c.mutate), c.size, c.max); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

func TestBuildRootfsIsReproducibleAcrossTime(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err = os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(src, "bin/harness")
	if err = os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	build := func() string {
		out := filepath.Join(t.TempDir(), RootfsFile)
		if err := BuildRootfs(t.Context(), m, src, out, 1); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return Digest(b)
	}
	first := build()
	// Change and modification times move on; the image must not.
	time.Sleep(1100 * time.Millisecond)
	now := time.Now()
	if err = os.Chtimes(exe, now, now); err != nil {
		t.Fatal(err)
	}
	if again := build(); again != first {
		t.Fatal("the same inputs built another image", first, again)
	}
}

func TestPackedImagesHaveTheGuestMountPointsAndAnExecutableEntrypoint(t *testing.T) {
	if !slices.Equal(MountPoints, capsuleprotocol.HarnessMountPoints) {
		t.Fatal("the package and the guest disagree on mount points")
	}
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	build := func(prepare func(src string)) string {
		t.Helper()
		src := t.TempDir()
		prepare(src)
		out := filepath.Join(t.TempDir(), RootfsFile)
		if err := BuildRootfs(t.Context(), m, src, out, 2); err != nil {
			t.Fatal(err)
		}
		return out
	}
	good := build(func(src string) {
		_ = os.MkdirAll(filepath.Join(src, "bin"), 0o755)
		_ = os.WriteFile(filepath.Join(src, "bin/harness"), []byte("x"), 0o755)
	})
	if err = InspectRootfs(t.Context(), good, m); err != nil {
		t.Fatal("a packed image failed inspection", err)
	}
	notExec := build(func(src string) {
		_ = os.MkdirAll(filepath.Join(src, "bin"), 0o755)
		_ = os.WriteFile(filepath.Join(src, "bin/harness"), []byte("x"), 0o644)
	})
	if err = InspectRootfs(t.Context(), notExec, m); !errors.Is(err, ErrInvalid) {
		t.Fatal("a non-executable entrypoint passed", err)
	}
	missing := build(func(string) {})
	if err = InspectRootfs(t.Context(), missing, m); !errors.Is(err, ErrInvalid) {
		t.Fatal("a missing entrypoint passed", err)
	}
	// A file where the guest mounts its runtime cannot be packed.
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "tmp"), []byte("x"), 0o644)
	if err = BuildRootfs(t.Context(), m, src, filepath.Join(t.TempDir(), RootfsFile), 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("a file over a mount point was packed", err)
	}
}
