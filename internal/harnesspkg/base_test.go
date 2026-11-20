package harnesspkg

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// Base agentcapsule-guest/2 adds the mount point /corpus (ADR 023 §5.4); a
// base-1 harness keeps the mount points it had.
func TestBaseTwoAddsTheCorpusMountPoint(t *testing.T) {
	base2 := strings.Replace(goodManifest, "guest/1", "guest/2", 1)
	for _, doc := range []string{goodManifest, base2} {
		if _, err := ParseManifest([]byte(doc)); err != nil {
			t.Fatal("a supported base was refused", err)
		}
	}
	if _, err := ParseManifest([]byte(strings.Replace(goodManifest, "guest/1", "guest/3", 1))); !errors.Is(err, ErrInvalid) {
		t.Fatal("an unknown base was accepted", err)
	}
	if !slices.Equal(MountPointsOf(GuestBase), capsuleprotocol.HarnessMountPoints) || !slices.Equal(MountPointsOf(GuestBase), MountPoints) {
		t.Fatal("base 1 changed its mount points", MountPointsOf(GuestBase))
	}
	if CorpusMountPoint != capsuleprotocol.CorpusMountPoint {
		t.Fatal("the package and the guest disagree on the corpus mount point")
	}
	if want := append(slices.Clone(capsuleprotocol.HarnessMountPoints), capsuleprotocol.CorpusMountPoint); !slices.Equal(MountPointsOf(GuestBase2), want) {
		t.Fatal("base 2 mount points", MountPointsOf(GuestBase2))
	}
	if !CorpusCapable(GuestBase2) || CorpusCapable(GuestBase) || CorpusCapable("agentcapsule-guest/3") {
		t.Fatal("only base 2 mounts corpora")
	}

	one, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	two, err := ParseManifest([]byte(base2))
	if err != nil {
		t.Fatal(err)
	}
	build := func(m HarnessManifest, prepare func(src string)) (string, error) {
		t.Helper()
		src := t.TempDir()
		if err := os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "bin/harness"), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		prepare(src)
		out := filepath.Join(t.TempDir(), RootfsFile)
		return out, BuildRootfs(t.Context(), m, src, out, 2)
	}
	image1, err := build(one, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	image2, err := build(two, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if err = InspectRootfs(t.Context(), image2, two, sandbox.Options{}); err != nil {
		t.Fatal("a packed base-2 image failed inspection", err)
	}
	if err = InspectRootfs(t.Context(), image1, one, sandbox.Options{}); err != nil {
		t.Fatal("a base-1 image no longer passes", err)
	}
	// A base-1 image has no /corpus: it cannot claim base 2.
	if err = InspectRootfs(t.Context(), image1, two, sandbox.Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("an image without /corpus passed as base 2", err)
	}
	// A file at /corpus is refused in base 2 only.
	file := func(src string) { _ = os.WriteFile(filepath.Join(src, "corpus"), []byte("x"), 0o644) }
	if _, err = build(two, file); !errors.Is(err, ErrInvalid) {
		t.Fatal("a file over /corpus was packed for base 2", err)
	}
	if _, err = build(one, file); err != nil {
		t.Fatal("base 1 has no /corpus mount point", err)
	}
}
