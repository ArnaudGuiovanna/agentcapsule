//go:build linux

package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// drive_limits.corpus caps each corpus drive (ADR 023 §5.1): absent means
// its default, a number left out takes its default, and values out of
// bounds are refused.
func TestCorpusDriveLimitsConfiguration(t *testing.T) {
	base := `{"version": 1, "host_id": "host", "boot_timeout": "30s", "boot_lease": "2m", "poll_interval": "1s", "attempt_timeout": "45s"`
	settings := func(extra string) (runtime.DriveLimits, error) {
		t.Helper()
		c, err := decodeServiceConfig(strings.NewReader(base + extra + "}"))
		if err != nil {
			t.Fatal(err)
		}
		opts, _, _, err := c.Settings()
		return opts.DriveLimits, err
	}
	if l, err := settings(""); err != nil || l.Corpus != runtime.DefaultDriveLimits.Corpus {
		t.Fatal("default corpus rate", l, err)
	}
	if l, err := settings(`, "drive_limits": {"corpus": {"bandwidth_mib_per_second": 32}}`); err != nil ||
		l.Corpus != (runtime.DriveRate{BandwidthMiBPerSecond: 32, IOPS: 4000}) || l.Volume != runtime.DefaultDriveLimits.Volume {
		t.Fatal("partial corpus rate", l, err)
	}
	if _, err := settings(`, "drive_limits": {"corpus": {"iops": 5}}`); err == nil {
		t.Fatal("accepted 5 operations a second")
	}
}

// The corpus cache and staging must be on the jails' file system, where
// their images and drives are hard linked: the preflight check fails
// otherwise (corpus_cache_filesystem), and checks the nearest existing
// directories before the worker creates them.
func TestCorpusFilesystemPreflight(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "jails"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := CorpusFilesystemCheck(root, filepath.Join(root, "corpora"), filepath.Join(root, "corpus-staging", "builds"))
	if r.Check != "corpus_cache_filesystem" || r.Status != preflight.OK {
		t.Fatal("a cache beside the jails", r)
	}
	// Before the worker's first start, the root has no jails yet.
	fresh := filepath.Join(t.TempDir(), "runtime")
	if r = CorpusFilesystemCheck(fresh, filepath.Join(fresh, "corpora")); r.Status != preflight.OK {
		t.Fatal("a root not created yet", r)
	}
	other, err := os.MkdirTemp("/dev/shm", "corpus-")
	if err != nil {
		t.Fatal("a second file system (/dev/shm) is needed", err)
	}
	t.Cleanup(func() { os.RemoveAll(other) })
	if r = CorpusFilesystemCheck(root, filepath.Join(root, "corpora"), other); r.Status != preflight.Fail || r.Fix == "" {
		t.Fatal("a staging directory on another file system", r)
	}
}
