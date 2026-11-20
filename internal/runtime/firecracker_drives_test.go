//go:build linux

package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// corpusImage writes a read-only image of size bytes under dir whose
// superblock carries the ext4 magic and uuid, as a cached corpus.ext4 does.
func corpusImage(t *testing.T, dir, name, uuid string, size int) CorpusImage {
	t.Helper()
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[1024+0x38:], 0xEF53)
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(raw) != 16 {
		t.Fatal("test UUID", uuid)
	}
	copy(b[1024+0x68:], raw)
	path := filepath.Join(dir, name)
	if err = os.WriteFile(path, b, 0o444); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(name))
	return CorpusImage{Path: path, Digest: "sha256:" + hex.EncodeToString(digest[:]), UUID: uuid, Mount: strings.TrimSuffix(name, ".ext4")}
}

const (
	financeUUID  = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
	handbookUUID = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
)

// bootFile returns the content of name in the boot archive appended to an
// initrd (newc), or nil.
func bootFile(t *testing.T, initrd []byte, name string) []byte {
	t.Helper()
	at := bytes.Index(initrd, []byte(name+"\x00"))
	if at < 110 {
		return nil
	}
	header := initrd[at-110 : at]
	if string(header[:6]) != "070701" {
		t.Fatal("not a newc header")
	}
	field := func(i int) int {
		v, err := strconv.ParseUint(string(header[6+8*i:14+8*i]), 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		return int(v)
	}
	size, nameSize := field(6), field(11)
	start := at + nameSize
	start += (4 - (start % 4)) % 4
	return initrd[start : start+size]
}

func preparedCorpora(t *testing.T, h *FirecrackerHost, a *HostAgent) (vmConfig, *capsuleprotocol.GuestCorpora) {
	t.Helper()
	_, config := preparedConfig(t, h, a)
	initrd, err := os.ReadFile(filepath.Join(h.jail(a.Run), "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	raw := bootFile(t, initrd, "etc/capsule/corpora.json")
	if raw == nil {
		return config, nil
	}
	first := capsuleprotocol.FirstExtraDrive(a.Harness != nil)
	c, err := capsuleprotocol.ParseGuestCorpora(raw, first)
	if err != nil {
		t.Fatal("corpora.json does not decode", err)
	}
	return config, &c
}

type driveConfig struct {
	ID       string `json:"drive_id"`
	Path     string `json:"path_on_host"`
	ReadOnly bool   `json:"is_read_only"`
	Cache    string `json:"cache_type"`
}

func drivesOf(t *testing.T, h *FirecrackerHost, a *HostAgent) []driveConfig {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.jail(a.Run), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Drives []driveConfig `json:"drives"`
	}
	if err = json.Unmarshal(b, &config); err != nil {
		t.Fatal(err)
	}
	return config.Drives
}

// The extra drives follow one order, the one corpora.json gives the guest:
// the data volume, the registry harness when there is one, then the corpora
// in binding order. Each corpus is the cached image itself, hard linked into
// the jail, read-only, with its own ceiling and a one-time burst of at most
// 256 MiB (ADR 023 §5.1).
func TestCorpusDrivesFollowTheHarnessInBindingOrder(t *testing.T) {
	for _, withHarness := range []bool{true, false} {
		h, a, _ := limitsFixture(t)
		if !withHarness {
			a.Harness = nil
		}
		cache := filepath.Join(h.root, "corpora")
		if err := os.Mkdir(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		finance := corpusImage(t, cache, "finance.ext4", financeUUID, 128<<10)
		handbook := corpusImage(t, cache, "handbook.ext4", handbookUUID, 128<<10)
		a.Corpora = []CorpusImage{finance, handbook}
		config, corpora := preparedCorpora(t, h, a)
		first := capsuleprotocol.FirstExtraDrive(withHarness)
		wantIDs := []string{"data", "harness", "corpus0", "corpus1"}
		if !withHarness {
			wantIDs = []string{"data", "corpus0", "corpus1"}
		}
		drives := drivesOf(t, h, a)
		if len(drives) != len(wantIDs) {
			t.Fatal("drives", drives)
		}
		for i, d := range drives {
			if d.ID != wantIDs[i] {
				t.Fatal("drive order", i, d.ID)
			}
		}
		if corpora == nil || len(corpora.Corpora) != 2 || corpora.Build != nil {
			t.Fatal("corpora.json", corpora)
		}
		for i, image := range []CorpusImage{finance, handbook} {
			m := corpora.Corpora[i]
			d := drives[first+i]
			if m.Index != first+i || m.Mount != image.Mount || m.UUID != image.UUID {
				t.Fatal("corpora.json names another drive", i, m)
			}
			if !d.ReadOnly || d.Cache != "Unsafe" {
				t.Fatal("a corpus drive must be read-only, without flushes", d)
			}
			jailed, err := os.Stat(filepath.Join(h.jail(a.Run), strings.TrimPrefix(d.Path, "/")))
			if err != nil {
				t.Fatal(err)
			}
			cached, err := os.Stat(image.Path)
			if err != nil || !os.SameFile(jailed, cached) {
				t.Fatal("a corpus drive is not the cached image's inode", err)
			}
		}
		for _, d := range config.Drives {
			if !strings.HasPrefix(d.ID, "corpus") {
				continue
			}
			bw, ops := d.RateLimiter.Bandwidth, d.RateLimiter.Ops
			if bw.Size != 128<<20 || ops.Size != 4000 || bw.OneTimeBurst == nil || *bw.OneTimeBurst != 128<<10 || ops.OneTimeBurst == nil || *ops.OneTimeBurst != 32 {
				t.Fatal("corpus ceiling", d.ID, *bw, *ops)
			}
		}
	}
	// A VM without corpora gets no corpora.json and no extra drive.
	h, a, _ := limitsFixture(t)
	if _, corpora := preparedCorpora(t, h, a); corpora != nil || len(drivesOf(t, h, a)) != 2 {
		t.Fatal("a VM without corpora", corpora)
	}
}

// A corpus may be read whole at full speed once, but never more than
// 256 MiB of it, whatever its size; then its drive's rate applies.
func TestTheCorpusBurstIsCapped(t *testing.T) {
	h, a, _ := limitsFixture(t)
	big := corpusImage(t, h.root, "big.ext4", financeUUID, 64<<10)
	// A sparse image larger than the cap.
	if err := os.Chmod(big.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big.Path, 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(big.Path, 0o444); err != nil {
		t.Fatal(err)
	}
	a.Corpora = []CorpusImage{big}
	h.opts.DriveLimits = DriveLimits{Corpus: DriveRate{BandwidthMiBPerSecond: 32, IOPS: 900}}
	config, _ := preparedCorpora(t, h, a)
	for _, d := range config.Drives {
		if d.ID != "corpus0" {
			continue
		}
		bw, ops := d.RateLimiter.Bandwidth, d.RateLimiter.Ops
		if bw.Size != 32<<20 || ops.Size != 900 || *bw.OneTimeBurst != CorpusBurstBytes || *ops.OneTimeBurst != CorpusBurstBytes/4096 {
			t.Fatal("corpus burst", *bw, *ops)
		}
		return
	}
	t.Fatal("no corpus drive")
}

// The builder's drives come after the harness: the source and the LFS
// objects read-only, the output read-write, at the volume's rate. Their
// sizes reach the guest, which checks them.
func TestBuildDrivesFollowTheHarness(t *testing.T) {
	for _, withLFS := range []bool{true, false} {
		h, a, _ := limitsFixture(t)
		staging := filepath.Join(h.root, "staging")
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		write := func(name string, size int64) string {
			path := filepath.Join(staging, name)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, size); err != nil {
				t.Fatal(err)
			}
			return path
		}
		a.Build = &BuildDrives{Source: write("source.bin", 3*4096), Output: write("output.ext4", 1<<20)}
		if withLFS {
			a.Build.LFS = write("lfs.bin", 5*4096)
		}
		_, corpora := preparedCorpora(t, h, a)
		drives := drivesOf(t, h, a)
		want := []driveConfig{{ID: "data"}, {ID: "harness", ReadOnly: true, Cache: "Unsafe"}, {ID: "source", ReadOnly: true, Cache: "Unsafe"}}
		if withLFS {
			want = append(want, driveConfig{ID: "lfs", ReadOnly: true, Cache: "Unsafe"})
		}
		want = append(want, driveConfig{ID: "output", Cache: "Writeback"})
		if len(drives) != len(want) {
			t.Fatal("drives", drives)
		}
		for i, d := range drives[1:] {
			if w := want[i+1]; d.ID != w.ID || d.ReadOnly != w.ReadOnly || d.Cache != w.Cache {
				t.Fatal("build drive", i+1, d)
			}
		}
		if corpora == nil || len(corpora.Corpora) != 0 || corpora.Build == nil {
			t.Fatal("corpora.json of the builder", corpora)
		}
		b := corpora.Build
		if b.Source != (capsuleprotocol.BuildDrive{Index: 2, Bytes: 3 * 4096}) || (b.LFS != nil) != withLFS {
			t.Fatal("build drives", b)
		}
		output := capsuleprotocol.BuildDrive{Index: 3, Bytes: 1 << 20}
		if withLFS {
			output.Index = 4
			if *b.LFS != (capsuleprotocol.BuildDrive{Index: 3, Bytes: 5 * 4096}) {
				t.Fatal("LFS drive", *b.LFS)
			}
		}
		if b.Output != output {
			t.Fatal("output drive", b.Output)
		}
	}
}

// A corpus image is never copied: on another file system than the jails,
// its boot fails and nothing is copied into the jail (ADR 023 §5.1).
func TestACorpusImageIsNeverCopied(t *testing.T) {
	h, a, _ := limitsFixture(t)
	other, err := os.MkdirTemp("/dev/shm", "corpus-")
	if err != nil {
		t.Fatal("a second file system (/dev/shm) is needed", err)
	}
	t.Cleanup(func() { os.RemoveAll(other) })
	if sameFilesystem(t, other, h.root) {
		t.Fatal("/dev/shm is on the test root's file system")
	}
	image := corpusImage(t, other, "finance.ext4", financeUUID, 64<<10)
	a.Corpora = []CorpusImage{image}
	if err = h.prepare(a); !errors.Is(err, ErrCorpusFilesystem) {
		t.Fatal("a corpus image on another file system", err)
	}
	if _, err = os.Stat(filepath.Join(h.jail(a.Run), "corpus0.ext4")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the corpus image was copied into the jail", err)
	}
	// The same refusal before the image is ever recorded.
	jails := filepath.Join(h.root, "jails")
	if err = CheckLinkable(jails, other); !errors.Is(err, ErrCorpusFilesystem) {
		t.Fatal("check of the corpus cache's file system", err)
	}
	if err = CheckLinkable(jails, image.Path); !errors.Is(err, ErrCorpusFilesystem) {
		t.Fatal("check of a corpus image's file system", err)
	}
	if err = CheckLinkable(jails, filepath.Join(h.root, "releases")); err != nil {
		t.Fatal("a cache beside the jails", err)
	}
	// The probes leave nothing behind.
	for _, dir := range []string{jails, other, filepath.Join(h.root, "releases")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".link-probe-") {
				t.Fatal("a probe link was left in", dir)
			}
		}
	}
}

func sameFilesystem(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y syscall.Stat_t
	if syscall.Stat(a, &x) != nil || syscall.Stat(b, &y) != nil {
		t.Fatal("stat")
	}
	return x.Dev == y.Dev
}

// A recorded corpus is a verified, shared, read-only image whose superblock
// carries the UUID the guest will check; at most four, each mount and image
// once. Corpora change only while no VM runs, and never for the builder.
func TestCorporaAreCheckedWhenRecorded(t *testing.T) {
	h, a, _ := limitsFixture(t)
	if err := os.MkdirAll(filepath.Join(h.root, "jails"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.Run = nil
	if err := h.save(&hostRegistry{Version: 2, Agents: map[string]*HostAgent{"a": a}}); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(h.root, "corpora")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	finance := corpusImage(t, cache, "finance.ext4", financeUUID, 64<<10)
	handbook := corpusImage(t, cache, "handbook.ext4", handbookUUID, 64<<10)
	if err := h.ReplaceCorpora(t.Context(), "a", []CorpusImage{finance, handbook}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.CorporaOf(t.Context(), "a"); err != nil || len(got) != 2 || got[1] != handbook {
		t.Fatal("recorded corpora", got, err)
	}
	writable := corpusImage(t, cache, "writable.ext4", "aaaaaaaa-1111-4111-8111-111111111111", 64<<10)
	if err := os.Chmod(writable.Path, 0o666); err != nil {
		t.Fatal(err)
	}
	small := corpusImage(t, cache, "small.ext4", "bbbbbbbb-1111-4111-8111-111111111111", 32<<10)
	other := func(c CorpusImage, change func(*CorpusImage)) CorpusImage { change(&c); return c }
	extra := func(i int) CorpusImage {
		return corpusImage(t, cache, "x"+strconv.Itoa(i)+".ext4", strings.Repeat(strconv.Itoa(i), 8)+"-1111-4111-8111-111111111111", 64<<10)
	}
	for name, bad := range map[string][]CorpusImage{
		"five":          {extra(1), extra(2), extra(3), extra(4), extra(5)},
		"same mount":    {finance, other(handbook, func(c *CorpusImage) { c.Mount = "finance" })},
		"same image":    {finance, other(finance, func(c *CorpusImage) { c.Mount = "again" })},
		"wrong uuid":    {other(finance, func(c *CorpusImage) { c.UUID = handbookUUID })},
		"bad mount":     {other(finance, func(c *CorpusImage) { c.Mount = "../etc" })},
		"bad digest":    {other(finance, func(c *CorpusImage) { c.Digest = "sha256:x" })},
		"relative path": {other(finance, func(c *CorpusImage) { c.Path = "finance.ext4" })},
		"missing":       {other(finance, func(c *CorpusImage) { c.Path = filepath.Join(cache, "none.ext4") })},
		"writable":      {writable},
		"small":         {small},
	} {
		if err := h.ReplaceCorpora(t.Context(), "a", bad); err == nil {
			t.Error("recorded:", name)
		}
	}
	if got, _ := h.CorporaOf(t.Context(), "a"); len(got) != 2 {
		t.Fatal("a refused change changed the record", got)
	}
	if err := h.ReplaceCorpora(t.Context(), "a", nil); err != nil {
		t.Fatal("removing every corpus", err)
	}
	// Not while a VM runs: the binding changes at the next boot.
	if err := h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents["a"].Run = &VMRun{ID: "0123456789abcdef", Generation: 1, Phase: "STARTING", Socket: filepath.Join(h.jail(&VMRun{ID: "0123456789abcdef"}), "vsock")}
		r.Agents["a"].Generation = 1
		return h.save(r)
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.ReplaceCorpora(t.Context(), "a", []CorpusImage{finance}); !errors.Is(err, ErrDrivesInUse) {
		t.Fatal("corpora changed under a running VM", err)
	}
}

// Build drives are raw, 4 KiB-aligned files beside the jails, each once.
func TestBuildDrivesAreCheckedWhenRecorded(t *testing.T) {
	h, a, _ := limitsFixture(t)
	if err := os.MkdirAll(filepath.Join(h.root, "jails"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.Run = nil
	if err := h.save(&hostRegistry{Version: 2, Agents: map[string]*HostAgent{"a": a}}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(h.root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	file := func(name string, size int64) string {
		path := filepath.Join(staging, name)
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	source, unaligned, output := file("source.bin", 4096), file("odd.bin", 4097), file("output.ext4", 8192)
	for name, bad := range map[string]BuildDrives{
		"no output":     {Source: source},
		"no source":     {Output: output},
		"unaligned":     {Source: unaligned, Output: output},
		"same file":     {Source: source, Output: source},
		"relative":      {Source: "source.bin", Output: output},
		"missing lfs":   {Source: source, LFS: filepath.Join(staging, "none"), Output: output},
		"empty":         {Source: file("empty.bin", 0), Output: output},
		"symbolic link": {Source: symlink(t, source, filepath.Join(staging, "link")), Output: output},
	} {
		if err := h.SetBuildDrives(t.Context(), "a", &bad); err == nil {
			t.Error("recorded:", name)
		}
	}
	// The builder mounts no corpus.
	cache := filepath.Join(h.root, "corpora")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.ReplaceCorpora(t.Context(), "a", []CorpusImage{corpusImage(t, cache, "finance.ext4", financeUUID, 64<<10)}); err != nil {
		t.Fatal(err)
	}
	if err := h.SetBuildDrives(t.Context(), "a", &BuildDrives{Source: source, Output: output}); err == nil {
		t.Fatal("build drives beside corpora")
	}
}

func symlink(t *testing.T, target, path string) string {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// The output drive is created sparse at its final size, for the builder's
// VMM alone to write.
func TestTheBuildOutputIsASparseFileOfItsSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.ext4")
	if err := CreateBuildOutput(path, 16<<20); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() != 16<<20 || st.Mode().Perm() != 0o600 || st.Sys().(*syscall.Stat_t).Blocks != 0 {
		t.Fatal("output drive", st, err)
	}
	if err = CreateBuildOutput(path, 16<<20); err == nil {
		t.Fatal("an existing output drive was replaced")
	}
	if err = CreateBuildOutput(filepath.Join(t.TempDir(), "odd"), 4097); err == nil {
		t.Fatal("an unaligned output drive")
	}
}

// drive_limits.corpus defaults to 128 MiB/s and 4000 operations a second,
// and is bounded as the others; a rate left out takes its default.
func TestDriveLimitsHaveACorpusRate(t *testing.T) {
	if DefaultDriveLimits.Corpus != (DriveRate{BandwidthMiBPerSecond: 128, IOPS: 4000}) {
		t.Fatal("default corpus rate", DefaultDriveLimits.Corpus)
	}
	partial := DriveLimits{Volume: DriveRate{BandwidthMiBPerSecond: 8, IOPS: 300}, Harness: DefaultDriveLimits.Harness}
	if got := partial.orDefault(); got.Corpus != DefaultDriveLimits.Corpus || got.Volume != partial.Volume || got.Validate() != nil {
		t.Fatal("a corpus rate left out", got)
	}
	for _, bad := range []DriveRate{{0, 4000}, {128, 9}, {4097, 4000}, {128, 1_000_001}} {
		l := DefaultDriveLimits
		l.Corpus = bad
		if l.Validate() == nil {
			t.Error("accepted corpus rate", bad)
		}
	}
}
