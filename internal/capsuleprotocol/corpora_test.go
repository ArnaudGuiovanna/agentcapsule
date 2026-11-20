package capsuleprotocol

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two examples of ADR 023 §5.2: an agent with a registry harness and two
// corpora, then the builder.
const (
	corporaExample = `{"schema": "agentcapsule.guest-corpora/v1",
 "corpora": [{"index": 2, "mount": "finance", "uuid": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"},
             {"index": 3, "mount": "handbook", "uuid": "6fa459ea-ee8a-4ca4-894e-db77e160355e"}]}`
	builderExample = `{"schema": "agentcapsule.guest-corpora/v1",
 "corpora": [],
 "build": {"source": {"index": 2, "bytes": 52428800},
           "lfs": {"index": 3, "bytes": 1073741824},
           "output": {"index": 4, "bytes": 17179869184}}}`
)

func TestTheADRExamplesOfCorporaJSONAreValid(t *testing.T) {
	c, err := ParseGuestCorpora([]byte(corporaExample), FirstExtraDrive(true))
	if err != nil || len(c.Corpora) != 2 || c.Corpora[1].Mount != "handbook" || c.Build != nil {
		t.Fatal("corpora example", c, err)
	}
	b, err := ParseGuestCorpora([]byte(builderExample), FirstExtraDrive(true))
	if err != nil || len(b.Corpora) != 0 || b.Build == nil || b.Build.LFS == nil || b.Build.Output.Index != 4 || b.Build.Output.Bytes != 16<<30 {
		t.Fatal("builder example", b, err)
	}
	// The same drives start at 1 when the harness is built in.
	if _, err = ParseGuestCorpora([]byte(corporaExample), FirstExtraDrive(false)); err == nil {
		t.Fatal("corpora placed after a harness drive the VM does not have")
	}
}

// corpora.json is decoded strictly, as every boot file: unknown fields,
// trailing data or an oversized file refuse the boot.
func TestCorporaJSONIsDecodedStrictly(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown top field":     strings.Replace(corporaExample, `"corpora"`, `"extra": 1, "corpora"`, 1),
		"unknown corpus field":  strings.Replace(corporaExample, `"mount": "finance"`, `"mount": "finance", "path": "/x"`, 1),
		"unknown build field":   strings.Replace(builderExample, `"source": {"index": 2,`, `"source": {"sha256": "x", "index": 2,`, 1),
		"trailing value":        corporaExample + ` {}`,
		"trailing garbage":      corporaExample + `x`,
		"not an object":         `[]`,
		"empty":                 ``,
		"oversized":             corporaExample + strings.Repeat(" ", 64<<10),
		"string index":          strings.Replace(corporaExample, `"index": 2`, `"index": "2"`, 1),
		"null corpora, nothing": `{"schema": "agentcapsule.guest-corpora/v1", "corpora": null}`,
	} {
		if _, err := ParseGuestCorpora([]byte(raw), 2); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestCorporaJSONOrderAndNamesAreChecked(t *testing.T) {
	uuid := func(i int) string { return strings.Repeat(string(rune('a'+i)), 8) + "-1111-4111-8111-111111111111" }
	corpus := func(index int, mount string, i int) CorpusMount {
		return CorpusMount{Index: index, Mount: mount, UUID: uuid(i)}
	}
	good := GuestCorpora{Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "a", 0), corpus(2, "b", 1), corpus(3, "c-1", 2), corpus(4, "d_2", 3)}}
	if err := good.Validate(1); err != nil {
		t.Fatal("four corpora", err)
	}
	build := &GuestBuildDrives{Source: BuildDrive{Index: 1, Bytes: 4096}, Output: BuildDrive{Index: 2, Bytes: 1 << 20}}
	if err := (GuestCorpora{Schema: CorporaSchema, Corpora: []CorpusMount{}, Build: build}).Validate(1); err != nil {
		t.Fatal("build drives without LFS", err)
	}
	bad := map[string]GuestCorpora{
		"schema":            {Schema: "agentcapsule.guest-corpora/v2", Corpora: good.Corpora[:1]},
		"five corpora":      {Schema: CorporaSchema, Corpora: append(append([]CorpusMount{}, good.Corpora...), corpus(5, "e", 4))},
		"nothing":           {Schema: CorporaSchema, Corpora: []CorpusMount{}},
		"gap":               {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "a", 0), corpus(3, "b", 1)}},
		"out of order":      {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(2, "a", 0), corpus(1, "b", 1)}},
		"over the harness":  {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(0, "a", 0)}},
		"same mount":        {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "a", 0), corpus(2, "a", 1)}},
		"same uuid":         {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "a", 0), corpus(2, "b", 0)}},
		"upper case mount":  {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "Finance", 0)}},
		"dot mount":         {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "..", 0)}},
		"slash mount":       {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "a/b", 0)}},
		"leading dash":      {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, "-a", 0)}},
		"long mount":        {Schema: CorporaSchema, Corpora: []CorpusMount{corpus(1, strings.Repeat("a", 64), 0)}},
		"upper case uuid":   {Schema: CorporaSchema, Corpora: []CorpusMount{{Index: 1, Mount: "a", UUID: strings.ToUpper(uuid(0))}}},
		"nil uuid":          {Schema: CorporaSchema, Corpora: []CorpusMount{{Index: 1, Mount: "a", UUID: "00000000-0000-0000-0000-000000000000"}}},
		"short uuid":        {Schema: CorporaSchema, Corpora: []CorpusMount{{Index: 1, Mount: "a", UUID: "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633"}}},
		"corpora and build": {Schema: CorporaSchema, Corpora: good.Corpora[:1], Build: &GuestBuildDrives{Source: BuildDrive{2, 4096}, Output: BuildDrive{3, 4096}}},
		"unaligned source":  {Schema: CorporaSchema, Corpora: []CorpusMount{}, Build: &GuestBuildDrives{Source: BuildDrive{1, 4097}, Output: BuildDrive{2, 4096}}},
		"empty output":      {Schema: CorporaSchema, Corpora: []CorpusMount{}, Build: &GuestBuildDrives{Source: BuildDrive{1, 4096}, Output: BuildDrive{2, 0}}},
		"output before lfs": {Schema: CorporaSchema, Corpora: []CorpusMount{}, Build: &GuestBuildDrives{Source: BuildDrive{1, 4096}, LFS: &BuildDrive{3, 4096}, Output: BuildDrive{2, 4096}}},
		"output after gap":  {Schema: CorporaSchema, Corpora: []CorpusMount{}, Build: &GuestBuildDrives{Source: BuildDrive{1, 4096}, Output: BuildDrive{3, 4096}}},
	}
	for name, c := range bad {
		if err := c.Validate(1); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, first := range []int{0, 3} {
		if err := good.Validate(first); err == nil {
			t.Error("first extra drive", first)
		}
	}
}

// The drive order is explicit: the data volume is drive 0, a registry
// harness drive 1, and the extra drives follow.
func TestDriveDevicesFollowTheDriveOrder(t *testing.T) {
	for index, want := range map[int]string{0: "/dev/vda", HarnessDrive: HarnessDevice, 2: "/dev/vdc", 25: "/dev/vdz"} {
		if got, err := DriveDevice(index); err != nil || got != want {
			t.Error(index, got, err)
		}
	}
	for _, index := range []int{-1, 26} {
		if _, err := DriveDevice(index); err == nil {
			t.Error("device of drive", index)
		}
	}
	if FirstExtraDrive(false) != 1 || FirstExtraDrive(true) != 2 {
		t.Fatal("extra drives start after the volume and the harness")
	}
}

// Ext4UUID reads the UUID of a real image, which mkfs.ext4 builds in a
// temporary directory on the test's disk, and refuses what is not ext4.
func TestExt4UUIDReadsTheSuperblockOfARealImage(t *testing.T) {
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		t.Fatal("mkfs.ext4 (e2fsprogs) is required", err)
	}
	const uuid = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
	image := filepath.Join(t.TempDir(), "corpus.ext4")
	cmd := exec.Command(mkfs, "-q", "-F", "-t", "ext4", "-U", uuid, "-O", "^has_journal", "-E", "root_owner=0:0,hash_seed="+uuid, image, "2M")
	cmd.Env = append(os.Environ(), "E2FSPROGS_FAKE_TIME=1", "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	f, err := os.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, err := Ext4UUID(f); err != nil || got != uuid {
		t.Fatal("UUID of the image", got, err)
	}
	// The guest compares it with corpora.json: another UUID does not match.
	if got, _ := Ext4UUID(f); got == "6fa459ea-ee8a-4ca4-894e-db77e160355e" {
		t.Fatal("two UUIDs read the same")
	}
	raw, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	notExt4 := bytes.Clone(raw)
	notExt4[1024+0x38] ^= 0xff
	if _, err = Ext4UUID(bytes.NewReader(notExt4)); !errors.Is(err, ErrProtocol) {
		t.Fatal("a superblock without the ext4 magic", err)
	}
	if _, err = Ext4UUID(bytes.NewReader(raw[:1500])); !errors.Is(err, ErrProtocol) {
		t.Fatal("a truncated superblock", err)
	}
	if _, err = Ext4UUID(bytes.NewReader(make([]byte, 4096))); !errors.Is(err, ErrProtocol) {
		t.Fatal("an empty drive", err)
	}
}

func TestBootArchiveCarriesCorporaOnlyWhenGiven(t *testing.T) {
	_, guest, err := NewBootCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	write := func(h *HarnessLaunch, c *GuestCorpora) ([]byte, error) {
		f, err := os.Create(filepath.Join(t.TempDir(), "initrd"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err = AppendBootConfig(f, guest, h, c); err != nil {
			return nil, err
		}
		return os.ReadFile(f.Name())
	}
	plain, err := write(nil, nil)
	if err != nil || bytes.Contains(plain, []byte("corpora.json")) {
		t.Fatal("a boot without corpora carries corpora.json", err)
	}
	c, err := ParseGuestCorpora([]byte(corporaExample), 2)
	if err != nil {
		t.Fatal(err)
	}
	launch := &HarnessLaunch{Entrypoint: []string{"/bin/harness"}}
	archive, err := write(launch, &c)
	if err != nil || !bytes.Contains(archive, []byte("etc/capsule/corpora.json")) || !bytes.Contains(archive, []byte(`"mount":"finance"`)) {
		t.Fatal("corpora.json missing", err)
	}
	// The indexes must follow the drives: without a harness drive, these
	// corpora would name the wrong devices.
	if _, err = write(nil, &c); err == nil {
		t.Fatal("corpora placed after a missing harness drive")
	}
	c.Corpora[0].UUID = "not-a-uuid"
	if _, err = write(launch, &c); err == nil {
		t.Fatal("an invalid corpora.json was archived")
	}
}
