package capsuleprotocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
)

// Corpora (ADR 023 §5). A VM mounts at most MaxCorpora corpora, each a
// read-only ext4 drive, at /corpus/<mount>; the builder of an organization
// gets raw build drives instead. The host appends CorporaConfigPath to the
// boot archive. capsule-init checks the UUID of each corpus drive before it
// mounts it, so a shift in the drive order refuses the boot instead of
// mounting the wrong corpus.
const (
	CorporaConfigPath = "/etc/capsule/corpora.json"
	CorporaSchema     = "agentcapsule.guest-corpora/v1"
	// CorpusMountPoint is the directory base agentcapsule-guest/2 adds to
	// HarnessMountPoints: capsule-init mounts the VM's corpora under it.
	CorpusMountPoint    = "/corpus"
	MaxCorpora          = 4
	MaxCorpusExtensions = wire.MaxCorpusExtensions
	// HarnessDrive is the index of a registry harness's drive. Drive 0 is
	// the agent's data volume; the extra drives follow (FirstExtraDrive).
	HarnessDrive = 1
	// MaxBuildDriveBytes bounds one build drive.
	MaxBuildDriveBytes = 1 << 40
	maxCorporaFile     = 64 << 10
	lastDrive          = 25 // /dev/vdz
)

// GuestCorpora is corpora.json. Corpora are mounted in their order; Build is
// present for the builder only, and then Corpora is empty.
type GuestCorpora struct {
	Schema  string            `json:"schema"`
	Corpora []CorpusMount     `json:"corpora"`
	Build   *GuestBuildDrives `json:"build,omitempty"`
}

// CorpusMount is one corpus drive: its index in the drive order, the
// directory under /corpus, and the UUID its ext4 superblock must carry.
type CorpusMount struct {
	Parent string `json:"parent,omitempty"`
	Index  int    `json:"index"`
	Mount  string `json:"mount"`
	UUID   string `json:"uuid"`
}

// GuestBuildDrives are the raw drives of one corpus build, in this order:
// the source archive, the LFS objects when there are any, then the output
// drive the builder writes the image to. A raw drive has no UUID: the guest
// checks its size, the builder its digest.
type GuestBuildDrives struct {
	Enricher bool        `json:"enricher,omitempty"`
	Source   BuildDrive  `json:"source"`
	LFS      *BuildDrive `json:"lfs,omitempty"`
	Output   BuildDrive  `json:"output"`
}

type BuildDrive struct {
	Index int   `json:"index"`
	Bytes int64 `json:"bytes"`
}

// Drives lists the build drives in their order.
func (b GuestBuildDrives) Drives() []BuildDrive {
	if b.Enricher {
		return []BuildDrive{b.Output}
	}
	drives := []BuildDrive{b.Source}
	if b.LFS != nil {
		drives = append(drives, *b.LFS)
	}
	return append(drives, b.Output)
}

// FirstExtraDrive is the index of the first corpus or build drive: after the
// data volume, and after the harness drive when the harness comes from the
// registry.
func FirstExtraDrive(registryHarness bool) int {
	if registryHarness {
		return HarnessDrive + 1
	}
	return HarnessDrive
}

// DriveDevice is the guest's device of drive index: /dev/vd plus the letter
// of that index, /dev/vda for drive 0.
func DriveDevice(index int) (string, error) {
	if index < 0 || index > lastDrive {
		return "", ErrProtocol
	}
	return "/dev/vd" + string(rune('a'+index)), nil
}

func ValidCorpusMount(m string) bool { return wire.ValidCorpusMount(m) }

func ValidUUID(u string) bool { return wire.ValidUUID(u) }

// Validate checks c for a VM whose extra drives start at first
// (FirstExtraDrive): at most MaxCorpora corpora with distinct mounts and
// UUIDs, or the build drives alone, each at the next index, with no gap.
func (c GuestCorpora) Validate(first int) error {
	if c.Schema != CorporaSchema || first < HarnessDrive || first > HarnessDrive+1 || c.Corpora == nil || len(c.Corpora) == 0 && c.Build == nil {
		return ErrProtocol
	}
	if c.Build != nil {
		if c.Build.Enricher {
			if len(c.Corpora) != 1 || c.Corpora[0].Parent != "" || c.Corpora[0].Mount != "base" || c.Build.Source != (BuildDrive{}) || c.Build.LFS != nil {
				return ErrProtocol
			}
		} else if len(c.Corpora) > 0 {
			return ErrProtocol
		}
	}
	if err := ValidateCorpusMounts(c.Corpora); err != nil {
		return err
	}
	next := first
	for _, m := range c.Corpora {
		if m.Index != next {
			return ErrProtocol
		}
		next++
	}
	if c.Build != nil {
		for _, d := range c.Build.Drives() {
			if d.Index != next || d.Bytes < 4096 || d.Bytes%4096 != 0 || d.Bytes > MaxBuildDriveBytes {
				return ErrProtocol
			}
			next++
		}
	}
	if next-1 > lastDrive {
		return ErrProtocol
	}
	return nil
}

// ValidateCorpusMounts requires each extension to follow its base. Limits apply
// independently to base bindings and the extensions of each base.
func ValidateCorpusMounts(mounts []CorpusMount) error {
	bases := map[string]int{}
	seen := map[string]bool{}
	uuids := map[string]bool{}
	for _, m := range mounts {
		key := m.Parent + "/" + m.Mount
		if !ValidCorpusMount(m.Mount) || !ValidUUID(m.UUID) || seen[key] || uuids[m.UUID] {
			return ErrProtocol
		}
		if m.Parent == "" {
			if len(bases) >= MaxCorpora {
				return ErrProtocol
			}
			bases[m.Mount] = 0
		} else {
			n, ok := bases[m.Parent]
			if !ok || n >= MaxCorpusExtensions {
				return ErrProtocol
			}
			bases[m.Parent] = n + 1
		}
		seen[key], uuids[m.UUID] = true, true
	}
	return nil
}

// ParseGuestCorpora decodes corpora.json strictly (unknown fields, trailing
// data and an oversized file are refused) and validates it for a VM whose
// extra drives start at first.
func ParseGuestCorpora(b []byte, first int) (GuestCorpora, error) {
	var c GuestCorpora
	if len(b) > maxCorporaFile {
		return c, ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return GuestCorpora{}, ErrProtocol
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return GuestCorpora{}, ErrProtocol
	}
	if err := c.Validate(first); err != nil {
		return GuestCorpora{}, err
	}
	return c, nil
}

// Ext4UUID reads the UUID of the ext4 filesystem on r from its superblock
// (1,024 bytes at offset 1,024): the magic 0xEF53, then the UUID at offset
// 0x68. It reads nothing else.
func Ext4UUID(r io.ReaderAt) (string, error) {
	sb := make([]byte, 1024)
	if _, err := r.ReadAt(sb, 1024); err != nil {
		return "", ErrProtocol
	}
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xEF53 {
		return "", ErrProtocol
	}
	u := hex.EncodeToString(sb[0x68:0x78])
	return u[0:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:32], nil
}
