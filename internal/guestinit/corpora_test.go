//go:build linux

package guestinit

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// The guest compares the UUID of each corpus drive with corpora.json before
// it mounts it: an image of another UUID, or a drive that holds no ext4,
// refuses the boot. The image is built by mkfs.ext4 in a temporary
// directory on the test's disk; nothing is mounted.
func TestACorpusDriveMustCarryItsUUID(t *testing.T) {
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		t.Fatal("mkfs.ext4 (e2fsprogs) is required", err)
	}
	const uuid = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
	image := filepath.Join(t.TempDir(), "corpus.ext4")
	if out, err := exec.Command(mkfs, "-q", "-F", "-t", "ext4", "-U", uuid, "-O", "^has_journal", image, "1M").CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	if err = checkDriveUUID(image, uuid, false); err != nil {
		t.Fatal("the expected UUID was refused", err)
	}
	if err = checkDriveUUID(image, "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b", false); !errors.Is(err, ErrGuest) {
		t.Fatal("another UUID was accepted", err)
	}
	raw := filepath.Join(t.TempDir(), "raw")
	if err = os.WriteFile(raw, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = checkDriveUUID(raw, uuid, false); !errors.Is(err, ErrGuest) {
		t.Fatal("a drive without ext4 was accepted", err)
	}
	if err = checkDriveUUID(filepath.Join(t.TempDir(), "missing"), uuid, false); !errors.Is(err, ErrGuest) {
		t.Fatal("a missing drive was accepted", err)
	}
	// In the guest, a corpus is a block device: a regular file is refused.
	if err = checkDriveUUID(image, uuid, true); !errors.Is(err, ErrGuest) {
		t.Fatal("a regular file passed for a block device", err)
	}
}

// A raw build drive has no UUID: the guest checks its size (ADR 023 C10).
func TestABuildDriveMustHaveItsSize(t *testing.T) {
	drive := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(drive, make([]byte, 3*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkDriveSize(drive, 3*4096, false); err != nil {
		t.Fatal("the expected size was refused", err)
	}
	for _, size := range []int64{2 * 4096, 4 * 4096} {
		if _, err := checkDriveSize(drive, size, false); !errors.Is(err, ErrGuest) {
			t.Fatal("another size was accepted", size, err)
		}
	}
	if _, err := checkDriveSize(drive, 3*4096, true); !errors.Is(err, ErrGuest) {
		t.Fatal("a regular file passed for a block device", err)
	}
}

// Mounting corpora is for the guest's PID 1 only.
func TestMountCorporaRunsOnlyAsTheGuestInit(t *testing.T) {
	c := capsuleprotocol.GuestCorpora{Schema: capsuleprotocol.CorporaSchema,
		Corpora: []capsuleprotocol.CorpusMount{{Index: 1, Mount: "finance", UUID: "6fa459ea-ee8a-4ca4-894e-db77e160355e"}}}
	if err := MountCorpora(&c, "", 1000, 1000); !errors.Is(err, ErrGuest) {
		t.Fatal(err)
	}
	if err := MountCorpora(nil, HarnessRoot, 1000, 1000); !errors.Is(err, ErrGuest) {
		t.Fatal(err)
	}
}
