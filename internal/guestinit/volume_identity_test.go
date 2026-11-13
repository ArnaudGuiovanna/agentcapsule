//go:build linux

package guestinit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVolumeMarkerRejectsRollbackAndMissingIncarnation(t *testing.T) {
	want := volumeIdentity{Incarnation: 2, VolumeID: "volume", UUID: "uuid"}
	for _, incarnation := range []uint64{0, 1, 2, 3} {
		disk := want
		disk.Incarnation = incarnation
		raw, err := json.Marshal(disk)
		if err != nil {
			t.Fatal(err)
		}
		err = checkVolumeIdentity(strings.NewReader(string(raw)), want)
		if (err == nil) != (incarnation == 2) {
			t.Fatal("incorrect image identity result", incarnation, err)
		}
	}
	if err := checkVolumeIdentity(strings.NewReader(`{"volume_id":"volume","uuid":"uuid"}`), want); err == nil {
		t.Fatal("legacy marker relabeled")
	}
	raw, _ := json.Marshal(want)
	if err := checkVolumeIdentity(strings.NewReader(string(raw)+"{}"), want); err == nil {
		t.Fatal("trailing marker accepted")
	}
}

// The restricted boot of a restored image moves its marker forward to the
// restore's incarnation, once: an interrupted boot finds it already moved. It
// never moves a marker back, nor takes another volume's image.
func TestRestoredVolumeMarkerMovesOnlyForward(t *testing.T) {
	want := volumeIdentity{Incarnation: 3, VolumeID: "volume", UUID: "uuid"}
	marker := func(v volumeIdentity) *strings.Reader {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return strings.NewReader(string(raw))
	}
	for incarnation, move := range map[uint64]bool{1: true, 2: true, 3: false} {
		disk := want
		disk.Incarnation = incarnation
		got, err := restoredVolumeIdentity(marker(disk), want)
		if err != nil || got != move {
			t.Fatal("restored marker", incarnation, got, err)
		}
	}
	for name, disk := range map[string]volumeIdentity{
		"later incarnation": {Incarnation: 4, VolumeID: "volume", UUID: "uuid"},
		"no incarnation":    {VolumeID: "volume", UUID: "uuid"},
		"other volume":      {Incarnation: 1, VolumeID: "other", UUID: "uuid"},
		"other container":   {Incarnation: 1, VolumeID: "volume", UUID: "other"},
	} {
		if _, err := restoredVolumeIdentity(marker(disk), want); err == nil {
			t.Fatal("restored marker accepted", name)
		}
	}
	raw, _ := json.Marshal(volumeIdentity{Incarnation: 1, VolumeID: "volume", UUID: "uuid"})
	if _, err := restoredVolumeIdentity(strings.NewReader(string(raw)+"{}"), want); err == nil {
		t.Fatal("trailing marker accepted")
	}
}
