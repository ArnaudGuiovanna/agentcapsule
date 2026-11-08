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
