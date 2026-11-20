//go:build linux && amd64

package main

import (
	"encoding/json"
	"os"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
)

// The harness's user and group, as StartHarness runs it.
const harnessUID, harnessGID = 1000, 1000

// mountCorpora reads the boot's corpora.json, if any, and mounts the corpora
// or exposes the build drives it names (ADR 023 §5), before the harness
// starts. The extra drives follow the harness drive when the harness comes
// from the registry (harnessRoot set). Without the file, /corpus is an empty
// read-only directory.
func mountCorpora(harnessRoot string) error {
	var corpora *capsuleprotocol.GuestCorpora
	if _, err := os.Lstat(capsuleprotocol.CorporaConfigPath); err == nil {
		var raw json.RawMessage
		if err = readPrivateJSON(capsuleprotocol.CorporaConfigPath, &raw); err != nil {
			return err
		}
		c, err := capsuleprotocol.ParseGuestCorpora(raw, capsuleprotocol.FirstExtraDrive(harnessRoot != ""))
		if err != nil {
			return guestinit.ErrGuest
		}
		corpora = &c
	} else if !os.IsNotExist(err) {
		return err
	}
	return guestinit.MountCorpora(corpora, harnessRoot, harnessUID, harnessGID)
}
