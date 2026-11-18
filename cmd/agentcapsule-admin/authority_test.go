//go:build linux && cgo

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// trimmedCommand runs the binary's entry point (command, in main_test.go)
// and returns what it printed without the trailing newline.
func trimmedCommand(t *testing.T, args ...string) (string, int) {
	t.Helper()
	out, code := command(t, args...)
	return strings.TrimSpace(out), code
}

// The init commands refuse while the authority service owns a directory
// they open (docs/adr/006-authority-service.md §1).
func TestInitCommandsRefuseWhileTheServiceRuns(t *testing.T) {
	dir := t.TempDir()
	keyRoot, restoreRoot := filepath.Join(dir, "keys"), filepath.Join(dir, "restore")
	keys, err := keyauthority.Initialize(t.Context(), keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	initRestore := []string{"init-restore-authority", "-root", restoreRoot, "-data-root", filepath.Join(dir, "data"),
		"-key-authority-root", keyRoot, "-key-authority-id", keys.Identity()}
	// The service's lock, as serve takes it.
	owner, err := authorityservice.Own(keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init-key-authority", "-root", keyRoot}, initRestore} {
		if out, code := trimmedCommand(t, args...); code == 0 || out != "authority_in_use" {
			t.Fatal(args[0], "ran beside the service:", out, code)
		}
	}
	if _, err = os.Stat(restoreRoot); !os.IsNotExist(err) {
		t.Fatal("a refused init wrote", err)
	}
	owner.Release()
	if out, code := trimmedCommand(t, initRestore...); code != 0 || !strings.Contains(out, `"key_authority_id":"`+keys.Identity()+`"`) {
		t.Fatal(out, code)
	}
	if out, code := trimmedCommand(t, "init-key-authority", "-root", keyRoot); code != 0 || !strings.Contains(out, keys.Identity()) {
		t.Fatal(out, code)
	}
	// A restore authority the service owns.
	if owner, err = authorityservice.Own(restoreRoot); err != nil {
		t.Fatal(err)
	}
	defer owner.Release()
	if out, code := trimmedCommand(t, initRestore...); code == 0 || out != "authority_in_use" {
		t.Fatal(out, code)
	}
}
