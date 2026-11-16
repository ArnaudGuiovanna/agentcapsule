//go:build linux && cgo

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// command runs the binary's entry point and returns what it printed.
func command(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, argv := os.Stdout, os.Stderr, os.Args
	os.Stdout, os.Stderr, os.Args = w, w, append([]string{"agentcapsule-admin"}, args...)
	code := run()
	os.Stdout, os.Stderr, os.Args = stdout, stderr, argv
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out)), code
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
		if out, code := command(t, args...); code == 0 || out != "authority_in_use" {
			t.Fatal(args[0], "ran beside the service:", out, code)
		}
	}
	if _, err = os.Stat(restoreRoot); !os.IsNotExist(err) {
		t.Fatal("a refused init wrote", err)
	}
	owner.Release()
	if out, code := command(t, initRestore...); code != 0 || !strings.Contains(out, `"key_authority_id":"`+keys.Identity()+`"`) {
		t.Fatal(out, code)
	}
	if out, code := command(t, "init-key-authority", "-root", keyRoot); code != 0 || !strings.Contains(out, keys.Identity()) {
		t.Fatal(out, code)
	}
	// A restore authority the service owns.
	if owner, err = authorityservice.Own(restoreRoot); err != nil {
		t.Fatal(err)
	}
	defer owner.Release()
	if out, code := command(t, initRestore...); code == 0 || out != "authority_in_use" {
		t.Fatal(out, code)
	}
}
