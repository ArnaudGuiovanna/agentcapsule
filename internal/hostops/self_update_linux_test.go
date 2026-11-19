package hostops

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCLIPreservesPrivatePermissionsAndChecksDigest(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agentcapsule")
	old := "#!/bin/sh\necho previous\n"
	candidate := "#!/bin/sh\necho updated\n"
	if err := os.WriteFile(exe, []byte(old), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0750); err != nil {
		t.Fatal(err)
	}
	check := func(version string) {
		t.Helper()
		result, err := exec.Command(exe, "version").Output()
		if err != nil || strings.TrimSpace(string(result)) != version {
			t.Fatalf("version: %q, %v", result, err)
		}
		st, err := os.Stat(exe)
		if err != nil || st.Mode().Perm() != 0750 {
			t.Fatalf("unexpected executable permissions: %v, %v", st, err)
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 1 {
			t.Fatalf("unexpected staging files: %v, %v", files, err)
		}
	}
	write := func(dst *os.File) error {
		_, err := io.WriteString(dst, candidate)
		return err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(candidate)))
	if err := installCLI(exe, strings.Repeat("0", 64), write); err == nil {
		t.Fatal("accepted a mismatched digest")
	}
	check("previous")
	if err := installCLI(exe, digest, func(dst *os.File) error {
		_, _ = io.WriteString(dst, candidate[:3])
		return io.ErrUnexpectedEOF
	}); err == nil {
		t.Fatal("accepted an interrupted download")
	}
	check("previous")
	if err := installCLI(exe, digest, write); err != nil {
		t.Fatal(err)
	}
	check("updated")
}
