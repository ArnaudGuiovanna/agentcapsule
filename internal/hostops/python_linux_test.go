package hostops

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapUsesExplicitOfflineTag(t *testing.T) {
	o, err := bootstrapArgs([]string{"install", "--profile", "/root/profile.json", "--offline=/mnt/media", "--to", "v0.2.0-dev.1", "--development-key", "/root/dev.pub", "--follow-install"})
	if err != nil || o.version != "v0.2.0-dev.1" || o.offline != "/mnt/media" || o.key != "/root/dev.pub" {
		t.Fatalf("arguments: %+v, %v", o, err)
	}
	for _, args := range [][]string{{"install", "--offline"}, {"install", "extra"}, {"install", "--unrecognized"}} {
		if _, err = bootstrapArgs(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestBootstrapChecksPreviousTrustPin(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "candidate")
	pin := filepath.Join(dir, "first-plan")
	if err := os.WriteFile(input, []byte("signed inputs"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkBootstrapPin(pin, input); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pin, []byte(fmt.Sprintf("%x", sha256.Sum256([]byte("signed inputs")))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkBootstrapPin(pin, input); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkBootstrapPin(pin, input); err == nil {
		t.Fatal("accepted changed bootstrap inputs")
	}
}
