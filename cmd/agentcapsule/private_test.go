package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestPrivateIdentityContextAndOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(dir, "config"))
	config, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	key, output := filepath.Join(dir, "private.pem"), filepath.Join(dir, "identity.json")
	args := []string{"identity", "create", "--key-file", key, "--display-name", "Alice", "--output-file", output}
	if err := run(context.Background(), args, bytes.NewReader(nil), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{key, output} {
		if _, err = readFile(path, true); err != nil {
			t.Fatal(err)
		}
		if f, err := createPrivateFile(path); err == nil {
			f.Close()
			t.Fatal("replaced existing private file")
		}
	}
	c := connection{URL: "https://example.test", Kind: "platform", Token: "first"}
	if err := saveContext(config, "test", c); err != nil {
		t.Fatal(err)
	}
	c.Token = "rotated"
	if err := saveContext(config, "test", c); err != nil {
		t.Fatal(err)
	}
	if actual, err := loadContext(config, "test"); err != nil || actual != c {
		t.Fatal("could not load rotated context", err)
	}
}
