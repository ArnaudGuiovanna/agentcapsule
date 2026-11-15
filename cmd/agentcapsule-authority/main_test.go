//go:build linux && cgo

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// command runs the binary's entry point and returns what it printed.
func command(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, argv := os.Stdout, os.Stderr, os.Args
	os.Stdout, os.Stderr, os.Args = w, w, append([]string{"agentcapsule-authority"}, args...)
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

type position struct {
	RestoreAuthority string `json:"restore_authority_id"`
	KeyAuthority     string `json:"key_authority_id"`
	Epoch            uint64 `json:"epoch"`
	PreviousEpoch    uint64 `json:"previous_epoch"`
	Sequence         uint64 `json:"sequence"`
	Recipient        string `json:"recipient"`
}

// succeed runs a command that must succeed and decodes its output.
func succeed(t *testing.T, args ...string) position {
	t.Helper()
	out, code := command(t, args...)
	var p position
	if code != 0 || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatalf("command failed (%d): %s", code, out)
	}
	return p
}

// The failover of the authorities with the commands of recovery.md: promote
// the replica, refuse to serve it again, then seed a new standby from the
// promoted authorities with snapshot and init-replica.
func TestPromoteCommandAndSeedingANewStandby(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	keys, err := keyauthority.Initialize(ctx, filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(ctx, filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	restoreID, keyID := catalog.Identity(), keys.Identity()
	catalog.Close()
	unlockFile := filepath.Join(dir, "unlock.key")
	recipient := succeed(t, "unlock-key", "-out", unlockFile).Recipient
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	armed := succeed(t, "snapshot", "-key-authority-root", filepath.Join(dir, "keys"), "-key-authority-id", keyID,
		"-restore-authority-root", filepath.Join(dir, "restore"), "-restore-authority-id", restoreID, "-recipient", recipient, "-out", snapshot)
	if armed.Epoch != 1 {
		t.Fatal(armed)
	}
	replicaRoot := filepath.Join(dir, "replica")
	succeed(t, "init-replica", "-root", replicaRoot, "-snapshot", snapshot)
	// The primary writes through the replica.
	catalog, err = restoreauthority.Open(ctx, filepath.Join(dir, "restore"), restoreID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.OpenReplica(ctx, replicaRoot, restoreID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if err = catalog.Replicate(ctx, replica); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(catalog)
	agent, volume := "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32)
	if err = keys.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Register(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	catalog.Close()
	// A running listener stops once another process promotes its replica.
	stopped := make(chan struct{})
	go watchPromotion(ctx, replica, 10*time.Millisecond, func() { close(stopped) })

	promoted := []string{"promote", "-replica-root", replicaRoot,
		"-key-authority-root", filepath.Join(dir, "promoted-keys"), "-key-authority-id", keyID,
		"-restore-authority-root", filepath.Join(dir, "promoted-restore"), "-restore-authority-id", restoreID,
		"-unlock-key-file", unlockFile}
	with := func(flag, value string) []string {
		args := append([]string(nil), promoted...)
		for i := range args {
			if args[i] == flag {
				args[i+1] = value
			}
		}
		return args
	}
	// Refused before anything is written: a key file others can read, an
	// unlock key that does not open the replica, another installation.
	if err = os.Chmod(unlockFile, 0640); err != nil {
		t.Fatal(err)
	}
	if out, code := command(t, promoted...); code == 0 || out != "unlock_key_file_must_be_private" {
		t.Fatal(out, code)
	}
	if err = os.Chmod(unlockFile, 0600); err != nil {
		t.Fatal(err)
	}
	otherKey := filepath.Join(dir, "other.key")
	succeed(t, "unlock-key", "-out", otherKey)
	if out, code := command(t, with("-unlock-key-file", otherKey)...); code == 0 || out != "unlock_key_does_not_open_replica" {
		t.Fatal(out, code)
	}
	if out, code := command(t, with("-key-authority-id", "keyauth_"+strings.Repeat("0", 32))...); code == 0 || out != "replica_identity_mismatch" {
		t.Fatal(out, code)
	}
	if _, err = os.Stat(filepath.Join(dir, "promoted-keys")); !os.IsNotExist(err) {
		t.Fatal("a refused promotion wrote", err)
	}
	// The promotion, then its repetition: the same epoch and position.
	first := succeed(t, promoted...)
	if first.Epoch != 2 || first.PreviousEpoch != 1 || first.Sequence != 2 || first.RestoreAuthority != restoreID || first.KeyAuthority != keyID {
		t.Fatal(first)
	}
	if again := succeed(t, promoted...); again != first {
		t.Fatal(again, first)
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the listener did not see the promotion")
	}
	replica.Close()
	// serve refuses the promoted replica.
	config := filepath.Join(dir, "replica.json")
	text, _ := json.Marshal(serveConfig{Version: 1, Root: replicaRoot, RestoreAuthority: restoreID, KeyAuthority: keyID, Listen: "127.0.0.1:0",
		Certificate: filepath.Join(dir, "none.crt"), Key: filepath.Join(dir, "none.key"), PrimaryCertificate: filepath.Join(dir, "none.crt")})
	if err = os.WriteFile(config, text, 0600); err != nil {
		t.Fatal(err)
	}
	if out, code := command(t, "serve", "-config", config); code == 0 || out != "replica_promoted" {
		t.Fatal(out, code)
	}
	// A new standby, seeded from the promoted authorities with a new unlock key.
	newKey := filepath.Join(dir, "new-unlock.key")
	newRecipient := succeed(t, "unlock-key", "-out", newKey).Recipient
	seed := filepath.Join(dir, "seed.sqlite")
	seeded := succeed(t, "snapshot", "-key-authority-root", filepath.Join(dir, "promoted-keys"), "-key-authority-id", keyID,
		"-restore-authority-root", filepath.Join(dir, "promoted-restore"), "-restore-authority-id", restoreID, "-recipient", newRecipient, "-out", seed)
	if seeded.Epoch != 2 || seeded.Sequence != 2 {
		t.Fatal(seeded)
	}
	standby := succeed(t, "init-replica", "-root", filepath.Join(dir, "standby"), "-snapshot", seed)
	if standby.Epoch != 2 || standby.Sequence != 2 {
		t.Fatal(standby)
	}
}
