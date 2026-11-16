//go:build linux && cgo

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The primary role keeps the daily receipt keys (docs/adr/006-authority-
// service.md §7): once it starts, it holds today's key and tomorrow's, and
// gives today's to the API. It stops cleanly with them.
func TestPrimaryKeepsTheDailyReceiptKeys(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	keyRoot, restoreRoot := filepath.Join(dir, "keys"), filepath.Join(dir, "restore")
	keys, err := keyauthority.Initialize(ctx, keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(ctx, restoreRoot, keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	restoreID, keyID := catalog.Identity(), keys.Identity()
	catalog.Close()
	sockets, err := os.MkdirTemp("", "acs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockets)
	uid := uint32(os.Getuid())
	config := writeConfig(t, filepath.Join(dir, "authority.json"), primaryConfig{Version: 2, Role: "primary",
		KeyAuthority: &authorityDirectory{Root: keyRoot, Identity: keyID}, RestoreAuthority: &authorityDirectory{Root: restoreRoot, Identity: restoreID},
		WorkerSocket: filepath.Join(sockets, "worker.sock"), APISocket: filepath.Join(sockets, "api.sock"), APIUID: &uid, MaxKeyHold: "1m"})
	service := startServe(t, config, "service_started")
	today := keyauthority.ReceiptDay(time.Now())
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		held, err := keys.ReceiptKeys()
		if err != nil {
			t.Fatal(err)
		}
		// Around midnight the service may have seen another day.
		usable := map[time.Time]bool{}
		for _, k := range held {
			usable[k.Day] = k.Usable
		}
		if usable[today] && usable[today.AddDate(0, 0, 1)] || usable[today.AddDate(0, 0, 1)] && usable[today.AddDate(0, 0, 2)] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the service did not create today's and tomorrow's keys", held)
		}
	}
	api, err := authorityclient.NewAPI(filepath.Join(sockets, "api.sock"), restoreID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	now := time.Now()
	key, err := api.ReceiptKey(ctx, now)
	if err != nil || len(key) != 32 {
		t.Fatal("today's key", err)
	}
	var held []byte
	if err = keys.WithKey(ctx, keyauthority.ReceiptKeyAgent, keyauthority.ReceiptKeyVolume(now), func(k []byte) error {
		held = bytes.Clone(k)
		return nil
	}); err != nil || !bytes.Equal(held, key) {
		t.Fatal("the API got another key than the authority's", err)
	}
	stopServe(t, service)
}
