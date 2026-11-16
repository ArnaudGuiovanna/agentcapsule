//go:build linux && cgo

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

const serveEnv = "AGENTCAPSULE_TEST_SERVE_CONFIG"

// TestServeChild is the service process of TestServiceOwnsTheAuthoritiesAlone.
func TestServeChild(t *testing.T) {
	path := os.Getenv(serveEnv)
	if path == "" {
		return // only the child process of TestServiceOwnsTheAuthoritiesAlone runs
	}
	os.Args = []string{"agentcapsule-authority", "serve", "-config", path}
	os.Exit(run())
}

// startServe runs serve with config in a child process, until it logs
// event.
func startServe(t *testing.T, config, event string) *exec.Cmd {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestServeChild$")
	child.Env = append(os.Environ(), serveEnv+"="+config)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	started := make(chan bool, 1)
	go func() {
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			if strings.Contains(lines.Text(), `"event":"`+event+`"`) {
				started <- true
				io.Copy(io.Discard, stdout)
				return
			}
		}
		started <- false
	}()
	select {
	case ok := <-started:
		if !ok {
			t.Fatal("serve did not start")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not start")
	}
	return child
}

func stopServe(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal("serve did not stop cleanly", err)
	}
}

func writeConfig(t *testing.T, path string, v any) string {
	t.Helper()
	text, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, text, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// One process at a time opens an authority directory: while the service
// runs, snapshot, promote, init-replica and a second serve refuse with
// authority_in_use. Before the service, nothing stopped a second process.
func TestServiceOwnsTheAuthoritiesAlone(t *testing.T) {
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

	// The service answers on its API socket: the account is this test's.
	api, err := authorityclient.New(filepath.Join(sockets, "api.sock"), authorityservice.RoleAPI, restoreID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	status, err := api.Status(ctx)
	if err != nil || status.Mode != restoreauthority.ModeStandalone || status.KeyRoot != keyRoot || status.RestoreRoot != restoreRoot || status.Epoch != 1 {
		t.Fatal(status, err)
	}
	unlockFile := filepath.Join(dir, "unlock.key")
	recipient := succeed(t, "unlock-key", "-out", unlockFile).Recipient
	snapshot := []string{"snapshot", "-key-authority-root", keyRoot, "-key-authority-id", keyID,
		"-restore-authority-root", restoreRoot, "-restore-authority-id", restoreID, "-recipient", recipient, "-out", filepath.Join(dir, "snapshot.sqlite")}
	for name, args := range map[string][]string{
		"snapshot":     snapshot,
		"second serve": {"serve", "-config", config},
		"promote": {"promote", "-replica-root", filepath.Join(dir, "no-replica"), "-key-authority-root", keyRoot, "-key-authority-id", keyID,
			"-restore-authority-root", restoreRoot, "-restore-authority-id", restoreID, "-unlock-key-file", unlockFile},
	} {
		if out, code := command(t, args...); code == 0 || out != "authority_in_use" {
			t.Fatal(name, "ran beside the service:", out, code)
		}
	}
	if _, err = os.Stat(filepath.Join(dir, "snapshot.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused snapshot wrote", err)
	}
	stopServe(t, service)
	if _, err = os.Lstat(filepath.Join(sockets, "worker.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stopped service left its socket", err)
	}
	// Stopped, it owns nothing: the snapshot runs.
	succeed(t, snapshot...)

	// The replica's service owns its directory the same way.
	replicaRoot := filepath.Join(dir, "replica")
	succeed(t, "init-replica", "-root", replicaRoot, "-snapshot", filepath.Join(dir, "snapshot.sqlite"))
	for _, side := range []string{"primary", "replica"} {
		succeed(t, "certificate", "-role", side, "-restore-authority-id", restoreID, "-key-authority-id", keyID,
			"-certificate", filepath.Join(dir, side+".crt"), "-key", filepath.Join(dir, side+".key"))
	}
	replicaConfig := writeConfig(t, filepath.Join(dir, "replica.json"), serveConfig{Version: 2, Role: "replica", Root: replicaRoot,
		RestoreAuthority: restoreID, KeyAuthority: keyID, Listen: "127.0.0.1:0", Certificate: filepath.Join(dir, "replica.crt"),
		Key: filepath.Join(dir, "replica.key"), PrimaryCertificate: filepath.Join(dir, "primary.crt")})
	replica := startServe(t, replicaConfig, "replica_started")
	for name, args := range map[string][]string{
		"init-replica": {"init-replica", "-root", replicaRoot, "-snapshot", filepath.Join(dir, "snapshot.sqlite")},
		"second serve": {"serve", "-config", replicaConfig},
		"promote": {"promote", "-replica-root", replicaRoot, "-key-authority-root", filepath.Join(dir, "promoted-keys"), "-key-authority-id", keyID,
			"-restore-authority-root", filepath.Join(dir, "promoted-restore"), "-restore-authority-id", restoreID, "-unlock-key-file", unlockFile},
	} {
		if out, code := command(t, args...); code == 0 || out != "authority_in_use" {
			t.Fatal(name, "ran beside the replica's service:", out, code)
		}
	}
	stopServe(t, replica)
	if _, err = os.Stat(filepath.Join(dir, "promoted-keys")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused promotion wrote", err)
	}
}

// A version 1 configuration is the replica's, as before the service;
// version 2 names its role.
func TestServeConfigurationNamesItsRole(t *testing.T) {
	keyID, restoreID := "keyauth_"+strings.Repeat("a", 32), "restoreauth_"+strings.Repeat("b", 32)
	replica := `"root":"/var/lib/r","restore_authority_id":"` + restoreID + `","key_authority_id":"` + keyID +
		`","listen":":7443","certificate":"/etc/r.crt","key":"/etc/r.key","primary_certificate":"/etc/p.crt"`
	primary := func(extra string) string {
		return `{"version":2,"role":"primary","key_authority":{"root":"/var/lib/k","identity":"` + keyID +
			`"},"restore_authority":{"root":"/var/lib/r","identity":"` + restoreID +
			`"},"worker_socket":"/run/a/worker.sock","api_socket":"/run/a/api.sock"` + extra + `}`
	}
	for text, role := range map[string]string{
		`{"version":1,` + replica + `}`:                  "replica",
		`{"version":2,"role":"replica",` + replica + `}`: "replica",
		primary(`,"api_uid":990`):                        "primary",
		primary(`,"api_uid":990,"max_key_hold":"10m"`):   "primary",
		primary(`,"api_uid":990,"metrics_listen":"127.0.0.1:9466","authority_replica":{"address":"standby:7443",` +
			`"certificate":"/etc/p.crt","key":"/etc/p.key","replica_certificate":"/etc/r.crt","degraded_after":"1m"}`): "primary",
		`{"version":1,"role":"replica",` + replica + `}`: "",
		`{"version":2,` + replica + `}`:                  "",
		`{"version":2,"role":"primary",` + replica + `}`: "",
		`{"version":3,"role":"replica",` + replica + `}`: "",
		primary(``):             "",
		primary(`,"api_uid":0`): "",
		primary(`,"api_uid":990,"max_key_hold":"10s"`): "",
		primary(`,"api_uid":990,"max_key_hold":"11m"`): "",
		primary(`,"api_uid":990,"unknown":1`):          "",
		primary(`,"api_uid":990,"authority_replica":{"address":"standby","certificate":"/etc/p.crt","key":"/etc/p.key","replica_certificate":"/etc/r.crt"}`):                            "",
		primary(`,"api_uid":990,"authority_replica":{"address":"standby:7443","certificate":"/etc/p.crt","key":"/etc/p.key","replica_certificate":"/etc/r.crt","degraded_after":"1s"}`): "",
		strings.Replace(primary(`,"api_uid":990`), "/var/lib/k", "/var/lib/r/k", 1):                                                                                                     "",
		strings.Replace(primary(`,"api_uid":990`), "/run/a/api.sock", "run/api.sock", 1):                                                                                                "",
		strings.Replace(primary(`,"api_uid":990`), "/run/a/api.sock", "/run/a/worker.sock", 1):                                                                                          "",
	} {
		c, err := parseConfig([]byte(text))
		got := ""
		switch {
		case err != nil:
		case c.replica != nil:
			got = "replica"
		case c.primary != nil:
			got = "primary"
		}
		if got != role {
			t.Error(text, "read as", got, err)
		}
	}
	c, err := parseConfig([]byte(primary(`,"api_uid":990`)))
	if err != nil || c.maxKeyHold != authorityservice.DefaultMaxKeyHold || c.link != nil || *c.primary.APIUID != 990 {
		t.Fatal(c, err)
	}
}
