//go:build linux && amd64

// Disposable reference SQL harness for the authenticated control integration
// tests. It uses the real protocol server and store; it is not a general process
// supervisor/capsule-init and exposes no unauthenticated diagnostic/fault RPC.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func must(err error) {
	if err != nil {
		fmt.Println("CAPSULE_CONTROL_BOOT_FAILED")
		os.Exit(1)
	}
}
func mount(source, target, kind string, flags uintptr) {
	must(os.MkdirAll(target, 0700))
	must(syscall.Mount(source, target, kind, flags, ""))
}
func main() {
	mount("proc", "/proc", "proc", 0)
	mount("sysfs", "/sys", "sysfs", 0)
	mount("devtmpfs", "/dev", "devtmpfs", 0)
	mount("/dev/vda", "/data", "ext4", syscall.MS_NOATIME)
	b, err := os.ReadFile(capsuleprotocol.BootConfigPath)
	must(err)
	var credentials capsuleprotocol.Credentials
	must(json.Unmarshal(b, &credentials))
	// Credentials stay on the initramfs, outside the persistent harness volume.
	store, err := harnessstore.Open(context.Background(), "/data/harness.db")
	must(err)
	startPlatformJobs(credentials.Platform)
	server, err := capsuleprotocol.NewServer(credentials, capsuleprotocol.ShutdownUnclean, store, func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if handled, result, err := platformIntent(ctx, e, tx); handled {
			return result, err
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects (sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL)"); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects(event_id) VALUES (?)", e.ID); err != nil {
			return nil, err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects").Scan(&count); err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Effects int `json:"effects"`
		}{count})
	})
	must(err)
	listener, err := capsuleprotocol.ListenControl()
	must(err)
	fmt.Println("CAPSULE_CONTROL_READY") // no identity, envelope, credentials or SQL data
	must(server.Serve(context.Background(), listener))
}
