//go:build linux

// agentcapsule-worker maintains VM placements and boot credentials, dispatches
// durable business jobs, and provisions encrypted guests when configured.
// Owner HTTP and guest-side business logic are separate components.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
)

func run() int {
	path := flag.String("config", "", "root-owned worker JSON configuration")
	migrate := flag.Bool("migrate", false, "apply control-plane schema migration before maintenance")
	archiveAgent := flag.String("archive-agent", "", "capture this agent once, leaving it stopped")
	archiveID := flag.String("archive-id", "", "stable arc_ identifier with 32 lowercase hex digits; reuse on retry")
	archiveRoot := flag.String("archive-root", "", "absolute private archive directory outside runtime and authorities")
	flag.Parse()
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if *path == "" || flag.NArg() != 0 {
		return fail("configuration_required")
	}
	archiveRequested := *archiveAgent != "" || *archiveID != "" || *archiveRoot != ""
	if archiveRequested && (*archiveAgent == "" || !volumearchive.ValidID(*archiveID) || !filepath.IsAbs(*archiveRoot)) {
		return fail("archive_configuration_invalid")
	}
	c, err := worker.LoadServiceConfig(*path)
	if err != nil {
		return fail("configuration_invalid")
	}
	opts, lease, maintenance, err := c.Settings()
	if err != nil {
		return fail("configuration_invalid")
	}
	if archiveRequested {
		if c.Provisioning == nil || c.KeyAuthority == nil || c.RestoreAuthority == nil {
			return fail("archive_requires_product_authorities")
		}
		for _, root := range []string{opts.Root, c.KeyAuthority.Root, c.RestoreAuthority.Root} {
			if err = restoreauthority.CheckSeparation(root, *archiveRoot); err != nil {
				return fail("archive_domain_overlap")
			}
		}
	}
	dsn := os.Getenv("AGENTCAPSULE_DATABASE_URL")
	if dsn == "" {
		return fail("database_configuration_required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := controlplane.Open(startup, dsn)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	if *migrate {
		if err = s.Migrate(startup); err != nil {
			return fail("database_migration_failed")
		}
	}
	if _, err = s.PendingCredentialRenewals(startup, c.HostID); err != nil {
		return fail("database_schema_unavailable")
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return fail("worker_identity_failed")
	}
	workerID := "maintenance-" + hex.EncodeToString(nonce)
	var w *worker.Placements
	if c.KeyAuthority != nil {
		keys, e := c.OpenVolumeKeys()
		if e != nil {
			return fail("key_authority_unavailable")
		}
		authority, e := c.OpenRestoreAuthority(startup, keys)
		if e != nil {
			return fail("restore_authority_unavailable")
		}
		defer authority.Close()
		if c.Provisioning != nil {
			w, err = worker.NewProvisioningPlacements(s, c.HostID, workerID, lease, opts, keys, authority, *c.Provisioning)
		} else {
			w, err = worker.NewPlacementsWithAuthority(s, c.HostID, workerID, lease, opts, keys, authority)
		}
	} else {
		w, err = worker.NewPlacements(s, c.HostID, workerID, lease, opts)
	}
	if err != nil {
		return fail("runtime_initialization_failed")
	}
	defer w.Close() // Listener ownership ends; surviving VMMs remain adoptable.
	transit, err := c.OpenTransit(s)
	if err != nil {
		return fail("transit_configuration_invalid")
	}
	if transit != nil {
		if err = w.EnableTransit(startup, transit); err != nil {
			return fail("transit_keys_unavailable")
		}
	}
	llm, err := c.OpenLLM(s)
	if err != nil {
		return fail("llm_configuration_invalid")
	}
	if llm != nil {
		if err = w.EnableLLM(llm); err != nil {
			return fail("llm_unavailable")
		}
	}
	importer, err := c.OpenRegistry(s, workerID)
	if err != nil {
		return fail("registry_configuration_invalid")
	}
	if importer != nil && !archiveRequested {
		// Imports run beside maintenance: a large download never delays delivery.
		go func() {
			_ = importer.Run(ctx, maintenance.Interval, func(error) {
				if ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "harness_import_retry")
				}
			})
		}()
	}
	if archiveRequested {
		archives, err := volumearchive.New(*archiveRoot)
		if err != nil {
			return fail("archive_storage_unavailable")
		}
		manifest, err := w.CaptureArchive(ctx, *archiveAgent, *archiveID, archives)
		if err != nil {
			return fail("archive_capture_failed_agent_may_be_stopped")
		}
		if err = json.NewEncoder(os.Stdout).Encode(manifest); err != nil {
			return fail("archive_receipt_write_failed_retry_same_id")
		}
		return 0
	}
	maintenance.Report = func(err error) {
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "maintenance_retry")
		} else if err == nil {
			fmt.Fprintln(os.Stdout, "maintenance_complete")
		}
	}
	fmt.Fprintln(os.Stdout, "maintenance_started")
	err = w.RunMaintenance(ctx, maintenance)
	if errors.Is(err, context.Canceled) {
		return 0
	}
	return fail("maintenance_stopped")
}

func main() { os.Exit(run()) }
