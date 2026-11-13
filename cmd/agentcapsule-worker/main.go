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
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
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
	// Events, one JSON object per line, from a closed vocabulary (OPS-02):
	// progress on standard output, retries and failures on standard error.
	vocabulary := map[string][]string{"event": {"maintenance_started", "maintenance_complete", "maintenance_retry", "wake_budget_exhausted",
		"harness_import_retry", "directory_publish_retry", "slim_callback_stopped", "job_done", "job_retried"},
		"reason": worker.RetryReasons(), "kind": worker.JobKinds()}
	events, problems := telemetry.NewLogger(os.Stdout, vocabulary), telemetry.NewLogger(os.Stderr, vocabulary)
	registry := telemetry.NewRegistry()
	if err = w.EnableTelemetry(registry, opts.Root, opts.MaxActive); err != nil {
		return fail("telemetry_unavailable")
	}
	if err = w.EnableJobEvents(events, problems); err != nil {
		return fail("telemetry_unavailable")
	}
	importRetries := registry.Counter("agentcapsule_worker_harness_import_retries_total", "Harness imports that failed and will be tried again.")
	publishRetries := registry.Counter("agentcapsule_worker_directory_publish_retries_total", "Directory publication passes that failed (the Directory unreachable or refusing).")
	if c.MetricsListen != "" && !archiveRequested {
		// Metrics are technical, but a scraper reaches them on the host only.
		host, _, err := net.SplitHostPort(c.MetricsListen)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return fail("metrics_listen_must_be_loopback")
		}
		metricsListener, err := net.Listen("tcp", c.MetricsListen)
		if err != nil {
			return fail("metrics_listener_unavailable")
		}
		metrics := &http.Server{Handler: registry.Handler(5 * time.Second), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second,
			ErrorLog: log.New(io.Discard, "", 0)}
		go func() { _ = metrics.Serve(metricsListener) }()
		defer metrics.Close()
	}
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
	if importer != nil {
		if err = w.EnableRegistry(importer); err != nil {
			return fail("registry_unavailable")
		}
	}
	if importer != nil && !archiveRequested {
		// Imports run beside maintenance: a large download never delays delivery.
		go func() {
			_ = importer.Run(ctx, maintenance.Interval, func(error) {
				if ctx.Err() == nil {
					importRetries.Inc()
					problems.Event("harness_import_retry")
				}
			})
		}()
	}
	dir, publishEvery, err := c.OpenDirectory()
	if err != nil {
		return fail("directory_configuration_invalid")
	}
	if dir != nil {
		defer dir.Close()
		if err = w.EnableDirectory(dir); err != nil {
			return fail("directory_unavailable")
		}
		if !archiveRequested {
			// Brings the Directory to the organizations' descriptions; an outage
			// only delays publication, every step is recorded in PostgreSQL.
			publisher := &directory.Publisher{Store: s, Directory: dir}
			go publisher.Run(ctx, publishEvery, func(error) {
				if ctx.Err() == nil {
					publishRetries.Inc()
					problems.Event("directory_publish_retry")
				}
			})
		}
	}
	link, linkListener, err := c.OpenSLIM()
	if err != nil {
		return fail("slim_configuration_invalid")
	}
	if link != nil && !archiveRequested {
		if err = w.EnableSLIM(link); err != nil {
			return fail("slim_unavailable")
		}
		// The bridge calls back here to reach the VMs; it starts and restarts
		// on its own, and deliveries wait for it without spending attempts.
		go func() {
			if err := slimlink.ServeLocal(ctx, linkListener, link); err != nil && ctx.Err() == nil {
				problems.Event("slim_callback_stopped")
			}
		}()
	} else if linkListener != nil {
		linkListener.Close()
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
			// An organization at its wake budget is a limit, not a fault: say
			// so, so that an operator does not look for one.
			if errors.Is(err, controlplane.ErrWakeBudget) {
				problems.Event("wake_budget_exhausted")
			}
			problems.Event("maintenance_retry", telemetry.Code("reason", worker.RetryReason(err)))
		} else if err == nil {
			events.Event("maintenance_complete")
		}
	}
	events.Event("maintenance_started")
	err = w.RunMaintenance(ctx, maintenance)
	if errors.Is(err, context.Canceled) {
		return 0
	}
	return fail("maintenance_stopped")
}

func main() { os.Exit(run()) }
