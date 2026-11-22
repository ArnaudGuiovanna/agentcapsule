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
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
)

func run() int {
	path := flag.String("config", "", "root-owned worker JSON configuration")
	archiveAgent := flag.String("archive-agent", "", "capture this agent once, leaving it stopped")
	archiveID := flag.String("archive-id", "", "stable arc_ identifier with 32 lowercase hex digits; reuse on retry")
	archiveRoot := flag.String("archive-root", "", "absolute private archive directory outside runtime and authorities")
	restoreAgent := flag.String("restore-agent", "", "restore this agent from -archive-id into a new incarnation, then exit")
	restoreID := flag.String("restore-id", "", "stable rst_ identifier with 32 lowercase hex digits; reuse to resume the restore")
	restoreHost := flag.String("restore-host", "", "restore every agent of this lost host, which this host took over, from its archives, then exit")
	archiveFetch := flag.String("archive-fetch", "", "the archive shipper (agentcapsule-archive-ship.py), to fetch an archive missing from -archive-root from the standby's copy or S3")
	check := flag.Bool("preflight", false, "check this host and configuration, print what to fix, change nothing, then exit")
	testAgent := flag.String("test-restore", "", "test the restore of this agent from its newest archive, or -archive-id, in -scratch, change nothing, then exit")
	scratch := flag.String("scratch", "", "absolute directory outside the runtime, archive and authority roots, where -test-restore works")
	collect := flag.Bool("collect-garbage", false, "remove the archives past retention, the archives of deleted agents and the unused cached harness images, then exit")
	dryRun := flag.Bool("dry-run", false, "with -collect-garbage: print what it would remove, remove nothing")
	confirm := flag.String("confirm", "", "with -collect-garbage: repeat this host's host_id; not needed with -dry-run")
	probeAlias := flag.String("probe-llm-alias", "", "diagnose this registered model alias, without generating content")
	probeOrg := flag.String("probe-organization", "", "organization of the model alias")
	flag.Parse()
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if *path == "" || flag.NArg() != 0 {
		return fail("configuration_required")
	}
	if *restoreHost != "" && (*restoreAgent != "" || *restoreID != "" || *archiveAgent != "" || *archiveID != "" || !filepath.IsAbs(*archiveRoot)) {
		return fail("restore_host_configuration_invalid")
	}
	if *testAgent != "" && (*restoreAgent != "" || *restoreID != "" || *restoreHost != "" || *archiveAgent != "" || *check || *collect ||
		!filepath.IsAbs(*archiveRoot) || !filepath.IsAbs(*scratch) || *archiveID != "" && !volumearchive.ValidID(*archiveID)) ||
		*testAgent == "" && *scratch != "" {
		return fail("restore_test_configuration_invalid")
	}
	if *collect && (*restoreAgent != "" || *restoreID != "" || *restoreHost != "" || *archiveAgent != "" || *archiveID != "" || *archiveRoot != "" ||
		*archiveFetch != "" || *check) || !*collect && (*dryRun || *confirm != "") {
		return fail("collect_garbage_configuration_invalid")
	}
	if *archiveFetch != "" && (!filepath.IsAbs(*archiveFetch) || (*restoreHost == "" && *restoreAgent == "" && *testAgent == "")) {
		return fail("archive_fetch_configuration_invalid")
	}
	// Production unless AGENTCAPSULE_MODE=development, which says so at
	// every start (docs/adr/010-transport-security-and-preflight.md).
	mode, err := operatorconfig.ModeFromEnvironment()
	if err != nil {
		return fail("mode_invalid")
	}
	if mode == operatorconfig.Development {
		fmt.Fprintln(os.Stderr, operatorconfig.DevelopmentWarning)
	}
	if *probeAlias != "" || *probeOrg != "" {
		if flag.NFlag() != 3 || *probeAlias == "" || *probeOrg == "" {
			return fail("probe_configuration_invalid")
		}
		return providerProbe(*path, mode, *probeOrg, *probeAlias)
	}
	if *check {
		return runPreflight(*path, mode)
	}
	if *testAgent != "" || *collect {
		c, err := worker.LoadServiceConfig(*path)
		if err != nil {
			return fail("configuration_invalid")
		}
		if c.CheckAccount() != nil {
			return fail("worker_runs_as_its_account_not_root")
		}
		if *collect {
			return collectGarbage(c, mode, *dryRun, *confirm)
		}
		return testRestore(c, mode, *testAgent, *archiveID, *archiveRoot, *scratch, *archiveFetch)
	}
	restoreRequested := *restoreAgent != "" || *restoreID != ""
	if restoreRequested && (*restoreAgent == "" || *archiveAgent != "" || !controlplane.ValidRestoreID(*restoreID) ||
		!volumearchive.ValidID(*archiveID) || !filepath.IsAbs(*archiveRoot)) {
		return fail("restore_configuration_invalid")
	}
	// A capture or a restore: one agent, or a lost host's, then exit; no
	// maintenance.
	hostRestoreRequested := *restoreHost != ""
	archiveRequested := *archiveAgent != "" || *archiveID != "" || *archiveRoot != "" || restoreRequested || hostRestoreRequested
	if archiveRequested && !restoreRequested && !hostRestoreRequested && (*archiveAgent == "" || !volumearchive.ValidID(*archiveID) || !filepath.IsAbs(*archiveRoot)) {
		return fail("archive_configuration_invalid")
	}
	c, err := worker.LoadServiceConfig(*path)
	if err != nil {
		return fail("configuration_invalid")
	}
	// With its helper, the worker runs as its own account, with no
	// capability, and never as root (ADR 024).
	if c.CheckAccount() != nil {
		return fail("worker_runs_as_its_account_not_root")
	}
	opts, lease, maintenance, err := c.Settings()
	if errors.Is(err, worker.ErrAuthorityServiceRequired) {
		return fail(worker.AuthorityFailure(err))
	}
	if err != nil {
		return fail("configuration_invalid")
	}
	// A guest's serial console is for debugging: development mode, or the
	// explicit vm_serial_console option (S-20).
	opts.SerialConsole = opts.SerialConsole || mode == operatorconfig.Development
	if err = c.CheckProductionTransport(); mode == operatorconfig.Production && errors.Is(err, worker.ErrClearTextCorpusSource) {
		return fail("corpus_local_rule_refused_in_production")
	} else if mode == operatorconfig.Production && err != nil {
		return fail("registry_local_rule_refused_in_production")
	}
	// RUN-012: no Firecracker without KVM, a compatible kernel, cgroup v2, room
	// on the runtime disk (DEP-3) and the pinned artifacts. The failed checks
	// say what to fix.
	if results := c.MandatoryPreflight(context.Background(), preflight.System()); preflight.Failed(results) {
		var failed []preflight.Result
		for _, r := range results {
			if r.Status == preflight.Fail {
				failed = append(failed, r)
			}
		}
		_ = preflight.Write(os.Stderr, failed)
		return 1
	}
	if archiveRequested {
		if c.Provisioning == nil || c.Authority == nil {
			return fail("archive_requires_product_authorities")
		}
		if err = restoreauthority.CheckSeparation(opts.Root, *archiveRoot); err != nil {
			return fail("archive_domain_overlap")
		}
	}
	dsn, code := operatorconfig.DatabaseURL(mode)
	if code != "" {
		return fail(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The authorities belong to the authority service (ADR 006): the worker
	// reaches them through its socket and never opens their directories. A
	// service that does not answer yet is waited for; one that holds other
	// authorities is refused.
	authority, err := c.OpenAuthority()
	if err != nil {
		return fail("configuration_invalid")
	}
	if authority != nil {
		defer authority.Close()
		waiting := telemetry.NewLogger(os.Stderr, map[string][]string{"event": {"authority_service_waiting"}})
		var once sync.Once
		if err = worker.WaitForAuthority(ctx, authority, opts.Root, func(error) {
			once.Do(func() { waiting.Event("authority_service_waiting") })
		}); err != nil {
			return fail(worker.AuthorityFailure(err))
		}
		if archiveRequested && authority.SeparateFrom(*archiveRoot) != nil {
			return fail("archive_domain_overlap")
		}
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	database, err := c.DatabaseConnections()
	if err != nil {
		return fail("configuration_invalid")
	}
	s, err := controlplane.OpenWith(startup, dsn, database)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	// The worker never migrates: agentcapsule-admin migrate does, as the
	// role that owns the schema, which the worker's role does not (ADR 001,
	// "Changes after the v0.1.0 audit"). It refuses a ledger behind, ahead
	// of or different from this binary's, as the API does.
	if err = s.Ready(startup); err != nil {
		return fail("database_schema_unavailable")
	}
	if _, err = s.PendingCredentialRenewals(startup, c.HostID); err != nil {
		return fail("database_schema_unavailable")
	}
	// A lost host never serves again (ADR 020): its worker gets no work.
	if _, err = s.HostTakeoverOf(startup, c.HostID); err == nil {
		return fail("host_taken_over")
	} else if !errors.Is(err, controlplane.ErrNotFound) {
		return fail("database_schema_unavailable")
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return fail("worker_identity_failed")
	}
	workerID := "maintenance-" + hex.EncodeToString(nonce)
	var w *worker.Placements
	if authority != nil {
		// The client is both authorities: keys are created and destroyed
		// through it, and a key in use is held under its binding.
		if c.Provisioning != nil {
			w, err = worker.NewProvisioningPlacements(s, c.HostID, workerID, lease, opts, authority, authority, *c.Provisioning)
		} else {
			w, err = worker.NewPlacementsWithAuthority(s, c.HostID, workerID, lease, opts, authority, authority)
		}
	} else {
		w, err = worker.NewPlacements(s, c.HostID, workerID, lease, opts)
	}
	if err != nil {
		return fail("runtime_initialization_failed")
	}
	defer w.Close() // Listener ownership ends; surviving VMMs remain adoptable.
	budget, err := c.Restarts()
	if err != nil || w.SetRestartBudget(budget) != nil {
		return fail("configuration_invalid")
	}
	// Events, one JSON object per line, from a closed vocabulary (OPS-02):
	// progress on standard output, retries and failures on standard error.
	vocabulary := map[string][]string{"event": {"maintenance_started", "maintenance_complete", "maintenance_retry", "wake_budget_exhausted",
		"harness_import_retry", "registry_unsigned_rules", "corpus_fetch_retry", "corpus_build_retry", "directory_publish_retry", "slim_callback_stopped", "job_done", "job_retried",
		"volume_archive_captured", "volume_archive_retry", "volume_archive_purged", "delivery_dead", "agent_failed"},
		"reason": append(append(append(worker.RetryReasons(), worker.ArchiveRetryReasons()...), worker.DeadDeliveryReasons()...), worker.AgentFailureReasons()...),
		"kind":   append(worker.JobKinds(), worker.DeadDeliveryKinds()...), "vm": worker.ArchiveVMs()}
	// The model gateway's events: a soft budget passed, a call refused (ADR 011).
	vocabulary["event"] = append(vocabulary["event"], worker.LLMEvents()...)
	for key, values := range worker.LLMEventCodes() {
		vocabulary[key] = append(vocabulary[key], values...)
	}
	events, problems := telemetry.NewLogger(os.Stdout, vocabulary), telemetry.NewLogger(os.Stderr, vocabulary)
	registry := telemetry.NewRegistry()
	if err = w.EnableTelemetry(registry, opts.Root, opts.MaxActive); err != nil {
		return fail("telemetry_unavailable")
	}
	if err = w.EnableDeletionTelemetry(registry); err != nil {
		return fail("telemetry_unavailable")
	}
	if err = w.EnableStreamTelemetry(registry); err != nil {
		return fail("telemetry_unavailable")
	}
	if err = w.EnableJobEvents(events, problems); err != nil {
		return fail("telemetry_unavailable")
	}
	pressure := c.Pressure()
	if err = w.EnableStoragePressure(pressure, registry); err != nil {
		return fail("configuration_invalid")
	}
	if c.TraceFile != "" && !archiveRequested {
		// Spans (OPR-3), every identifier pseudonymized with the
		// installation's key, which the API reads too.
		key, err := s.TraceKey(startup)
		if err != nil {
			return fail("database_schema_unavailable")
		}
		tracer, err := telemetry.NewFileTracer(c.TraceFile, "agentcapsule-worker", key)
		clear(key)
		if err != nil {
			return fail("trace_file_unavailable")
		}
		defer tracer.Close()
		tracer.Count(registry)
		if err = w.EnableTracing(tracer); err != nil {
			return fail("telemetry_unavailable")
		}
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
	// One dedicated listening connection: new work for this host wakes the
	// dispatch (P-01), and the harnesses' output streams (ADR 022) learn of a
	// cancellation or an outcome.
	hub, err := pgnotify.New(s.Connect, "agentcapsule_work", "agentcapsule_invocation_stream")
	if err != nil {
		return fail("database_initialization_failed")
	}
	if !archiveRequested {
		go func() { _ = hub.Run(ctx) }()
		wake, stopWake := hub.Subscribe("agentcapsule_work", c.HostID)
		defer stopWake()
		maintenance.Wake = wake
	}
	transit, err := c.OpenTransit(s)
	if err != nil {
		return fail("transit_configuration_invalid")
	}
	if transit != nil {
		if err = w.EnableTransit(startup, transit); err != nil {
			return fail("transit_keys_unavailable")
		}
		bounds, err := c.OutputStreamBounds()
		if err != nil {
			return fail("configuration_invalid")
		}
		if err = w.EnableOutputStreams(bounds, hub); err != nil {
			return fail("transit_keys_unavailable")
		}
	}
	llm, err := c.OpenLLM(s, mode == operatorconfig.Production)
	if err != nil {
		return fail("llm_configuration_invalid")
	}
	if llm != nil {
		llm.Observe(worker.NewLLMTelemetry(registry, problems, s.LLMUnresolvedCalls))
		if err = w.EnableLLM(llm); err != nil {
			return fail("llm_unavailable")
		}
	}
	fetcher, err := c.OpenCorpusFetcher(s, workerID)
	if err != nil {
		return fail("corpus_configuration_invalid")
	}
	if cache := c.CorpusCachePath(); cache != "" {
		if err = w.EnableCorpusCache(cache); err != nil {
			return fail("corpus_configuration_invalid")
		}
	}
	if fetcher != nil && transit == nil {
		return fail("corpus_requires_transit")
	}
	if fetcher != nil && !archiveRequested {
		fetcher.Pressure = pressure.Refuse
		fetcher.Telemetry = worker.NewCorpusTelemetry(registry)
		builder, err := c.OpenCorpusBuilder(w, transit, fetcher.Telemetry)
		if err != nil {
			return fail("corpus_configuration_invalid")
		}
		builder.Observe(registry)
		go func() {
			_ = builder.Run(ctx, maintenance.Interval, func(error) {
				if ctx.Err() == nil {
					problems.Event("corpus_build_retry")
				}
			})
		}()

		go func() {
			_ = fetcher.Run(ctx, maintenance.Interval, func(error) {
				if ctx.Err() == nil {
					problems.Event("corpus_fetch_retry")
				}
			})
		}()
	}
	importer, err := c.OpenRegistry(s, workerID, mode == operatorconfig.Production)
	if errors.Is(err, worker.ErrInspection) {
		return fail("registry_inspection_unavailable")
	}
	if errors.Is(err, ociregistry.ErrUnsigned) {
		return fail("registry_signatures_required_in_production")
	}
	if err != nil {
		return fail("registry_configuration_invalid")
	}
	if n := len(c.UnsignedRegistryRules()); importer != nil && n > 0 {
		// Each rule that imports unsigned packages, as its configuration
		// allows (L-16); the preflight names them.
		problems.Event("registry_unsigned_rules", telemetry.Int("rules", int64(n)))
	}
	if importer != nil {
		if err = w.EnableRegistry(importer); err != nil {
			return fail("registry_unavailable")
		}
		importer.Pressure = pressure.Refuse
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
			retry := func(error) {
				if ctx.Err() == nil {
					publishRetries.Inc()
					problems.Event("directory_publish_retry")
				}
			}
			// A Directory that cannot be reached defers the publication: it
			// counts as a failed pass, so that the outage alerts.
			publisher.Deferred = retry
			go publisher.Run(ctx, publishEvery, retry)
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
	if !archiveRequested {
		// Nightly archives (REC-02): taken by this process, between passes.
		archives, err := c.OpenArchives()
		if err != nil {
			return fail("archive_storage_unavailable")
		}
		if archives != nil {
			if _, _, err = s.VolumeArchiveFreshness(startup, c.HostID); err != nil {
				return fail("database_schema_unavailable")
			}
			if err = w.EnableArchiveTelemetry(registry, archives); err != nil {
				return fail("telemetry_unavailable")
			}
			archives.Report = func(r worker.ArchiveReport) {
				vm := telemetry.Code("vm", r.VM())
				if r.Err == nil {
					events.Event("volume_archive_captured", vm, telemetry.Int("bytes", r.Size),
						telemetry.Seconds("seconds", r.Duration), telemetry.Int("removed", int64(r.Removed)))
				} else if ctx.Err() == nil {
					problems.Event("volume_archive_retry", vm, telemetry.Code("reason", worker.ArchiveRetryReason(r.Err)))
				}
				if r.RetentionErr != nil && ctx.Err() == nil {
					problems.Event("volume_archive_retry", vm, telemetry.Code("reason", "retention"))
				}
			}
			// The archives of deleted agents, whose key is destroyed (ADR 018).
			archives.Purged = func(removed int, err error) {
				if removed > 0 {
					events.Event("volume_archive_purged", telemetry.Int("removed", int64(removed)))
				}
				if err != nil {
					problems.Event("volume_archive_retry", telemetry.Code("reason", "purge"))
				}
			}
			maintenance.Archives = archives
		}
	}
	// While the authorities do not answer, a restore pauses, then resumes
	// from its last durable step (ADR 006 §4).
	pauses := telemetry.NewLogger(os.Stderr, map[string][]string{"event": {"restore_paused"}, "reason": worker.RestorePauses()})
	paused := func(err error) { pauses.Event("restore_paused", telemetry.Code("reason", worker.RestorePause(err))) }
	var fetch worker.ArchiveFetcher
	if *archiveFetch != "" {
		fetch = c.Fetcher(*archiveFetch, *archiveRoot)
	}
	if hostRestoreRequested {
		archives, err := volumearchive.New(*archiveRoot)
		if err != nil {
			return fail("archive_storage_unavailable")
		}
		// One line per agent as it goes, then the totals (docs/recovery.md).
		out := json.NewEncoder(os.Stdout)
		items, err := w.RestoreHost(ctx, *restoreHost, archives, fetch, paused, func(item worker.HostRestoreItem) { _ = out.Encode(item) })
		if errors.Is(err, worker.ErrNotTakenOver) {
			return fail("restore_host_not_taken_over")
		}
		if err != nil {
			return fail("restore_host_interrupted_run_again")
		}
		totals := map[string]int{"restored": 0, "skipped": 0, "failed": 0}
		for _, item := range items {
			totals[item.Result]++
		}
		_ = out.Encode(struct {
			LostHost string `json:"lost_host"`
			Host     string `json:"host"`
			Restored int    `json:"restored"`
			Skipped  int    `json:"skipped"`
			Failed   int    `json:"failed"`
		}{*restoreHost, c.HostID, totals["restored"], totals["skipped"], totals["failed"]})
		if totals["failed"] > 0 {
			return fail("restore_host_incomplete_run_again")
		}
		return 0
	}
	if restoreRequested {
		archives, err := volumearchive.New(*archiveRoot)
		if err != nil {
			return fail("archive_storage_unavailable")
		}
		// From the archive root, or fetched from a store and verified first.
		store := "local"
		if _, err = archives.Manifest(*archiveID); err != nil && fetch != nil {
			if store, err = w.FetchArchive(ctx, archives, fetch, *archiveID, paused); err != nil {
				return fail("restore_failed_" + worker.RestoreFailure(err))
			}
		}
		result, err := w.RestoreFromArchive(ctx, *restoreID, *restoreAgent, *archiveID, archives, paused)
		if err != nil {
			// Once the restore is recorded, the agent stays out of service
			// until the same command succeeds (see docs/recovery.md).
			return fail("restore_failed_" + worker.RestoreFailure(err))
		}
		unmatched, queued, skipped := worker.RestoreCounts(result.Losses)
		if err = json.NewEncoder(os.Stdout).Encode(struct {
			RestoreID    string `json:"restore_id"`
			AgentID      string `json:"agent_id"`
			ArchiveID    string `json:"archive_id"`
			ArchiveStore string `json:"archive_store"`
			Incarnation  uint64 `json:"incarnation"`
			Losses       int    `json:"losses"`
			Unmatched    int    `json:"unmatched_losses"`
			Queued       int    `json:"reruns_queued"`
			Skipped      int    `json:"reruns_skipped"`
		}{result.RestoreID, result.AgentID, result.ArchiveID, store, result.Incarnation, len(result.Losses), unmatched, queued, skipped}); err != nil {
			return fail("restore_receipt_write_failed_retry_same_id")
		}
		return 0
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

// runPreflight prints every check of the configuration and of this host, and
// exits 1 when one fails. It changes nothing: it creates no runtime root,
// opens no authority and writes no row.
func runPreflight(path string, mode operatorconfig.Mode) int {
	_, modeResult := preflight.Mode()
	results := []preflight.Result{modeResult}
	c, err := worker.LoadServiceConfig(path)
	if err == nil {
		_, _, _, err = c.Settings()
	}
	if err != nil {
		results = append(results, preflight.Result{Check: "configuration", Status: preflight.Fail,
			Detail: path + " is not a valid worker configuration",
			Fix:    "a root-owned regular file, not writable by group or others, with the fields of runtime/worker/config.example.json"})
		_ = preflight.Write(os.Stdout, results)
		return 1
	}
	results = append(results, preflight.Result{Check: "configuration", Status: preflight.OK, Detail: path})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	results = append(results, c.Preflight(ctx, preflight.System(), mode, os.Getenv(operatorconfig.DatabaseVariable))...)
	if err = preflight.Write(os.Stdout, results); err != nil || preflight.Failed(results) {
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
