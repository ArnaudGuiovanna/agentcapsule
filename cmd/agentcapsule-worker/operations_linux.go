//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
)

// The operator's commands that run beside the maintenance worker (OPR-5):
// they start no VM, take no barrier and skip the mandatory preflight, so
// that a full disk or a host without KVM does not stop them.

// testRestore tests the restore of one agent from its newest archive, or
// -archive-id, and prints what it checked (docs/recovery.md, Test a
// restore). It changes nothing: see worker.RestoreTest.
func testRestore(c worker.ServiceConfig, mode operatorconfig.Mode, agent, archiveID, archiveRoot, scratch, fetchScript string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if c.Provisioning == nil || c.Authority == nil {
		return fail("archive_requires_product_authorities")
	}
	opts, _, _, err := c.Settings()
	if errors.Is(err, worker.ErrAuthorityServiceRequired) {
		return fail(worker.AuthorityFailure(err))
	}
	if err != nil {
		return fail("configuration_invalid")
	}
	for _, pair := range [][2]string{{opts.Root, archiveRoot}, {opts.Root, scratch}, {archiveRoot, scratch}} {
		if restoreauthority.CheckSeparation(pair[0], pair[1]) != nil {
			return fail("archive_domain_overlap")
		}
	}
	dsn, code := operatorconfig.DatabaseURL(mode)
	if code != "" {
		return fail(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	authority, err := c.OpenAuthority()
	if err != nil {
		return fail("configuration_invalid")
	}
	defer authority.Close()
	waiting := telemetry.NewLogger(os.Stderr, map[string][]string{"event": {"authority_service_waiting"}})
	var once sync.Once
	if err = worker.WaitForAuthority(ctx, authority, opts.Root, func(error) {
		once.Do(func() { waiting.Event("authority_service_waiting") })
	}); err != nil {
		return fail(worker.AuthorityFailure(err))
	}
	if authority.SeparateFrom(archiveRoot) != nil || authority.SeparateFrom(scratch) != nil {
		return fail("archive_domain_overlap")
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := controlplane.Open(startup, dsn)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	if err = s.Ready(startup); err != nil {
		return fail("database_schema_unavailable")
	}
	// The archive root is read, never created.
	if st, err := os.Stat(archiveRoot); err != nil || !st.IsDir() {
		return fail("archive_storage_unavailable")
	}
	archives, err := volumearchive.New(archiveRoot)
	if err != nil {
		return fail("archive_storage_unavailable")
	}
	t := worker.RestoreTest{Store: s, HostID: c.HostID, Authority: authority, RuntimeRoot: opts.Root, Archives: archives, Scratch: scratch}
	if fetchScript != "" {
		t.Fetch = func(root string) worker.ArchiveFetcher { return worker.ScriptFetcher([]string{fetchScript}, root) }
	}
	report, err := t.Run(ctx, agent, archiveID)
	if err != nil {
		return fail("restore_test_failed_" + worker.RestoreTestFailure(err))
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fail("restore_test_report_write_failed")
	}
	return 0
}

// collectGarbage runs the maintenance worker's cleanup now, on this host
// (worker.GarbageCollection), under the guards of the operator's destructive
// commands (ADR 014 §7): -confirm repeats the host's host_id, -dry-run
// removes nothing; a run is audited in operator_audit, a dry run is not. It
// prints what it removed, or would remove, as one JSON object.
func collectGarbage(c worker.ServiceConfig, mode operatorconfig.Mode, dryRun bool, confirm string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if !dryRun && (c.HostID == "" || confirm != c.HostID) {
		return fail("confirmation_required")
	}
	dsn, code := operatorconfig.DatabaseURL(mode)
	if code != "" {
		return fail(code)
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
	if err = s.Ready(startup); err != nil {
		return fail("database_schema_unavailable")
	}
	g, err := c.GarbageCollection(s)
	if err != nil {
		return fail("configuration_invalid")
	}
	report, err := g.Run(ctx, dryRun)
	out := struct {
		controlplane.OperatorOutcome
		worker.GarbageReport
	}{controlplane.OperatorOutcome{Action: "garbage.collected", Target: c.HostID, Outcome: "unchanged", DryRun: dryRun}, report}
	if report.Found() {
		out.Outcome = "done"
	}
	if !dryRun {
		// Recorded even after an error: what it removed is gone.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		command := controlplane.OperatorCommand{Actor: fmt.Sprintf("local-uid:%d", os.Geteuid())}
		if _, auditErr := s.RecordGarbageCollection(cleanup, command, c.HostID, report.Found()); auditErr != nil {
			err = errors.Join(err, auditErr)
		}
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		return fail("outcome_output_failed")
	}
	if err != nil {
		return fail("collect_garbage_interrupted_run_again")
	}
	return 0
}
