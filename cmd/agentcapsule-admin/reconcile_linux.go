//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// reconcile brings PostgreSQL up to the authorities after a failover, before
// the API opens (docs/adr/006-authority-service.md §7, wave 7; ADR 005,
// "What the code must do", items 14 and 15). It runs as the API's account,
// on the authority service's API socket, with the API's three flags and
// database. It replays the access revocation records PostgreSQL lacks,
// keeps PostgreSQL's own records and revocation subjects in the authority,
// copies the subjects into revocation_catalogue, resumes the deletions the
// authority sealed, reports the stores that differ, and records that it
// reconciled the service's epoch: the API opens only then. Run it again after
// any failure: each step can be repeated. It prints what it did and found as
// one JSON object, with the window to announce after a degraded period.
func reconcile(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	access := newAccessFlags(f)
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *access.socket == "" || *access.restoreID == "" || *access.keyID == "" {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	client, err := authorityclient.NewAPI(*access.socket, *access.restoreID, *access.keyID)
	if err != nil {
		return fail("authority_configuration_invalid")
	}
	defer client.Close()
	if _, err = client.Status(ctx); err != nil {
		switch {
		case errors.Is(err, authorityservice.ErrIdentity):
			return fail("authority_identity_mismatch")
		case errors.Is(err, authorityservice.ErrRole):
			return fail("authority_socket_role_mismatch")
		case errors.Is(err, authorityservice.ErrProtocol):
			return fail("authority_protocol_unsupported")
		}
		return fail("authority_service_unavailable")
	}
	if err = s.Ready(ctx); err != nil {
		return fail("database_schema_unavailable")
	}
	result, err := s.Reconcile(ctx, client)
	switch {
	case errors.Is(err, controlplane.ErrReconciliationRecord):
		return fail("reconcile_record_invalid")
	case errors.Is(err, controlplane.ErrReconciliationConflict):
		return fail("reconcile_conflict_try_again")
	case errors.Is(err, controlplane.ErrAuthorityUnavailable):
		return fail("authority_unavailable_try_again")
	case err != nil:
		return fail("reconcile_failed_try_again")
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}
