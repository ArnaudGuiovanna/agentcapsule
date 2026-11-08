//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

func configureDelegation(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("configure-delegation", flag.ContinueOnError)
	action := f.String("action", "", "install, rotate, revoke-trust or revoke-token")
	operation := f.String("operation-id", "", "stable unique ID preserved for retries")
	tenant := f.String("tenant-id", "", "existing organization")
	issuer := f.String("issuer", "", "configured issuer")
	audience := f.String("audience", "", "configured audience (except token revocation)")
	tokenID := f.String("token-id", "", "JTI to revoke permanently within tenant and issuer")
	file := f.String("trust-file", "", "local public trust JSON, required for install/rotate")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *operation == "" || *tenant == "" || *issuer == "" {
		return fail("configuration_required")
	}
	in := controlplane.DelegationChange{OperationID: *operation, Actor: fmt.Sprintf("local-uid:%d", os.Geteuid()), Action: *action, TenantID: *tenant, Issuer: *issuer, Audience: *audience, TokenID: *tokenID}
	if *action == "install" || *action == "rotate" {
		if *file == "" {
			return fail("trust_file_required")
		}
		cfg, err := operatorconfig.ReadDelegationConfig(*file)
		if err != nil {
			return fail("delegated_identity_configuration_invalid")
		}
		for i := range cfg.Trusts {
			t := &cfg.Trusts[i]
			if t.TenantID == *tenant && t.Issuer == *issuer && t.Audience == *audience {
				in.Trust = t
			}
		}
		if in.Trust == nil {
			return fail("configured_trust_not_found")
		}
	} else if *file != "" {
		return fail("trust_file_not_used_for_revocation")
	}
	dsn := os.Getenv("AGENTCAPSULE_DATABASE_URL")
	if dsn == "" {
		return fail("database_configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := controlplane.Open(ctx, dsn)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	if err = s.Migrate(ctx); err != nil {
		return fail("database_migration_failed")
	}
	out, err := s.ChangeDelegationAuthority(ctx, in)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("delegation_change_rejected_" + reason)
		}
		return fail("delegation_change_unconfirmed_retry_with_same_operation")
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return fail("delegation_output_failed")
	}
	return 0
}
