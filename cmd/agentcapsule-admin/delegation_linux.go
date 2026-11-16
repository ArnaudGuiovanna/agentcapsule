//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	action := f.String("action", "", "install, rotate, add-key, retire-key, revoke-trust or revoke-token")
	operation := f.String("operation-id", "", "stable unique ID preserved for retries")
	tenant := f.String("tenant-id", "", "existing organization")
	issuer := f.String("issuer", "", "configured issuer")
	audience := f.String("audience", "", "configured audience (except token revocation)")
	tokenID := f.String("token-id", "", "JTI to revoke permanently within tenant and issuer")
	file := f.String("trust-file", "", "local public trust JSON, required for install/rotate")
	keyID := f.String("key-id", "", "the key's kid, for add-key and retire-key")
	publicKey := f.String("public-key", "", "Ed25519 public key in standard base64, for add-key")
	overlap := f.Duration("overlap", 0, "for retire-key: how long tokens signed with the key stay valid (0: none)")
	g := newGuard(f, "the issuer (rotate, revoke-trust), the token ID (revoke-token) or the key ID (add-key, retire-key)")
	access := newAccessFlags(f)
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *operation == "" || *tenant == "" || *issuer == "" {
		return fail("configuration_required")
	}
	// Rotating rejects the tokens of earlier generations, revoking ends
	// sign-ins or a token for good, and adding or retiring a key changes who
	// may sign in (ADR 014): each names its target again.
	switch *action {
	case "rotate", "revoke-trust":
		if !g.allows(*issuer) {
			return fail("confirmation_required")
		}
	case "revoke-token":
		if !g.allows(*tokenID) {
			return fail("confirmation_required")
		}
	case "add-key", "retire-key":
		if !g.allows(*keyID) {
			return fail("confirmation_required")
		}
	}
	in := controlplane.DelegationChange{OperationID: *operation, Actor: operatorName(), Action: *action, TenantID: *tenant, Issuer: *issuer, Audience: *audience, TokenID: *tokenID, KeyID: *keyID, Overlap: *overlap, DryRun: *g.dryRun}
	if *publicKey != "" {
		decoded, err := base64.StdEncoding.Strict().DecodeString(*publicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != *publicKey {
			return fail("public_key_invalid")
		}
		in.PublicKey = ed25519.PublicKey(decoded)
	}
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
		return fail("trust_file_used_only_by_install_and_rotate")
	}
	dsn, code := databaseURL()
	if code != "" {
		return fail(code)
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
	// A change that revokes access appends its record to the authority
	// service before it commits (ADR 006 wave 5); a dry run records nothing.
	switch *action {
	case "rotate", "revoke-trust", "revoke-token", "retire-key":
		if !*g.dryRun {
			authorities, code := access.attach(ctx, s)
			if code != "" {
				return fail(code)
			}
			if authorities != nil {
				defer authorities.Close()
			}
		}
	}
	out, err := s.ChangeDelegationAuthority(ctx, in)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("delegation_change_rejected_" + reason)
		}
		if errors.Is(err, controlplane.ErrAuthorityUnavailable) {
			return fail("authority_unavailable_try_again")
		}
		return fail("delegation_change_unconfirmed_retry_with_same_operation")
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return fail("delegation_output_failed")
	}
	return 0
}
