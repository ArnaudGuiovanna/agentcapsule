//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

func bootstrapPlatform(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("bootstrap-platform", flag.ContinueOnError)
	keyPath := f.String("receipt-key-file", "", "private 32-byte receipt encryption key (reuse installation key)")
	tokenPath := f.String("token-file", "", "private platform bootstrap token file")
	account := f.String("platform-account", "platform-operator", "local platform operator identity")
	lifetime := f.Duration("token-lifetime", 30*24*time.Hour, "platform token lifetime")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *keyPath == "" || *tokenPath == "" || *keyPath == *tokenPath {
		return fail("configuration_required")
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
	key, err := operatorconfig.EnsurePrivate(*keyPath, 32, func() []byte {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b
	})
	if err != nil {
		return fail("receipt_key_file_invalid")
	}
	accounts, err := controlplane.NewAccounts(s, key)
	if err != nil || accounts.InitializeReceiptKey(ctx) != nil {
		return fail("receipt_key_does_not_match_installation")
	}
	secret, err := operatorconfig.EnsurePrivate(*tokenPath, 48, func() []byte {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return []byte("acpp_" + base64.RawURLEncoding.EncodeToString(b))
	})
	if err != nil {
		return fail("token_file_invalid")
	}
	if err = s.BootstrapPlatformToken(ctx, *account, string(secret), *lifetime); err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("platform_bootstrap_rejected_" + reason)
		}
		return fail("platform_bootstrap_unconfirmed_retry_with_same_files")
	}
	fmt.Fprintln(os.Stdout, "platform_bootstrap_complete")
	return 0
}
