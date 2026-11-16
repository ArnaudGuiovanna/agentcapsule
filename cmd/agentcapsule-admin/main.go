//go:build linux

// agentcapsule-admin performs local, trusted installation operations. It has no
// HTTP listener. Bootstrap secrets are written to private files, never stdout.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

func run() int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if len(os.Args) > 1 && os.Args[1] == "bootstrap-platform" {
		return bootstrapPlatform(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "abandon-provisioning" {
		return abandonProvisioning(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "clear-agent-failure" {
		return clearAgentFailure(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "replay-dead-letter" {
		return replayDeadLetter(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "list-credentials" {
		return listCredentials(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "revoke-credential" {
		return revokeCredential(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "configure-delegation" {
		return configureDelegation(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "init-key-authority" {
		return initializeKeyAuthority(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "init-restore-authority" {
		return initializeRestoreAuthority(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "activate-transit-keys" {
		return activateTransitKeys(os.Args[2:])
	}
	if len(os.Args) > 1 && (os.Args[1] == "configure-host" || os.Args[1] == "approve-local-harness") {
		return configureCatalog(os.Args[1], os.Args[2:])
	}
	if len(os.Args) < 2 || os.Args[1] != "bootstrap" {
		return fail("usage: agentcapsule-admin bootstrap | bootstrap-platform | list-credentials | revoke-credential | abandon-provisioning | clear-agent-failure | replay-dead-letter | configure-delegation | init-key-authority | init-restore-authority | configure-host | approve-local-harness | activate-transit-keys")
	}
	f := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	keyPath := f.String("receipt-key-file", "", "private 32-byte receipt encryption key")
	tokenPath := f.String("token-file", "", "private bootstrap service token file")
	account := f.String("service-account", "installation-admin", "bootstrap service account")
	lifetime := f.Duration("token-lifetime", 30*24*time.Hour, "bootstrap token lifetime")
	if err := f.Parse(os.Args[2:]); err != nil {
		return 1
	}
	if f.NArg() != 0 || *keyPath == "" || *tokenPath == "" || *keyPath == *tokenPath {
		return fail("configuration_required")
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
	key, err := operatorconfig.EnsurePrivate(*keyPath, 32, func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b })
	if err != nil {
		return fail("receipt_key_file_invalid")
	}
	accounts, err := controlplane.NewAccounts(s, key)
	if err != nil || accounts.InitializeReceiptKey(ctx) != nil {
		return fail("receipt_key_does_not_match_installation")
	}
	token, err := operatorconfig.EnsurePrivate(*tokenPath, 47, func() []byte {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return []byte("acp_" + base64.RawURLEncoding.EncodeToString(b))
	})
	if err != nil {
		return fail("token_file_invalid")
	}
	if err = s.BootstrapServiceToken(ctx, *account, string(token), *lifetime); err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("bootstrap_rejected_" + reason)
		}
		return fail("bootstrap_unconfirmed_retry_with_same_files")
	}
	fmt.Fprintln(os.Stdout, "bootstrap_complete")
	return 0
}

func configureCatalog(command string, args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	var host, name, version, artifact *string
	var storage *int64
	if command == "configure-host" {
		host = f.String("host-id", "", "stable worker host identity")
		storage = f.Int64("storage-mib", 0, "total reserved encrypted-container capacity")
	} else {
		name = f.String("name", "", "harness name")
		version = f.String("version", "", "immutable release version")
		artifact = f.String("artifact", "", "approved local guest initrd")
	}
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 {
		return fail("configuration_invalid")
	}
	var digest string
	if artifact != nil {
		file, err := os.OpenFile(*artifact, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fail("artifact_unavailable")
		}
		defer file.Close()
		st, err := file.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return fail("artifact_invalid")
		}
		h := sha256.New()
		if _, err = io.Copy(h, file); err != nil {
			return fail("artifact_unavailable")
		}
		digest = fmt.Sprintf("sha256:%x", h.Sum(nil))
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
	if command == "configure-host" {
		err = s.ConfigureHostStorage(ctx, *host, *storage)
	} else {
		_, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: *name, Version: *version}, digest)
	}
	if err != nil {
		return fail("catalog_configuration_rejected")
	}
	fmt.Fprintln(os.Stdout, "catalog_configuration_complete")
	return 0
}

// ownAuthorities takes the lock of the authority directories an init
// command opens: it refuses with authority_in_use while the authority
// service, or another command, runs on one (docs/adr/006-authority-service.md §1).
func ownAuthorities(dirs ...string) (*authorityservice.Owner, string) {
	owner, err := authorityservice.Own(dirs...)
	switch {
	case errors.Is(err, authorityservice.ErrInUse):
		return nil, "authority_in_use"
	case err != nil:
		return nil, "authority_directory_unavailable"
	}
	return owner, ""
}

func initializeKeyAuthority(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("init-key-authority", flag.ContinueOnError)
	root := f.String("root", "", "private authority directory outside the data restore domain")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *root == "" {
		return fail("configuration_required")
	}
	owner, code := ownAuthorities(*root)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := keyauthority.Initialize(ctx, *root)
	if err != nil {
		return fail("key_authority_initialization_failed")
	}
	// This is a public identity to pin in worker configuration, never a key.
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		AuthorityID string `json:"authority_id"`
	}{s.Identity()}); err != nil {
		return fail("identity_output_failed")
	}
	return 0
}
func main() { os.Exit(run()) }

// databaseURL returns AGENTCAPSULE_DATABASE_URL once it satisfies the mode:
// in production, a Unix socket or verified TLS
// (docs/adr/010-transport-security-and-preflight.md). Otherwise it returns
// the code to print.
func databaseURL() (string, string) {
	mode, err := operatorconfig.ModeFromEnvironment()
	if err != nil {
		return "", "mode_invalid"
	}
	if mode == operatorconfig.Development {
		fmt.Fprintln(os.Stderr, operatorconfig.DevelopmentWarning)
	}
	return operatorconfig.DatabaseURL(mode)
}

func initializeRestoreAuthority(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("init-restore-authority", flag.ContinueOnError)
	root := f.String("root", "", "private independent restore authority directory")
	data := f.String("data-root", "", "runtime data directory excluded from the authority")
	keyRoot := f.String("key-authority-root", "", "existing independent key authority directory")
	keyID := f.String("key-authority-id", "", "pinned public key authority identity")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *root == "" || *data == "" || *keyRoot == "" || *keyID == "" {
		return fail("configuration_required")
	}
	owner, code := ownAuthorities(*root, *keyRoot)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	keys, err := keyauthority.Open(*keyRoot, *keyID)
	if err != nil {
		return fail("key_authority_unavailable")
	}
	if keys.SeparateFrom(*data) != nil || restoreauthority.CheckSeparation(*root, *data) != nil {
		return fail("authority_must_be_outside_restore_domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	catalog, err := restoreauthority.Initialize(ctx, *root, keys.Identity())
	if err != nil {
		return fail("restore_authority_initialization_failed")
	}
	defer catalog.Close()
	// Public configuration only. The catalogue's signing secret is never output.
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		AuthorityID    string `json:"authority_id"`
		KeyAuthorityID string `json:"key_authority_id"`
	}{catalog.Identity(), catalog.KeyAuthorityIdentity()}); err != nil {
		return fail("identity_output_failed")
	}
	return 0
}
