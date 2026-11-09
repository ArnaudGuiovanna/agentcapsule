package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrMigrationHistory refuses an unknown, modified or incomplete migration
// history. Retrying with the correct binary is safe; deleting history is not a
// repair procedure. Database owners remain trusted to preserve this metadata.
var ErrMigrationHistory = errors.New("database migration history does not match this binary")

type schemaMigration struct {
	version int64
	name    string
	sql     string
}

//go:embed migrations/0002_organization_identity.sql
var organizationIdentitySQL string

//go:embed migrations/0003_platform_organizations.sql
var platformOrganizationsSQL string

//go:embed migrations/0004_delegated_identity.sql
var delegatedIdentitySQL string

//go:embed migrations/0005_tenant_members.sql
var tenantMembersSQL string

//go:embed migrations/0006_tenant_teams.sql
var tenantTeamsSQL string

//go:embed migrations/0007_placement_control_contract.sql
var placementControlContractSQL string

//go:embed migrations/0008_token_issuer.sql
var tokenIssuerSQL string

//go:embed migrations/0009_receipt_expiry_index.sql
var receiptExpiryIndexSQL string

//go:embed migrations/0010_tenant_agents.sql
var tenantAgentsSQL string

//go:embed migrations/0011_service_accounts.sql
var serviceAccountsSQL string

//go:embed migrations/0012_llm_providers.sql
var llmProvidersSQL string

//go:embed migrations/0013_llm_budgets.sql
var llmBudgetsSQL string

//go:embed migrations/0014_instruction_queues.sql
var instructionQueuesSQL string

//go:embed migrations/0015_lifecycle_audit.sql
var lifecycleAuditSQL string

//go:embed migrations/0016_scheduling.sql
var schedulingSQL string

//go:embed migrations/0017_attachments.sql
var attachmentsSQL string

//go:embed migrations/0018_async_completion.sql
var asyncCompletionSQL string

//go:embed migrations/0019_harness_registry.sql
var harnessRegistrySQL string

//go:embed migrations/0020_registry_access_denied.sql
var registryAccessDeniedSQL string

//go:embed migrations/0021_agent_release_change.sql
var agentReleaseChangeSQL string

//go:embed migrations/0022_release_signatures.sql
var releaseSignaturesSQL string

// Append migrations; never edit an installed migration. The original schema
// also upgrades pre-ledger installations, preserving its historical backfills.
// Later calls validate its checksum without replaying DDL or those backfills.
var controlPlaneMigrations = []schemaMigration{
	{version: 1, name: "control-plane-baseline", sql: schemaSQL},
	{version: 2, name: "organization-identity", sql: organizationIdentitySQL},
	{version: 3, name: "platform-organizations", sql: platformOrganizationsSQL},
	{version: 4, name: "delegated-identity", sql: delegatedIdentitySQL},
	{version: 5, name: "tenant-members", sql: tenantMembersSQL},
	{version: 6, name: "tenant-teams", sql: tenantTeamsSQL},
	{version: 7, name: "placement-control-contract", sql: placementControlContractSQL},
	{version: 8, name: "token-issuer", sql: tokenIssuerSQL},
	{version: 9, name: "receipt-expiry-index", sql: receiptExpiryIndexSQL},
	{version: 10, name: "tenant-agents", sql: tenantAgentsSQL},
	{version: 11, name: "service-accounts", sql: serviceAccountsSQL},
	{version: 12, name: "llm-providers", sql: llmProvidersSQL},
	{version: 13, name: "llm-budgets", sql: llmBudgetsSQL},
	{version: 14, name: "instruction-queues", sql: instructionQueuesSQL},
	{version: 15, name: "lifecycle-audit", sql: lifecycleAuditSQL},
	{version: 16, name: "scheduling", sql: schedulingSQL},
	{version: 17, name: "attachments", sql: attachmentsSQL},
	{version: 18, name: "async-completion", sql: asyncCompletionSQL},
	{version: 19, name: "harness-registry", sql: harnessRegistrySQL},
	{version: 20, name: "registry-access-denied", sql: registryAccessDeniedSQL},
	{version: 21, name: "agent-release-change", sql: agentReleaseChangeSQL},
	{version: 22, name: "release-signatures", sql: releaseSignaturesSQL},
}

func (s *Store) migrate(ctx context.Context, migrations []schemaMigration) error {
	if len(migrations) == 0 {
		return ErrMigrationHistory
	}
	for i, m := range migrations {
		if m.version != int64(i+1) || m.name == "" || m.sql == "" {
			return ErrMigrationHistory
		}
	}
	tx, err := s.beginCensus(ctx, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610042)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version bigint PRIMARY KEY CHECK (version > 0),
        name text NOT NULL CHECK (name <> ''),
        checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return err
	}
	applied := 0
	for rows.Next() {
		var version int64
		var name string
		var checksum []byte
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return err
		}
		if applied >= len(migrations) || version != int64(applied+1) {
			rows.Close()
			return ErrMigrationHistory
		}
		m := migrations[applied]
		want := sha256.Sum256([]byte(m.sql))
		if name != m.name || !bytes.Equal(checksum, want[:]) {
			rows.Close()
			return fmt.Errorf("%w: version %d", ErrMigrationHistory, version)
		}
		applied++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, m := range migrations[applied:] {
		if _, err = tx.Exec(ctx, m.sql); err != nil {
			return fmt.Errorf("apply schema migration %d: %w", m.version, err)
		}
		checksum := sha256.Sum256([]byte(m.sql))
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum)
            VALUES($1,$2,$3)`, m.version, m.name, checksum[:]); err != nil {
			return err
		}
	}
	var count int
	var durable bool
	if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_and(relpersistence='p' AND relkind='r'),false)
        FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY($1)`,
		durableTables).Scan(&count, &durable); err != nil {
		return err
	}
	if count != len(durableTables) || !durable {
		return ErrUnsafeDatabase
	}
	return commit(ctx, tx)
}

// checkMigrationLedger is the read-only counterpart of migrate. The API never
// migrates, so readiness must fail when the installed ledger is behind, ahead of
// or different from the migrations compiled into this binary.
func checkMigrationLedger(ctx context.Context, tx pgx.Tx, migrations []schemaMigration) error {
	rows, err := tx.Query(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return err
	}
	defer rows.Close()
	applied := 0
	for rows.Next() {
		var version int64
		var name string
		var checksum []byte
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			return err
		}
		if applied >= len(migrations) || version != int64(applied+1) {
			return fmt.Errorf("%w: unexpected installed version %d", ErrMigrationHistory, version)
		}
		want := sha256.Sum256([]byte(migrations[applied].sql))
		if name != migrations[applied].name || !bytes.Equal(checksum, want[:]) {
			return fmt.Errorf("%w: version %d differs from this binary", ErrMigrationHistory, version)
		}
		applied++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if applied != len(migrations) {
		return fmt.Errorf("%w: schema at version %d, binary requires %d", ErrMigrationHistory, applied, len(migrations))
	}
	return nil
}
