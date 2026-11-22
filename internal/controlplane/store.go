// Package controlplane holds the platform's durable state in PostgreSQL and the
// transactions that change it: organizations, identities and authorization,
// agents and their lifecycle, requests and their delivery, schedules, LLM
// accounting, corpora, audit and the schema migrations. internal/api serves it
// over HTTP, and internal/worker drives the hosts from it. Authentication
// adapters must supply the caller identity from the trusted user/vsock channel,
// never from a caller-controlled request field.
package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/workqueue"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound     = persistence.ErrNotFound
	ErrUnavailable  = errors.New("agent is not accepting new work")
	ErrMandate      = errors.New("mandate unavailable, expired or exhausted")
	ErrTransition   = errors.New("request transition is not permitted")
	ErrConflict     = errors.New("idempotency key reused with a different request")
	ErrExpired      = errors.New("request deadline has elapsed")
	ErrQueueFull    = errors.New("instruction queue is full")
	ErrTooLarge     = errors.New("content exceeds the size limit")
	ErrStorageQuota = errors.New("organization storage quota exceeded")
	// ErrAttachment: a referenced file is unknown, expired, already used, sent
	// for another agent or uploaded by someone else. Nothing was admitted.
	ErrAttachment     = errors.New("attachment is not usable for this invocation")
	ErrCommitUnknown  = errors.New("commit outcome unknown; retry the same idempotency key")
	ErrUnsafeDatabase = errors.New("database durability settings are unsafe")
)

type State string

const (
	PendingApproval State = "PENDING_APPROVAL"
	Delivering      State = "DELIVERING"
)

type Receipt struct {
	RequestID string
	State     State
	Replayed  bool
}

type Store struct {
	workqueue.Queue
	pool *pgxpool.Pool
	// legacyClosed refuses the legacy owner domain's acp_ tokens (D-01).
	legacyClosed atomic.Bool
	// access appends the access revocation records (access_revocations.go);
	// nil without the authority service, in development.
	access atomic.Pointer[accessRecorder]
}

// newStore attaches domain services to the same pool and transaction discipline.
func newStore(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool}
	s.Queue = workqueue.New(pool, s.transact)
	return s
}

func (s *Store) transact(ctx context.Context, run func(pgx.Tx) error) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := run(tx); err != nil {
		return err
	}
	return commit(ctx, tx)
}

//go:embed schema.sql
var schemaSQL string

// Open opens the store with pgx's pool and PostgreSQL's defaults; a process
// opens it with its own bounds (OpenWith, connections.go).
func Open(ctx context.Context, connectionString string) (*Store, error) {
	return OpenWith(ctx, connectionString, Connections{})
}

func (s *Store) Close() { s.pool.Close() }

func rollback(tx pgx.Tx) {
	forgetRecords(tx)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// commit commits tx, then appends the access revocation records it
// inserted to the authority service, with no lock held (access_revocations.go).
func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		forgetRecords(tx)
		return errors.Join(ErrCommitUnknown, err)
	}
	recordCommitted(ctx, tx)
	return nil
}

func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	return s.beginCensus(ctx, false)
}

// The shared gate precedes every application row lock. Store activation takes
// it exclusively, so its current catalogue check cannot race a revocation's
// intent/census commit. Never upgrade a shared transaction or hold it over RPC.
func (s *Store) beginCensus(ctx context.Context, exclusive bool) (pgx.Tx, error) {
	return s.beginWithOptions(ctx, exclusive, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// The preamble (the gate, the request ID, synchronous commit, the durability
// check) is one round trip (connections.go). A caller reopening an existing
// installation must not accidentally use UNLOGGED tables. Missing tables may be
// added by an explicit migration; operations requiring them fail closed until
// that migration has run.
func (s *Store) beginWithOptions(ctx context.Context, exclusive bool, options pgx.TxOptions) (pgx.Tx, error) {
	return s.beginPreamble(ctx, exclusive, options)
}

// durableTables are every table of the control plane: each holds state that
// must survive a crash, so none may be UNLOGGED (or a view). Every
// transaction refuses to start if one is, and a migration fails unless all
// exist as logged tables. TestEveryTableIsDurable checks that a migration
// that creates a table lists it here.
var durableTables = []string{"harness_audit", "harness_imports", "attachment_segments", "attachments", "agent_idle_watch", "queue_limits", "queue_audit", "llm_budgets", "llm_usage", "llm_providers", "llm_model_aliases", "llm_audit", "service_tokens", "tenant_service_audit", "agent_assignments", "tenant_agent_audit", "placement_control_contracts", "tenant_team_audit", "tenant_http_receipts", "tenant_member_audit", "schema_migrations", "delegation_issuers", "delegation_trusts", "delegation_revocations", "delegation_admin_receipts", "delegation_audit", "platform_credentials", "organization_audit", "organizations", "principals", "memberships", "teams", "team_memberships", "users", "api_tokens", "http_receipts", "api_receipt_key", "harness_releases", "agent_specs", "platform_operations", "store_enrollments", "store_initializations", "revocation_catalogue", "store_enrollment_receipts", "agents", "agent_placements", "placement_renewals", "worker_hosts", "worker_jobs", "mandates", "agent_requests", "idempotency_keys", "agent_mailboxes", "outbox", "inbox_items", "deletion_operations", "deletion_targets", "request_closure_targets", "request_closures", "store_seals", "store_removals", "transit_keys", "transit_configuration", "transit_payloads", "transit_parties", "owner_instructions", "owner_messages", "peer_wakes", "volume_archives", "volume_restores", "volume_restore_losses", "invocation_reruns", "llm_alias_grants", "delegation_keys", "platform_audit", "capacity_waits", "instruction_replays", "access_revocations",
	"peer_redeliveries", "system_images", "deployment_hosts", "host_system_images", "agent_template_revisions", "agent_volume_growth", "deployment_audit", "agent_rollouts", "agent_rollout_steps", "agent_deployments", "agent_deployment_members", "agent_pools", "agent_pool_members", "host_takeovers", "volume_relocations", "agent_directory", "guest_failures", "failed_agents",
	"applications", "app_policies", "app_activations", "app_invitations", "app_personal_reservations", "application_audit", "application_clients",
	"organization_capability_policies", "agent_capability_policies", "capability_audit", "operator_audit", "audit_retention",
	"authority_reconciliations", "tenant_refusal_audit", "trace_pseudonym_key", "organization_quotas",
	"source_credentials", "corpus_audit", "corpora", "corpus_builds", "corpus_releases",
	"agent_corpora", "corpus_review_files", "corpus_review_segments", "corpus_extensions", "corpus_enrichers",
	"invocation_streams", "invocation_stream_chunks", "agent_activity", "llm_budget_windows"}

// Migrate is explicit; opening a store never changes an existing schema.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, controlPlaneMigrations)
}

type agent struct {
	ID, Owner, Phase, Mode, Kind string
	// Tenant is empty for historical owner-domain agents.
	Tenant  string
	Visible bool
}

// Every multi-agent mutation takes the same sorted row-lock order. Agent IDs and
// request participants are immutable. NO KEY UPDATE excludes other phase/budget
// mutations while allowing FK KEY SHARE checks: concurrent deletion manifests
// must not deadlock by referencing each other's already-locked agent rows.
func lockAgents(ctx context.Context, tx pgx.Tx, ids ...string) (map[string]agent, error) {
	rows, err := tx.Query(ctx, `SELECT id, coalesce(owner_user_id,''), phase, inbound_mode, discoverable, coalesce(tenant_id,''), kind
        FROM agents WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := make(map[string]agent)
	for rows.Next() {
		var a agent
		if err := rows.Scan(&a.ID, &a.Owner, &a.Phase, &a.Mode, &a.Visible, &a.Tenant, &a.Kind); err != nil {
			return nil, err
		}
		agents[a.ID] = a
	}
	return agents, rows.Err()
}

func newID(prefix string) string { return persistence.ID(prefix) }

func requestHash(v any) ([32]byte, error) {
	b, err := json.Marshal(v)
	return sha256.Sum256(b), err
}

// The response FK is deferred until COMMIT. Thus a claimed key can never remain
// committed without its request. Conflicting INSERTs wait for their predecessor;
// the following SELECT gets a new READ COMMITTED snapshot, including its result.
func claim(ctx context.Context, tx pgx.Tx, actor, operation, key string, hash [32]byte, proposed Receipt) (Receipt, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO idempotency_keys
        (actor,operation,key,request_hash,response_ref,response_state) VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (actor,operation,key) DO NOTHING`, actor, operation, key, hash[:], proposed.RequestID, proposed.State)
	if err != nil {
		return Receipt{}, err
	}
	if tag.RowsAffected() == 1 {
		return proposed, nil
	}
	var storedHash []byte
	var receipt Receipt
	if err = tx.QueryRow(ctx, `SELECT request_hash,response_ref,response_state FROM idempotency_keys
        WHERE actor=$1 AND operation=$2 AND key=$3`, actor, operation, key).Scan(&storedHash, &receipt.RequestID, &receipt.State); err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(storedHash, hash[:]) {
		return Receipt{}, ErrConflict
	}
	receipt.Replayed = true
	return receipt, nil
}

func enqueueRequest(ctx context.Context, tx pgx.Tx, id, recipient string, deadline time.Time) error {
	var seq int64
	if err := tx.QueryRow(ctx, "UPDATE agents SET next_seq=next_seq+1 WHERE id=$1 RETURNING next_seq", recipient).Scan(&seq); err != nil {
		return err
	}
	mailboxID := newID("mbx")
	if _, err := tx.Exec(ctx, `INSERT INTO agent_mailboxes(id,dest_agent_id,seq,kind,ref_id,expires_at)
        VALUES ($1,$2,$3,'request',$4,$5)`, mailboxID, recipient, seq, id, deadline); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "INSERT INTO outbox(id,mailbox_id) VALUES ($1,$2)", newID("out"), mailboxID)
	return err
}

// requireIdentity rejects missing authenticated identities.
// It does not authenticate a token or a vsock peer itself.
func requireIdentity(identity, key string) error {
	if identity == "" || key == "" {
		return fmt.Errorf("authenticated identity and idempotency key are required")
	}
	return nil
}
