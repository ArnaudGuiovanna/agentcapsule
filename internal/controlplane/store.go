// Package controlplane implements transactional request admission and consent.
// Authentication adapters must supply the caller identity from the trusted
// user/vsock channel, never from a caller-controlled request field. This package
// does not yet implement the complete lifecycle, delivery scheduler or HTTP API.
package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound     = errors.New("resource not found")
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

type Store struct{ pool *pgxpool.Pool }

//go:embed schema.sql
var schemaSQL string

func Open(ctx context.Context, connectionString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	tx, err := s.begin(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	rollback(tx)
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(ErrCommitUnknown, err)
	}
	return nil
}

func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	return s.beginCensus(ctx, false)
}

// The shared gate precedes every application row lock. Store activation takes
// it exclusively, so its current catalogue check cannot race a revocation's
// intent/census commit. Never upgrade a shared transaction or hold it over RPC.
func (s *Store) beginCensus(ctx context.Context, exclusive bool) (pgx.Tx, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	lock := "pg_advisory_xact_lock_shared"
	if exclusive {
		lock = "pg_advisory_xact_lock"
	}
	if _, err = tx.Exec(ctx, "SELECT "+lock+"(hashtextextended(current_schema()::text,756610045))"); err != nil {
		rollback(tx)
		return nil, err
	}
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit = on"); err == nil {
		var safe bool
		err = tx.QueryRow(ctx, `SELECT current_setting('fsync') = 'on'
            AND current_setting('full_page_writes') = 'on'`).Scan(&safe)
		if err == nil && !safe {
			err = ErrUnsafeDatabase
		}
	}
	if err == nil {
		// A caller reopening an existing installation must not accidentally use
		// UNLOGGED tables. Missing tables may be added by an explicit migration;
		// operations requiring them fail closed until that migration has run.
		var count int
		var durable bool
		err = tx.QueryRow(ctx, `SELECT count(*), coalesce(bool_and(relpersistence='p'),true)
            FROM pg_class WHERE relnamespace=current_schema()::regnamespace
            AND relname=ANY($1)`, durableTables).Scan(&count, &durable)
		if err == nil && !durable {
			err = ErrUnsafeDatabase
		}
	}
	if err != nil {
		rollback(tx)
		return nil, err
	}
	return tx, nil
}

var durableTables = []string{"attachment_segments", "attachments", "agent_idle_watch", "queue_limits", "queue_audit", "llm_budgets", "llm_usage", "llm_providers", "llm_model_aliases", "llm_audit", "service_tokens", "tenant_service_audit", "agent_assignments", "tenant_agent_audit", "placement_control_contracts", "tenant_team_audit", "tenant_http_receipts", "tenant_member_audit", "schema_migrations", "delegation_issuers", "delegation_trusts", "delegation_revocations", "delegation_admin_receipts", "delegation_audit", "platform_credentials", "organization_audit", "organizations", "principals", "memberships", "teams", "team_memberships", "users", "api_tokens", "http_receipts", "api_receipt_key", "harness_releases", "agent_specs", "platform_operations", "store_enrollments", "store_initializations", "revocation_catalogue", "store_enrollment_receipts", "agents", "agent_placements", "placement_renewals", "worker_hosts", "worker_jobs", "mandates", "agent_requests", "idempotency_keys", "agent_mailboxes", "outbox", "inbox_items", "deletion_operations", "deletion_targets", "request_closure_targets", "request_closures", "store_seals", "store_removals", "transit_keys", "transit_configuration", "transit_payloads", "transit_parties", "owner_instructions", "owner_messages"}

// Migrate is explicit; opening a store never changes an existing schema.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, controlPlaneMigrations)
}

type agent struct {
	ID, Owner, Phase, Mode string
	// Tenant is empty for historical owner-domain agents.
	Tenant  string
	Visible bool
}

// Every multi-agent mutation takes the same sorted row-lock order. Agent IDs and
// request participants are immutable. NO KEY UPDATE excludes other phase/budget
// mutations while allowing FK KEY SHARE checks: concurrent deletion manifests
// must not deadlock by referencing each other's already-locked agent rows.
func lockAgents(ctx context.Context, tx pgx.Tx, ids ...string) (map[string]agent, error) {
	rows, err := tx.Query(ctx, `SELECT id, coalesce(owner_user_id,''), phase, inbound_mode, discoverable, coalesce(tenant_id,'')
        FROM agents WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := make(map[string]agent)
	for rows.Next() {
		var a agent
		if err := rows.Scan(&a.ID, &a.Owner, &a.Phase, &a.Mode, &a.Visible, &a.Tenant); err != nil {
			return nil, err
		}
		agents[a.ID] = a
	}
	return agents, rows.Err()
}

func newID(prefix string) string {
	var id [16]byte
	_, _ = rand.Read(id[:]) // crypto/rand.Read is guaranteed to fill or terminate on Go 1.25+.
	return prefix + "_" + hex.EncodeToString(id[:])
}

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
