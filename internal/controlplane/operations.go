package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrStoragePressure: a file system of the host is past its storage pressure
// threshold (OPS-03, ADR 014). New agents, which need a volume, and harness
// imports, which need an image, are refused until space returns. Agents that
// exist keep running.
var ErrStoragePressure = errors.New("host storage past its pressure threshold")

// RecordStoragePressure is the worker's observation of its host: whether the
// file system of its volumes (data) and the one of its harness images are
// past the threshold. The API reads it before reserving anything.
func (s *Store) RecordStoragePressure(ctx context.Context, host string, data, images bool) error {
	if !catalogName(host) {
		return ErrInput
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO worker_hosts(host_id,data_pressure,image_pressure,pressure_observed_at)
        VALUES($1,$2,$3,clock_timestamp())
        ON CONFLICT (host_id) DO UPDATE SET data_pressure=$2,image_pressure=$3,pressure_observed_at=clock_timestamp()`, host, data, images)
	return err
}

// refuseUnderDataPressure refuses a new volume on a host whose data file
// system is past the threshold.
func refuseUnderDataPressure(ctx context.Context, tx pgx.Tx, host string) error {
	var pressure bool
	err := tx.QueryRow(ctx, "SELECT data_pressure FROM worker_hosts WHERE host_id=$1", host).Scan(&pressure)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err == nil && pressure {
		return ErrStoragePressure
	}
	return err
}

// refuseUnderImagePressure refuses an import while a host's image file system
// is past the threshold: any host may be the one that downloads it.
func refuseUnderImagePressure(ctx context.Context, tx pgx.Tx) error {
	var pressure bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM worker_hosts WHERE image_pressure)").Scan(&pressure); err != nil {
		return err
	}
	if pressure {
		return ErrStoragePressure
	}
	return nil
}

// OperatorCommand is who runs a destructive operator command, and whether it
// is a dry run (API-02, ADR 014). A dry run checks everything, changes
// nothing and records nothing.
type OperatorCommand struct {
	// Actor is the local identity running the command, local-uid:<n>.
	Actor  string
	DryRun bool
}

// OperatorOutcome is what a destructive operator command did, or would do in
// a dry run: done, unchanged (already in that state) or refused, with the
// refusal's reason.
type OperatorOutcome struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	DryRun  bool   `json:"dry_run"`
	// Events is, for an audit retention, how many events it would delete now.
	Events *int64 `json:"events,omitempty"`
}

// RefusalReason names an error decided by the database state or the input:
// repeating the same command cannot change it, unlike a failure whose commit
// result is unknown.
func RefusalReason(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrInput):
		return "invalid_input", true
	case errors.Is(err, ErrForbidden):
		return "forbidden", true
	case errors.Is(err, ErrNotFound):
		return "not_found", true
	case errors.Is(err, ErrConflict), errors.Is(err, ErrTransition):
		return "conflict", true
	case errors.Is(err, ErrHostLost):
		return "host_lost", true
	}
	return "", false
}

func validActor(actor string) bool {
	return actor != "" && len(actor) <= 100 && !strings.ContainsAny(actor, "\x00\n\r")
}

// operatorCommand runs apply in one transaction and audits its outcome in the
// same one. A definite refusal is audited in its own transaction: the
// refused change rolled back. A dry run rolls back and audits nothing.
func (s *Store) operatorCommand(ctx context.Context, cmd OperatorCommand, action, target string, apply func(pgx.Tx) (bool, error)) (OperatorOutcome, error) {
	out := OperatorOutcome{Action: action, Target: target, DryRun: cmd.DryRun}
	if !validActor(cmd.Actor) || len(target) > 100 {
		return out, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	changed, err := apply(tx)
	if err != nil {
		reason, definite := RefusalReason(err)
		if !definite {
			return out, err
		}
		out.Outcome, out.Reason = "refused", reason
		rollback(tx)
		if !cmd.DryRun {
			if _, auditErr := s.pool.Exec(ctx, `INSERT INTO operator_audit(id,actor,action,target,outcome,reason) VALUES($1,$2,$3,$4,'refused',$5)`,
				newID("opa"), cmd.Actor, action, target, reason); auditErr != nil {
				return out, errors.Join(err, auditErr)
			}
		}
		return out, err
	}
	out.Outcome = "unchanged"
	if changed {
		out.Outcome = "done"
	}
	if cmd.DryRun {
		return out, nil
	}
	if _, err = tx.Exec(ctx, `INSERT INTO operator_audit(id,actor,action,target,outcome) VALUES($1,$2,$3,$4,$5)`,
		newID("opa"), cmd.Actor, action, target, out.Outcome); err != nil {
		return out, err
	}
	return out, commit(ctx, tx)
}

// auditTables hold the audit trail: the tenants' events, the platform's, the
// operator's, and the replays of dead letters (ADR 017). The retention
// applies to all of them, by the time each recorded its event (at), which an
// index of the table starts with.
var auditTables = []struct{ table, at string }{{"organization_audit", "created_at"}, {"delegation_audit", "created_at"},
	{"tenant_member_audit", "created_at"}, {"tenant_team_audit", "created_at"}, {"tenant_agent_audit", "created_at"},
	{"tenant_service_audit", "created_at"}, {"llm_audit", "created_at"}, {"queue_audit", "created_at"}, {"harness_audit", "created_at"},
	{"platform_audit", "created_at"}, {"operator_audit", "created_at"}, {"capability_audit", "created_at"},
	{"instruction_replays", "replayed_at"}}

// AuditRetention returns the audit retention in days, or nil when every event
// is kept (the default, ADR 014).
func (s *Store) AuditRetention(ctx context.Context) (*int, error) {
	var days *int
	err := s.pool.QueryRow(ctx, "SELECT retention_days FROM audit_retention").Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return days, err
}

// SetAuditRetention sets how long audit events are kept, from 30 to 36500
// days, or, with nil, keeps every event. Once set, the worker deletes the
// older events (PurgeAudit). The outcome counts the events the retention
// would delete now.
func (s *Store) SetAuditRetention(ctx context.Context, cmd OperatorCommand, days *int) (OperatorOutcome, error) {
	target := "keep_all"
	if days != nil {
		target = fmt.Sprintf("%d_days", *days)
	}
	var events int64
	out, err := s.operatorCommand(ctx, cmd, "audit.retention_set", target, func(tx pgx.Tx) (bool, error) {
		if days != nil && (*days < 30 || *days > 36500) {
			return false, ErrInput
		}
		var current *int
		err := tx.QueryRow(ctx, "SELECT retention_days FROM audit_retention FOR UPDATE").Scan(&current)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		if days != nil {
			for _, a := range auditTables {
				var n int64
				if err = tx.QueryRow(ctx, "SELECT count(*) FROM "+a.table+" WHERE "+a.at+" < clock_timestamp()-make_interval(days => $1)", *days).Scan(&n); err != nil {
					return false, err
				}
				events += n
			}
		}
		if (current == nil) == (days == nil) && (days == nil || *current == *days) {
			return false, nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_retention(singleton,retention_days) VALUES(true,$1)
            ON CONFLICT (singleton) DO UPDATE SET retention_days=$1,changed_at=clock_timestamp()`, days)
		return err == nil, err
	})
	if err == nil && days != nil {
		out.Events = &events
	}
	return out, err
}

// PurgeAudit deletes, in bounded batches per table, the audit events older
// than the retention, and records the purge. Without a retention it deletes
// nothing. It returns how many events it deleted.
func (s *Store) PurgeAudit(ctx context.Context, batch int) (int64, error) {
	if batch < 1 || batch > 10000 {
		return 0, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	var days *int
	err = tx.QueryRow(ctx, "SELECT retention_days FROM audit_retention FOR SHARE").Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && days == nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, a := range auditTables {
		tag, err := tx.Exec(ctx, "DELETE FROM "+a.table+" WHERE ctid = ANY(ARRAY(SELECT ctid FROM "+a.table+
			" WHERE "+a.at+" < clock_timestamp()-make_interval(days => $1) LIMIT $2))", *days, batch)
		if err != nil {
			return 0, err
		}
		total += tag.RowsAffected()
	}
	if total == 0 {
		return 0, nil
	}
	if _, err = tx.Exec(ctx, `INSERT INTO operator_audit(id,actor,action,target,outcome) VALUES($1,'worker','audit.purged',$2,'done')`,
		newID("opa"), fmt.Sprintf("%d_events", total)); err != nil {
		return 0, err
	}
	return total, commit(ctx, tx)
}
