package controlplane

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Diagnostics is the database's part of an operator's diagnostic export
// (API-02, ADR 014). It is aggregated on purpose: counts by kind, state and
// error code, never an organization, member, agent, request or token, and no
// content. Host IDs and migration names are the operator's own.
type Diagnostics struct {
	PostgreSQL string `json:"postgresql_version"`
	// Migrations are the applied migrations; ExpectedMigration is the last one
	// this binary knows.
	Migrations        []AppliedMigration `json:"migrations"`
	ExpectedMigration int                `json:"expected_migration"`
	Hosts             []HostDiagnostics  `json:"hosts"`
	AgentsByPhase     map[string]int64   `json:"agents_by_phase"`
	// Deliveries counts the mailboxes by kind and delivery state; DEAD ones are
	// the dead letters.
	Deliveries []CountBy `json:"deliveries"`
	Imports    []CountBy `json:"harness_imports"`
	// FailedOperations counts the provisioning and lifecycle operations that
	// failed in the last 7 days, by kind and error code: boots among them.
	FailedOperations []CountBy `json:"failed_operations_7d"`
	// AuditRetentionDays is the audit retention; absent when every event is kept.
	AuditRetentionDays *int `json:"audit_retention_days,omitempty"`
}

type AppliedMigration struct {
	Version   int64     `json:"version"`
	Name      string    `json:"name"`
	AppliedAt time.Time `json:"applied_at"`
}

// HostDiagnostics is one worker host: its queue, its VMs, its storage
// reservation and the storage pressure its worker last recorded.
type HostDiagnostics struct {
	HostID string `json:"host_id"`
	HostStatistics
}

type HostStatistics struct {
	Queue              []QueueByKind    `json:"queue"`
	RunningVMs         int64            `json:"running_vms"`
	UncleanStops       int64            `json:"unclean_stops"`
	StorageLimitMiB    int64            `json:"storage_limit_mib"`
	StorageReservedMiB int64            `json:"storage_reserved_mib"`
	DataPressure       bool             `json:"data_pressure"`
	ImagePressure      bool             `json:"image_pressure"`
	PressureObservedAt *time.Time       `json:"pressure_observed_at,omitempty"`
	JobFailures        map[string]int64 `json:"job_failures_by_kind"`
}

// QueueByKind is WorkKindStats with the oldest wait in seconds.
type QueueByKind struct {
	Kind             string  `json:"kind"`
	Jobs             int64   `json:"jobs"`
	Due              int64   `json:"due"`
	Failing          int64   `json:"failing"`
	OldestDueSeconds float64 `json:"oldest_due_seconds"`
}

// CountBy is a count for a kind, a state and an error code.
type CountBy struct {
	Kind  string     `json:"kind,omitempty"`
	State string     `json:"state,omitempty"`
	Code  string     `json:"code,omitempty"`
	Count int64      `json:"count"`
	Last  *time.Time `json:"last,omitempty"`
}

// Diagnostics reads the database's state for an operator's diagnostic export.
func (s *Store) Diagnostics(ctx context.Context) (Diagnostics, error) {
	return s.diagnostics(ctx, nil)
}

func (s *Store) PlatformDiagnostics(ctx context.Context, p Principal) (Diagnostics, error) {
	return s.diagnostics(ctx, &p)
}

func (s *Store) diagnostics(ctx context.Context, p *Principal) (Diagnostics, error) {
	d := Diagnostics{ExpectedMigration: len(controlPlaneMigrations), Migrations: []AppliedMigration{}, Hosts: []HostDiagnostics{},
		AgentsByPhase: map[string]int64{}, Deliveries: []CountBy{}, Imports: []CountBy{}, FailedOperations: []CountBy{}}
	tx, err := s.begin(ctx)
	if err != nil {
		return d, err
	}
	defer rollback(tx)
	if p != nil {
		if err = authorizePlatform(ctx, tx, *p); err != nil {
			return d, err
		}
	}
	if err = tx.QueryRow(ctx, "SHOW server_version").Scan(&d.PostgreSQL); err != nil {
		return d, err
	}
	rows, err := tx.Query(ctx, "SELECT version,name,applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var m AppliedMigration
		if err = rows.Scan(&m.Version, &m.Name, &m.AppliedAt); err != nil {
			rows.Close()
			return d, err
		}
		d.Migrations = append(d.Migrations, m)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return d, err
	}
	rows, err = tx.Query(ctx, `SELECT h.host_id,h.storage_limit_mib,h.data_pressure,h.image_pressure,h.pressure_observed_at,
        (SELECT coalesce(sum(x.volume_mib+x.reserved_growth_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=h.host_id AND a.phase<>'DELETED'),
        (SELECT count(*) FROM agent_placements p WHERE p.host_id=h.host_id AND p.state='RUNNING'),
        (SELECT count(*) FROM agent_placements p WHERE p.host_id=h.host_id AND p.unclean_stop)
        FROM worker_hosts h ORDER BY h.host_id`)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		h := HostDiagnostics{HostStatistics: HostStatistics{Queue: []QueueByKind{}, JobFailures: map[string]int64{}}}
		if err = rows.Scan(&h.HostID, &h.StorageLimitMiB, &h.DataPressure, &h.ImagePressure, &h.PressureObservedAt,
			&h.StorageReservedMiB, &h.RunningVMs, &h.UncleanStops); err != nil {
			rows.Close()
			return d, err
		}
		d.Hosts = append(d.Hosts, h)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return d, err
	}
	for i := range d.Hosts {
		h := &d.Hosts[i]
		rows, err = tx.Query(ctx, `SELECT kind,count(*),
            count(*) FILTER (WHERE lease_token='' AND available_at<=clock_timestamp()),
            count(*) FILTER (WHERE failures>=3),
            coalesce(extract(epoch FROM clock_timestamp()-min(available_at) FILTER (WHERE lease_token='' AND available_at<=clock_timestamp())),0),
            coalesce(sum(failures),0)
            FROM worker_jobs WHERE host_id=$1 GROUP BY kind ORDER BY kind`, h.HostID)
		if err != nil {
			return d, err
		}
		for rows.Next() {
			var q QueueByKind
			var failures int64
			if err = rows.Scan(&q.Kind, &q.Jobs, &q.Due, &q.Failing, &q.OldestDueSeconds, &failures); err != nil {
				rows.Close()
				return d, err
			}
			h.Queue = append(h.Queue, q)
			h.JobFailures[q.Kind] = failures
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return d, err
		}
	}
	if err = countInto(ctx, tx, "SELECT phase,'','',count(*),NULL::timestamptz FROM agents GROUP BY phase", func(c CountBy) {
		d.AgentsByPhase[c.Kind] = c.Count
	}); err != nil {
		return d, err
	}
	for _, q := range []struct {
		sql  string
		into *[]CountBy
	}{
		{"SELECT kind,delivery_state,'',count(*),NULL::timestamptz FROM agent_mailboxes GROUP BY kind,delivery_state ORDER BY kind,delivery_state", &d.Deliveries},
		{"SELECT '',status,error_code,count(*),max(coalesce(completed_at,created_at)) FROM harness_imports GROUP BY status,error_code ORDER BY status,error_code", &d.Imports},
		{`SELECT kind,status,error_code,count(*),max(coalesce(completed_at,created_at)) FROM platform_operations
            WHERE status='FAILED' AND created_at>clock_timestamp()-interval '7 days' GROUP BY kind,status,error_code ORDER BY kind,error_code`, &d.FailedOperations},
	} {
		if err = countInto(ctx, tx, q.sql, func(c CountBy) { *q.into = append(*q.into, c) }); err != nil {
			return d, err
		}
	}
	if err = tx.QueryRow(ctx, "SELECT (SELECT retention_days FROM audit_retention)").Scan(&d.AuditRetentionDays); err != nil {
		return d, err
	}
	return d, commit(ctx, tx)
}

func countInto(ctx context.Context, tx pgx.Tx, sql string, add func(CountBy)) error {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c CountBy
		if err = rows.Scan(&c.Kind, &c.State, &c.Code, &c.Count, &c.Last); err != nil {
			return err
		}
		add(c)
	}
	return rows.Err()
}
