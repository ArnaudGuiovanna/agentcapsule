package controlplane

import (
	"context"
	"time"
)

// The retention of finished model calls (v0.1.0 audit, P-04 and P-05,
// migration model-call-retention). llm_usage kept every call forever. Since
// the budgets count their windows (llm_budget_windows), nothing reads a
// finished call once its month is over, but:
//   - the organization's usage report, which reads the calls of the current
//     UTC day or month: the retention is at least MinModelCallRetention,
//     longer than any month;
//   - a call in flight or of unknown outcome, which counts in its windows
//     until it is settled or released, and which the organization
//     reconciles: only a settled or released call goes;
//   - an audit event that names the call (an organization's resolution,
//     llm_audit): the call goes once the audit's own retention removed it
//     (ADR 014);
//   - a corpus build in progress, whose costs sum its builder's calls since
//     it started: the calls of a builder agent go once its build is in
//     review or ended.
// Each agent's last activity is kept apart (agent_activity) and survives the
// deletion. A request key is idempotent for as long as its call is kept. The
// windows of the budgets that started before the retention go with the calls:
// nothing reads them.

// Model call retention bounds and default (docs/worker.md).
const (
	MinModelCallRetention     = 35 * 24 * time.Hour
	MaxModelCallRetention     = 3650 * 24 * time.Hour
	DefaultModelCallRetention = 90 * 24 * time.Hour
)

// finishedModelCalls selects at most $3 settled or released calls created
// before $1 minus the retention ($2 microseconds) that nothing needs any
// more (see above), oldest first.
const finishedModelCalls = `SELECT u.id FROM llm_usage u
    WHERE u.state IN ('settled','released') AND u.created_at < ` + dbNow + `-$2::bigint*interval '1 microsecond'
      AND NOT EXISTS(SELECT 1 FROM llm_audit a WHERE a.usage_id=u.id)
      AND NOT EXISTS(SELECT 1 FROM corpus_builds b WHERE b.tenant_id=u.tenant_id AND b.builder_agent_id=u.agent_id
          AND b.state IN ('QUEUED','FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING'))
    ORDER BY u.created_at LIMIT $3 FOR UPDATE OF u SKIP LOCKED`

// ModelCallPurge counts what one purge deleted.
type ModelCallPurge struct {
	Calls, Windows int64
}

// PurgeModelCalls deletes, across the installation, at most limit finished
// model calls created more than retention ago that nothing needs any more,
// and at most limit budget windows that started before then, in one
// transaction. now is the database clock when nil.
func (s *Store) PurgeModelCalls(ctx context.Context, now *time.Time, retention time.Duration, limit int) (ModelCallPurge, error) {
	var out ModelCallPurge
	if limit < 1 || limit > 1000 || retention < MinModelCallRetention || retention > MaxModelCallRetention {
		return out, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	args := []any{nowArg(now), retention.Microseconds(), limit}
	tag, err := tx.Exec(ctx, `DELETE FROM llm_usage WHERE id IN (`+finishedModelCalls+`)`, args...)
	if err != nil {
		return out, err
	}
	out.Calls = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `DELETE FROM llm_budget_windows WHERE (budget_id,window_start) IN (
        SELECT budget_id,window_start FROM llm_budget_windows WHERE window_start < `+dbNow+`-$2::bigint*interval '1 microsecond'
         ORDER BY window_start LIMIT $3 FOR UPDATE SKIP LOCKED)`, args...)
	if err != nil {
		return out, err
	}
	out.Windows = tag.RowsAffected()
	return out, commit(ctx, tx)
}
