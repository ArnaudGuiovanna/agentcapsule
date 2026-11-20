package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"github.com/jackc/pgx/v5"
)

// CorpusWork is one leased phase, pinned to a host because its staging disks
// live there. Each successful claim creates a new, single-use token.
type CorpusWork struct {
	ID, Tenant, Corpus, Name, Phase, Host, Token, Builder string
	Source                                                repository.Source
	Path, Ref, Commit, CredentialID                       string
	Attempt                                               int
	SourceDrive, LFSDrive, Pointers                       json.RawMessage
	Cursor, AgentID, InvocationID                         string
	Deadline, PhaseStarted                                time.Time
}

func (s *Store) ClaimCorpusWork(ctx context.Context, host, worker, builder string, fetch bool, lease time.Duration) (CorpusWork, error) {
	var j CorpusWork
	if !validOrganizationText(host, 100) || !validOrganizationText(worker, 160) || len(builder) > 255 || lease < time.Second || lease > 24*time.Hour {
		return j, ErrInput
	}
	phases := []string{"SCANNING", "CONVERTING", "PACKAGING"}
	if fetch {
		phases = []string{"QUEUED", "FETCHING", "FETCHING_LFS"}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return j, err
	}
	defer rollback(tx)
	var kind, url string
	err = tx.QueryRow(ctx, `SELECT b.id,b.tenant_id,c.id,c.name,b.state,coalesce(b.builder,$3),c.source_kind,c.source_url,c.source_path,b.requested_ref,coalesce(b.commit_sha,''),
 coalesce(c.source_credential_id,''),b.phase_attempts+1,b.source_drive,b.lfs_drive,b.pointers,coalesce(b.scan_cursor,''),coalesce(b.builder_agent_id,''),coalesce(b.invocation_id,''),b.deadline_at,b.phase_started_at
 FROM corpus_builds b JOIN organizations o ON o.id=b.tenant_id JOIN corpora c ON c.id=b.corpus_id
 WHERE o.status='active' AND b.state=ANY($1) AND (b.host_id IS NULL OR b.host_id=$2) AND b.deadline_at>clock_timestamp()
 AND (b.lease_until IS NULL OR b.lease_until<=clock_timestamp()) AND b.next_attempt_at<=clock_timestamp()
 AND (b.state<>'QUEUED' OR NOT EXISTS(SELECT 1 FROM corpus_builds prev WHERE prev.tenant_id=b.tenant_id AND
 (prev.state IN ('FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING') OR prev.state='QUEUED' AND (prev.created_at,prev.id)<(b.created_at,b.id))))
 ORDER BY b.created_at,b.id LIMIT 1 FOR UPDATE OF o,b SKIP LOCKED`, phases, host, builder).Scan(&j.ID, &j.Tenant, &j.Corpus, &j.Name, &j.Phase, &j.Builder, &kind, &url, &j.Path, &j.Ref, &j.Commit, &j.CredentialID, &j.Attempt, &j.SourceDrive, &j.LFSDrive, &j.Pointers, &j.Cursor, &j.AgentID, &j.InvocationID, &j.Deadline, &j.PhaseStarted)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrNoWork
	}
	if err != nil {
		return j, err
	}
	if j.Source, err = repository.ParseURL(kind, url); err != nil {
		return j, err
	}
	if j.Phase == "QUEUED" {
		j.Phase = "FETCHING"
	}
	j.Host = host
	j.Token = newID("clease")
	tag, err := tx.Exec(ctx, `UPDATE corpus_builds b SET host_id=$2,builder=$3,state=$4,started_at=coalesce(started_at,clock_timestamp()),
 lease_token=$5,lease_until=least(deadline_at,clock_timestamp()+$6*interval '1 microsecond'),attempts=attempts+1,phase_attempts=phase_attempts+1 WHERE id=$1
 AND (state<>'QUEUED' OR NOT EXISTS(SELECT 1 FROM corpus_builds a WHERE a.tenant_id=b.tenant_id AND a.state IN ('FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING')))`,
		j.ID, host, j.Builder, j.Phase, j.Token, lease.Microseconds())
	if err != nil {
		return j, err
	}
	if tag.RowsAffected() != 1 {
		return j, ErrNoWork
	}
	return j, commit(ctx, tx)
}

const corpusLease = " WHERE id=$1 AND lease_token=$2 AND state=$3 AND lease_until>clock_timestamp() AND deadline_at>clock_timestamp()"

func (s *Store) writeCorpusLease(ctx context.Context, j CorpusWork, sql string, values ...any) error {
	args := append([]any{j.ID, j.Token, j.Phase}, values...)
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) PinCorpusCommit(ctx context.Context, j CorpusWork, sha string) error {
	if j.Phase != "FETCHING" || !repository.ValidCommit(sha) {
		return ErrInput
	}
	return s.writeCorpusLease(ctx, j, "UPDATE corpus_builds SET commit_sha=$4"+corpusLease+" AND (commit_sha IS NULL OR commit_sha=$4)", sha)
}

const corpusNext = ",phase_started_at=clock_timestamp(),lease_until=NULL,lease_token=NULL,phase_attempts=0,next_attempt_at=clock_timestamp(),invocation_id=NULL"

// CompleteCorpusDownload transitions only the phase that produced these bytes.
func (s *Store) CompleteCorpusDownload(ctx context.Context, j CorpusWork, drive any) error {
	var update string
	switch j.Phase {
	case "FETCHING":
		update = "source_drive=$4,state='SCANNING'"
	case "FETCHING_LFS":
		update = "lfs_drive=$4,state='CONVERTING'"
	default:
		return ErrInput
	}
	return s.writeCorpusLease(ctx, j, "UPDATE corpus_builds SET "+update+corpusNext+corpusLease+" AND commit_sha IS NOT NULL", drive)
}
func (s *Store) FailCorpusWork(ctx context.Context, j CorpusWork, code string, final bool, delay time.Duration) error {
	if final {
		return s.writeCorpusLease(ctx, j, `UPDATE corpus_builds SET state='FAILED',error_code=$4,completed_at=clock_timestamp(),lease_until=NULL,lease_token=NULL,costs=`+corpusCosts+corpusLease, code)
	}
	return s.writeCorpusLease(ctx, j, `UPDATE corpus_builds SET next_attempt_at=clock_timestamp()+$4*interval '1 microsecond',lease_until=NULL,lease_token=NULL`+corpusLease, delay.Microseconds())
}

const corpusCosts = `(SELECT jsonb_build_object('llm_calls',count(*),'input_tokens',coalesce(sum(input_tokens),0),
 'output_tokens',coalesce(sum(output_tokens),0),'audio_seconds',coalesce(sum(audio_seconds),0),'pages',coalesce(sum(pages),0),
 'cost_micros',CASE WHEN count(*)=count(estimated_cost_micro) THEN coalesce(sum(estimated_cost_micro),0) END)
 FROM llm_usage u WHERE u.tenant_id=corpus_builds.tenant_id AND u.agent_id=corpus_builds.builder_agent_id
 AND u.created_at>=corpus_builds.started_at AND u.state='settled')`

// FinishCorpusScan stores one validated page. Advancing the cursor and
// forgetting its invocation are atomic, including the final page.
func (s *Store) FinishCorpusScan(ctx context.Context, j CorpusWork, pointers, files, estimate any, next string, lfs bool) error {
	if j.Phase != "SCANNING" {
		return ErrInput
	}
	phase := "SCANNING"
	if next == "" {
		phase = "CONVERTING"
		if lfs {
			phase = "FETCHING_LFS"
		}
	}
	return s.writeCorpusLease(ctx, j, "UPDATE corpus_builds SET state=$4,pointers=$5,files=files || $6::jsonb,estimate=$7,scan_cursor=nullif($8,''),costs="+corpusCosts+corpusNext+corpusLease, phase, pointers, files, estimate, next)
}
func (s *Store) FinishCorpusConversion(ctx context.Context, j CorpusWork, files any) error {
	if j.Phase != "CONVERTING" {
		return ErrInput
	}
	return s.writeCorpusLease(ctx, j, "UPDATE corpus_builds SET state='PACKAGING',files=files || $4::jsonb,costs="+corpusCosts+corpusNext+corpusLease, files)
}
func (s *Store) WaitCorpusWork(ctx context.Context, j CorpusWork, delay time.Duration) error {
	return s.writeCorpusLease(ctx, j, `UPDATE corpus_builds SET phase_attempts=greatest(0,phase_attempts-1),attempts=greatest(0,attempts-1),next_attempt_at=clock_timestamp()+$4*interval '1 microsecond',lease_until=NULL,lease_token=NULL`+corpusLease, delay.Microseconds())
}
