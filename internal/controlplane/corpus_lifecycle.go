package controlplane

import (
	"context"
	"encoding/json"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"github.com/jackc/pgx/v5"
)

const tenantCorpusPins = `SELECT digest,image_bytes AS size FROM corpus_releases WHERE tenant_id=$1 AND deprecated_at IS NULL
 UNION ALL SELECT ext->>'digest',(ext->>'bytes')::bigint FROM corpus_releases CROSS JOIN LATERAL jsonb_array_elements(extensions) ext WHERE tenant_id=$1 AND deprecated_at IS NULL
 UNION ALL SELECT image_digest,image_bytes FROM corpus_builds WHERE tenant_id=$1 AND state='REVIEW'
 UNION ALL SELECT x.image_digest,x.image_bytes FROM corpus_extensions x JOIN corpus_builds b ON b.id=x.build_id WHERE b.tenant_id=$1 AND b.state='REVIEW' AND x.state='READY'`

// corpusOccupation counts identical active images once, including their reviews.
func corpusOccupation(ctx context.Context, tx pgx.Tx, tenant string) (bytes int64, builds int, err error) {
	err = tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0),(SELECT count(*) FROM corpus_builds WHERE tenant_id=$1 AND state IN ('QUEUED','FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING'))
 FROM (SELECT digest,max(size) AS bytes FROM (
 `+tenantCorpusPins+`
 ) pins GROUP BY digest) held`, tenant).Scan(&bytes, &builds)
	return
}
func (a *Accounts) RequestCorpusBuild(ctx context.Context, p Principal, id, key string, in RequestCorpusBuildInput) (APIReceipt, error) {
	if in.Ref != "" && (!repository.ValidRef(in.Ref) || in.Commit != "") || in.Commit != "" && !repository.ValidCommit(in.Commit) {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.build/"+id, in, func(tx pgx.Tx) (int, any, error) {
		var defaultRef string
		if err := tx.QueryRow(ctx, "SELECT source_ref FROM corpora WHERE tenant_id=$1 AND id=$2", p.TenantID, id).Scan(&defaultRef); err != nil {
			return 0, nil, corpusRowError(err)
		}
		if err := refuseUnderImagePressure(ctx, tx); err != nil {
			return 0, nil, err
		}
		if err := lockOrganizationQuota(ctx, tx, p.TenantID); err != nil {
			return 0, nil, err
		}
		q, _, err := organizationQuotas(ctx, tx, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		bytes, builds, err := corpusOccupation(ctx, tx, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		if q.MaxCorpusBuilds != nil && builds >= *q.MaxCorpusBuilds {
			return 0, nil, &OrganizationQuotaError{Quota: "max_corpus_builds"}
		}
		if q.MaxCorpusStorageMiB != nil && bytes >= *q.MaxCorpusStorageMiB<<20 {
			return 0, nil, &OrganizationQuotaError{Quota: "max_corpus_storage_mib"}
		}
		ref := in.Ref
		if ref == "" {
			ref = defaultRef
		}
		build := newID("cbd")
		if _, err = tx.Exec(ctx, `INSERT INTO corpus_builds(id,tenant_id,corpus_id,requested_ref,commit_sha) VALUES($1,$2,$3,$4,nullif($5,''))`, build, p.TenantID, id, ref, in.Commit); err != nil {
			return 0, nil, err
		}
		b, err := scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.id=$1", build))
		if err != nil {
			return 0, nil, err
		}
		return 202, b, auditCorpus(ctx, tx, p, "corpus_build.requested", id, build, "", "")
	})
}
func (a *Accounts) CancelCorpusBuild(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.cancel/"+id, struct{}{}, func(tx pgx.Tx) (int, any, error) {
		b, err := scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.id=$1 AND b.tenant_id=$2 FOR UPDATE", id, p.TenantID))
		if err != nil {
			return 0, nil, err
		}
		switch b.State {
		case "PUBLISHED", "FAILED", "EXPIRED", "CANCELED":
			return 0, nil, ErrTransition
		}
		if err = cancelCorpusInvocation(ctx, tx, id); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE corpus_builds SET state='CANCELED',completed_at=clock_timestamp(),lease_token=NULL,lease_until=NULL WHERE id=$1`, id); err != nil {
			return 0, nil, err
		}
		if err = purgeCorpusReview(ctx, tx, id); err != nil {
			return 0, nil, err
		}
		b, err = scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.id=$1", id))
		if err != nil {
			return 0, nil, err
		}
		return 200, b, auditCorpus(ctx, tx, p, "corpus_build.canceled", b.CorpusID, id, "", "")
	})
}
func cancelCorpusInvocation(ctx context.Context, tx pgx.Tx, build string) error {
	var op string
	err := tx.QueryRow(ctx, "SELECT coalesce(invocation_id,'') FROM corpus_builds WHERE id=$1", build).Scan(&op)
	if err != nil || op == "" {
		return err
	}
	return cancelGuestInvocation(ctx, tx, op)
}
func cancelGuestInvocation(ctx context.Context, tx pgx.Tx, op string) error {
	if _, err := tx.Exec(ctx, "UPDATE agent_mailboxes SET delivery_state='CANCELED',lease_token='',lease_until=NULL WHERE instruction_id=$1 AND delivery_state='PENDING'", op); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE platform_operations SET status='CANCELED',error_code='canceled',completed_at=clock_timestamp() WHERE id=$1 AND status IN ('PENDING','RUNNING')", op)
	return err
}
func purgeCorpusReview(ctx context.Context, tx pgx.Tx, id string) error {
	rows, err := tx.Query(ctx, `UPDATE corpus_extensions SET state='CANCELED',lease_token=NULL,lease_until=NULL WHERE build_id=$1 AND state IN ('QUEUED','RUNNING') RETURNING coalesce(invocation_id,'')`, id)
	if err != nil {
		return err
	}
	ops, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op != "" {
			if err = cancelGuestInvocation(ctx, tx, op); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM agent_corpora WHERE build_id=$1", id); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "DELETE FROM corpus_review_files WHERE build_id=$1", id)
	return err
}
func (a *Accounts) PublishCorpusBuild(ctx context.Context, p Principal, id, key string, version int) (APIReceipt, error) {
	if version < 1 || version > 2147483647 {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.publish/"+id, version, func(tx pgx.Tx) (int, any, error) {
		b, err := scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.id=$1 AND b.tenant_id=$2 FOR UPDATE", id, p.TenantID))
		if err != nil {
			return 0, nil, err
		}
		if b.State != "REVIEW" {
			return 0, nil, ErrTransition
		}
		var active bool
		if err = tx.QueryRow(ctx, `SELECT b.review_expires_at>clock_timestamp() FROM corpora c JOIN corpus_builds b ON b.corpus_id=c.id WHERE b.id=$1 FOR UPDATE OF c`, id).Scan(&active); err != nil {
			return 0, nil, err
		}
		if !active {
			return 0, nil, ErrTransition
		}
		var snapshot json.RawMessage
		var ready bool
		err = tx.QueryRow(ctx, `SELECT coalesce(bool_and(x.state='READY'),true),coalesce(jsonb_agg(jsonb_build_object('name',e.name,'digest',x.image_digest,'uuid',x.image_uuid,'bytes',x.image_bytes) ORDER BY e.name),'[]'::jsonb) FROM corpus_extensions x JOIN corpus_enrichers e ON e.id=x.enricher_id WHERE x.build_id=$1`, id).Scan(&ready, &snapshot)
		if err != nil {
			return 0, nil, err
		}
		if !ready {
			return 0, nil, ErrTransition
		}
		tag, err := tx.Exec(ctx, `INSERT INTO corpus_releases(id,tenant_id,corpus_id,build_id,version,digest,image_bytes,image_uuid,host_id,commit_sha,builder,created_by,extensions)
 SELECT $2,tenant_id,corpus_id,id,$3,image_digest,image_bytes,image_uuid,host_id,commit_sha,builder,$4,$5 FROM corpus_builds WHERE id=$1 ON CONFLICT(corpus_id,version) DO NOTHING`, id, newID("crl"), version, p.ID, snapshot)
		if err != nil {
			return 0, nil, err
		}
		r, err := scanCorpusRelease(tx.QueryRow(ctx, releaseSelect+" WHERE r.corpus_id=$1 AND r.version=$2", b.CorpusID, version))
		if err != nil {
			return 0, nil, err
		}
		var same bool
		if err = tx.QueryRow(ctx, "SELECT extensions=$2::jsonb FROM corpus_releases WHERE id=$1", r.ID, snapshot).Scan(&same); err != nil {
			return 0, nil, err
		}
		if !same || r.Digest != b.ImageDigest {
			return 0, nil, ErrCorpusVersionConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE corpus_builds SET state='PUBLISHED',release_id=$2,completed_at=clock_timestamp() WHERE id=$1`, id, r.ID); err != nil {
			return 0, nil, err
		}
		status := 200
		if tag.RowsAffected() > 0 {
			status = 201
		}
		return status, r, auditCorpus(ctx, tx, p, "corpus_build.published", b.CorpusID, id, r.ID, "")
	})
}
func (a *Accounts) DeprecateCorpusRelease(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.deprecate/"+id, struct{}{}, func(tx pgx.Tx) (int, any, error) {
		tag, err := tx.Exec(ctx, `UPDATE corpus_releases SET deprecated_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2 AND deprecated_at IS NULL`, id, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		r, err := scanCorpusRelease(tx.QueryRow(ctx, releaseSelect+" WHERE r.id=$1 AND r.tenant_id=$2", id, p.TenantID))
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 0 {
			err = auditCorpus(ctx, tx, p, "corpus_release.deprecated", r.CorpusID, "", id, "")
		}
		return 200, r, err
	})
}

// ExpireCorpusBuilds expires due work under the same row locks as a worker's
// phase transition or a publication. An expired lease can never finish a phase.
func (s *Store) ExpireCorpusBuilds(ctx context.Context) (int, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `WITH due AS (SELECT id FROM corpus_builds WHERE (state='REVIEW' AND review_expires_at<=clock_timestamp()) OR
 (state IN ('QUEUED','FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING') AND deadline_at<=clock_timestamp()) ORDER BY created_at LIMIT 100 FOR UPDATE SKIP LOCKED)
 UPDATE corpus_builds b SET state=CASE WHEN state='REVIEW' THEN 'EXPIRED' ELSE 'FAILED' END,error_code=CASE WHEN state<>'REVIEW' THEN 'timeout' END,
 lease_token=NULL,lease_until=NULL,completed_at=clock_timestamp() FROM due WHERE b.id=due.id RETURNING b.id`)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err = cancelCorpusInvocation(ctx, tx, id); err != nil {
			return 0, err
		}

		if err = purgeCorpusReview(ctx, tx, id); err != nil {
			return 0, err
		}
	}
	timed, err := tx.Query(ctx, `UPDATE corpus_extensions SET state='FAILED',error_code='timeout',lease_token=NULL,lease_until=NULL WHERE state IN ('QUEUED','RUNNING') AND deadline_at<=clock_timestamp() RETURNING coalesce(invocation_id,'')`)
	if err != nil {
		return 0, err
	}
	ops, err := pgx.CollectRows(timed, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	for _, op := range ops {
		if op != "" {
			if err = cancelGuestInvocation(ctx, tx, op); err != nil {
				return 0, err
			}
		}
	}
	return len(ids), commit(ctx, tx)
}

// CorpusImagesInUse returns a host's database pins. Runtime pins are added
// while the runtime registry is locked during collection.
func (s *Store) CorpusImagesInUse(ctx context.Context, host string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `WITH rel AS (
 SELECT id FROM corpus_releases WHERE host_id=$1 AND deprecated_at IS NULL
 UNION SELECT r.id FROM agent_corpora ac JOIN agents a ON a.id=ac.agent_id JOIN corpus_releases r ON ac.release_id=r.id WHERE a.phase<>'DELETED' AND r.host_id=$1
 UNION SELECT cr.id FROM agent_rollouts u JOIN agent_template_revisions tr ON (tr.tenant_id,tr.name,tr.revision)=(u.tenant_id,u.template_name,u.revision)
 CROSS JOIN LATERAL jsonb_array_elements(coalesce(tr.spec->'corpora','[]')) ref JOIN corpora c ON c.name=ref->>'name'
 JOIN corpus_releases cr ON cr.corpus_id=c.id AND cr.version=(ref->>'version')::int WHERE c.tenant_id=u.tenant_id AND cr.host_id=$1 AND u.status<>'completed'),
 rev AS (SELECT id FROM corpus_builds WHERE host_id=$1 AND state='REVIEW' UNION SELECT b.id FROM agent_corpora ac JOIN agents a ON a.id=ac.agent_id JOIN corpus_builds b ON ac.build_id=b.id WHERE a.phase<>'DELETED' AND b.host_id=$1)
 SELECT digest FROM corpus_releases JOIN rel USING(id) UNION SELECT ext->>'digest' FROM corpus_releases JOIN rel USING(id) CROSS JOIN LATERAL jsonb_array_elements(extensions) ext
 UNION SELECT image_digest FROM corpus_builds JOIN rev USING(id) UNION SELECT x.image_digest FROM corpus_extensions x JOIN rev ON rev.id=x.build_id WHERE x.state='READY' `, host)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// CorpusStagingFinished distinguishes removable builds from active downloads
// and from directories not owned by this host.
func (s *Store) CorpusStagingFinished(ctx context.Context, host, build string) (bool, error) {
	var done bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM corpus_builds WHERE host_id=$1 AND id=$2 AND state IN ('REVIEW','PUBLISHED','FAILED','CANCELED','EXPIRED') UNION ALL SELECT 1 FROM corpus_extensions x JOIN corpus_builds b ON b.id=x.build_id WHERE b.host_id=$1 AND x.id=$2 AND x.state IN ('READY','FAILED','CANCELED'))`, host, build).Scan(&done)
	return done, err
}

// CorpusBuildOutcomes counts durable transitions. A published build did
// reach review, even if its worker restarted before the next metrics scrape.
func (s *Store) CorpusBuildOutcomes(ctx context.Context, host string) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT outcome,count(*) FROM (
 SELECT 'review'::text AS outcome FROM corpus_builds WHERE review_at IS NOT NULL AND host_id=$1
 UNION ALL SELECT CASE WHEN state='FAILED' THEN error_code ELSE lower(state) END FROM corpus_builds
 WHERE (host_id=$1 OR host_id IS NULL) AND state IN ('FAILED','CANCELED','EXPIRED')) t GROUP BY outcome`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var code string
		var n int64
		if err = rows.Scan(&code, &n); err != nil {
			return nil, err
		}
		out[code] = n
	}
	return out, rows.Err()
}
