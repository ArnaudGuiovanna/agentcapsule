package controlplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
	"github.com/jackc/pgx/v5"
)

type AuthorizeCorpusEnricherInput struct {
	Name    string           `json:"name"`
	Harness HarnessReference `json:"harness"`
}
type CorpusEnricher struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Harness HarnessReference `json:"harness"`
	Digest  string           `json:"digest"`
	Signer  string           `json:"signer"`
}
type RequestCorpusExtensionInput struct {
	EnricherID string `json:"enricher_id"`
}
type CorpusExtension struct {
	ID         string `json:"id"`
	BuildID    string `json:"build_id"`
	EnricherID string `json:"enricher_id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Digest     string `json:"digest,omitempty"`
	ImageBytes int64  `json:"image_bytes,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}
type CorpusExtensionImage struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	UUID   string `json:"uuid"`
	Bytes  int64  `json:"bytes"`
}

const enricherSelect = `SELECT e.id,e.name,r.name,r.version,r.artifact_digest,r.signer FROM corpus_enrichers e JOIN harness_releases r ON r.id=e.release_id`

func scanEnricher(r pgx.Row) (CorpusEnricher, error) {
	var e CorpusEnricher
	err := r.Scan(&e.ID, &e.Name, &e.Harness.Name, &e.Harness.Version, &e.Digest, &e.Signer)
	return e, corpusRowError(err)
}
func (a *Accounts) ListCorpusEnrichers(ctx context.Context, p Principal, after string, limit int) ([]CorpusEnricher, error) {
	return corpusRead(ctx, a, p, authorization.ManageCorpus, func(tx pgx.Tx) ([]CorpusEnricher, error) {
		return corpusPage(ctx, tx, limit, scanEnricher, enricherSelect+" WHERE e.tenant_id=$1 AND e.id>$2 ORDER BY e.id LIMIT $3", p.TenantID, after, limit)
	})
}
func (a *Accounts) AuthorizeCorpusEnricher(ctx context.Context, p Principal, key string, in AuthorizeCorpusEnricherInput) (APIReceipt, error) {
	if !wire.ValidCorpusMount(in.Name) || !catalogName(in.Harness.Name) || !catalogName(in.Harness.Version) {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus_enricher.authorize", in, func(tx pgx.Tx) (int, any, error) {
		var release string
		err := tx.QueryRow(ctx, `SELECT id FROM harness_releases WHERE name=$1 AND version=$2 AND enabled AND source='oci' AND base=$3 AND signer IS NOT NULL FOR SHARE`, in.Harness.Name, in.Harness.Version, GuestBase2).Scan(&release)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrRelease
		}
		if err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO corpus_enrichers(id,tenant_id,name,release_id,authorized_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,name) DO NOTHING`, newID("cen"), p.TenantID, in.Name, release, p.ID)
		if err != nil {
			return 0, nil, err
		}
		e, err := scanEnricher(tx.QueryRow(ctx, enricherSelect+" WHERE e.tenant_id=$1 AND e.name=$2", p.TenantID, in.Name))
		if err != nil {
			return 0, nil, err
		}
		if e.Harness != in.Harness {
			return 0, nil, ErrCorpusVersionConflict
		}
		if tag.RowsAffected() == 0 {
			return 200, e, nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO corpus_audit(id,tenant_id,actor_principal_id,credential_id,action,enricher_id) VALUES($1,$2,$3,nullif($4,''),'corpus_enricher.authorized',$5)`, newID("audit"), p.TenantID, p.ID, p.TokenID, e.ID)
		return 201, e, err
	})
}

const extensionSelect = `SELECT x.id,x.build_id,x.enricher_id,e.name,x.state,coalesce(x.image_digest,''),coalesce(x.image_bytes,0),coalesce(x.error_code,'') FROM corpus_extensions x JOIN corpus_enrichers e ON e.id=x.enricher_id`

func scanExtension(r pgx.Row) (CorpusExtension, error) {
	var x CorpusExtension
	err := r.Scan(&x.ID, &x.BuildID, &x.EnricherID, &x.Name, &x.State, &x.Digest, &x.ImageBytes, &x.ErrorCode)
	return x, corpusRowError(err)
}
func (a *Accounts) CorpusExtension(ctx context.Context, p Principal, id string) (CorpusExtension, error) {
	return corpusRead(ctx, a, p, authorization.ManageCorpus, func(tx pgx.Tx) (CorpusExtension, error) {
		return scanExtension(tx.QueryRow(ctx, extensionSelect+" WHERE x.tenant_id=$1 AND x.id=$2", p.TenantID, id))
	})
}
func (a *Accounts) BuildExtensions(ctx context.Context, p Principal, build string) ([]CorpusExtension, error) {
	return corpusRead(ctx, a, p, authorization.ManageCorpus, func(tx pgx.Tx) ([]CorpusExtension, error) {
		var exists string
		if err := tx.QueryRow(ctx, "SELECT id FROM corpus_builds WHERE id=$1 AND tenant_id=$2", build, p.TenantID).Scan(&exists); err != nil {
			return nil, corpusRowError(err)
		}
		rows, err := tx.Query(ctx, extensionSelect+" WHERE x.tenant_id=$1 AND x.build_id=$2 ORDER BY e.name", p.TenantID, build)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CorpusExtension, error) { return scanExtension(r) })
	})
}
func (a *Accounts) RequestCorpusExtension(ctx context.Context, p Principal, build, key string, in RequestCorpusExtensionInput) (APIReceipt, error) {
	if !validOrganizationText(in.EnricherID, 100) {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus_extension.request/"+build, in, func(tx pgx.Tx) (int, any, error) {
		var available bool
		err := tx.QueryRow(ctx, "SELECT state='REVIEW' AND review_expires_at>clock_timestamp() FROM corpus_builds WHERE tenant_id=$1 AND id=$2 FOR UPDATE", p.TenantID, build).Scan(&available)
		if err != nil {
			return 0, nil, corpusRowError(err)
		}
		if !available {
			return 0, nil, ErrTransition
		}
		var release string
		err = tx.QueryRow(ctx, `SELECT e.release_id FROM corpus_enrichers e JOIN harness_releases r ON e.release_id=r.id WHERE e.tenant_id=$1 AND e.id=$2 AND r.enabled AND r.signer IS NOT NULL FOR SHARE OF r`, p.TenantID, in.EnricherID).Scan(&release)
		if err != nil {
			return 0, nil, corpusRowError(err)
		}
		var count int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM corpus_extensions WHERE build_id=$1 AND enricher_id<>$2", build, in.EnricherID).Scan(&count); err != nil {
			return 0, nil, err
		}
		if count >= wire.MaxCorpusExtensions {
			return 0, nil, ErrInput
		}
		tag, err := tx.Exec(ctx, `INSERT INTO corpus_extensions(id,tenant_id,build_id,enricher_id) VALUES($1,$2,$3,$4) ON CONFLICT(build_id,enricher_id) DO UPDATE SET state='QUEUED',error_code=NULL,invocation_id=NULL,deadline_at=clock_timestamp()+interval '24 hours',next_attempt_at=clock_timestamp() WHERE corpus_extensions.state='FAILED'`, newID("cex"), p.TenantID, build, in.EnricherID)
		if err != nil {
			return 0, nil, err
		}
		x, err := scanExtension(tx.QueryRow(ctx, extensionSelect+" WHERE x.build_id=$1 AND x.enricher_id=$2", build, in.EnricherID))
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() > 0 {
			_, err = tx.Exec(ctx, `INSERT INTO corpus_audit(id,tenant_id,actor_principal_id,credential_id,action,build_id,enricher_id,extension_id) VALUES($1,$2,$3,nullif($4,''),'corpus_extension.requested',$5,$6,$7)`, newID("audit"), p.TenantID, p.ID, p.TokenID, build, in.EnricherID, x.ID)
		}
		return 202, x, err
	})
}

type CorpusExtensionWork struct{ ID, Build, Tenant, Corpus, Name, Commit, Host, Enricher, Release, HarnessVersion, HarnessName, HarnessDigest, BaseDigest, BaseUUID, InvocationID, Token string }

func (s *Store) ClaimCorpusExtension(ctx context.Context, host string) (CorpusExtensionWork, error) {
	var w CorpusExtensionWork
	tx, err := s.begin(ctx)
	if err != nil {
		return w, err
	}
	defer rollback(tx)
	err = tx.QueryRow(ctx, `SELECT x.id,b.id,b.tenant_id,b.corpus_id,e.name,b.commit_sha,b.host_id,e.id,r.id,r.version,r.name,r.artifact_digest,b.image_digest,b.image_uuid::text,coalesce(x.invocation_id,'')
 FROM corpus_extensions x JOIN corpus_enrichers e ON e.id=x.enricher_id JOIN corpus_builds b ON b.id=x.build_id JOIN harness_releases r ON r.id=e.release_id
 WHERE b.host_id=$1 AND b.state='REVIEW' AND b.review_expires_at>clock_timestamp() AND x.state IN ('QUEUED','RUNNING') AND x.deadline_at>clock_timestamp() AND x.next_attempt_at<=clock_timestamp() AND coalesce(x.lease_until,'-infinity')<=clock_timestamp()
 AND (x.state='RUNNING' OR NOT EXISTS(SELECT 1 FROM corpus_extensions older WHERE older.enricher_id=e.id AND (older.state='RUNNING' OR older.state='QUEUED' AND (older.created_at,older.id)<(x.created_at,x.id))))
 ORDER BY x.created_at,x.id LIMIT 1 FOR UPDATE OF e,x SKIP LOCKED`, host).Scan(&w.ID, &w.Build, &w.Tenant, &w.Corpus, &w.Name, &w.Commit, &w.Host, &w.Enricher, &w.Release, &w.HarnessVersion, &w.HarnessName, &w.HarnessDigest, &w.BaseDigest, &w.BaseUUID, &w.InvocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, ErrNoWork
	}
	if err != nil {
		return w, err
	}
	w.Token = newID("clease")
	_, err = tx.Exec(ctx, `UPDATE corpus_extensions SET state='RUNNING',lease_token=$2,lease_until=least(deadline_at,clock_timestamp()+interval '30 minutes') WHERE id=$1`, w.ID, w.Token)
	if err != nil {
		return w, err
	}
	return w, commit(ctx, tx)
}

const extensionLease = ` FROM corpus_extensions x JOIN corpus_builds b ON b.id=x.build_id WHERE x.id=$1 AND x.lease_token=$2 AND x.state='RUNNING' AND x.lease_until>clock_timestamp() AND x.deadline_at>clock_timestamp() AND b.state='REVIEW' AND b.review_expires_at>clock_timestamp() FOR UPDATE OF b,x`

func lockExtension(ctx context.Context, tx pgx.Tx, w CorpusExtensionWork) error {
	var id string
	err := tx.QueryRow(ctx, "SELECT b.id"+extensionLease, w.ID, w.Token).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	return err
}
func (s *Store) EnsureCorpusEnricher(ctx context.Context, w CorpusExtensionWork, r AgentResources) (string, bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer rollback(tx)
	if err = lockExtension(ctx, tx, w); err != nil {
		return "", false, err
	}
	var image string
	err = tx.QueryRow(ctx, `SELECT i.id FROM system_images i JOIN host_system_images h USING(kernel_digest,initrd_digest),harness_releases r WHERE r.id=$1 AND r.enabled AND r.signer IS NOT NULL AND r.base=$4 AND h.host_id=$2 AND $3=ANY(i.features) ORDER BY i.id LIMIT 1 FOR SHARE OF i,r,h`, w.Release, w.Host, FeatureCorpusExtensions, GuestBase2).Scan(&image)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrRelease
	}
	if err != nil {
		return "", false, err
	}
	id, ready, err := reserveCorpusGuest(ctx, tx, w.Tenant, w.Host, w.Release, image, "corpus_enricher", w.Enricher, r)
	if err != nil {
		return "", false, err
	}
	_, err = tx.Exec(ctx, "UPDATE corpus_extensions SET agent_id=$2 WHERE id=$1", w.ID, id)
	if err != nil {
		return "", false, err
	}
	return id, ready, commit(ctx, tx)
}
func (c *AgentCatalog) CorpusExtensionInvocation(ctx context.Context, w CorpusExtensionWork, raw json.RawMessage) (json.RawMessage, bool, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer rollback(tx)
	if err = lockExtension(ctx, tx, w); err != nil {
		return nil, false, err
	}
	var agent, requester, op string
	var micros int64
	err = tx.QueryRow(ctx, `SELECT a.id,a.builder_principal,coalesce(x.invocation_id,''),(extract(epoch FROM x.deadline_at-clock_timestamp())*1000000)::bigint FROM corpus_extensions x JOIN agents a ON a.id=x.agent_id AND a.enricher_id=x.enricher_id WHERE x.id=$1`, w.ID).Scan(&agent, &requester, &op, &micros)
	if err != nil {
		return nil, false, err
	}
	return c.corpusGuestInvocation(ctx, tx, agent, requester, op, w.Host, micros, raw, func(op string) error {
		_, err := tx.Exec(ctx, "UPDATE corpus_extensions SET invocation_id=$2 WHERE id=$1", w.ID, op)
		return err
	})
}
func (s *Store) SettleCorpusExtension(ctx context.Context, w CorpusExtensionWork, img *CorpusExtensionImage, failure string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockExtension(ctx, tx, w); err != nil {
		return err
	}
	if img != nil {
		if !reference.ValidDigest(img.Digest) || !wire.ValidUUID(img.UUID) || img.Bytes <= 0 {
			return ErrInput
		}
		if err = lockOrganizationQuota(ctx, tx, w.Tenant); err != nil {
			return err
		}
		q, _, err := organizationQuotas(ctx, tx, w.Tenant)
		if err != nil {
			return err
		}
		if q.MaxCorpusStorageMiB != nil {
			used, _, err := corpusOccupation(ctx, tx, w.Tenant)
			if err != nil {
				return err
			}
			var pinned bool
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ("+tenantCorpusPins+") p WHERE digest=$2)", w.Tenant, img.Digest).Scan(&pinned); err != nil {
				return err
			}
			if !pinned && img.Bytes > (*q.MaxCorpusStorageMiB<<20)-used {
				failure = "quota_exceeded"
			}
		}
	}
	switch {
	case failure != "":
		_, err = tx.Exec(ctx, `UPDATE corpus_extensions SET state='FAILED',error_code=$2,lease_token=NULL,lease_until=NULL WHERE id=$1`, w.ID, failure)
	case img != nil:
		_, err = tx.Exec(ctx, `UPDATE corpus_extensions SET state='READY',image_digest=$2,image_uuid=$3,image_bytes=$4,lease_token=NULL,lease_until=NULL WHERE id=$1`, w.ID, img.Digest, img.UUID, img.Bytes)
	default:
		_, err = tx.Exec(ctx, `UPDATE corpus_extensions SET next_attempt_at=clock_timestamp()+interval '1 second',lease_token=NULL,lease_until=NULL WHERE id=$1`, w.ID)
	}
	if err != nil {
		return err
	}
	return commit(ctx, tx)
}
