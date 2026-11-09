package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/jackc/pgx/v5"
)

// MaxImportAttempts bounds transient retries of one import before it is
// rejected as unavailable; a new request can then start over.
const MaxImportAttempts = 5

// HarnessImport is the state of one asynchronous import (REG-001, REG-008).
type HarnessImport struct {
	ID          string     `json:"id"`
	Reference   string     `json:"reference"`
	Digest      string     `json:"digest"`
	State       string     `json:"state"`
	ErrorCode   string     `json:"error_code,omitempty"`
	ReleaseID   string     `json:"release_id,omitempty"`
	Attempts    int        `json:"attempts"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// HarnessRelease is an immutable, runnable harness version.
type HarnessRelease struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Digest       string     `json:"digest"`
	Source       string     `json:"source"`
	Reference    string     `json:"reference,omitempty"`
	RootfsDigest string     `json:"rootfs_digest,omitempty"`
	RootfsBytes  int64      `json:"rootfs_bytes,omitempty"`
	State        string     `json:"state"`
	CreatedAt    time.Time  `json:"created_at"`
	DeprecatedAt *time.Time `json:"deprecated_at,omitempty"`
}

type HarnessImportInput struct {
	Reference string `json:"reference"`
}

const importColumns = `id,reference,manifest_digest,status,error_code,coalesce(release_id,''),attempts,created_at,completed_at`

func scanImport(row pgx.Row) (HarnessImport, error) {
	var v HarnessImport
	err := row.Scan(&v.ID, &v.Reference, &v.Digest, &v.State, &v.ErrorCode, &v.ReleaseID, &v.Attempts, &v.CreatedAt, &v.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

const releaseColumns = `id,name,version,artifact_digest,source,coalesce(reference,''),coalesce(rootfs_digest,''),coalesce(rootfs_bytes,0),
    CASE WHEN enabled THEN 'READY' ELSE 'DEPRECATED' END,created_at,deprecated_at`

func scanRelease(row pgx.Row) (HarnessRelease, error) {
	var v HarnessRelease
	err := row.Scan(&v.ID, &v.Name, &v.Version, &v.Digest, &v.Source, &v.Reference, &v.RootfsDigest, &v.RootfsBytes, &v.State, &v.CreatedAt, &v.DeprecatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func auditHarness(ctx context.Context, tx pgx.Tx, p Principal, action string, importID, releaseID *string) error {
	_, err := tx.Exec(ctx, `INSERT INTO harness_audit(id,actor_account,credential_id,action,import_id,release_id) VALUES($1,$2,$3,$4,$5,$6)`,
		newID("audit"), p.ID, p.TokenID, action, importID, releaseID)
	return err
}

// RequestHarnessImport records an import of a package pinned by digest. Only
// syntax is checked here; the worker enforces the registry trust policy before
// any connection. A package already released, or already being imported, is
// answered with that record instead of a new download.
func (a *Accounts) RequestHarnessImport(ctx context.Context, p Principal, key string, in HarnessImportInput) (APIReceipt, error) {
	ref, err := ociregistry.ParseReference(in.Reference)
	if err != nil {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/harness-imports", key), in, func() (int, any, error) {
		// One import per digest at a time: serialize requests for the same package.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "harness-import/"+ref.Digest); err != nil {
			return 0, nil, err
		}
		var releaseID string
		err := tx.QueryRow(ctx, "SELECT id FROM harness_releases WHERE source='oci' AND artifact_digest=$1", ref.Digest).Scan(&releaseID)
		if err == nil {
			v, err := scanImport(tx.QueryRow(ctx, `SELECT `+importColumns+` FROM harness_imports WHERE release_id=$1 ORDER BY created_at DESC LIMIT 1`, releaseID))
			return 200, v, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, err
		}
		v, err := scanImport(tx.QueryRow(ctx, `SELECT `+importColumns+` FROM harness_imports WHERE manifest_digest=$1 AND status='IMPORTING'`, ref.Digest))
		if err == nil {
			return 202, v, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return 0, nil, err
		}
		id := newID("imp")
		v, err = scanImport(tx.QueryRow(ctx, `INSERT INTO harness_imports(id,reference,manifest_digest,requested_by) VALUES($1,$2,$3,$4)
            RETURNING `+importColumns, id, ref.String(), ref.Digest, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditHarness(ctx, tx, p, "import.requested", &id, nil); err != nil {
			return 0, nil, err
		}
		return 202, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) GetHarnessImport(ctx context.Context, p Principal, id string) (HarnessImport, error) {
	if !validOrganizationText(id, 100) {
		return HarnessImport{}, ErrNotFound
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return HarnessImport{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return HarnessImport{}, err
	}
	v, err := scanImport(tx.QueryRow(ctx, `SELECT `+importColumns+` FROM harness_imports WHERE id=$1`, id))
	if err != nil {
		return HarnessImport{}, err
	}
	return v, commit(ctx, tx)
}

// ListHarnessReleases is open to the platform operator and to organization
// members who can read agents: releases carry no tenant data.
func (a *Accounts) ListHarnessReleases(ctx context.Context, p Principal, includeDeprecated bool) ([]HarnessRelease, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if p.Kind == "platform" {
		err = authorizePlatform(ctx, tx, p)
	} else {
		_, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+releaseColumns+` FROM harness_releases WHERE $1 OR enabled ORDER BY name,created_at`, includeDeprecated)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []HarnessRelease{}
	for rows.Next() {
		v, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, commit(ctx, tx)
}

// DeprecateHarnessRelease stops new agents from using a release. Agents
// already pinned to it keep running; upgrading them is a separate, manual step.
func (a *Accounts) DeprecateHarnessRelease(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrNotFound
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		ID string `json:"release_id"`
	}{id}
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/harness-releases/"+id+"/deprecate", key), in, func() (int, any, error) {
		tag, err := tx.Exec(ctx, `UPDATE harness_releases SET enabled=false,deprecated_at=clock_timestamp() WHERE id=$1 AND enabled`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 1 {
			if err = auditHarness(ctx, tx, p, "release.deprecated", nil, &id); err != nil {
				return 0, nil, err
			}
		}
		v, err := scanRelease(tx.QueryRow(ctx, `SELECT `+releaseColumns+` FROM harness_releases WHERE id=$1`, id))
		return 200, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// ImportJob is an import claimed by a worker under a lease.
type ImportJob struct {
	ID, Reference, Digest, Token string
	Attempt                      int
}

// ClaimHarnessImport leases the oldest due import. The lease is the only
// authority to complete it; an expired lease lets another worker retry.
func (s *Store) ClaimHarnessImport(ctx context.Context, worker string, lease time.Duration) (ImportJob, error) {
	var job ImportJob
	if worker == "" || lease < time.Second {
		return job, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return job, err
	}
	defer rollback(tx)
	token := newID("lease")
	err = tx.QueryRow(ctx, `UPDATE harness_imports SET lease_owner=$1,lease_token=$2,lease_until=clock_timestamp()+$3::bigint*interval '1 microsecond',
            attempts=attempts+1
        WHERE id=(SELECT id FROM harness_imports WHERE status='IMPORTING' AND next_attempt_at<=clock_timestamp()
            AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id,reference,manifest_digest,attempts`, worker, token, lease.Microseconds()).Scan(&job.ID, &job.Reference, &job.Digest, &job.Attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ImportJob{}, ErrNoWork
	}
	if err != nil {
		return ImportJob{}, err
	}
	job.Token = token
	return job, commit(ctx, tx)
}

// ImportedRelease is what the worker verified about the package.
type ImportedRelease struct {
	Name, Version, RootfsDigest string
	RootfsBytes                 int64
}

// CompleteHarnessImport publishes the release. name:version is immutable: if
// it already belongs to another digest, the import is rejected instead.
func (s *Store) CompleteHarnessImport(ctx context.Context, job ImportJob, r ImportedRelease) (HarnessImport, error) {
	if !catalogName(r.Name) || !catalogName(r.Version) || r.RootfsBytes < 1 || len(r.RootfsDigest) != 71 {
		return HarnessImport{}, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return HarnessImport{}, err
	}
	defer rollback(tx)
	if err = holdImportLease(ctx, tx, job); err != nil {
		return HarnessImport{}, err
	}
	// Two packages claiming the same name:version serialize here: the first
	// becomes the release, the second is rejected as a version conflict.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "harness-release/"+r.Name+"/"+r.Version); err != nil {
		return HarnessImport{}, err
	}
	var releaseID, digest string
	err = tx.QueryRow(ctx, "SELECT id,artifact_digest FROM harness_releases WHERE name=$1 AND version=$2 FOR UPDATE", r.Name, r.Version).Scan(&releaseID, &digest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		releaseID = newID("rel")
		if _, err = tx.Exec(ctx, `INSERT INTO harness_releases(id,name,version,artifact_digest,source,reference,rootfs_digest,rootfs_bytes)
            VALUES($1,$2,$3,$4,'oci',$5,$6,$7)`, releaseID, r.Name, r.Version, job.Digest, job.Reference, r.RootfsDigest, r.RootfsBytes); err != nil {
			return HarnessImport{}, err
		}
	case err != nil:
		return HarnessImport{}, err
	case digest != job.Digest:
		return finishImport(ctx, tx, job.ID, "REJECTED", "version_conflict", nil)
	}
	return finishImport(ctx, tx, job.ID, "READY", "", &releaseID)
}

// FailHarnessImport records a failed attempt. A permanent cause rejects the
// import; a transient one schedules a retry, and the last attempt rejects it.
func (s *Store) FailHarnessImport(ctx context.Context, job ImportJob, code string, transient bool, retryAfter time.Duration) (HarnessImport, error) {
	switch code {
	case "policy", "not_found", "access_denied", "integrity", "unavailable":
	default:
		return HarnessImport{}, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return HarnessImport{}, err
	}
	defer rollback(tx)
	if err = holdImportLease(ctx, tx, job); err != nil {
		return HarnessImport{}, err
	}
	if transient && job.Attempt < MaxImportAttempts {
		v, err := scanImport(tx.QueryRow(ctx, `UPDATE harness_imports SET lease_owner=NULL,lease_token=NULL,lease_until=NULL,
            next_attempt_at=clock_timestamp()+$2::bigint*interval '1 microsecond' WHERE id=$1 RETURNING `+importColumns, job.ID, retryAfter.Microseconds()))
		if err != nil {
			return HarnessImport{}, err
		}
		return v, commit(ctx, tx)
	}
	return finishImport(ctx, tx, job.ID, "REJECTED", code, nil)
}

func holdImportLease(ctx context.Context, tx pgx.Tx, job ImportJob) error {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT status='IMPORTING' AND lease_token=$2 AND lease_until>clock_timestamp() FROM harness_imports WHERE id=$1 FOR UPDATE`,
		job.ID, job.Token).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !ok {
		return ErrLeaseLost
	}
	return nil
}

func finishImport(ctx context.Context, tx pgx.Tx, id, status, code string, releaseID *string) (HarnessImport, error) {
	v, err := scanImport(tx.QueryRow(ctx, `UPDATE harness_imports SET status=$2,error_code=$3,release_id=$4,completed_at=clock_timestamp(),
        lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE id=$1 RETURNING `+importColumns, id, status, code, releaseID))
	if err != nil {
		return HarnessImport{}, err
	}
	return v, commit(ctx, tx)
}

// RetainedHarnessDigests lists the package (manifest) digests a host must keep
// in its cache: every approved, non-deprecated release; deprecated releases
// still pinned by an agent of this host that is not deleted; and packages being
// imported, which reach the cache just before their release is published.
func (s *Store) RetainedHarnessDigests(ctx context.Context, host string) (map[string]bool, error) {
	if !catalogName(host) {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT r.artifact_digest FROM harness_releases r WHERE r.source='oci' AND (r.enabled OR EXISTS(
            SELECT 1 FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.release_id=r.id AND x.host_id=$1 AND a.phase<>'DELETED'))
        UNION SELECT manifest_digest FROM harness_imports WHERE status='IMPORTING'`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keep := map[string]bool{}
	for rows.Next() {
		var d string
		if err = rows.Scan(&d); err != nil {
			return nil, err
		}
		keep[d] = true
	}
	return keep, rows.Err()
}
