// Package corpus reads the corpus catalog, its builds, releases, and tenant storage accounting.
package corpus

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

type CorpusExtensionImage struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	UUID   string `json:"uuid"`
	Bytes  int64  `json:"bytes"`
}

type CorpusSource struct {
	Kind         string `json:"kind"`
	URL          string `json:"url"`
	Ref          string `json:"ref"`
	Path         string `json:"path,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
}
type CreateCorpusInput struct {
	Name   string       `json:"name"`
	Title  string       `json:"title,omitempty"`
	Source CorpusSource `json:"source"`
}
type CorpusReleaseReference struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}
type Corpus struct {
	ID string `json:"id"`
	CreateCorpusInput
	LatestBuildID string                  `json:"latest_build_id,omitempty"`
	LatestRelease *CorpusReleaseReference `json:"latest_release,omitempty"`
	CreatedAt     time.Time               `json:"created_at"`
}
type CorpusBuild struct {
	ID              string          `json:"id"`
	CorpusID        string          `json:"corpus_id"`
	State           string          `json:"state"`
	RequestedRef    string          `json:"requested_ref,omitempty"`
	Commit          string          `json:"commit,omitempty"`
	Builder         string          `json:"builder,omitempty"`
	ArchiveBytes    int64           `json:"archive_bytes,omitempty"`
	LFSObjects      int             `json:"lfs_objects,omitempty"`
	LFSBytes        int64           `json:"lfs_bytes,omitempty"`
	Files           json.RawMessage `json:"files"`
	Costs           json.RawMessage `json:"costs"`
	Estimate        json.RawMessage `json:"estimate,omitempty"`
	ImageBytes      int64           `json:"image_bytes,omitempty"`
	ImageDigest     string          `json:"image_digest,omitempty"`
	ErrorCode       string          `json:"error_code,omitempty"`
	ReleaseID       string          `json:"release_id,omitempty"`
	Attempts        int             `json:"attempts"`
	CreatedAt       time.Time       `json:"created_at"`
	DeadlineAt      time.Time       `json:"deadline_at"`
	ReviewAt        *time.Time      `json:"review_at,omitempty"`
	ReviewExpiresAt *time.Time      `json:"review_expires_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
}
type CorpusRelease struct {
	Extensions []CorpusExtensionImage `json:"extensions"`
	CorpusReleaseReference
	CorpusID     string     `json:"corpus_id"`
	Digest       string     `json:"digest"`
	ImageBytes   int64      `json:"image_bytes"`
	BuildID      string     `json:"build_id"`
	Commit       string     `json:"commit"`
	Builder      string     `json:"builder"`
	HostID       string     `json:"host_id"`
	State        string     `json:"state"`
	CreatedAt    time.Time  `json:"created_at"`
	DeprecatedAt *time.Time `json:"deprecated_at,omitempty"`
}

const corpusSelect = `SELECT c.id,c.name,c.title,c.source_kind,c.source_url,c.source_ref,c.source_path,coalesce(c.source_credential_id,''),c.created_at,
 coalesce((SELECT b.id FROM corpus_builds b WHERE b.corpus_id=c.id ORDER BY b.created_at DESC,b.id DESC LIMIT 1),''),
 (SELECT jsonb_build_object('id',r.id,'name',c.name,'version',r.version) FROM corpus_releases r WHERE r.corpus_id=c.id AND r.deprecated_at IS NULL ORDER BY r.version DESC LIMIT 1)
 FROM corpora c`

func scanCorpus(row pgx.Row) (Corpus, error) {
	var v Corpus
	err := row.Scan(&v.ID, &v.Name, &v.Title, &v.Source.Kind, &v.Source.URL, &v.Source.Ref, &v.Source.Path, &v.Source.CredentialID, &v.CreatedAt, &v.LatestBuildID, &v.LatestRelease)
	return v, corpusRowError(err)
}

const buildSelect = `SELECT b.id,b.corpus_id,b.state,b.requested_ref,coalesce(b.commit_sha,''),coalesce(b.builder,''),coalesce((b.source_drive->>'bytes')::bigint,0),coalesce((b.lfs_drive->>'objects')::int,0),coalesce((b.lfs_drive->>'object_bytes')::bigint,0),b.files,b.costs,b.estimate,coalesce(b.image_bytes,0),coalesce(b.image_digest,''),coalesce(b.error_code,''),coalesce(b.release_id,''),b.attempts,b.created_at,b.deadline_at,b.review_at,b.review_expires_at,b.completed_at FROM corpus_builds b`

func scanBuild(row pgx.Row) (CorpusBuild, error) {
	var b CorpusBuild
	err := row.Scan(&b.ID, &b.CorpusID, &b.State, &b.RequestedRef, &b.Commit, &b.Builder, &b.ArchiveBytes, &b.LFSObjects, &b.LFSBytes, &b.Files, &b.Costs, &b.Estimate, &b.ImageBytes, &b.ImageDigest, &b.ErrorCode, &b.ReleaseID, &b.Attempts, &b.CreatedAt, &b.DeadlineAt, &b.ReviewAt, &b.ReviewExpiresAt, &b.CompletedAt)
	return b, corpusRowError(err)
}

const releaseSelect = `SELECT r.id,c.name,r.version,r.corpus_id,r.digest,r.image_bytes,r.build_id,r.commit_sha,r.builder,r.host_id,CASE WHEN r.deprecated_at IS NULL THEN 'active' ELSE 'deprecated' END,r.created_at,r.deprecated_at,r.extensions FROM corpus_releases r JOIN corpora c ON c.id=r.corpus_id`

func scanCorpusRelease(row pgx.Row) (CorpusRelease, error) {
	var r CorpusRelease
	err := row.Scan(&r.ID, &r.Name, &r.Version, &r.CorpusID, &r.Digest, &r.ImageBytes, &r.BuildID, &r.Commit, &r.Builder, &r.HostID, &r.State, &r.CreatedAt, &r.DeprecatedAt, &r.Extensions)
	return r, corpusRowError(err)
}
func corpusRowError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return persistence.ErrNotFound
	}
	return err
}
func Page[T any](ctx context.Context, tx pgx.Tx, limit int, scan func(pgx.Row) (T, error), sql string, args ...any) ([]T, error) {
	if limit < 1 || limit > 201 {
		return nil, persistence.ErrInput
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func Get(ctx context.Context, tx pgx.Tx, tenant string, id string) (Corpus, error) {
	return scanCorpus(tx.QueryRow(ctx, corpusSelect+" WHERE c.tenant_id=$1 AND c.id=$2", tenant, id))
}

func List(ctx context.Context, tx pgx.Tx, tenant string, name, after string, limit int) ([]Corpus, error) {
	return Page(ctx, tx, limit, scanCorpus, corpusSelect+" WHERE c.tenant_id=$1 AND ($2='' OR c.name=$2) AND c.id>$3 ORDER BY c.id LIMIT $4", tenant, name, after, limit)
}

func GetBuild(ctx context.Context, tx pgx.Tx, tenant string, id string) (CorpusBuild, error) {
	return scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.tenant_id=$1 AND b.id=$2", tenant, id))
}

func ListBuilds(ctx context.Context, tx pgx.Tx, tenant string, corpus, state, after string, limit int) ([]CorpusBuild, error) {
	return Page(ctx, tx, limit, scanBuild, buildSelect+` WHERE b.tenant_id=$1 AND ($2='' OR b.corpus_id=$2) AND ($3='' OR b.state=$3) AND ($4='' OR (b.created_at,b.id)<(SELECT created_at,id FROM corpus_builds WHERE tenant_id=$1 AND id=$4)) ORDER BY b.created_at DESC,b.id DESC LIMIT $5`, tenant, corpus, state, after, limit)
}

func GetRelease(ctx context.Context, tx pgx.Tx, tenant string, id string) (CorpusRelease, error) {
	return scanCorpusRelease(tx.QueryRow(ctx, releaseSelect+" WHERE r.tenant_id=$1 AND r.id=$2", tenant, id))
}

func ListReleases(ctx context.Context, tx pgx.Tx, tenant string, corpus, after string, deprecated bool, limit int) ([]CorpusRelease, error) {
	return Page(ctx, tx, limit, scanCorpusRelease, releaseSelect+` WHERE r.tenant_id=$1 AND ($2='' OR r.corpus_id=$2) AND r.id>$3 AND ($4 OR r.deprecated_at IS NULL) ORDER BY r.id LIMIT $5`, tenant, corpus, after, deprecated, limit)
}

// LockBuild reads a tenant's build for a state transition.
func LockBuild(ctx context.Context, tx pgx.Tx, tenant, id string) (CorpusBuild, error) {
	return scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.id=$1 AND b.tenant_id=$2 FOR UPDATE", id, tenant))
}

func ReleaseVersion(ctx context.Context, tx pgx.Tx, tenant, id string, version int) (CorpusRelease, error) {
	return scanCorpusRelease(tx.QueryRow(ctx, releaseSelect+" WHERE r.tenant_id=$1 AND r.corpus_id=$2 AND r.version=$3", tenant, id, version))
}

const tenantCorpusPins = `SELECT digest,image_bytes AS size FROM corpus_releases WHERE tenant_id=$1 AND deprecated_at IS NULL
 UNION ALL SELECT ext->>'digest',(ext->>'bytes')::bigint FROM corpus_releases CROSS JOIN LATERAL jsonb_array_elements(extensions) ext WHERE tenant_id=$1 AND deprecated_at IS NULL
 UNION ALL SELECT image_digest,image_bytes FROM corpus_builds WHERE tenant_id=$1 AND state='REVIEW'
 UNION ALL SELECT x.image_digest,x.image_bytes FROM corpus_extensions x JOIN corpus_builds b ON b.id=x.build_id WHERE b.tenant_id=$1 AND b.state='REVIEW' AND x.state='READY'`

// Occupation counts identical active images once, including their reviews.
func Occupation(ctx context.Context, tx pgx.Tx, tenant string) (bytes int64, builds int, err error) {
	err = tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0),(SELECT count(*) FROM corpus_builds WHERE tenant_id=$1 AND state IN ('QUEUED','FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING'))
 FROM (SELECT digest,max(size) AS bytes FROM (
 `+tenantCorpusPins+`
 ) pins GROUP BY digest) held`, tenant).Scan(&bytes, &builds)
	return
}

// HoldsDigest reports whether this organization already accounts for an image.
func HoldsDigest(ctx context.Context, tx pgx.Tx, tenant, digest string) (bool, error) {
	var held bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ("+tenantCorpusPins+") pins WHERE digest=$2)", tenant, digest).Scan(&held)
	return held, err
}
