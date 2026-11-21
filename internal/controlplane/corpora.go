package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"github.com/jackc/pgx/v5"
)

var (
	ErrCorpusNameTaken             = errors.New("corpus name taken")
	ErrCorpusUnavailable           = errors.New("corpus unavailable")
	ErrSourceCredentialUnavailable = errors.New("source credential unavailable for this repository")
	ErrCorpusVersionConflict       = errors.New("corpus version already names another digest")
)

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
type RequestCorpusBuildInput struct {
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
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
		return ErrNotFound
	}
	return err
}
func corpusPermission(ctx context.Context, tx pgx.Tx, p Principal, action authorization.Action) error {
	scope, _ := authorization.RequiredScope(action)
	current, err := authorizeTenant(ctx, tx, p, scope)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), action) {
		return ErrForbidden
	}
	return nil
}
func corpusRead[T any](ctx context.Context, a *Accounts, p Principal, action authorization.Action, read func(pgx.Tx) (T, error)) (T, error) {
	var zero T
	tx, err := a.store.begin(ctx)
	if err != nil {
		return zero, err
	}
	defer rollback(tx)
	if err = corpusPermission(ctx, tx, p, action); err != nil {
		return zero, err
	}
	v, err := read(tx)
	if err != nil {
		return zero, err
	}
	return v, commit(ctx, tx)
}
func (a *Accounts) corpusMutation(ctx context.Context, p Principal, action authorization.Action, key, op string, in any, change func(pgx.Tx) (int, any, error), extra ...authorization.Action) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, action); err != nil {
		return APIReceipt{}, err
	}
	for _, required := range extra {
		if err = corpusPermission(ctx, tx, p, required); err != nil {
			return APIReceipt{}, err
		}
	}
	out, err := a.withTenantReceipt(ctx, tx, p, op, key, in, func() (int, any, error) { return change(tx) })
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}
func auditCorpus(ctx context.Context, tx pgx.Tx, p Principal, action, corpus, build, release, agent string) error {
	_, err := tx.Exec(ctx, `INSERT INTO corpus_audit(id,tenant_id,actor_principal_id,credential_id,action,corpus_id,build_id,release_id,agent_id)
 VALUES($1,$2,$3,nullif($4,''),$5,nullif($6,''),nullif($7,''),nullif($8,''),nullif($9,''))`, newID("audit"), p.TenantID, p.ID, p.TokenID, action, corpus, build, release, agent)
	return err
}
func (a *Accounts) CreateCorpus(ctx context.Context, p Principal, key string, in CreateCorpusInput) (APIReceipt, error) {
	src, err := repository.ParseURL(in.Source.Kind, in.Source.URL)
	if err != nil || !sourceCredentialName.MatchString(in.Name) || len(in.Title) > 200 || !repository.ValidRef(in.Source.Ref) || len(in.Source.Path) > 1024 || strings.ContainsAny(in.Source.Path, "\\\x00") || in.Source.Path != "" && (in.Source.Path == "." || !fs.ValidPath(in.Source.Path)) || len(in.Source.CredentialID) > 100 {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.create", in, func(tx pgx.Tx) (int, any, error) {
		if in.Source.CredentialID != "" {
			var ok bool
			err := tx.QueryRow(ctx, `SELECT status='active' AND kind=$3 AND host=$4 FROM source_credentials WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, in.Source.CredentialID, src.Kind, src.Host).Scan(&ok)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && !ok {
				return 0, nil, ErrSourceCredentialUnavailable
			}
			if err != nil {
				return 0, nil, err
			}
		}
		id := newID("cor")
		tag, err := tx.Exec(ctx, `INSERT INTO corpora(id,tenant_id,name,title,source_kind,source_url,source_ref,source_path,source_credential_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,nullif($9,'')) ON CONFLICT(tenant_id,name) DO NOTHING`, id, p.TenantID, in.Name, in.Title, src.Kind, in.Source.URL, in.Source.Ref, in.Source.Path, in.Source.CredentialID)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, ErrCorpusNameTaken
		}
		v, err := scanCorpus(tx.QueryRow(ctx, corpusSelect+" WHERE c.id=$1", id))
		if err != nil {
			return 0, nil, err
		}
		return 201, v, auditCorpus(ctx, tx, p, "corpus.created", id, "", "", "")
	})
}
func corpusPage[T any](ctx context.Context, tx pgx.Tx, limit int, scan func(pgx.Row) (T, error), sql string, args ...any) ([]T, error) {
	if limit < 1 || limit > 201 {
		return nil, ErrInput
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
func (a *Accounts) Corpus(ctx context.Context, p Principal, id string) (Corpus, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (Corpus, error) {
		return scanCorpus(tx.QueryRow(ctx, corpusSelect+" WHERE c.tenant_id=$1 AND c.id=$2", p.TenantID, id))
	})
}
func (a *Accounts) ListCorpora(ctx context.Context, p Principal, name, after string, limit int) ([]Corpus, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]Corpus, error) {
		return corpusPage(ctx, tx, limit, scanCorpus, corpusSelect+" WHERE c.tenant_id=$1 AND ($2='' OR c.name=$2) AND c.id>$3 ORDER BY c.id LIMIT $4", p.TenantID, name, after, limit)
	})
}
func (a *Accounts) CorpusBuild(ctx context.Context, p Principal, id string) (CorpusBuild, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (CorpusBuild, error) {
		return scanBuild(tx.QueryRow(ctx, buildSelect+" WHERE b.tenant_id=$1 AND b.id=$2", p.TenantID, id))
	})
}
func (a *Accounts) ListCorpusBuilds(ctx context.Context, p Principal, corpus, state, after string, limit int) ([]CorpusBuild, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]CorpusBuild, error) {
		return corpusPage(ctx, tx, limit, scanBuild, buildSelect+` WHERE b.tenant_id=$1 AND ($2='' OR b.corpus_id=$2) AND ($3='' OR b.state=$3) AND ($4='' OR (b.created_at,b.id)<(SELECT created_at,id FROM corpus_builds WHERE tenant_id=$1 AND id=$4)) ORDER BY b.created_at DESC,b.id DESC LIMIT $5`, p.TenantID, corpus, state, after, limit)
	})
}
func (a *Accounts) CorpusRelease(ctx context.Context, p Principal, id string) (CorpusRelease, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (CorpusRelease, error) {
		return scanCorpusRelease(tx.QueryRow(ctx, releaseSelect+" WHERE r.tenant_id=$1 AND r.id=$2", p.TenantID, id))
	})
}
func (a *Accounts) ListCorpusReleases(ctx context.Context, p Principal, corpus, after string, deprecated bool, limit int) ([]CorpusRelease, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]CorpusRelease, error) {
		return corpusPage(ctx, tx, limit, scanCorpusRelease, releaseSelect+` WHERE r.tenant_id=$1 AND ($2='' OR r.corpus_id=$2) AND r.id>$3 AND ($4 OR r.deprecated_at IS NULL) ORDER BY r.id LIMIT $5`, p.TenantID, corpus, after, deprecated, limit)
	})
}
