package controlplane

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	corpusdb "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/corpus"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"github.com/jackc/pgx/v5"
)

var (
	ErrCorpusNameTaken             = errors.New("corpus name taken")
	ErrCorpusUnavailable           = errors.New("corpus unavailable")
	ErrSourceCredentialUnavailable = errors.New("source credential unavailable for this repository")
	ErrCorpusVersionConflict       = errors.New("corpus version already names another digest")
)

type CorpusSource = corpusdb.CorpusSource
type CreateCorpusInput = corpusdb.CreateCorpusInput
type CorpusReleaseReference = corpusdb.CorpusReleaseReference
type Corpus = corpusdb.Corpus
type CorpusBuild = corpusdb.CorpusBuild
type CorpusRelease = corpusdb.CorpusRelease

type RequestCorpusBuildInput struct {
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
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
		v, err := corpusdb.Get(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return 201, v, auditCorpus(ctx, tx, p, "corpus.created", id, "", "", "")
	})
}
func (a *Accounts) Corpus(ctx context.Context, p Principal, id string) (Corpus, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (Corpus, error) {
		return corpusdb.Get(ctx, tx, p.TenantID, id)
	})
}

func (a *Accounts) ListCorpora(ctx context.Context, p Principal, name, after string, limit int) ([]Corpus, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]Corpus, error) {
		return corpusdb.List(ctx, tx, p.TenantID, name, after, limit)
	})
}

func (a *Accounts) CorpusBuild(ctx context.Context, p Principal, id string) (CorpusBuild, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (CorpusBuild, error) {
		return corpusdb.GetBuild(ctx, tx, p.TenantID, id)
	})
}

func (a *Accounts) ListCorpusBuilds(ctx context.Context, p Principal, corpus, state, after string, limit int) ([]CorpusBuild, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]CorpusBuild, error) {
		return corpusdb.ListBuilds(ctx, tx, p.TenantID, corpus, state, after, limit)
	})
}

func (a *Accounts) CorpusRelease(ctx context.Context, p Principal, id string) (CorpusRelease, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (CorpusRelease, error) {
		return corpusdb.GetRelease(ctx, tx, p.TenantID, id)
	})
}

func (a *Accounts) ListCorpusReleases(ctx context.Context, p Principal, corpus, after string, deprecated bool, limit int) ([]CorpusRelease, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) ([]CorpusRelease, error) {
		return corpusdb.ListReleases(ctx, tx, p.TenantID, corpus, after, deprecated, limit)
	})
}
