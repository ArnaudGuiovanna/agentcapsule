package controlplane

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

type CorpusBinding struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Mount   string `json:"mount,omitempty"`
}
type AgentCorpusEntry struct {
	Mount   string                  `json:"mount"`
	Release *CorpusReleaseReference `json:"release,omitempty"`
	BuildID string                  `json:"build_id,omitempty"`
	Digest  string                  `json:"digest"`
}
type AgentCorpora struct {
	AgentID  string             `json:"agent_id"`
	Corpora  []AgentCorpusEntry `json:"corpora"`
	Previous []AgentCorpusEntry `json:"previous,omitempty"`
	Applies  string             `json:"applies"`
}
type resolvedCorpus struct {
	corpus, release, mount string
}

func resolveCorpusBindings(ctx context.Context, tx pgx.Tx, tenant, host string, entries []CorpusBinding, active bool) ([]resolvedCorpus, error) {
	if len(entries) > 4 {
		return nil, ErrInput
	}
	mounts := map[string]bool{}
	names := map[string]bool{}
	bindings := make([]resolvedCorpus, 0, len(entries))
	for _, entry := range entries {
		m := entry.Mount
		if m == "" {
			m = entry.Name
		}
		if !sourceCredentialName.MatchString(entry.Name) || entry.Version < 1 || entry.Version > 2147483647 || !capsuleprotocol.ValidCorpusMount(m) || mounts[m] || names[entry.Name] {
			return nil, ErrInput
		}
		mounts[m], names[entry.Name] = true, true
		bound := resolvedCorpus{mount: m}
		err := tx.QueryRow(ctx, `SELECT r.corpus_id,r.id FROM corpus_releases r JOIN corpora c ON c.id=r.corpus_id WHERE r.tenant_id=$1 AND r.host_id=$2 AND c.name=$3 AND r.version=$4 AND (NOT $5 OR r.deprecated_at IS NULL) FOR SHARE OF r`, tenant, host, entry.Name, entry.Version, active).Scan(&bound.corpus, &bound.release)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCorpusUnavailable
		}
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, bound)
	}
	return bindings, nil
}
func insertCorpusBindings(batch *pgx.Batch, tenant string, agents []string, entries []resolvedCorpus) {
	for n, e := range entries {
		batch.Queue(`INSERT INTO agent_corpora(tenant_id,agent_id,position,corpus_id,release_id,mount) SELECT $1,id,$3,$4,$5,$6 FROM unnest($2::text[]) id`, tenant, agents, n, e.corpus, e.release, e.mount)
	}
}
func agentCorpora(ctx context.Context, tx pgx.Tx, tenant, id string) (AgentCorpora, error) {
	v := AgentCorpora{AgentID: id, Applies: "next_boot", Corpora: []AgentCorpusEntry{}}
	rows, err := tx.Query(ctx, `SELECT ac.mount,CASE WHEN r.id IS NOT NULL THEN jsonb_build_object('id',r.id,'name',c.name,'version',r.version) END,
 coalesce(b.id,''),coalesce(r.digest,b.image_digest) FROM agent_corpora ac JOIN corpora c ON c.id=ac.corpus_id LEFT JOIN corpus_releases r ON r.id=ac.release_id LEFT JOIN corpus_builds b ON b.id=ac.build_id
 WHERE ac.tenant_id=$1 AND ac.agent_id=$2 AND (b.id IS NULL OR b.state='PUBLISHED' OR b.state='REVIEW' AND b.review_expires_at>clock_timestamp()) ORDER BY ac.position`, tenant, id)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AgentCorpusEntry
		if err = rows.Scan(&e.Mount, &e.Release, &e.BuildID, &e.Digest); err != nil {
			return v, err
		}
		v.Corpora = append(v.Corpora, e)
	}
	return v, rows.Err()
}
func (a *Accounts) GetAgentCorpora(ctx context.Context, p Principal, id string) (AgentCorpora, error) {
	return corpusRead(ctx, a, p, authorization.ReadCorpus, func(tx pgx.Tx) (AgentCorpora, error) {
		if err := corpusPermission(ctx, tx, p, authorization.ReadAgentMetadata); err != nil {
			return AgentCorpora{}, err
		}
		if _, _, err := tenantAgentForUpdate(ctx, tx, p, id); err != nil {
			return AgentCorpora{}, err
		}
		return agentCorpora(ctx, tx, p.TenantID, id)
	})
}

func lockBindingAgent(ctx context.Context, tx pgx.Tx, p Principal, id string, mounting bool) (string, error) {
	a, host, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return "", err
	}
	if a.Phase != "LIVE" {
		return "", ErrUnavailable
	}
	if mounting {
		var release, image string
		if err = tx.QueryRow(ctx, "SELECT release_id,coalesce(system_image,'') FROM agent_specs WHERE agent_id=$1", id).Scan(&release, &image); err != nil {
			return "", err
		}
		if err = corporaMountable(ctx, tx, release, image); err != nil {
			return "", err
		}
	}
	return host, nil
}

func (a *Accounts) SetAgentCorpora(ctx context.Context, p Principal, id, key string, entries []CorpusBinding) (APIReceipt, error) {
	if entries == nil {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ConfigureAgent, key, "agent.corpora/"+id, entries, func(tx pgx.Tx) (int, any, error) {
		host, err := lockBindingAgent(ctx, tx, p, id, len(entries) > 0)
		if err != nil {
			return 0, nil, err
		}
		previous, err := agentCorpora(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		resolved, err := resolveCorpusBindings(ctx, tx, p.TenantID, host, entries, true)
		if err != nil {
			return 0, nil, err
		}
		batch := &pgx.Batch{}
		batch.Queue("DELETE FROM agent_corpora WHERE agent_id=$1", id)
		insertCorpusBindings(batch, p.TenantID, []string{id}, resolved)
		if err = tx.SendBatch(ctx, batch).Close(); err != nil {
			return 0, nil, err
		}
		v, err := agentCorpora(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		v.Previous = previous.Corpora
		return 200, v, auditTenantAgent(ctx, tx, p, id, nil, "agent.corpora_changed")
	}, authorization.ReadCorpus)
}

type TryCorpusInput struct {
	AgentID string `json:"agent_id"`
	Mount   string `json:"mount,omitempty"`
}

func (a *Accounts) TryCorpusBuild(ctx context.Context, p Principal, build, key string, in TryCorpusInput) (APIReceipt, error) {
	if !validOrganizationText(in.AgentID, 100) {
		return APIReceipt{}, ErrInput
	}
	return a.corpusMutation(ctx, p, authorization.ManageCorpus, key, "corpus.try/"+build, in, func(tx pgx.Tx) (int, any, error) {
		var corpus, name, state, host string
		var available bool
		err := tx.QueryRow(ctx, `SELECT b.corpus_id,c.name,b.state,coalesce(b.host_id,''),coalesce(b.review_expires_at>clock_timestamp(),false) FROM corpus_builds b JOIN corpora c ON c.id=b.corpus_id WHERE b.id=$1 AND b.tenant_id=$2 FOR UPDATE OF b`, build, p.TenantID).Scan(&corpus, &name, &state, &host, &available)
		if err != nil {
			return 0, nil, corpusRowError(err)
		}
		if state != "REVIEW" || !available {
			return 0, nil, ErrTransition
		}
		agentHost, err := lockBindingAgent(ctx, tx, p, in.AgentID, true)
		if err != nil {
			return 0, nil, err
		}
		if agentHost != host {
			return 0, nil, ErrCorpusUnavailable
		}
		mount := in.Mount
		if mount == "" {
			mount = name
		}
		if !capsuleprotocol.ValidCorpusMount(mount) {
			return 0, nil, ErrInput
		}
		var position *int
		err = tx.QueryRow(ctx, `SELECT coalesce((SELECT position FROM agent_corpora WHERE agent_id=$1 AND corpus_id=$2),
 (SELECT min(pos) FROM generate_series(0,3) pos WHERE NOT EXISTS (SELECT 1 FROM agent_corpora WHERE agent_id=$1 AND position=pos))) WHERE NOT EXISTS(SELECT 1 FROM agent_corpora WHERE agent_id=$1 AND corpus_id<>$2 AND mount=$3)`, in.AgentID, corpus, mount).Scan(&position)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && position == nil {
			return 0, nil, ErrInput
		}
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_corpora(tenant_id,agent_id,corpus_id,position,mount,build_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(agent_id,corpus_id) DO UPDATE SET release_id=NULL,build_id=EXCLUDED.build_id,mount=EXCLUDED.mount`, p.TenantID, in.AgentID, corpus, *position, mount, build)
		if err != nil {
			return 0, nil, err
		}
		v, err := agentCorpora(ctx, tx, p.TenantID, in.AgentID)
		if err != nil {
			return 0, nil, err
		}
		return 200, v, auditCorpus(ctx, tx, p, "corpus_build.tried", corpus, build, "", in.AgentID)
	}, authorization.ConfigureAgent)
}

// BootCorpus is a tenant-checked disk to resolve on the agent's host at boot.
type BootCorpus struct{ ReleaseID, Digest, UUID, Mount string }

func (s *Store) BootCorpora(ctx context.Context, id, host string) ([]BootCorpus, error) {
	rows, err := s.pool.Query(ctx, `SELECT coalesce(ac.release_id,ac.build_id),coalesce(r.digest,b.image_digest),coalesce(r.image_uuid,b.image_uuid)::text,ac.mount
 FROM agent_corpora ac JOIN agent_specs x ON x.agent_id=ac.agent_id LEFT JOIN corpus_releases r ON r.id=ac.release_id LEFT JOIN corpus_builds b ON b.id=ac.build_id
 WHERE ac.agent_id=$1 AND x.host_id=$2 AND (b.id IS NULL OR b.state='PUBLISHED' OR b.state='REVIEW' AND b.review_expires_at>clock_timestamp()) ORDER BY ac.position`, id, host)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[BootCorpus])
}
