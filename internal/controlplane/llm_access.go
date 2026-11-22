package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/budgets"
	"github.com/jackc/pgx/v5"
)

// ErrLLMAliasDenied refuses a model call, before any reservation, when the
// alias's access is "listed" and no active grant names the calling agent,
// directly or through an active assignment of the agent to an active team.
var ErrLLMAliasDenied = budgets.ErrAliasDenied

// LLMAliasGrant lets one agent, or the agents assigned to one team, call an
// alias whose access is "listed" (ADR 011).
type LLMAliasGrant struct {
	ID        string     `json:"id"`
	Alias     string     `json:"alias"`
	AgentID   *string    `json:"agent_id,omitempty"`
	TeamID    *string    `json:"team_id,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type CreateLLMAliasGrantInput struct {
	AgentID string `json:"agent_id,omitempty"`
	TeamID  string `json:"team_id,omitempty"`
}

type SetLLMAliasAccessInput struct {
	Access string `json:"access"`
}

// SetLLMAliasPricesInput replaces the alias's prices. Both token prices are
// required, so that a price is never left at zero by omission; zero then means
// a free model. The prices of audio per minute and of OCR per page are
// optional: absent, that unit becomes unpriced, and a hard cost budget refuses
// its calls (ADR 023 §12).
type SetLLMAliasPricesInput struct {
	InputMicroPerMTok   *int64 `json:"input_micro_per_mtok"`
	OutputMicroPerMTok  *int64 `json:"output_micro_per_mtok"`
	AudioMicroPerMinute *int64 `json:"audio_micro_per_minute,omitempty"`
	OCRMicroPerPage     *int64 `json:"ocr_micro_per_page,omitempty"`
}

const grantColumns = `id,alias,agent_id,team_id,status,created_at,revoked_at`

func scanGrant(row pgx.Row) (LLMAliasGrant, error) {
	var g LLMAliasGrant
	err := row.Scan(&g.ID, &g.Alias, &g.AgentID, &g.TeamID, &g.Status, &g.CreatedAt, &g.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return g, err
}

func auditLLMGrant(ctx context.Context, tx pgx.Tx, p Principal, provider, alias, grant, subject, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO llm_audit(id,tenant_id,actor_principal_id,provider_id,alias,grant_id,subject_id,action) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		newID("audit"), p.TenantID, p.ID, provider, alias, grant, subject, action)
	return err
}

// aliasForChange locks an alias of the caller's organization for a policy
// change. A disabled alias cannot change: it is never reachable again.
func aliasForChange(ctx context.Context, tx pgx.Tx, tenant, alias string) (LLMAlias, error) {
	v, err := scanAlias(tx.QueryRow(ctx, `SELECT `+aliasColumns+` FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2 FOR UPDATE`, tenant, alias))
	if err != nil {
		return LLMAlias{}, err
	}
	if v.Status != "active" {
		return LLMAlias{}, ErrTransition
	}
	return v, nil
}

// SetLLMAliasAccess opens an alias to every agent of the organization or
// restricts it to the agents its grants name. It applies from the next
// reservation; a call already reserved goes on.
func (a *Accounts) SetLLMAliasAccess(ctx context.Context, p Principal, alias, key string, in SetLLMAliasAccessInput) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) || !validAliasAccess(in.Access) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ Alias, Access string }{alias, in.Access}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.access", key, hashed, func() (int, any, error) {
		cur, err := aliasForChange(ctx, tx, p.TenantID, alias)
		if err != nil {
			return 0, nil, err
		}
		if cur.Access == in.Access {
			return 200, cur, nil
		}
		v, err := scanAlias(tx.QueryRow(ctx, `UPDATE llm_model_aliases SET access=$3 WHERE tenant_id=$1 AND alias=$2 RETURNING `+aliasColumns, p.TenantID, alias, in.Access))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, v.ProviderID, &alias, "alias.access_set"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// SetLLMAliasPrices replaces an alias's prices. A call keeps the prices of its
// reservation, so the change applies to calls reserved after it.
func (a *Accounts) SetLLMAliasPrices(ctx context.Context, p Principal, alias, key string, in SetLLMAliasPricesInput) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) || in.InputMicroPerMTok == nil || in.OutputMicroPerMTok == nil ||
		!validPrice(in.InputMicroPerMTok) || !validPrice(in.OutputMicroPerMTok) || !validPrice(in.AudioMicroPerMinute) || !validPrice(in.OCRMicroPerPage) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
		return APIReceipt{}, err
	}
	// Token prices alone keep the request hash they had before unit prices.
	var hashed any = struct {
		Alias         string
		Input, Output int64
	}{alias, *in.InputMicroPerMTok, *in.OutputMicroPerMTok}
	if in.AudioMicroPerMinute != nil || in.OCRMicroPerPage != nil {
		hashed = struct {
			Alias         string
			Input, Output int64
			Audio, Page   *int64
		}{alias, *in.InputMicroPerMTok, *in.OutputMicroPerMTok, in.AudioMicroPerMinute, in.OCRMicroPerPage}
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.prices", key, hashed, func() (int, any, error) {
		cur, err := aliasForChange(ctx, tx, p.TenantID, alias)
		if err != nil {
			return 0, nil, err
		}
		if cur.Priced && cur.InputMicroPerMTok == *in.InputMicroPerMTok && cur.OutputMicroPerMTok == *in.OutputMicroPerMTok &&
			samePrice(cur.AudioMicroPerMinute, in.AudioMicroPerMinute) && samePrice(cur.OCRMicroPerPage, in.OCRMicroPerPage) {
			return 200, cur, nil
		}
		v, err := scanAlias(tx.QueryRow(ctx, `UPDATE llm_model_aliases SET input_micro_per_mtok=$3,output_micro_per_mtok=$4,priced=true,
            audio_micro_per_minute=$5,ocr_micro_per_page=$6 WHERE tenant_id=$1 AND alias=$2 RETURNING `+aliasColumns,
			p.TenantID, alias, *in.InputMicroPerMTok, *in.OutputMicroPerMTok, in.AudioMicroPerMinute, in.OCRMicroPerPage))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, v.ProviderID, &alias, "alias.prices_set"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func samePrice(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// CreateLLMAliasGrant names an agent, or a team, that may call an alias whose
// access is "listed". A grant on an alias open to the organization is kept and
// applies once the alias is listed.
func (a *Accounts) CreateLLMAliasGrant(ctx context.Context, p Principal, alias, key string, in CreateLLMAliasGrantInput) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) || (in.AgentID == "") == (in.TeamID == "") ||
		(in.AgentID != "" && !validOrganizationText(in.AgentID, 100)) || (in.TeamID != "" && !validOrganizationText(in.TeamID, 100)) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ Alias, AgentID, TeamID string }{alias, in.AgentID, in.TeamID}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.grant", key, hashed, func() (int, any, error) {
		cur, err := aliasForChange(ctx, tx, p.TenantID, alias)
		if err != nil {
			return 0, nil, err
		}
		subject := in.AgentID
		if in.AgentID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND id=$2)`, p.TenantID, in.AgentID).Scan(&ok); err != nil {
				return 0, nil, err
			}
			if !ok {
				return 0, nil, ErrNotFound
			}
		} else {
			subject = in.TeamID
			team, err := teamByID(ctx, tx, p.TenantID, in.TeamID)
			if err != nil {
				return 0, nil, err
			}
			if team.Status != "active" {
				return 0, nil, ErrTransition
			}
		}
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_alias_grants WHERE tenant_id=$1 AND alias=$2 AND status='active'
            AND (agent_id=nullif($3,'') OR team_id=nullif($4,'')))`, p.TenantID, alias, in.AgentID, in.TeamID).Scan(&taken); err != nil {
			return 0, nil, err
		}
		if taken {
			return 0, nil, ErrConflict
		}
		g, err := scanGrant(tx.QueryRow(ctx, `INSERT INTO llm_alias_grants(id,tenant_id,alias,agent_id,team_id,created_by) VALUES($1,$2,$3,nullif($4,''),nullif($5,''),$6)
            RETURNING `+grantColumns, newID("llmg"), p.TenantID, alias, in.AgentID, in.TeamID, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLMGrant(ctx, tx, p, cur.ProviderID, alias, g.ID, subject, "alias.grant_created"); err != nil {
			return 0, nil, err
		}
		return 201, g, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// RevokeLLMAliasGrant ends a grant from the next reservation. Revoking the last
// grant of a listed alias leaves it reachable by no agent, never by all.
func (a *Accounts) RevokeLLMAliasGrant(ctx context.Context, p Principal, alias, id, key string) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) || !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.grant.revoke", key, struct{ Alias, ID string }{alias, id}, func() (int, any, error) {
		cur, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+` FROM llm_alias_grants WHERE tenant_id=$1 AND alias=$2 AND id=$3 FOR UPDATE`, p.TenantID, alias, id))
		if err != nil {
			return 0, nil, err
		}
		if cur.Status == "revoked" {
			return 200, cur, nil
		}
		g, err := scanGrant(tx.QueryRow(ctx, `UPDATE llm_alias_grants SET status='revoked',revoked_by=$4,revoked_at=clock_timestamp()
            WHERE tenant_id=$1 AND alias=$2 AND id=$3 RETURNING `+grantColumns, p.TenantID, alias, id, p.ID))
		if err != nil {
			return 0, nil, err
		}
		var provider string
		if err = tx.QueryRow(ctx, `SELECT provider_id FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2`, p.TenantID, alias).Scan(&provider); err != nil {
			return 0, nil, err
		}
		subject := g.AgentID
		if subject == nil {
			subject = g.TeamID
		}
		if err = auditLLMGrant(ctx, tx, p, provider, alias, g.ID, *subject, "alias.grant_revoked"); err != nil {
			return 0, nil, err
		}
		return 200, g, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// ListLLMAliasGrants lists an alias's grants, revoked ones included.
func (a *Accounts) ListLLMAliasGrants(ctx context.Context, p Principal, alias, after string, limit int) ([]LLMAliasGrant, error) {
	if !validOrganizationText(alias, 100) || limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	items := []LLMAliasGrant{}
	err := a.readLLM(ctx, p, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2)`, p.TenantID, alias).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT `+grantColumns+` FROM llm_alias_grants WHERE tenant_id=$1 AND alias=$2 AND id>$3 ORDER BY id LIMIT $4`, p.TenantID, alias, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGrant(rows)
			if err != nil {
				return err
			}
			items = append(items, g)
		}
		return rows.Err()
	})
	return items, err
}

// aliasGranted says whether an agent may call a listed alias: an active grant
// names the agent, or names an active team to which the agent has an active
// assignment.
func aliasGranted(ctx context.Context, tx pgx.Tx, tenant, alias, agent string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_alias_grants g WHERE g.tenant_id=$1 AND g.alias=$2 AND g.status='active' AND (g.agent_id=$3
        OR EXISTS(SELECT 1 FROM agent_assignments s JOIN teams t ON (t.tenant_id,t.id)=(s.tenant_id,s.team_id)
            WHERE s.tenant_id=g.tenant_id AND s.agent_id=$3 AND s.team_id=g.team_id AND s.status='active' AND t.status='active')))`,
		tenant, alias, agent).Scan(&ok)
	return ok, err
}
