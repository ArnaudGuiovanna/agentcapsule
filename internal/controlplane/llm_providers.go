package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// LLMProvider is the metadata of a tenant's upstream provider. The credential
// is write-only: no field, receipt or audit event ever carries it back.
type LLMProvider struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	BaseURL    string     `json:"base_url"`
	Status     string     `json:"status"`
	Generation int64      `json:"secret_generation"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

type LLMAlias struct {
	Alias         string    `json:"alias"`
	ProviderID    string    `json:"provider_id"`
	UpstreamModel string    `json:"upstream_model"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	// Estimation prices; zero when not set.
	InputMicroPerMTok  int64 `json:"input_micro_per_mtok"`
	OutputMicroPerMTok int64 `json:"output_micro_per_mtok"`
}

type CreateLLMProviderInput struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url"`
	Secret  string `json:"secret"`
}

type CreateLLMAliasInput struct {
	Alias         string `json:"alias"`
	ProviderID    string `json:"provider_id"`
	UpstreamModel string `json:"upstream_model"`
	// Optional price used only to ESTIMATE cost, in micro-units of the tenant's
	// currency per million tokens. Zero means "no estimate".
	InputMicroPerMTok  int64 `json:"input_micro_per_mtok,omitempty"`
	OutputMicroPerMTok int64 `json:"output_micro_per_mtok,omitempty"`
}

// LLMRoute is what the gateway needs for one call. It holds a decrypted
// credential and must stay in the gateway process memory.
type LLMRoute struct {
	Kind, BaseURL, UpstreamModel string
	Secret                       string
}

func validProviderURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 300 || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		// Plain HTTP only to a local model server; never across a network.
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

func validProviderSecret(s string) bool {
	return len(s) >= 8 && len(s) <= 4096 && strings.TrimSpace(s) == s && strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func (a *Accounts) sealProviderSecret(tenant, provider string, generation int64, secret string) []byte {
	nonce := make([]byte, a.llm.NonceSize())
	_, _ = rand.Read(nonce)
	return a.llm.Seal(nonce, nonce, []byte(secret), providerAAD(tenant, provider, generation))
}

func (a *Accounts) openProviderSecret(tenant, provider string, generation int64, sealed []byte) (string, error) {
	n := a.llm.NonceSize()
	if len(sealed) < n {
		return "", ErrInput
	}
	plain, err := a.llm.Open(nil, sealed[:n], sealed[n:], providerAAD(tenant, provider, generation))
	return string(plain), err
}

func providerAAD(tenant, provider string, generation int64) []byte {
	b := binary.BigEndian.AppendUint64([]byte("agentcapsule.llm-provider/"+tenant+"/"+provider+"/"), uint64(generation))
	return b
}

func secretDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

const providerColumns = `id,name,kind,base_url,status,secret_generation,created_at,rotated_at`

func scanProvider(row pgx.Row) (LLMProvider, error) {
	var v LLMProvider
	err := row.Scan(&v.ID, &v.Name, &v.Kind, &v.BaseURL, &v.Status, &v.Generation, &v.CreatedAt, &v.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func auditLLM(ctx context.Context, tx pgx.Tx, p Principal, provider string, alias *string, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO llm_audit(id,tenant_id,actor_principal_id,provider_id,alias,action) VALUES($1,$2,$3,$4,$5,$6)`,
		newID("audit"), p.TenantID, p.ID, provider, alias, action)
	return err
}

func (a *Accounts) CreateLLMProvider(ctx context.Context, p Principal, key string, in CreateLLMProviderInput) (APIReceipt, error) {
	if !validOrganizationText(in.Name, 100) || (in.Kind != "openai_compatible" && in.Kind != "anthropic") || !validProviderURL(in.BaseURL) || !validProviderSecret(in.Secret) {
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
	hashed := struct {
		Name, Kind, BaseURL, SecretSHA256 string
	}{in.Name, in.Kind, in.BaseURL, secretDigest(in.Secret)}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.provider.create", key, hashed, func() (int, any, error) {
		id := newID("llmp")
		v, err := scanProvider(tx.QueryRow(ctx, `INSERT INTO llm_providers(id,tenant_id,name,kind,base_url,secret_ciphertext,created_by)
            VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+providerColumns, id, p.TenantID, in.Name, in.Kind, in.BaseURL, a.sealProviderSecret(p.TenantID, id, 1, in.Secret), p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, id, nil, "provider.created"); err != nil {
			return 0, nil, err
		}
		return 201, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// RotateLLMProviderSecret replaces the credential without rebuilding anything:
// the next resolved call uses the new generation.
func (a *Accounts) RotateLLMProviderSecret(ctx context.Context, p Principal, id, key, secret string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !validProviderSecret(secret) {
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
	var generation int64
	var status string
	if err = tx.QueryRow(ctx, `SELECT secret_generation,status FROM llm_providers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id).Scan(&generation, &status); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ ID, SecretSHA256 string }{id, secretDigest(secret)}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.provider.rotate", key, hashed, func() (int, any, error) {
		if status != "active" {
			return 0, nil, ErrTransition
		}
		v, err := scanProvider(tx.QueryRow(ctx, `UPDATE llm_providers SET secret_ciphertext=$3,secret_generation=$4,rotated_at=clock_timestamp()
            WHERE tenant_id=$1 AND id=$2 RETURNING `+providerColumns, p.TenantID, id, a.sealProviderSecret(p.TenantID, id, generation+1, secret), generation+1))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, id, nil, "provider.rotated"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// DisableLLMProvider makes the credential unusable from the next resolution and
// erases its ciphertext. A disabled provider cannot be re-enabled; create a new
// one, so a revoked key never comes back by accident.
func (a *Accounts) DisableLLMProvider(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
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
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_providers WHERE tenant_id=$1 AND id=$2 FOR UPDATE)`, p.TenantID, id).Scan(&exists); err != nil {
		return APIReceipt{}, err
	}
	if !exists {
		return APIReceipt{}, ErrNotFound
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.provider.disable", key, struct{ ID string }{id}, func() (int, any, error) {
		var was string
		if err := tx.QueryRow(ctx, `SELECT status FROM llm_providers WHERE tenant_id=$1 AND id=$2`, p.TenantID, id).Scan(&was); err != nil {
			return 0, nil, err
		}
		if was == "disabled" {
			v, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM llm_providers WHERE tenant_id=$1 AND id=$2`, p.TenantID, id))
			return 200, v, err
		}
		v, err := scanProvider(tx.QueryRow(ctx, `UPDATE llm_providers SET status='disabled',disabled_at=clock_timestamp(),secret_ciphertext='\x'::bytea
            WHERE tenant_id=$1 AND id=$2 RETURNING `+providerColumns, p.TenantID, id))
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE llm_model_aliases SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND provider_id=$2 AND status='active'`, p.TenantID, id); err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, id, nil, "provider.disabled"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) CreateLLMAlias(ctx context.Context, p Principal, key string, in CreateLLMAliasInput) (APIReceipt, error) {
	if !validOrganizationText(in.Alias, 100) || !validOrganizationText(in.ProviderID, 100) || !validOrganizationText(in.UpstreamModel, 200) ||
		in.InputMicroPerMTok < 0 || in.OutputMicroPerMTok < 0 || in.InputMicroPerMTok > 1e12 || in.OutputMicroPerMTok > 1e12 {
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
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.create", key, in, func() (int, any, error) {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM llm_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, in.ProviderID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		} else if err != nil {
			return 0, nil, err
		}
		if status != "active" {
			return 0, nil, ErrTransition
		}
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2)`, p.TenantID, in.Alias).Scan(&taken); err != nil {
			return 0, nil, err
		}
		if taken {
			return 0, nil, ErrConflict
		}
		v, err := scanAlias(tx.QueryRow(ctx, `INSERT INTO llm_model_aliases(tenant_id,alias,provider_id,upstream_model,created_by,input_micro_per_mtok,output_micro_per_mtok) VALUES($1,$2,$3,$4,$5,$6,$7)
            RETURNING `+aliasColumns, p.TenantID, in.Alias, in.ProviderID, in.UpstreamModel, p.ID, in.InputMicroPerMTok, in.OutputMicroPerMTok))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, in.ProviderID, &in.Alias, "alias.created"); err != nil {
			return 0, nil, err
		}
		return 201, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

const aliasColumns = `alias,provider_id,upstream_model,status,created_at,input_micro_per_mtok,output_micro_per_mtok`

func scanAlias(row pgx.Row) (LLMAlias, error) {
	var v LLMAlias
	err := row.Scan(&v.Alias, &v.ProviderID, &v.UpstreamModel, &v.Status, &v.CreatedAt, &v.InputMicroPerMTok, &v.OutputMicroPerMTok)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func (a *Accounts) DisableLLMAlias(ctx context.Context, p Principal, alias, key string) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) {
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
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.disable", key, struct{ Alias string }{alias}, func() (int, any, error) {
		var provider, status string
		if err := tx.QueryRow(ctx, `SELECT provider_id,status FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2 FOR UPDATE`, p.TenantID, alias).Scan(&provider, &status); errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		} else if err != nil {
			return 0, nil, err
		}
		if status == "disabled" {
			v, err := scanAlias(tx.QueryRow(ctx, `SELECT `+aliasColumns+` FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2`, p.TenantID, alias))
			return 200, v, err
		}
		v, err := scanAlias(tx.QueryRow(ctx, `UPDATE llm_model_aliases SET status='disabled',disabled_at=clock_timestamp()
            WHERE tenant_id=$1 AND alias=$2 RETURNING `+aliasColumns, p.TenantID, alias))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, provider, &alias, "alias.disabled"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) readLLM(ctx context.Context, p Principal, fn func(tx pgx.Tx) error) error {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeProviderManage)
	if err != nil {
		return err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ManageProviders) {
		return ErrForbidden
	}
	if err = fn(tx); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (a *Accounts) ListLLMProviders(ctx context.Context, p Principal, after string, limit int) ([]LLMProvider, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	items := []LLMProvider{}
	err := a.readLLM(ctx, p, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+providerColumns+` FROM llm_providers WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, p.TenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanProvider(rows)
			if err != nil {
				return err
			}
			items = append(items, v)
		}
		return rows.Err()
	})
	return items, err
}

func (a *Accounts) ListLLMAliases(ctx context.Context, p Principal, after string, limit int) ([]LLMAlias, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	items := []LLMAlias{}
	err := a.readLLM(ctx, p, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+aliasColumns+` FROM llm_model_aliases WHERE tenant_id=$1 AND alias>$2 ORDER BY alias LIMIT $3`, p.TenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanAlias(rows)
			if err != nil {
				return err
			}
			items = append(items, v)
		}
		return rows.Err()
	})
	return items, err
}

// ResolveLLMRoute is the gateway's lookup, keyed by a tenant taken from the
// authenticated channel, never from a request body. A disabled organization,
// alias or provider resolves to ErrNotFound on the very next call.
func (a *Accounts) ResolveLLMRoute(ctx context.Context, tenantID, alias string) (LLMRoute, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(alias, 100) {
		return LLMRoute{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return LLMRoute{}, err
	}
	defer rollback(tx)
	var r LLMRoute
	var providerID string
	var generation int64
	var sealed []byte
	err = tx.QueryRow(ctx, `SELECT p.id,p.kind,p.base_url,m.upstream_model,p.secret_generation,p.secret_ciphertext
        FROM organizations o JOIN llm_model_aliases m ON m.tenant_id=o.id
        JOIN llm_providers p ON (p.tenant_id,p.id)=(m.tenant_id,m.provider_id)
        WHERE o.id=$1 AND o.status='active' AND m.alias=$2 AND m.status='active' AND p.status='active' FOR SHARE OF m, p`, tenantID, alias).
		Scan(&providerID, &r.Kind, &r.BaseURL, &r.UpstreamModel, &generation, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return LLMRoute{}, ErrNotFound
	}
	if err != nil {
		return LLMRoute{}, err
	}
	if r.Secret, err = a.openProviderSecret(tenantID, providerID, generation, sealed); err != nil {
		return LLMRoute{}, err
	}
	return r, commit(ctx, tx)
}
