package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/jackc/pgx/v5"
)

// LLMProvider is the metadata of a tenant's upstream provider. The credential
// is write-only: no field, receipt or audit event ever carries it back.
type LLMProvider struct {
	AuthMode   string     `json:"auth_mode"`
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
	// Estimation prices, in micro-units of the organization's currency per
	// million tokens. Priced is false until the organization sets them; zero
	// prices are then a free model.
	InputMicroPerMTok  int64 `json:"input_micro_per_mtok"`
	OutputMicroPerMTok int64 `json:"output_micro_per_mtok"`
	Priced             bool  `json:"priced"`
	// Access is "organization" (every agent of the organization) or "listed"
	// (only the agents the alias's grants name, directly or through a team).
	Access string `json:"access"`
	// Operations are what the alias's model serves, in canonical order: chat,
	// vision, embed, transcribe, ocr (ADR 023 §12).
	Operations []string `json:"operations"`
	// Prices of audio per minute and of OCR per page, in micro-units; absent,
	// that unit is unpriced.
	AudioMicroPerMinute *int64 `json:"audio_micro_per_minute,omitempty"`
	OCRMicroPerPage     *int64 `json:"ocr_micro_per_page,omitempty"`
	// The request policy (llmgateway.RequestPolicy): the top-level fields
	// and tool types a forwarded request may use beside the plain ones, in
	// sorted order, and the output cap of a call that declares none
	// (absent: the platform's default) with the field it is written in.
	AllowedFields    []string `json:"allowed_fields"`
	AllowedToolTypes []string `json:"allowed_tool_types"`
	MaxOutputTokens  *int64   `json:"max_output_tokens,omitempty"`
	OutputCapField   string   `json:"output_cap_field"`
}

type CreateLLMProviderInput struct {
	AuthMode string `json:"auth_mode,omitempty"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	BaseURL  string `json:"base_url"`
	Secret   string `json:"secret"`
}

type CreateLLMAliasInput struct {
	Alias         string `json:"alias"`
	ProviderID    string `json:"provider_id"`
	UpstreamModel string `json:"upstream_model"`
	// Optional prices used only to ESTIMATE cost, in micro-units of the
	// tenant's currency per million tokens. Either one makes the alias priced;
	// the other is then zero. Neither leaves the alias unpriced.
	InputMicroPerMTok  *int64 `json:"input_micro_per_mtok,omitempty"`
	OutputMicroPerMTok *int64 `json:"output_micro_per_mtok,omitempty"`
	// Access is "organization" (default) or "listed".
	Access string `json:"access,omitempty"`
	// Operations default to chat only.
	Operations []string `json:"operations,omitempty"`
	// Optional prices of audio per minute and of OCR per page.
	AudioMicroPerMinute *int64 `json:"audio_micro_per_minute,omitempty"`
	OCRMicroPerPage     *int64 `json:"ocr_micro_per_page,omitempty"`
	// The optional request policy; absent, the alias allows only the plain
	// fields and the client's own tools, and keeps the default output cap.
	AllowedFields    []string `json:"allowed_fields,omitempty"`
	AllowedToolTypes []string `json:"allowed_tool_types,omitempty"`
	MaxOutputTokens  *int64   `json:"max_output_tokens,omitempty"`
	OutputCapField   string   `json:"output_cap_field,omitempty"`
}

// ErrProviderAddress: an https provider URL names an internal address
// directly (a loopback, private, link-local or cloud metadata address, or
// localhost). The worker would refuse to call it. A model server on the
// operator's network is registered by its name, and the operator must allow it
// in the worker's configuration (ADR 010).
var ErrProviderAddress = fmt.Errorf("%w: the provider URL names an internal address", ErrInput)

// LLMRoute is what the gateway needs for one call. It holds a decrypted
// credential and must stay in the gateway process memory. ProviderID and
// Generation name the credential, so that the reservation can check that the
// provider still serves it (ReserveLLM).
type LLMRoute struct {
	AuthMode                     string
	Kind, BaseURL, UpstreamModel string
	Secret                       string
	ProviderID                   string
	Generation                   int64
	Policy                       llmgateway.RequestPolicy
}

// checkProviderURL accepts https to a host that is not an internal address
// written out, and plain HTTP to a model server on the worker's host, for
// development: production refuses plain HTTP before anything is sent. The
// worker checks every address again when it connects, after DNS resolution.
func checkProviderURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 300 || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrInput
	}
	switch h := u.Hostname(); u.Scheme {
	case "https":
		if llmgateway.InternalHost(h) {
			return ErrProviderAddress
		}
		return nil
	case "http":
		// Plain HTTP only to a local model server; never across a network.
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return ErrInput
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

const providerColumns = `id,name,kind,base_url,status,secret_generation,created_at,rotated_at,auth_mode`

func scanProvider(row pgx.Row) (LLMProvider, error) {
	var v LLMProvider
	err := row.Scan(&v.ID, &v.Name, &v.Kind, &v.BaseURL, &v.Status, &v.Generation, &v.CreatedAt, &v.RotatedAt, &v.AuthMode)
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
	if in.AuthMode == "" {
		in.AuthMode = "secret"
	}
	if !validOrganizationText(in.Name, 100) || (in.Kind != "openai_compatible" && in.Kind != "anthropic") || !(in.AuthMode == "none" && in.Secret == "" || in.AuthMode == "secret" && validProviderSecret(in.Secret)) {
		return APIReceipt{}, ErrInput
	}
	if err := checkProviderURL(in.BaseURL); err != nil {
		return APIReceipt{}, err
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
		sealed := []byte{}
		if in.AuthMode == "secret" {
			sealed = a.sealProviderSecret(p.TenantID, id, 1, in.Secret)
		}
		v, err := scanProvider(tx.QueryRow(ctx, `INSERT INTO llm_providers(id,tenant_id,name,kind,base_url,secret_ciphertext,created_by,auth_mode)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+providerColumns, id, p.TenantID, in.Name, in.Kind, in.BaseURL, sealed, p.ID, in.AuthMode))
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
	var status, authMode string
	if err = tx.QueryRow(ctx, `SELECT secret_generation,status,auth_mode FROM llm_providers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id).Scan(&generation, &status, &authMode); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ ID, SecretSHA256 string }{id, secretDigest(secret)}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.provider.rotate", key, hashed, func() (int, any, error) {
		if status != "active" || authMode != "secret" {
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
		// The previous credential is revoked: a rollback would bring it back.
		revoked := a.store.revocations(tx, p.TenantID)
		if err = revoked.add(ctx, authoritylog.AccessLLMProvider, p.TenantID, [][]string{{id, "generation", strconv.FormatInt(generation, 10)}}); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(v)
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, r, commit(ctx, tx))
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
		revoked := a.store.revocations(tx, p.TenantID)
		if err = revoked.add(ctx, authoritylog.AccessLLMProvider, p.TenantID, [][]string{{id}}); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(v)
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, r, commit(ctx, tx))
}

// maxPriceMicroPerMTok bounds a price: a million currency units per million
// tokens. Costs stay exact far beyond it (see costMicro).
const maxPriceMicroPerMTok = 1e12

func validPrice(v *int64) bool { return v == nil || (*v >= 0 && *v <= maxPriceMicroPerMTok) }

func validAliasAccess(access string) bool { return access == "organization" || access == "listed" }

func (a *Accounts) CreateLLMAlias(ctx context.Context, p Principal, key string, in CreateLLMAliasInput) (APIReceipt, error) {
	if !validOrganizationText(in.Alias, 100) || !validOrganizationText(in.ProviderID, 100) || !validOrganizationText(in.UpstreamModel, 200) ||
		!validPrice(in.InputMicroPerMTok) || !validPrice(in.OutputMicroPerMTok) || (in.Access != "" && !validAliasAccess(in.Access)) ||
		!validPrice(in.AudioMicroPerMinute) || !validPrice(in.OCRMicroPerPage) {
		return APIReceipt{}, ErrInput
	}
	operations := []string{LLMChat}
	if in.Operations != nil {
		var err error
		if operations, err = normalizeOperations(in.Operations, "openai_compatible"); err != nil {
			return APIReceipt{}, err
		}
	}
	policy, err := normalizeRequestPolicy(SetLLMAliasRequestPolicyInput{AllowedFields: in.AllowedFields, AllowedToolTypes: in.AllowedToolTypes,
		MaxOutputTokens: in.MaxOutputTokens, OutputCapField: in.OutputCapField}, "")
	if err != nil {
		return APIReceipt{}, err
	}
	access := in.Access
	if access == "" {
		access = "organization"
	}
	priced := in.InputMicroPerMTok != nil || in.OutputMicroPerMTok != nil
	var inputPrice, outputPrice int64
	if in.InputMicroPerMTok != nil {
		inputPrice = *in.InputMicroPerMTok
	}
	if in.OutputMicroPerMTok != nil {
		outputPrice = *in.OutputMicroPerMTok
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
		var status, kind string
		if err := tx.QueryRow(ctx, `SELECT status,kind FROM llm_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, p.TenantID, in.ProviderID).Scan(&status, &kind); errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNotFound
		} else if err != nil {
			return 0, nil, err
		}
		if status != "active" {
			return 0, nil, ErrTransition
		}
		if _, err := normalizeOperations(operations, kind); err != nil {
			return 0, nil, err
		}
		if _, err := normalizeRequestPolicy(policy, kind); err != nil {
			return 0, nil, err
		}
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2)`, p.TenantID, in.Alias).Scan(&taken); err != nil {
			return 0, nil, err
		}
		if taken {
			return 0, nil, ErrConflict
		}
		v, err := scanAlias(tx.QueryRow(ctx, `INSERT INTO llm_model_aliases(tenant_id,alias,provider_id,upstream_model,created_by,input_micro_per_mtok,output_micro_per_mtok,priced,access,
            operations,audio_micro_per_minute,ocr_micro_per_page,allowed_fields,allowed_tool_types,max_output_tokens,output_cap_field)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING `+aliasColumns, p.TenantID, in.Alias, in.ProviderID, in.UpstreamModel, p.ID, inputPrice, outputPrice, priced, access,
			operations, in.AudioMicroPerMinute, in.OCRMicroPerPage, policy.AllowedFields, policy.AllowedToolTypes, policy.MaxOutputTokens, policy.OutputCapField))
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

const aliasColumns = `alias,provider_id,upstream_model,status,created_at,input_micro_per_mtok,output_micro_per_mtok,priced,access,operations,audio_micro_per_minute,ocr_micro_per_page,
    allowed_fields,allowed_tool_types,max_output_tokens,output_cap_field`

func scanAlias(row pgx.Row) (LLMAlias, error) {
	var v LLMAlias
	err := row.Scan(&v.Alias, &v.ProviderID, &v.UpstreamModel, &v.Status, &v.CreatedAt, &v.InputMicroPerMTok, &v.OutputMicroPerMTok, &v.Priced, &v.Access,
		&v.Operations, &v.AudioMicroPerMinute, &v.OCRMicroPerPage, &v.AllowedFields, &v.AllowedToolTypes, &v.MaxOutputTokens, &v.OutputCapField)
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
//
// It takes no row lock (FIX-2): the reservation that follows is what orders
// the call with a disabling or a rotation (reserveLLM). Those are plain
// UPDATEs under the organization's row FOR UPDATE; the reservation holds
// that row FOR KEY SHARE and reads the alias's and the provider's status and
// the credential's generation again, so a route resolved before such a
// change committed is never used. FOR SHARE on the alias and the provider,
// taken on every call until then, conflicted with those UPDATEs and added
// nothing: it ended with this transaction, before the reservation.
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
	var sealed []byte
	var maxOutput *int64
	err = tx.QueryRow(ctx, `SELECT p.id,p.kind,p.base_url,m.upstream_model,p.secret_generation,p.secret_ciphertext,p.auth_mode,
        m.allowed_fields,m.allowed_tool_types,m.max_output_tokens,m.output_cap_field
        FROM organizations o JOIN llm_model_aliases m ON m.tenant_id=o.id
        JOIN llm_providers p ON (p.tenant_id,p.id)=(m.tenant_id,m.provider_id)
        WHERE o.id=$1 AND o.status='active' AND m.alias=$2 AND m.status='active' AND p.status='active'`, tenantID, alias).
		Scan(&r.ProviderID, &r.Kind, &r.BaseURL, &r.UpstreamModel, &r.Generation, &sealed, &r.AuthMode,
			&r.Policy.AllowedFields, &r.Policy.AllowedToolTypes, &maxOutput, &r.Policy.OutputCapField)
	if errors.Is(err, pgx.ErrNoRows) {
		return LLMRoute{}, ErrNotFound
	}
	if err != nil {
		return LLMRoute{}, err
	}
	if maxOutput != nil {
		r.Policy.MaxOutputTokens = int(*maxOutput)
	}
	if r.AuthMode == "secret" {
		if r.Secret, err = a.openProviderSecret(tenantID, r.ProviderID, r.Generation, sealed); err != nil {
			return LLMRoute{}, err
		}
	}
	return r, commit(ctx, tx)
}
