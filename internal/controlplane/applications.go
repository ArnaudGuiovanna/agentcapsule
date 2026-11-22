package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type ApplicationConfig struct {
	Name             string    `json:"name"`
	Issuer           string    `json:"issuer"`
	Audience         string    `json:"audience"`
	ClientID         string    `json:"client_id"`
	RedirectURIs     []string  `json:"redirect_uris"`
	VerificationKeys []OIDCKey `json:"verification_keys"`
}

type Application struct {
	minimumIAT time.Time
	signerID   string
	ApplicationConfig
	ID         string   `json:"id"`
	TenantID   string   `json:"tenant_id"`
	Status     string   `json:"status"`
	Generation int64    `json:"generation"`
	PolicyIDs  []string `json:"policy_ids"`
}

func httpsEndpoint(s string) bool {
	u, err := url.Parse(s)
	return err == nil && validOrganizationText(s, 2048) && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "*")
}

func (c ApplicationConfig) valid() bool {
	if !catalogName(c.Name) || !httpsEndpoint(c.Issuer) || !validOrganizationText(c.Audience, 200) || !validOrganizationText(c.ClientID, 200) || c.ClientID == c.Audience || len(c.RedirectURIs) < 1 || len(c.RedirectURIs) > 16 || !validOIDCKeys(c.VerificationKeys) {
		return false
	}
	for _, uri := range c.RedirectURIs {
		if !httpsEndpoint(uri) {
			return false
		}
	}
	return true
}

const appSelect = `SELECT a.id,a.tenant_id,a.name,a.issuer,a.audience,a.client_id,a.redirect_uris,a.verification_keys,a.generation,CASE WHEN signer.status='active' THEN p.status ELSE 'disabled' END,a.minimum_iat,signer.id,
  ARRAY(SELECT id FROM app_policies WHERE app_id=a.id AND applied ORDER BY id)
  FROM applications a JOIN principals p ON (p.tenant_id,p.id)=(a.tenant_id,a.id) JOIN principals signer ON signer.id=a.signing_principal `

func scanApp(row pgx.Row) (Application, error) {
	var v Application
	err := row.Scan(&v.ID, &v.TenantID, &v.Name, &v.Issuer, &v.Audience, &v.ClientID, &v.RedirectURIs, &v.VerificationKeys, &v.Generation, &v.Status, &v.minimumIAT, &v.signerID, &v.PolicyIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func readApp(ctx context.Context, tx pgx.Tx, tenant, id string) (Application, error) {
	return scanApp(tx.QueryRow(ctx, appSelect+" WHERE a.tenant_id=$1 AND a.id=$2", tenant, id))
}

func auditApplication(ctx context.Context, tx pgx.Tx, p Principal, target, action string) error {
	if _, err := tx.Exec(ctx, "UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1", p.TenantID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "INSERT INTO application_audit(id,tenant_id,actor,target,action) VALUES($1,$2,$3,$4,$5)", newID("audit"), p.TenantID, p.ID, target, action)
	return err
}

func appAdmin(ctx context.Context, tx pgx.Tx, p Principal) error {
	if p.service != nil {
		return ErrForbidden
	}
	_, err := authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageIdentities)
	return err
}

func (a *Accounts) ListApplications(ctx context.Context, p Principal, after string, limit int) ([]Application, error) {
	if len(after) > 100 || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = appAdmin(ctx, tx, p); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, appSelect+" WHERE a.tenant_id=$1 AND a.id>$2 ORDER BY a.id LIMIT $3", p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Application{}
	for rows.Next() {
		v, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}

func (a *Accounts) ShowApplication(ctx context.Context, p Principal, id string) (Application, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return Application{}, err
	}
	defer rollback(tx)
	if err = appAdmin(ctx, tx, p); err != nil {
		return Application{}, err
	}
	v, err := readApp(ctx, tx, p.TenantID, id)
	if err != nil {
		return v, err
	}
	return v, commit(ctx, tx)
}

type IssuedApplication struct {
	Application
	ProvisioningToken string `json:"provisioning_token"`
}

// A key generation has its own revocable authority record. Restoring a
// backup made before rotation can never make its old public keys authoritative.
func registerAppSigner(ctx context.Context, tx pgx.Tx, tenant string) (string, error) {
	id := newID("sig")
	_, err := tx.Exec(ctx, "INSERT INTO principals(id,tenant_id,kind,display_name) VALUES($1,$2,'service','OIDC signing keys')", id, tenant)
	return id, err
}

func issueAppToken(ctx context.Context, tx pgx.Tx, p Principal, id string) (string, error) {
	raw := newServiceSecret()
	hash := sha256.Sum256([]byte(raw))
	_, err := tx.Exec(ctx, `INSERT INTO service_tokens(id,tenant_id,principal_id,token_hash,scopes,expires_at,issued_by)
    VALUES($1,$2,$3,$4,ARRAY['application:sync'],clock_timestamp()+interval '90 days',$5)`, newID("stk"), p.TenantID, id, hash[:], p.ID)
	return raw, err
}

func (a *Accounts) RegisterApplication(ctx context.Context, p Principal, key string, in ApplicationConfig) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = appAdmin(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	if !in.valid() {
		return APIReceipt{}, ErrInput
	}
	out, err := a.withTenantReceipt(ctx, tx, p, "application.register", key, in, func() (int, any, error) {
		// Only a client the platform operator approved for this organization
		// (application_clients.go). The answer is the same whether another
		// organization holds the client or none does; the lock holds the
		// approval until this registration commits.
		var approval string
		err := tx.QueryRow(ctx, `SELECT id FROM application_clients WHERE tenant_id=$1 AND issuer=$2 AND client_id=$3 FOR KEY SHARE`,
			p.TenantID, in.Issuer, in.ClientID).Scan(&approval)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrClientNotApproved
		}
		if err != nil {
			return 0, nil, err
		}
		id := newID("app")
		if _, err := tx.Exec(ctx, `INSERT INTO principals(id,tenant_id,kind,display_name) VALUES($1,$2,'service',$3)`, id, p.TenantID, in.Name); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,'agent_user')`, p.TenantID, id); err != nil {
			return 0, nil, err
		}
		signer, err := registerAppSigner(ctx, tx, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		// A conflict is with this organization's own applications: their
		// names, or this client already registered.
		tag, err := tx.Exec(ctx, `INSERT INTO applications(id,tenant_id,name,issuer,audience,client_id,redirect_uris,verification_keys,signing_principal)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, id, p.TenantID, in.Name, in.Issuer, in.Audience, in.ClientID, in.RedirectURIs, in.VerificationKeys, signer)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, ErrTransition
		}
		token, err := issueAppToken(ctx, tx, p, id)
		if err != nil {
			return 0, nil, err
		}
		v, err := readApp(ctx, tx, p.TenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return 201, IssuedApplication{v, token}, auditApplication(ctx, tx, p, id, "application.registered")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}

type RotateApplication struct {
	VerificationKeys []OIDCKey `json:"verification_keys,omitempty"`
}

func (a *Accounts) ChangeApplication(ctx context.Context, p Principal, id, key string, in *RotateApplication) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = appAdmin(ctx, tx, p); err != nil {
		return APIReceipt{}, err
	}
	v, err := readApp(ctx, tx, p.TenantID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	op := "application.revoke"
	if in != nil {
		op = "application.rotate"
		if in.VerificationKeys != nil && !validOIDCKeys(in.VerificationKeys) {
			return APIReceipt{}, ErrInput
		}
	}
	payload := struct {
		ID     string
		Rotate *RotateApplication
	}{id, in}
	out, err := a.withTenantReceipt(ctx, tx, p, op, key, payload, func() (int, any, error) {
		if v.Status != "active" {
			if in == nil {
				return 200, v, nil
			}
			return 0, nil, ErrTransition
		}
		revoked := a.store.revocations(tx, p.TenantID)
		tokens, err := collect(tx.Query(ctx, "UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=$3 WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL RETURNING id", p.TenantID, id, p.ID))
		if err != nil {
			return 0, nil, err
		}
		if err = revoked.add(ctx, authoritylog.AccessServiceToken, p.TenantID, objects(tokens)); err != nil {
			return 0, nil, err
		}
		var response any
		if in == nil {
			if _, err = tx.Exec(ctx, "UPDATE principals SET status='disabled' WHERE tenant_id=$1 AND id=$2", p.TenantID, id); err != nil {
				return 0, nil, err
			}
			if err = revoked.add(ctx, authoritylog.AccessPrincipal, p.TenantID, [][]string{{id}}); err != nil {
				return 0, nil, err
			}
			v.Status = "disabled"
			response = v
		} else {
			if in.VerificationKeys != nil {
				signer, err := registerAppSigner(ctx, tx, p.TenantID)
				if err != nil {
					return 0, nil, err
				}
				if _, err = tx.Exec(ctx, "UPDATE principals SET status='disabled' WHERE id=$1", v.signerID); err != nil {
					return 0, nil, err
				}
				if err = revoked.add(ctx, authoritylog.AccessPrincipal, p.TenantID, [][]string{{v.signerID}}); err != nil {
					return 0, nil, err
				}
				v.VerificationKeys = slices.Clone(in.VerificationKeys)
				if err = tx.QueryRow(ctx, "UPDATE applications SET verification_keys=$2,signing_principal=$3,generation=generation+1 WHERE id=$1 RETURNING generation", id, v.VerificationKeys, signer).Scan(&v.Generation); err != nil {
					return 0, nil, err
				}
			}
			raw, err := issueAppToken(ctx, tx, p, id)
			if err != nil {
				return 0, nil, err
			}
			response = IssuedApplication{v, raw}
		}
		if err = auditApplication(ctx, tx, p, id, op); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(response)
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, out, commit(ctx, tx))
}
