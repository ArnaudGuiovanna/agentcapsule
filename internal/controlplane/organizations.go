package controlplane

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type Organization struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	PolicyVersion int64     `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
}

// InitialOrganizationOwner registers an intended identity. It is not an
// authentication assertion and grants no token or access to legacy resources.
type InitialOrganizationOwner struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name"`
}
type CreateOrganizationInput struct {
	Name         string                   `json:"name"`
	InitialOwner InitialOrganizationOwner `json:"initial_owner"`
}
type CreateOrganizationResponse struct {
	Organization
	OwnerPrincipalID string `json:"owner_principal_id"`
}

func validOrganizationText(s string, max int) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}

func validRegisteredIdentity(s string) bool {
	return len(s) >= 1 && len(s) <= 1024 && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}

func scanOrganization(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Name, &o.Status, &o.PolicyVersion, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, err
}

func auditOrganization(ctx context.Context, tx pgx.Tx, p Principal, id, action string, changed bool) error {
	_, err := tx.Exec(ctx, `INSERT INTO organization_audit(id,tenant_id,actor_account,credential_id,action,changed)
        VALUES($1,$2,$3,$4,$5,$6)`, newID("audit"), id, p.ID, p.TokenID, action, changed)
	return err
}

func (a *Accounts) CreateOrganization(ctx context.Context, p Principal, key string, in CreateOrganizationInput) (APIReceipt, error) {
	if !validOrganizationText(in.Name, 100) || !validOrganizationText(in.InitialOwner.DisplayName, 100) || !validRegisteredIdentity(in.InitialOwner.Issuer) || !validRegisteredIdentity(in.InitialOwner.Subject) {
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
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/organizations", key), in, func() (int, any, error) {
		o, err := scanOrganization(tx.QueryRow(ctx, `INSERT INTO organizations(id,name) VALUES($1,$2)
            RETURNING id,name,status,policy_version,created_at`, newID("org"), in.Name))
		if err != nil {
			return 0, nil, err
		}
		owner := newID("prn")
		if _, err = tx.Exec(ctx, `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name)
            VALUES($1,$2,'user',$3,$4,$5)`, owner, o.ID, in.InitialOwner.Issuer, in.InitialOwner.Subject, in.InitialOwner.DisplayName); err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,'org_owner')`, o.ID, owner); err != nil {
			return 0, nil, err
		}
		if err = auditOrganization(ctx, tx, p, o.ID, "organization.created", true); err != nil {
			return 0, nil, err
		}
		return 201, CreateOrganizationResponse{Organization: o, OwnerPrincipalID: owner}, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) GetOrganization(ctx context.Context, p Principal, id string) (Organization, error) {
	if !validOrganizationText(id, 100) {
		return Organization{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return Organization{}, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return Organization{}, err
	}
	o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1`, id))
	if err != nil {
		return Organization{}, err
	}
	return o, commit(ctx, tx)
}

func (a *Accounts) ListOrganizations(ctx context.Context, p Principal, after string, limit int) ([]Organization, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizePlatform(ctx, tx, p); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	items := []Organization{}
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return items, commit(ctx, tx)
}

func (a *Accounts) DisableOrganization(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
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
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/organizations/"+id+"/disable", key), struct{}{}, func() (int, any, error) {
		o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return 0, nil, err
		}
		changed := o.Status != "disabled"
		if changed {
			o, err = scanOrganization(tx.QueryRow(ctx, `UPDATE organizations SET status='disabled',policy_version=policy_version+1
                WHERE id=$1 RETURNING id,name,status,policy_version,created_at`, id))
			if err != nil {
				return 0, nil, err
			}
		}
		if err = auditOrganization(ctx, tx, p, id, "organization.disabled", changed); err != nil {
			return 0, nil, err
		}
		return 200, o, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
