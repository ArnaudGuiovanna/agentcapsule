package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/jackc/pgx/v5"
)

// An application's OIDC client, its issuer and client ID, serves the one
// organization the platform operator approved it for (ADR 001, "Changes
// after the v0.1.0 audit", finding S-10). An organization registers an
// application only for a client approved for it; a member's token reaches
// the application of the organization its client is approved for, and only
// that one. Withdrawing an approval disables the application that used it,
// and frees the client for another organization.

// ApplicationClient is the platform operator's approval of an OIDC client
// for one organization.
type ApplicationClient struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"client_id"`
	// ApprovedBy is the platform account, or "migration" for a client an
	// application registered before approvals existed.
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// ApplicationClientInput names the client to approve.
type ApplicationClientInput struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

func (in ApplicationClientInput) valid() bool {
	return httpsEndpoint(in.Issuer) && validOrganizationText(in.ClientID, 200)
}

// ErrClientNotApproved refuses the registration of an application whose
// client the platform operator did not approve for the organization. It is
// the same whether another organization holds the client or none does.
var ErrClientNotApproved = errors.New("the application's client is not approved for this organization")

const clientColumns = `id,tenant_id,issuer,client_id,approved_by,approved_at`

func scanClient(row pgx.Row) (ApplicationClient, error) {
	var c ApplicationClient
	err := row.Scan(&c.ID, &c.OrganizationID, &c.Issuer, &c.ClientID, &c.ApprovedBy, &c.ApprovedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

// lockClientOrganization takes the organization's row first, like every
// change of its identity configuration.
func lockClientOrganization(ctx context.Context, tx pgx.Tx, org string) (string, error) {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM organizations WHERE id=$1 FOR UPDATE`, org).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return status, err
}

// ApproveApplicationClient approves a client for an active organization. A
// client approved for it already confirms (200); one approved for another
// organization is refused (409): the operator withdraws that approval first.
func (a *Accounts) ApproveApplicationClient(ctx context.Context, p Principal, org, key string, in ApplicationClientInput) (APIReceipt, error) {
	if !validOrganizationText(org, 100) || !in.valid() {
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
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/organizations/"+org+"/application-clients", key), in, func() (int, any, error) {
		status, err := lockClientOrganization(ctx, tx, org)
		if err != nil {
			return 0, nil, err
		}
		if status != "active" {
			return 0, nil, ErrTransition
		}
		c, err := scanClient(tx.QueryRow(ctx, `INSERT INTO application_clients(`+clientColumns+`) VALUES($1,$2,$3,$4,$5,clock_timestamp())
            ON CONFLICT (issuer,client_id) DO NOTHING RETURNING `+clientColumns, newID("apc"), org, in.Issuer, in.ClientID, p.ID))
		if errors.Is(err, ErrNotFound) {
			c, err = scanClient(tx.QueryRow(ctx, `SELECT `+clientColumns+` FROM application_clients WHERE issuer=$1 AND client_id=$2`, in.Issuer, in.ClientID))
			if err != nil {
				return 0, nil, err
			}
			if c.OrganizationID != org {
				return 0, nil, ErrTransition
			}
			return 200, c, auditOrganization(ctx, tx, p, org, "application_client.approved", false)
		}
		if err != nil {
			return 0, nil, err
		}
		return 201, c, auditOrganization(ctx, tx, p, org, "application_client.approved", true)
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// ListApplicationClients lists the clients approved for an organization, for
// the platform operator.
func (a *Accounts) ListApplicationClients(ctx context.Context, p Principal, org, after string, limit int) ([]ApplicationClient, error) {
	if !validOrganizationText(org, 100) || len(after) > 100 || limit < 1 || limit > 200 {
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
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, org).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT `+clientColumns+` FROM application_clients WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, org, after, limit)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ApplicationClient, error) { return scanClient(row) })
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []ApplicationClient{}
	}
	return items, commit(ctx, tx)
}

// WithdrawApplicationClient withdraws an organization's approval of a
// client. The organization's application of that client, if any, is
// disabled in the same transaction, like an application's revocation: its
// members' tokens and its backend's token stop at once. The client may then
// be approved for another organization.
func (a *Accounts) WithdrawApplicationClient(ctx context.Context, p Principal, org, id, key string) (APIReceipt, error) {
	if !validOrganizationText(org, 100) || !validOrganizationText(id, 100) {
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
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/organizations/"+org+"/application-clients/"+id+"/withdraw", key), struct{}{}, func() (int, any, error) {
		if _, err := lockClientOrganization(ctx, tx, org); err != nil {
			return 0, nil, err
		}
		c, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientColumns+` FROM application_clients WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, org, id))
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM application_clients WHERE id=$1`, c.ID); err != nil {
			return 0, nil, err
		}
		apps, err := collect(tx.Query(ctx, `UPDATE principals p SET status='disabled' FROM applications a
            WHERE a.tenant_id=$1 AND a.issuer=$2 AND a.client_id=$3 AND (p.tenant_id,p.id)=(a.tenant_id,a.id) AND p.status='active'
            RETURNING p.id`, org, c.Issuer, c.ClientID))
		if err != nil {
			return 0, nil, err
		}
		// The platform's own revocation: its operator reads it.
		revoked := a.store.revocations(tx, "")
		if len(apps) > 0 {
			if _, err = tx.Exec(ctx, "UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1", org); err != nil {
				return 0, nil, err
			}
			if err = revoked.add(ctx, authoritylog.AccessPrincipal, org, objects(apps)); err != nil {
				return 0, nil, err
			}
		}
		if err = auditOrganization(ctx, tx, p, org, "application_client.withdrawn", true); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(map[string]string{"id": c.ID, "status": "withdrawn"})
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, r, commit(ctx, tx))
}
