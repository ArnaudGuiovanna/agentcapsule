package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type InviteInput struct {
	Email     string    `json:"email"`
	PolicyID  string    `json:"policy_id"`
	TeamID    string    `json:"team_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Invitation struct {
	ID        string    `json:"id"`
	Proof     string    `json:"proof"`
	ExpiresAt time.Time `json:"expires_at"`
}
type AcceptInvitation struct {
	Proof string `json:"proof"`
}
type MemberEvent struct {
	Version  int64  `json:"version"`
	TeamID   string `json:"team_id,omitempty"`
	Disabled bool   `json:"disabled"`
}
type Activation struct {
	AdmittedWork struct {
		Pending int `json:"pending"`
		Running int `json:"running"`
	} `json:"admitted_work"`

	ID            string `json:"id"`
	ApplicationID string `json:"application_id"`
	PolicyID      string `json:"policy_id"`
	PrincipalID   string `json:"principal_id"`
	MemberEvent
	State      string            `json:"state"`
	Reason     string            `json:"reason,omitempty"`
	RetryAfter int               `json:"retry_after_seconds,omitempty"`
	Agents     map[string]string `json:"agents"`
}

func normalizeInviteEmail(s string) (string, bool) {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s || len(s) > 254 {
		return "", false
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" {
		return "", false
	}
	return local + "@" + strings.ToLower(domain), true
}
func (a *Accounts) Invite(ctx context.Context, p Principal, appID, key string, in InviteInput) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if p.service != nil {
		return APIReceipt{}, ErrForbidden
	}
	if p.app != nil {
		if p.app.App != appID || !slices.Contains(p.app.Scopes, "member:invite") {
			return APIReceipt{}, ErrForbidden
		}
		var locked string
		if err = tx.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", p.TenantID).Scan(&locked); err != nil {
			return APIReceipt{}, err
		}
		if _, err = authorizeTenant(ctx, tx, p, "member:invite"); err != nil {
			return APIReceipt{}, err
		}
	} else if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageMembers); err != nil {
		return APIReceipt{}, err
	}
	app, err := readApp(ctx, tx, p.TenantID, appID)
	if err != nil {
		return APIReceipt{}, err
	}
	if app.Status != "active" {
		return APIReceipt{}, ErrTransition
	}
	pol, err := readPolicy(ctx, tx, p.TenantID, in.PolicyID)
	if err != nil {
		return APIReceipt{}, err
	}
	if pol.ApplicationID != appID || !pol.Applied {
		return APIReceipt{}, ErrNotFound
	}
	if p.app != nil && !slices.Contains(pol.ManagerIDs, p.ID) {
		return APIReceipt{}, ErrForbidden
	}
	if err = eligibleTeam(ctx, tx, p.TenantID, in.TeamID, pol.PolicySpec); err != nil {
		return APIReceipt{}, err
	}
	email, ok := normalizeInviteEmail(in.Email)
	if !ok {
		return APIReceipt{}, ErrInput
	}
	out, err := a.withTenantReceipt(ctx, tx, p, "application.invite/"+appID, key, in, func() (int, any, error) {
		var fresh bool
		if err := tx.QueryRow(ctx, "SELECT $1::timestamptz>clock_timestamp() AND $1<=clock_timestamp()+interval '7 days'", in.ExpiresAt).Scan(&fresh); err != nil {
			return 0, nil, err
		}
		if !fresh {
			return 0, nil, ErrInput
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return 0, nil, err
		}
		invite := Invitation{newID("ivt"), base64.RawURLEncoding.EncodeToString(entropy[:]), in.ExpiresAt}
		hash := sha256.Sum256([]byte(invite.Proof))
		_, err := tx.Exec(ctx, `INSERT INTO app_invitations(id,tenant_id,app_id,policy_id,proof_hash,email,team_id,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,nullif($7,''),$8)`, invite.ID, p.TenantID, appID, pol.ID, hash[:], email, in.TeamID, in.ExpiresAt)
		if err != nil {
			return 0, nil, err
		}
		return 201, invite, auditApplication(ctx, tx, p, invite.ID, "application.invited")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}

func readActivation(ctx context.Context, tx pgx.Tx, tenant, appID, id string) (Activation, error) {
	var v Activation
	err := tx.QueryRow(ctx, `SELECT v.id,v.app_id,v.policy_id,v.principal_id,coalesce(v.team_id,''),v.version,
        v.disabled OR m.status<>'active' OR p.status<>'active' OR app.status<>'active'
      FROM app_activations v JOIN memberships m ON m.principal_id=v.principal_id JOIN principals p ON p.id=v.principal_id
      JOIN principals app ON app.id=v.app_id WHERE v.tenant_id=$1 AND v.app_id=$2 AND v.id=$3`, tenant, appID, id).Scan(&v.ID, &v.ApplicationID, &v.PolicyID, &v.PrincipalID, &v.TeamID, &v.Version, &v.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func (a *Accounts) AcceptInvitation(ctx context.Context, appID, key, token string, in AcceptInvitation) (APIReceipt, error) {
	claims, ok := selectApplication(token)
	if !ok {
		return APIReceipt{}, ErrAuthentication
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	var tenant string
	err = tx.QueryRow(ctx, `SELECT o.id FROM applications a JOIN organizations o ON o.id=a.tenant_id WHERE a.id=$1 AND a.issuer=$2 AND a.client_id=$3 AND o.status='active' FOR UPDATE OF o`, appID, claims.Issuer, claims.client()).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrAuthentication
	}
	if err != nil {
		return APIReceipt{}, err
	}
	app, err := readApp(ctx, tx, tenant, appID)
	if err != nil {
		return APIReceipt{}, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return APIReceipt{}, err
	}
	c, b, err := verifyAppToken(app, token, now)
	if err != nil {
		return APIReceipt{}, err
	}
	email, ok := normalizeInviteEmail(c.Email)
	if !c.VerifiedEmail || !ok || !slices.Contains(b.Scopes, "member:accept") {
		return APIReceipt{}, ErrForbidden
	}
	if len(in.Proof) != 43 {
		return APIReceipt{}, ErrNotFound
	}
	hash := sha256.Sum256([]byte(in.Proof))
	var invite, policyID, team, id string
	var fresh bool
	err = tx.QueryRow(ctx, `SELECT id,policy_id,coalesce(team_id,''),coalesce(activation_id,''),expires_at>clock_timestamp()
      FROM app_invitations WHERE tenant_id=$1 AND app_id=$2 AND proof_hash=$3 AND email=$4 FOR UPDATE`, tenant, appID, hash[:], email).Scan(&invite, &policyID, &team, &id, &fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	if id == "" && !fresh {
		return APIReceipt{}, ErrExpired
	}
	pol, err := readPolicy(ctx, tx, tenant, policyID)
	if err != nil {
		return APIReceipt{}, err
	}
	p := Principal{Kind: "tenant", TenantID: tenant, ID: appID}
	var existing string
	err = tx.QueryRow(ctx, `SELECT v.id FROM app_activations v JOIN principals p ON p.id=v.principal_id JOIN memberships m ON m.principal_id=p.id
        WHERE v.tenant_id=$1 AND v.app_id=$2 AND p.issuer=$3 AND p.subject=$4 AND p.status='active' AND m.status='active' AND NOT v.disabled`, tenant, appID, c.Issuer, c.Subject).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, err
	}
	if id != "" && id != existing {
		return APIReceipt{}, ErrForbidden
	}
	if existing != "" {
		id = existing
	}
	if id == "" {
		if err = eligibleTeam(ctx, tx, tenant, team, pol.PolicySpec); err != nil {
			return APIReceipt{}, err
		}
		// A lost commit may already have recorded this member as a volume owner
		// outside PostgreSQL. The same verified subject must retry as that owner.
		pID := applicationStableID("prn", appID, c.Subject)
		// A newly registered issuer cannot take over a manually registered
		// principal, even when a subject or email happens to match.
		tag, err := tx.Exec(ctx, `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name) VALUES($1,$2,'user',$3,$4,$5) ON CONFLICT DO NOTHING`, pID, tenant, c.Issuer, c.Subject, "Member")
		if err != nil {
			return APIReceipt{}, err
		}
		if tag.RowsAffected() != 1 {
			return APIReceipt{}, ErrForbidden
		}
		if _, err = tx.Exec(ctx, `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,'agent_user')`, tenant, pID); err != nil {
			return APIReceipt{}, err
		}
		id = newID("act")
		if _, err = tx.Exec(ctx, `INSERT INTO app_activations(id,tenant_id,app_id,policy_id,principal_id,team_id) VALUES($1,$2,$3,$4,$5,nullif($6,''))`, id, tenant, appID, pol.ID, pID, team); err != nil {
			return APIReceipt{}, err
		}
		if err = joinAppTeam(ctx, tx, p, pID, team); err != nil {
			return APIReceipt{}, err
		}
		if err = auditApplication(ctx, tx, p, id, "application.activated"); err != nil {
			return APIReceipt{}, err
		}
	}
	v, err := readActivation(ctx, tx, tenant, appID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	if v.PolicyID != policyID {
		return APIReceipt{}, ErrTransition
	}
	_, err = tx.Exec(ctx, "UPDATE app_invitations SET activation_id=$2 WHERE id=$1 AND activation_id IS NULL", invite, id)
	if err != nil {
		return APIReceipt{}, err
	}
	// Receipts are scoped to Alice, never to the application shared by Alice and Bob.
	actor := Principal{ID: v.PrincipalID, TenantID: tenant}
	out, err := a.withTenantReceipt(ctx, tx, actor, "invitation.accept", key, invite, func() (int, any, error) {
		err := a.allocateSlots(ctx, tx, p, v, pol)
		if err != nil {
			return 0, nil, err
		}
		err = activationState(ctx, tx, p.TenantID, &v, pol)
		return 200, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return out, commit(ctx, tx)
}

func joinAppTeam(ctx context.Context, tx pgx.Tx, p Principal, member, team string) error {
	if team == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO team_memberships(tenant_id,team_id,principal_id,source_app_id) VALUES($1,$2,$3,$4)
       ON CONFLICT(tenant_id,team_id,principal_id) DO UPDATE SET status='active',source_app_id=excluded.source_app_id
       WHERE team_memberships.status='revoked'`, p.TenantID, team, member, p.ID)
	return err
}

func (a *Accounts) allocateSlots(ctx context.Context, tx pgx.Tx, p Principal, v Activation, pol AssignmentPolicy) error {
	waiting := false
	var holds [][]string
	for _, slot := range pol.Slots {
		if slot.PoolID == "" {
			continue
		}
		var reserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_personal_reservations WHERE tenant_id=$1 AND principal_id=$2 AND policy_id=$3 AND slot=$4)`, p.TenantID, v.PrincipalID, pol.ID, slot.Name).Scan(&reserved); err != nil {
			return err
		}
		if reserved {
			continue
		}
		var agent string
		// The tenant's exclusive lock serializes allocation and changes of rights.
		err := tx.QueryRow(ctx, `SELECT agent_id FROM `+assignablePoolInventory+` free WHERE tenant_id=$1 AND pool_id=$2 ORDER BY agent_id LIMIT 1`, p.TenantID, slot.PoolID).Scan(&agent)
		if errors.Is(err, pgx.ErrNoRows) {
			switch pol.OnExhaustion {
			case "wait":
				waiting = true
				continue
			case "refuse":
				return ErrPoolExhausted
			case "create":
				ids, reserveErr := reservePoolAgents(ctx, tx, p, slot.PoolID, 1)
				if reserveErr != nil {
					return reserveErr
				}
				agent, err = ids[0], nil
			}
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_personal_reservations(tenant_id,agent_id,principal_id,policy_id,slot) VALUES($1,$2,$3,$4,$5)`, p.TenantID, agent, v.PrincipalID, pol.ID, slot.Name); err != nil {
			return err
		}
		if a.store.recorder() != nil {
			var volume string
			if err = tx.QueryRow(ctx, "SELECT volume_id FROM store_enrollments WHERE agent_id=$1", agent).Scan(&volume); err != nil {
				return err
			}
			holds = append(holds, []string{agent, volume, v.PrincipalID})
		}
		if err := writePolicyGrant(ctx, tx, p, pol.ID, agent, v.PrincipalID, "", slot.Permissions); err != nil {
			return err
		}
	}
	// Record only after every slot has passed admission. No personal volume
	// becomes accessible until its recovery record is also safe on failover.
	for _, h := range holds {
		if err := a.store.recordPersonalVolume(ctx, tx, p.TenantID, h); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, "UPDATE app_activations SET retry_at=CASE WHEN $2 THEN clock_timestamp()+interval '5 seconds' END WHERE id=$1", v.ID, waiting)
	return err
}

// A formerly assigned pool agent can contain private state even after all
// of its grants were revoked. Keep such a volume out of future allocations.
const assignablePoolInventory = `(SELECT i.* FROM agent_pool_inventory i WHERE NOT EXISTS (
  SELECT 1 FROM agent_assignments history WHERE (history.tenant_id,history.agent_id)=(i.tenant_id,i.agent_id)) AND NOT EXISTS (
  SELECT 1 FROM personal_volume_holds h WHERE (h.tenant_id,h.agent_id)=(i.tenant_id,i.agent_id)))`

var ErrPoolExhausted = errors.New("personal agent pool exhausted")

func activationState(ctx context.Context, tx pgx.Tx, tenant string, v *Activation, pol AssignmentPolicy) error {
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE o.status='PENDING'),count(*) FILTER(WHERE o.status='RUNNING')
      FROM platform_operations o JOIN agents a ON a.id=o.agent_id WHERE a.tenant_id=$1 AND o.requested_by_principal_id=$2 AND o.kind='instruction'
      AND o.status IN ('PENDING','RUNNING')`, tenant, v.PrincipalID).Scan(&v.AdmittedWork.Pending, &v.AdmittedWork.Running); err != nil {
		return err
	}
	v.State = "ready"
	v.Agents = map[string]string{}
	if v.Disabled {
		v.State = "disabled"
		return nil
	}
	for _, slot := range pol.Slots {
		agent := slot.AgentID
		if slot.PoolID != "" {
			err := tx.QueryRow(ctx, `SELECT agent_id FROM app_personal_reservations WHERE tenant_id=$1 AND principal_id=$2 AND policy_id=$3 AND slot=$4`, tenant, v.PrincipalID, pol.ID, slot.Name).Scan(&agent)
			if errors.Is(err, pgx.ErrNoRows) {
				if v.State != "failed" {
					v.State, v.Reason, v.RetryAfter = "waiting_capacity", "pool_exhausted", 5
				}
				continue
			}
			if err != nil {
				return err
			}
		} else if slot.TeamID != v.TeamID {
			continue
		}
		perms, err := effectiveAgentPermissions(ctx, tx, tenant, v.PrincipalID, agent)
		if err != nil {
			return err
		}
		if len(perms) == 0 {
			v.State, v.Reason, v.RetryAfter = "failed", "assignment_revoked", 0
			continue
		}
		var phase string
		var failed bool
		if err := tx.QueryRow(ctx, `SELECT phase,EXISTS(SELECT 1 FROM failed_agents f WHERE f.agent_id=a.id) OR EXISTS(SELECT 1 FROM platform_operations o WHERE o.agent_id=a.id AND o.kind='provision' AND o.status='FAILED') FROM agents a WHERE a.tenant_id=$1 AND a.id=$2`, tenant, agent).Scan(&phase, &failed); err != nil {
			return err
		}
		v.Agents[slot.Name] = agent
		if failed || phase != "LIVE" && phase != "PROVISIONING" {
			v.State, v.Reason, v.RetryAfter = "failed", "agent_unavailable", 0
		} else if phase != "LIVE" && v.State == "ready" {
			v.State, v.Reason, v.RetryAfter = "preparing", "agent_provisioning", 5
		}
	}
	return nil
}

// Sync can be invoked by the application's backend (one fixed, non-content
// scope) or a human responsible for membership in the same organization.
func authorizeAppSync(ctx context.Context, tx pgx.Tx, p Principal, appID string) error {
	if p.service == nil {
		_, err := authorizeMemberMutation(ctx, tx, p)
		return err
	}
	if !tenantBound(p) || p.ID != appID {
		return ErrForbidden
	}
	var id string
	if err := tx.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", p.TenantID).Scan(&id); err != nil {
		return err
	}
	_, err := authorizeTenant(ctx, tx, p, "application:sync")
	return err
}

func (a *Accounts) ShowActivation(ctx context.Context, p Principal, appID, id string) (Activation, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return Activation{}, err
	}
	defer rollback(tx)
	if p.app != nil {
		if _, err = authorizeTenant(ctx, tx, p, "org:read"); err != nil {
			return Activation{}, err
		}
		if p.app.App != appID {
			return Activation{}, ErrNotFound
		}
	} else if err = authorizeAppSync(ctx, tx, p, appID); err != nil {
		return Activation{}, err
	}
	v, err := readActivation(ctx, tx, p.TenantID, appID, id)
	if err != nil {
		return Activation{}, err
	}
	if p.app != nil && p.ID != v.PrincipalID {
		return Activation{}, ErrNotFound
	}
	pol, err := readPolicy(ctx, tx, p.TenantID, v.PolicyID)
	if err != nil {
		return v, err
	}
	if err = activationState(ctx, tx, p.TenantID, &v, pol); err != nil {
		return v, err
	}
	return v, commit(ctx, tx)
}

func (a *Accounts) SyncActivation(ctx context.Context, p Principal, appID, id, key string, in MemberEvent) (APIReceipt, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizeAppSync(ctx, tx, p, appID); err != nil {
		return APIReceipt{}, err
	}
	v, err := readActivation(ctx, tx, p.TenantID, appID, id)
	if err != nil {
		return APIReceipt{}, err
	}
	app, err := readApp(ctx, tx, p.TenantID, appID)
	if err != nil {
		return APIReceipt{}, err
	}
	if app.Status != "active" {
		return APIReceipt{}, ErrTransition
	}
	if in.Version < 1 || in.Disabled && in.TeamID != "" {
		return APIReceipt{}, ErrInput
	}
	pol, err := readPolicy(ctx, tx, p.TenantID, v.PolicyID)
	if err != nil {
		return APIReceipt{}, err
	}
	out, err := a.withTenantReceipt(ctx, tx, p, "activation.sync/"+id, key, in, func() (int, any, error) {
		if in.Version < v.Version || in.Version == v.Version && in != v.MemberEvent || v.Disabled && !in.Disabled {
			return 0, nil, ErrTransition
		}
		actor := Principal{ID: appID, TenantID: p.TenantID}
		revoked := a.store.revocations(tx, p.TenantID)
		if !v.Disabled {
			var role, status string
			if err := tx.QueryRow(ctx, "SELECT role,status FROM memberships WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, v.PrincipalID).Scan(&role, &status); err != nil {
				return 0, nil, err
			}
			if status != "active" || role != "agent_user" {
				return 0, nil, ErrForbidden
			}
			if err := eligibleTeam(ctx, tx, p.TenantID, in.TeamID, pol.PolicySpec); err != nil {
				return 0, nil, err
			}
			if in.Disabled {
				if _, err := tx.Exec(ctx, "UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, v.PrincipalID); err != nil {
					return 0, nil, err
				}
				if _, err := tx.Exec(ctx, "UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, v.PrincipalID); err != nil {
					return 0, nil, err
				}
				if err := revoked.add(ctx, authoritylog.AccessMember, p.TenantID, [][]string{{v.PrincipalID}}); err != nil {
					return 0, nil, err
				}
			} else {
				if v.TeamID != in.TeamID {
					tag, err := tx.Exec(ctx, `UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND team_id=$3 AND source_app_id=$4 AND status='active'`, p.TenantID, v.PrincipalID, v.TeamID, appID)
					if err != nil {
						return 0, nil, err
					}
					if tag.RowsAffected() == 1 {
						if err = revoked.add(ctx, authoritylog.AccessTeamMembership, p.TenantID, [][]string{{v.TeamID, v.PrincipalID}}); err != nil {
							return 0, nil, err
						}
					}
					if err = joinAppTeam(ctx, tx, actor, v.PrincipalID, in.TeamID); err != nil {
						return 0, nil, err
					}
				}
				if err := a.allocateSlots(ctx, tx, actor, v, pol); err != nil {
					return 0, nil, err
				}
			}
		}
		if in.Version > v.Version {
			if _, err := tx.Exec(ctx, `UPDATE app_activations SET version=$2,team_id=nullif($3,''),disabled=$4 WHERE id=$1`, id, in.Version, in.TeamID, in.Disabled); err != nil {
				return 0, nil, err
			}
			if err := auditApplication(ctx, tx, p, id, "application.member_updated"); err != nil {
				return 0, nil, err
			}
			v.MemberEvent = in
		}
		if err := activationState(ctx, tx, p.TenantID, &v, pol); err != nil {
			return 0, nil, err
		}
		body, err := revoked.body(v)
		return 200, body, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return a.store.settled(ctx, out, commit(ctx, tx))
}

// RetryWaitingActivations continues durable waiting slots after a pool grows
// or the API restarts. Each candidate rechecks the applicant and integration
// after taking the same tenant lock used by offboarding and reservations.
func (a *Accounts) RetryWaitingActivations(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		_ = a.retryWaiting(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *Accounts) retryWaiting(ctx context.Context) error {
	rows, err := a.store.pool.Query(ctx, `SELECT v.tenant_id,v.app_id,v.id FROM app_activations v JOIN memberships m ON m.principal_id=v.principal_id
        JOIN principals app ON app.id=v.app_id JOIN organizations o ON o.id=v.tenant_id
        WHERE v.retry_at<=clock_timestamp() AND NOT v.disabled AND app.status='active' AND o.status='active' AND m.status='active' AND m.role='agent_user'
        ORDER BY v.retry_at,v.id LIMIT 32`)
	if err != nil {
		return err
	}
	var pending [][3]string
	for rows.Next() {
		var ids [3]string
		if err := rows.Scan(&ids[0], &ids[1], &ids[2]); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, ids)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, ids := range pending {
		if err = a.retryOne(ctx, ids); err != nil {
			return err
		}
	}
	return nil
}
func (a *Accounts) retryOne(ctx context.Context, ids [3]string) error {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var active bool
	err = tx.QueryRow(ctx, `SELECT status='active' FROM organizations WHERE id=$1 FOR UPDATE`, ids[0]).Scan(&active)
	if err != nil || !active {
		return err
	}
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_activations v JOIN memberships m ON m.principal_id=v.principal_id
        JOIN principals app ON app.id=v.app_id JOIN principals member ON member.id=v.principal_id WHERE v.id=$1 AND NOT v.disabled AND v.retry_at<=clock_timestamp() AND
        app.status='active' AND member.status='active' AND m.status='active' AND m.role='agent_user')`, ids[2]).Scan(&active)
	if err != nil || !active {
		return err
	}
	v, err := readActivation(ctx, tx, ids[0], ids[1], ids[2])
	if err != nil {
		return err
	}
	pol, err := readPolicy(ctx, tx, ids[0], v.PolicyID)
	if err != nil {
		return err
	}
	if err = a.allocateSlots(ctx, tx, Principal{ID: ids[1], TenantID: ids[0]}, v, pol); err != nil {
		return err
	}
	return commit(ctx, tx)
}
