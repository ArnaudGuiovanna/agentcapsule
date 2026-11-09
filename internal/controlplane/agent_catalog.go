package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

var (
	ErrRelease         = errors.New("approved harness release unavailable or immutable version conflict")
	ErrAgentExists     = errors.New("owner already has a companion")
	ErrStorageCapacity = errors.New("host storage reservation exhausted")
)

type HarnessReference struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type AgentResources struct {
	VCPUs         int `json:"vcpus"`
	MemoryMiB     int `json:"memory_mib"`
	DataVolumeMiB int `json:"data_volume_mib"`
}
type CreateAgentInput struct {
	OwnerUserID string           `json:"owner_user_id,omitempty"`
	Name        string           `json:"name"`
	Harness     HarnessReference `json:"harness"`
	Resources   AgentResources   `json:"resources"`
	AutoStart   bool             `json:"auto_start"`
}
type AgentCreation struct {
	AgentID     string `json:"agent_id"`
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
}
type AgentView struct {
	ID            string         `json:"id"`
	OwnerUserID   string         `json:"owner_user_id"`
	Name          string         `json:"name"`
	State         string         `json:"state"`
	HarnessDigest string         `json:"harness_digest"`
	Resources     AgentResources `json:"resources"`
	CreatedAt     time.Time      `json:"created_at"`
}
type PlatformOperation struct {
	ID            string     `json:"id"`
	AgentID       string     `json:"agent_id"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	ErrorCode     string     `json:"error_code,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	UncleanStop   *bool      `json:"unclean_stop,omitempty"`
	DeletionPhase string     `json:"deletion_phase,omitempty"`
}

// AgentCatalog binds creation to the operator-selected host. Clients cannot
// provide host paths, UID assignments or host IDs through the public API.
type AgentCatalog struct {
	accounts *Accounts
	host     string
	transit  *Transit
}

func NewAgentCatalogWithTransit(accounts *Accounts, host string, transit *Transit) (*AgentCatalog, error) {
	c, err := NewAgentCatalog(accounts, host)
	if err != nil {
		return nil, err
	}
	if transit == nil || transit.store != accounts.store {
		return nil, ErrInput
	}
	c.transit = transit
	return c, nil
}

func NewAgentCatalog(accounts *Accounts, host string) (*AgentCatalog, error) {
	if accounts == nil || !catalogName(host) {
		return nil, ErrInput
	}
	return &AgentCatalog{accounts: accounts, host: host}, nil
}
func catalogName(v string) bool {
	if len(v) < 1 || len(v) > 100 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return v != "." && v != ".."
}
func displayName(v string) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= 100 && strings.TrimSpace(v) != "" && strings.IndexFunc(v, unicode.IsControl) < 0
}

// RegisterLocalRelease records a trusted operator approval of a digest. This
// does not fetch or validate an OCI artifact; the worker must verify the pinned
// artifact against this digest before provisioning. A version cannot be rebound.
func (s *Store) RegisterLocalRelease(ctx context.Context, ref HarnessReference, digest string) (string, error) {
	if !catalogName(ref.Name) || !catalogName(ref.Version) || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 || strings.ToLower(digest) != digest {
		return "", ErrInput
	}
	if _, err := hex.DecodeString(digest[7:]); err != nil {
		return "", ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(tx)
	_, err = tx.Exec(ctx, `INSERT INTO harness_releases(id,name,version,artifact_digest,source)
        VALUES($1,$2,$3,$4,'local-approved') ON CONFLICT(name,version) DO NOTHING`, newID("rel"), ref.Name, ref.Version, digest)
	if err != nil {
		return "", err
	}
	var id, original, source string
	err = tx.QueryRow(ctx, "SELECT id,artifact_digest,source FROM harness_releases WHERE name=$1 AND version=$2 FOR SHARE", ref.Name, ref.Version).Scan(&id, &original, &source)
	if err != nil {
		return "", err
	}
	if original != digest || source != "local-approved" {
		return "", ErrRelease
	}
	return id, commit(ctx, tx)
}

// ConfigureHostStorage is trusted installation configuration, never a client
// quota override. Reservation and reconfiguration serialize on worker_hosts.
func (s *Store) ConfigureHostStorage(ctx context.Context, host string, limitMiB int64) error {
	if !catalogName(host) || limitMiB < 64 || limitMiB > 1<<40 {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	var reserved int64
	if err = tx.QueryRow(ctx, `SELECT coalesce(sum(volume_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=$1 AND a.phase<>'DELETED'`, host).Scan(&reserved); err != nil {
		return err
	}
	if reserved > limitMiB {
		return ErrStorageCapacity
	}
	if _, err = tx.Exec(ctx, "UPDATE worker_hosts SET storage_limit_mib=$2 WHERE host_id=$1", host, limitMiB); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func agentPermission(ctx context.Context, tx pgx.Tx, p Principal, serviceScope string) error {
	if p.Kind == "service" {
		return authorizePrincipal(ctx, tx, p, "service", serviceScope)
	}
	return authorizePrincipal(ctx, tx, p, "user", "agent:own")
}

// Reserve creates only a durable provisioning operation. It does not publish a
// LIVE agent or claim an existing formatted/encrypted volume. A worker must
// fulfill the enrollment contract before activation and success publication.
// The intended HTTP boundary is a long-running operation (202), never a false
// 201/STOPPED response before the volume exists.
func (c *AgentCatalog) Reserve(ctx context.Context, p Principal, key string, in CreateAgentInput) (APIReceipt, error) {
	if p.Kind == "tenant" {
		return c.reserveTenant(ctx, p, key, in)
	}
	if !displayName(in.Name) || !catalogName(in.Harness.Name) || !catalogName(in.Harness.Version) {
		return APIReceipt{}, ErrInput
	}
	r := in.Resources
	if r.VCPUs < 1 || r.VCPUs > 8 || r.MemoryMiB < 128 || r.MemoryMiB > 8192 || r.DataVolumeMiB < 64 || r.DataVolumeMiB > 32768 {
		return APIReceipt{}, ErrInput
	}
	owner := in.OwnerUserID
	if p.Kind == "user" {
		if owner != "" && owner != p.ID {
			return APIReceipt{}, ErrNotFound
		}
		owner = p.ID
	}
	if owner == "" {
		return APIReceipt{}, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = lockHTTPReceipt(ctx, tx, scope(p, "POST", "/v1/agents", key)); err != nil {
		return APIReceipt{}, err
	}
	// Services must establish their management scope before looking up another
	// user's existence. Personal callers can target only their own account.
	if p.Kind == "service" {
		if err = agentPermission(ctx, tx, p, "agent:manage"); err != nil {
			return APIReceipt{}, err
		}
	} else if p.Kind != "user" {
		return APIReceipt{}, ErrForbidden
	}
	// Serializes distinct creation keys for the same owner, as well as disabling
	// the owner. The current schema permits a single retained companion identity.
	var active bool
	err = tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1 FOR NO KEY UPDATE", owner).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	if err = agentPermission(ctx, tx, p, "agent:manage"); err != nil {
		return APIReceipt{}, err
	}
	result, err := c.accounts.withReceipt(ctx, tx, scope(p, "POST", "/v1/agents", key), in, func() (int, any, error) {
		var existing bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agents WHERE owner_user_id=$1)", owner).Scan(&existing); err != nil {
			return 0, nil, err
		}
		if existing {
			return 0, nil, ErrAgentExists
		}
		var release string
		// Imported (OCI) releases are not bootable until the worker runs harness
		// artifacts; until then only operator-approved local images are offered.
		err := tx.QueryRow(ctx, "SELECT id FROM harness_releases WHERE name=$1 AND version=$2 AND enabled AND source='local-approved' FOR SHARE", in.Harness.Name, in.Harness.Version).Scan(&release)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrRelease
		}
		if err != nil {
			return 0, nil, err
		}
		if err = lockWorkerHost(ctx, tx, c.host); err != nil {
			return 0, nil, err
		}
		var available bool
		err = tx.QueryRow(ctx, `SELECT storage_limit_mib>0 AND storage_limit_mib >= $2::bigint +
            (SELECT coalesce(sum(x.volume_mib),0) FROM agent_specs x JOIN agents a ON a.id=x.agent_id WHERE x.host_id=$1 AND a.phase<>'DELETED')
            FROM worker_hosts WHERE host_id=$1`, c.host, r.DataVolumeMiB).Scan(&available)
		if err != nil {
			return 0, nil, err
		}
		if !available {
			return 0, nil, ErrStorageCapacity
		}
		id, op := newID("agt"), newID("op")
		if _, err = tx.Exec(ctx, "INSERT INTO agents(id,owner_user_id,phase) VALUES($1,$2,'PROVISIONING')", id, owner); err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_specs(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, in.Name, release, c.host, r.VCPUs, r.MemoryMiB, r.DataVolumeMiB, in.AutoStart)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,owner_user_id,agent_id,host_id,seq,kind)
            VALUES($1,$2,$3,$4,1,'provision')`, op, owner, id, c.host)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO store_enrollments(agent_id,operation_id,volume_id) VALUES($1,$2,$3)`, id, op, newID("vol"))
		return 202, AgentCreation{AgentID: id, OperationID: op, Status: "PENDING"}, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

const agentViewColumns = `a.id,a.owner_user_id,x.name,
        CASE WHEN a.phase<>'LIVE' THEN a.phase
          WHEN p.state='RUNNING' AND NOT p.fence_only AND pc.agent_id IS NOT NULL THEN 'READY'
          WHEN p.state='RUNNING' THEN 'STARTING' ELSE coalesce(p.state,'STOPPED') END,
        r.artifact_digest,x.vcpus,x.memory_mib,x.volume_mib,x.created_at`
const agentViewFrom = ` FROM agents a JOIN agent_specs x ON x.agent_id=a.id JOIN harness_releases r ON r.id=x.release_id
        LEFT JOIN agent_placements p ON p.agent_id=a.id
        LEFT JOIN placement_control_contracts pc ON pc.agent_id=p.agent_id AND pc.host_id=p.host_id
          AND pc.generation=p.generation AND pc.vm_id=p.vm_id AND pc.protocol='capsule.v1'
          AND pc.incarnation=coalesce((SELECT incarnation FROM store_enrollments WHERE agent_id=a.id),1) `

func scanAgentView(row pgx.Row) (AgentView, error) {
	var v AgentView
	err := row.Scan(&v.ID, &v.OwnerUserID, &v.Name, &v.State, &v.HarnessDigest, &v.Resources.VCPUs, &v.Resources.MemoryMiB, &v.Resources.DataVolumeMiB, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func (c *AgentCatalog) List(ctx context.Context, p Principal, after string, limit int) ([]AgentView, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = agentPermission(ctx, tx, p, "agent:read"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, "SELECT "+agentViewColumns+agentViewFrom+`WHERE a.tenant_id IS NULL AND a.id>$1 AND ($2='service' OR a.owner_user_id=$3) ORDER BY a.id LIMIT $4`, after, p.Kind, p.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentView, 0)
	for rows.Next() {
		v, err := scanAgentView(rows)
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

func (c *AgentCatalog) Get(ctx context.Context, p Principal, id string) (AgentView, error) {
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return AgentView{}, err
	}
	defer rollback(tx)
	if err = agentPermission(ctx, tx, p, "agent:read"); err != nil {
		return AgentView{}, err
	}
	v, err := scanAgentView(tx.QueryRow(ctx, "SELECT "+agentViewColumns+agentViewFrom+`WHERE a.tenant_id IS NULL AND a.id=$1 AND ($2='service' OR a.owner_user_id=$3)`, id, p.Kind, p.ID))
	if err != nil {
		return AgentView{}, err
	}
	return v, commit(ctx, tx)
}

func (c *AgentCatalog) Operation(ctx context.Context, p Principal, id string) (PlatformOperation, error) {
	if p.Kind == "tenant" {
		return c.operationTenant(ctx, p, id)
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return PlatformOperation{}, err
	}
	defer rollback(tx)
	if err = agentPermission(ctx, tx, p, "agent:read"); err != nil {
		return PlatformOperation{}, err
	}
	var v PlatformOperation
	err = tx.QueryRow(ctx, `SELECT o.id,o.agent_id,o.kind,o.status,o.error_code,o.created_at,o.completed_at,o.unclean_stop,
        CASE WHEN o.kind<>'delete' OR d.agent_id IS NULL THEN ''
             WHEN a.phase='DELETED' THEN 'COMPLETE'
             WHEN d.phase='FENCING' THEN 'FENCING'
             WHEN EXISTS(SELECT 1 FROM store_seals x WHERE x.agent_id=o.agent_id) THEN 'CLEANUP_PENDING'
             ELSE 'RETIRING' END
        FROM platform_operations o JOIN agents a ON a.id=o.agent_id
        LEFT JOIN deletion_operations d ON d.operation_id=o.id
        WHERE a.tenant_id IS NULL AND o.id=$1 AND ($2='service' OR o.owner_user_id=$3)`, id, p.Kind, p.ID).
		Scan(&v.ID, &v.AgentID, &v.Kind, &v.Status, &v.ErrorCode, &v.CreatedAt, &v.CompletedAt, &v.UncleanStop, &v.DeletionPhase)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformOperation{}, ErrNotFound
	}
	if err != nil {
		return PlatformOperation{}, err
	}
	return v, commit(ctx, tx)
}
