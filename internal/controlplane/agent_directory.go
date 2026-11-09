package controlplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// DirectoryProfile is what an organization publishes about one of its agents
// in the private Directory: a description and OASF 1.1.0 skill and domain IDs.
// A published record grants no right: search results are filtered again by
// organization and visibility, and requests keep their own checks.
type DirectoryProfile struct {
	Visible     bool   `json:"visible"`
	Description string `json:"description"`
	Skills      []int  `json:"skills"`
	Domains     []int  `json:"domains"`
}

// DirectoryEntry is an agent's profile and the state of its record.
// Publication is pending (the Directory is behind), published, unpublished (no
// record: hidden, stopped being live, or never described) or invalid (the
// schema refused the record; Error says why).
type DirectoryEntry struct {
	AgentID     string     `json:"agent_id"`
	Visible     bool       `json:"visible"`
	Description string     `json:"description"`
	Skills      []int      `json:"skills"`
	Domains     []int      `json:"domains"`
	Publication string     `json:"publication"`
	Error       *string    `json:"error,omitempty"`
	RecordCID   *string    `json:"record_cid,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// DirectoryAgent is one search result, as PostgreSQL describes it now.
type DirectoryAgent struct {
	AgentID     string `json:"agent_id"`
	Description string `json:"description"`
	Skills      []int  `json:"skills"`
	Domains     []int  `json:"domains"`
}

const maxDirectoryIDs = 20

// validTaxonomyIDs accepts distinct positive OASF class IDs. Whether each one
// exists is the schema server's decision, reported as an invalid record.
func validTaxonomyIDs(ids []int, min int) bool {
	if len(ids) < min || len(ids) > maxDirectoryIDs {
		return false
	}
	seen := map[int]bool{}
	for _, id := range ids {
		if id < 1 || id > 99_999_999 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validDescription(s string) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > 1000 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' {
			return false
		}
	}
	return true
}

func (in DirectoryProfile) valid() bool {
	return validDescription(in.Description) && validTaxonomyIDs(in.Skills, 1) && validTaxonomyIDs(in.Domains, 0)
}

// SetDirectoryProfile describes a live organization agent for the Directory
// and sets whether it is discoverable. The worker's publisher then brings the
// Directory to this state; GetDirectoryProfile reports its progress. Hiding an
// agent keeps its description and removes its record.
func (c *AgentCatalog) SetDirectoryProfile(ctx context.Context, p Principal, id, key string, in DirectoryProfile) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) || !in.valid() {
		return APIReceipt{}, ErrInput
	}
	in.Skills, in.Domains = sortedCopy(in.Skills), sortedCopy(in.Domains)
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ConfigureAgent); err != nil {
		return APIReceipt{}, err
	}
	a, _, err := tenantAgentForUpdate(ctx, tx, p, id)
	if err != nil {
		return APIReceipt{}, err
	}
	body := struct {
		AgentID string           `json:"agent_id"`
		Profile DirectoryProfile `json:"profile"`
	}{id, in}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "agent.directory/"+id, key, body, func() (int, any, error) {
		if a.Phase != "LIVE" {
			return 0, nil, ErrUnavailable
		}
		// First, so that a first description starts at revision 1: a change of
		// discoverability bumps an existing row's revision through the trigger.
		if _, err := tx.Exec(ctx, "UPDATE agents SET discoverable=$2 WHERE id=$1 AND discoverable<>$2", id, in.Visible); err != nil {
			return 0, nil, err
		}
		// A new description is a new revision; an unchanged one is not.
		if _, err := tx.Exec(ctx, `INSERT INTO agent_directory(agent_id,tenant_id,description,skills,domains) VALUES($1,$2,$3,$4,$5)
            ON CONFLICT (agent_id) DO UPDATE SET description=EXCLUDED.description,skills=EXCLUDED.skills,domains=EXCLUDED.domains,
              revision=agent_directory.revision+1,state='pending',error=NULL,next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
            WHERE (agent_directory.description,agent_directory.skills,agent_directory.domains)
              IS DISTINCT FROM (EXCLUDED.description,EXCLUDED.skills,EXCLUDED.domains)`,
			id, p.TenantID, in.Description, in.Skills, in.Domains); err != nil {
			return 0, nil, err
		}
		// Who can find an agent is not an authorization rule: no policy bump.
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,action)
            VALUES($1,$2,$3,$4,'agent.directory_changed')`, newID("audit"), p.TenantID, p.ID, id); err != nil {
			return 0, nil, err
		}
		entry, err := directoryEntry(ctx, tx, id)
		return 200, entry, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// GetDirectoryProfile reports an agent's profile and publication state to
// whoever may read the agent's metadata.
func (c *AgentCatalog) GetDirectoryProfile(ctx context.Context, p Principal, id string) (DirectoryEntry, error) {
	if p.Kind != "tenant" || !validOrganizationText(id, 100) {
		return DirectoryEntry{}, ErrInput
	}
	if _, err := c.getTenant(ctx, p, id); err != nil {
		return DirectoryEntry{}, err
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return DirectoryEntry{}, err
	}
	defer rollback(tx)
	entry, err := directoryEntry(ctx, tx, id)
	if err != nil {
		return DirectoryEntry{}, err
	}
	return entry, commit(ctx, tx)
}

func directoryEntry(ctx context.Context, tx pgx.Tx, id string) (DirectoryEntry, error) {
	e := DirectoryEntry{AgentID: id, Skills: []int{}, Domains: []int{}, Publication: "unpublished"}
	var revision, published int64
	var state string
	err := tx.QueryRow(ctx, `SELECT a.discoverable,d.description,d.skills,d.domains,d.revision,d.published_revision,d.state,d.error,d.published_cid,d.updated_at
        FROM agents a JOIN agent_directory d ON d.agent_id=a.id WHERE a.id=$1`, id).
		Scan(&e.Visible, &e.Description, &e.Skills, &e.Domains, &revision, &published, &state, &e.Error, &e.RecordCID, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = tx.QueryRow(ctx, "SELECT discoverable FROM agents WHERE id=$1", id).Scan(&e.Visible); err != nil {
			return DirectoryEntry{}, err
		}
		return e, nil
	}
	if err != nil {
		return DirectoryEntry{}, err
	}
	e.Publication = state
	if revision > published {
		e.Publication = "pending"
	}
	return e, nil
}

func sortedCopy(ids []int) []int {
	out := slices.Clone(ids)
	slices.Sort(out)
	if out == nil {
		out = []int{}
	}
	return out
}

// DirectoryWork is one agent whose Directory record is behind its revision, or
// whose previous record is still to delete. Publish is the desired state at
// claim time: a record for Revision, or none.
type DirectoryWork struct {
	AgentID, TenantID          string
	Revision                   int64
	Publish                    bool
	Description                string
	Skills, Domains            []int
	CreatedAt                  time.Time
	PublishedCID, RetiredCID   string
	PublishedRevision, Attempt int64
}

// ClaimDirectoryWork leases due work to one publisher. The lease keeps other
// publishers away while this one talks to the Directory outside any
// transaction; an expired lease makes the work due again.
func (s *Store) ClaimDirectoryWork(ctx context.Context, limit int, lease time.Duration) ([]DirectoryWork, error) {
	if limit < 1 || limit > 100 || lease < time.Second {
		return nil, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `WITH due AS (
          SELECT agent_id FROM agent_directory
          WHERE (revision > published_revision OR retired_cid IS NOT NULL) AND next_attempt_at <= clock_timestamp()
            AND (lease_until IS NULL OR lease_until < clock_timestamp())
          ORDER BY next_attempt_at, agent_id LIMIT $1 FOR UPDATE SKIP LOCKED)
        UPDATE agent_directory d SET lease_until=clock_timestamp()+make_interval(secs => $2), attempts=d.attempts+1
        FROM due, agents a, organizations o
        WHERE d.agent_id=due.agent_id AND a.id=d.agent_id AND o.id=d.tenant_id
        RETURNING d.agent_id,d.tenant_id,d.revision,(a.discoverable AND a.phase='LIVE' AND o.status='active'),
          d.description,d.skills,d.domains,d.created_at,coalesce(d.published_cid,''),coalesce(d.retired_cid,''),d.published_revision,d.attempts`,
		limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	var work []DirectoryWork
	for rows.Next() {
		var w DirectoryWork
		if err = rows.Scan(&w.AgentID, &w.TenantID, &w.Revision, &w.Publish, &w.Description, &w.Skills, &w.Domains, &w.CreatedAt,
			&w.PublishedCID, &w.RetiredCID, &w.PublishedRevision, &w.Attempt); err != nil {
			rows.Close()
			return nil, err
		}
		work = append(work, w)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return work, commit(ctx, tx)
}

// directoryUpdate applies one publisher step if the agent's record is still
// where the publisher left it; otherwise another step won and ErrConflict
// sends the work back to the queue.
func (s *Store) directoryUpdate(ctx context.Context, query string, args ...any) error {
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// RecordDirectoryPublished records that the Directory holds cid for revision.
// A different record published before becomes the retired one, deleted next.
func (s *Store) RecordDirectoryPublished(ctx context.Context, w DirectoryWork, cid string) error {
	if cid == "" {
		return ErrInput
	}
	return s.directoryUpdate(ctx, `UPDATE agent_directory SET published_revision=$2,state='published',error=NULL,
        retired_cid=CASE WHEN published_cid IS DISTINCT FROM $3 THEN published_cid END,published_cid=$3,
        attempts=0,lease_until=NULL,next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE agent_id=$1 AND published_revision=$4 AND published_cid IS NOT DISTINCT FROM nullif($5,'') AND retired_cid IS NULL`,
		w.AgentID, w.Revision, cid, w.PublishedRevision, w.PublishedCID)
}

// RecordDirectoryUnpublished records that revision has no record: the agent is
// hidden or gone, or (reason set) the schema refused its record. The record
// published before, if any, becomes the retired one.
func (s *Store) RecordDirectoryUnpublished(ctx context.Context, w DirectoryWork, reason string) error {
	state, errorText := "unpublished", any(nil)
	if reason != "" {
		state, errorText = "invalid", truncateRunes(reason, 2000)
	}
	return s.directoryUpdate(ctx, `UPDATE agent_directory SET published_revision=$2,state=$3,error=$4,
        retired_cid=published_cid,published_cid=NULL,
        attempts=0,lease_until=NULL,next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE agent_id=$1 AND published_revision=$5 AND published_cid IS NOT DISTINCT FROM nullif($6,'') AND retired_cid IS NULL`,
		w.AgentID, w.Revision, state, errorText, w.PublishedRevision, w.PublishedCID)
}

// RecordDirectoryRetired records that the retired record is gone. The lease
// ends here unless a revision is still to publish in the same claim.
func (s *Store) RecordDirectoryRetired(ctx context.Context, agentID, cid string) error {
	return s.directoryUpdate(ctx, `UPDATE agent_directory SET retired_cid=NULL,updated_at=clock_timestamp(),
        lease_until=CASE WHEN revision>published_revision THEN lease_until END,
        attempts=CASE WHEN revision>published_revision THEN attempts ELSE 0 END
        WHERE agent_id=$1 AND retired_cid=$2`, agentID, cid)
}

// DeferDirectoryWork releases the lease and retries later: the Directory was
// unreachable, or another step changed the record meanwhile.
func (s *Store) DeferDirectoryWork(ctx context.Context, agentID string, delay time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_directory SET lease_until=NULL,
        next_attempt_at=clock_timestamp()+make_interval(secs => $2) WHERE agent_id=$1`, agentID, delay.Seconds())
	return err
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// DirectoryScopeFromVM returns the organization whose records a running agent
// may search, after the placement check every VM call passes. An agent of the
// historical domain has no organization and no Directory scope.
func (s *Store) DirectoryScopeFromVM(ctx context.Context, caller VMCaller) (string, error) {
	return s.vmTenant(ctx, caller)
}

// FindDirectoryAgentsFromVM turns Directory hits into results the caller may
// see. The Directory is only an index: a hit counts only if it is the agent's
// current record, the agent is still discoverable, live, of the caller's
// organization and not the caller, and it still has one of the skills asked.
// Descriptions come from PostgreSQL, never from the Directory.
func (s *Store) FindDirectoryAgentsFromVM(ctx context.Context, caller VMCaller, cids []string, skills []int) ([]DirectoryAgent, error) {
	if len(cids) > 100 || !validTaxonomyIDs(skills, 1) {
		return nil, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return nil, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT a.id,d.description,d.skills,d.domains
        FROM agent_directory d JOIN agents a ON a.id=d.agent_id JOIN organizations o ON o.id=d.tenant_id
        WHERE d.published_cid=ANY($1) AND a.id<>$2 AND a.discoverable AND a.phase='LIVE' AND o.status='active'
          AND d.tenant_id=(SELECT tenant_id FROM agents WHERE id=$2) AND d.skills && $3
        ORDER BY a.id`, cids, caller.AgentID, skills)
	if err != nil {
		return nil, err
	}
	result := []DirectoryAgent{}
	for rows.Next() {
		var a DirectoryAgent
		if err = rows.Scan(&a.AgentID, &a.Description, &a.Skills, &a.Domains); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, commit(ctx, tx)
}
