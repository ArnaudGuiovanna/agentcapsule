package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
)

const (
	DefaultAttachmentTTL = time.Hour
	MaxAttachmentTTL     = 24 * time.Hour
)

// Attachment is metadata only. Content never leaves through this type.
type Attachment struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Name      string    `json:"name"`
	MediaType string    `json:"media_type"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AttachmentUpload describes the bytes sent with it. DeclaredSHA256, when given,
// must match what arrived: a corrupted upload is refused, never stored.
type AttachmentUpload struct {
	Name           string
	MediaType      string
	DeclaredSHA256 string
	TTLSeconds     int
}

// segmentBinding authenticates each encrypted segment to exactly one file,
// position, tenant, agent and uploader. A segment copied elsewhere, reordered,
// truncated or attributed to someone else fails to open.
type segmentBinding struct {
	Domain   string `json:"domain"`
	Version  int    `json:"version"`
	ID       string `json:"id"`
	Tenant   string `json:"tenant"`
	Agent    string `json:"agent"`
	Uploader string `json:"uploader"`
	KeyID    string `json:"key_id"`
	Index    int    `json:"index"`
	Segments int    `json:"segments"`
	Size     int64  `json:"size"`
	Hash     string `json:"sha256"`
}

func (b segmentBinding) aad() []byte {
	b.Domain, b.Version = "agentcapsule.attachment-segment", 1
	out, _ := json.Marshal(b)
	return out
}

const attachmentColumns = `id,agent_id,name,media_type,size_bytes,encode(sha256,'hex'),status,created_at,expires_at`

func scanAttachment(row pgx.Row) (Attachment, error) {
	var v Attachment
	err := row.Scan(&v.ID, &v.AgentID, &v.Name, &v.MediaType, &v.Size, &v.SHA256, &v.State, &v.CreatedAt, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func newAttachmentID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "att_" + hex.EncodeToString(b[:])
}

// UploadAttachment stores a file for one agent. Only a principal who may invoke
// that agent may upload for it; the file is then usable only by that principal,
// only for that agent, and only until it expires unattached.
func (c *AgentCatalog) UploadAttachment(ctx context.Context, p Principal, agentID, key string, in AttachmentUpload, body []byte) (APIReceipt, error) {
	if p.Kind != "tenant" || !validOrganizationText(agentID, 100) {
		return APIReceipt{}, ErrNotFound
	}
	if len(body) > capsuleprotocol.MaxAttachmentBytes {
		return APIReceipt{}, ErrTooLarge
	}
	ttl := DefaultAttachmentTTL
	if in.TTLSeconds != 0 {
		ttl = time.Duration(in.TTLSeconds) * time.Second
		if in.TTLSeconds < 0 || ttl < time.Minute || ttl > MaxAttachmentTTL {
			return APIReceipt{}, ErrInput
		}
	}
	if len(body) == 0 || !capsuleprotocol.ValidAttachmentName(in.Name) || !capsuleprotocol.ValidAttachmentType(in.MediaType) {
		return APIReceipt{}, ErrInput
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if in.DeclaredSHA256 != "" && in.DeclaredSHA256 != digest {
		return APIReceipt{}, ErrInput
	}
	if c.transit == nil {
		return APIReceipt{}, ErrTransitKey
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = c.mayInvoke(ctx, tx, p, agentID); err != nil {
		return APIReceipt{}, err
	}
	request := struct {
		Agent, Name, MediaType, SHA256 string
		Size                           int
		TTL                            int
	}{agentID, in.Name, in.MediaType, digest, len(body), in.TTLSeconds}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "attachment.upload/"+agentID, key, request, func() (int, any, error) {
		// Admissions of one organization serialize here so two uploads cannot
		// both take the last bytes of the quota.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "attachment-quota/"+p.TenantID); err != nil {
			return 0, nil, err
		}
		limits, err := queueLimits(ctx, tx, p.TenantID)
		if err != nil {
			return 0, nil, err
		}
		var used int64
		if err = tx.QueryRow(ctx, `SELECT coalesce(sum(size_bytes),0) FROM attachments WHERE tenant_id=$1 AND status<>'purged'`, p.TenantID).Scan(&used); err != nil {
			return 0, nil, err
		}
		if used+int64(len(body)) > limits.MaxAttachmentBytes {
			return 0, nil, ErrStorageQuota
		}
		k, err := c.transit.activeKey(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		id := newAttachmentID()
		segments := (len(body) + capsuleprotocol.AttachmentSegmentBytes - 1) / capsuleprotocol.AttachmentSegmentBytes
		v, err := scanAttachment(tx.QueryRow(ctx, `INSERT INTO attachments(id,tenant_id,agent_id,uploader_principal_id,name,media_type,size_bytes,sha256,key_id,segments,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+$11::bigint*interval '1 microsecond') RETURNING `+attachmentColumns,
			id, p.TenantID, agentID, p.ID, in.Name, in.MediaType, len(body), sum[:], c.transit.active, segments, ttl.Microseconds()))
		if err != nil {
			return 0, nil, err
		}
		binding := segmentBinding{ID: id, Tenant: p.TenantID, Agent: agentID, Uploader: p.ID, KeyID: c.transit.active, Segments: segments, Size: int64(len(body)), Hash: digest}
		for i := 0; i < segments; i++ {
			end := min((i+1)*capsuleprotocol.AttachmentSegmentBytes, len(body))
			binding.Index = i
			nonce := make([]byte, k.cipher.NonceSize())
			_, _ = rand.Read(nonce)
			sealed := k.cipher.Seal(nonce, nonce, body[i*capsuleprotocol.AttachmentSegmentBytes:end], binding.aad())
			if _, err = tx.Exec(ctx, "INSERT INTO attachment_segments(attachment_id,idx,ciphertext) VALUES($1,$2,$3)", id, i, sealed); err != nil {
				return 0, nil, err
			}
		}
		if err = auditTenantAgent(ctx, tx, p, agentID, nil, "attachment.uploaded"); err != nil {
			return 0, nil, err
		}
		return 201, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// mayInvoke applies the invocation rule: scope agent:invoke and a current
// assignment with invoke. An agent the caller cannot see is not found.
func (c *AgentCatalog) mayInvoke(ctx context.Context, tx pgx.Tx, p Principal, agentID string) error {
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentInvoke)
	if err != nil {
		return err
	}
	a, _, err := tenantAgentForUpdate(ctx, tx, p, agentID)
	if err != nil {
		return err
	}
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, agentID)
	if err != nil {
		return err
	}
	access := tenantAccess(p)
	if !authorization.CanAccessAssignedAgent(access, authorization.InvokeAgent, toPermissions(perms)) {
		if authorization.CanAdminister(access, authorization.Role(current.Role), authorization.ReadAgentMetadata) || len(perms) > 0 {
			return ErrForbidden
		}
		return ErrNotFound
	}
	if a.Phase != "LIVE" {
		return ErrUnavailable
	}
	return nil
}

// GetAttachment shows metadata to the uploader or to a role allowed to read
// agent metadata. Never content.
func (c *AgentCatalog) GetAttachment(ctx context.Context, p Principal, id string) (Attachment, error) {
	if p.Kind != "tenant" || !capsuleprotocol.ValidAttachmentID(id) {
		return Attachment{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return Attachment{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentRead)
	if err != nil {
		return Attachment{}, err
	}
	administrative := authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAgentMetadata)
	v, err := scanAttachment(tx.QueryRow(ctx, `SELECT `+attachmentColumns+` FROM attachments
        WHERE id=$1 AND tenant_id=$2 AND ($3 OR uploader_principal_id=$4)`, id, p.TenantID, administrative, p.ID))
	if err != nil {
		return Attachment{}, err
	}
	return v, commit(ctx, tx)
}

// DeleteAttachment lets the uploader free an attachment not yet bound to an
// invocation. Its segments are deleted in the same transaction.
func (c *AgentCatalog) DeleteAttachment(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if p.Kind != "tenant" || !capsuleprotocol.ValidAttachmentID(id) {
		return APIReceipt{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenant(ctx, tx, p, authorization.ScopeAgentInvoke); err != nil {
		return APIReceipt{}, err
	}
	var agentID, status string
	err = tx.QueryRow(ctx, `SELECT agent_id,status FROM attachments WHERE id=$1 AND tenant_id=$2 AND uploader_principal_id=$3 FOR UPDATE`, id, p.TenantID, p.ID).Scan(&agentID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	in := struct {
		ID string `json:"attachment_id"`
	}{id}
	result, err := c.accounts.withTenantReceipt(ctx, tx, p, "attachment.delete/"+id, key, in, func() (int, any, error) {
		if status != "pending" {
			return 0, nil, ErrTransition
		}
		if err := purgeAttachments(ctx, tx, []string{id}); err != nil {
			return 0, nil, err
		}
		if err := auditTenantAgent(ctx, tx, p, agentID, nil, "attachment.deleted"); err != nil {
			return 0, nil, err
		}
		v, err := scanAttachment(tx.QueryRow(ctx, `SELECT `+attachmentColumns+` FROM attachments WHERE id=$1`, id))
		return 200, v, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return result, commit(ctx, tx)
}

// bindAttachments attaches the requester's pending uploads for this agent to a
// new invocation, in the admission transaction. All or nothing: one unusable
// reference refuses the whole invocation, so nothing is half-attached.
func bindAttachments(ctx context.Context, tx pgx.Tx, p Principal, agentID, op string, ids []string) error {
	for i, id := range ids {
		tag, err := tx.Exec(ctx, `UPDATE attachments SET status='attached',operation_id=$1,attached_at=clock_timestamp(),position=$6
            WHERE id=$2 AND tenant_id=$3 AND agent_id=$4 AND uploader_principal_id=$5 AND status='pending' AND expires_at>clock_timestamp()`,
			op, id, p.TenantID, agentID, p.ID, i)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrAttachment
		}
	}
	return nil
}

func validAttachmentList(ids []string) bool {
	if len(ids) > capsuleprotocol.MaxInvocationAttachments {
		return false
	}
	seen := slices.Clone(ids)
	slices.Sort(seen)
	if len(slices.Compact(seen)) != len(ids) {
		return false
	}
	for _, id := range ids {
		if !capsuleprotocol.ValidAttachmentID(id) {
			return false
		}
	}
	return true
}

// attachmentRefs is what the guest is told, in the requester's order. A purged
// attachment of a running invocation means the content is gone: refuse rather
// than deliver an envelope pointing at nothing.
func attachmentRefs(ctx context.Context, tx pgx.Tx, op string) ([]capsuleprotocol.AttachmentRef, error) {
	rows, err := tx.Query(ctx, `SELECT id,name,media_type,size_bytes,encode(sha256,'hex'),status FROM attachments
        WHERE operation_id=$1 ORDER BY position,id`, op)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []capsuleprotocol.AttachmentRef
	for rows.Next() {
		var r capsuleprotocol.AttachmentRef
		var status string
		if err = rows.Scan(&r.ID, &r.Name, &r.MediaType, &r.Size, &r.SHA256, &status); err != nil {
			return nil, err
		}
		if status != "attached" {
			return nil, ErrTransitPayload
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// ReadAttachmentFromVM returns one decrypted segment to the running capsule the
// file was sent to, and only while the invocation carrying it is running: being
// delivered, or acknowledged "working" and not yet due. In practice the guest
// reads after acknowledging "working", since its platform calls wait for the
// exclusive delivery turn to end. Identity comes from the authenticated channel.
func (t *Transit) ReadAttachmentFromVM(ctx context.Context, caller VMCaller, id string, index int) (capsuleprotocol.AttachmentSegment, error) {
	var out capsuleprotocol.AttachmentSegment
	if !capsuleprotocol.ValidAttachmentID(id) || index < 0 {
		return out, ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return out, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return out, err
	}
	var b segmentBinding
	var hash []byte
	err = tx.QueryRow(ctx, `SELECT a.tenant_id,a.uploader_principal_id,a.key_id,a.segments,a.size_bytes,a.sha256 FROM attachments a
        JOIN platform_operations o ON o.id=a.operation_id
        WHERE a.id=$1 AND a.agent_id=$2 AND a.status='attached' AND o.agent_id=$2 AND o.status='RUNNING'
          AND (EXISTS(SELECT 1 FROM agent_mailboxes m WHERE m.instruction_id=o.id AND m.delivery_state='PENDING' AND NOT m.closing)
            OR EXISTS(SELECT 1 FROM owner_instructions i WHERE i.operation_id=o.id AND i.working_since IS NOT NULL
                      AND i.completion_key IS NULL AND i.result_due_at>clock_timestamp()))
        FOR SHARE OF a`, id, caller.AgentID).Scan(&b.Tenant, &b.Uploader, &b.KeyID, &b.Segments, &b.Size, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if index >= b.Segments {
		return out, ErrNotFound
	}
	var sealed []byte
	if err = tx.QueryRow(ctx, "SELECT ciphertext FROM attachment_segments WHERE attachment_id=$1 AND idx=$2", id, index).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrTransitPayload
		}
		return out, err
	}
	k, err := t.checkKey(ctx, tx, b.KeyID)
	if err != nil {
		return out, err
	}
	if len(sealed) < k.cipher.NonceSize()+k.cipher.Overhead() {
		return out, ErrTransitPayload
	}
	b.ID, b.Agent, b.Index, b.Hash = id, caller.AgentID, index, hex.EncodeToString(hash)
	n := k.cipher.NonceSize()
	data, err := k.cipher.Open(nil, sealed[:n], sealed[n:], b.aad())
	if err != nil {
		return out, ErrTransitPayload
	}
	if err = commit(ctx, tx); err != nil {
		clear(data)
		return out, err
	}
	return capsuleprotocol.AttachmentSegment{Index: index, Total: b.Segments, Data: data}, nil
}

func purgeAttachments(ctx context.Context, tx pgx.Tx, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, "DELETE FROM attachment_segments WHERE attachment_id=ANY($1)", ids); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE attachments SET status='purged',purged_at=clock_timestamp() WHERE id=ANY($1) AND status<>'purged'", ids)
	return err
}

// PurgeAttachments deletes the stored bytes of attachments that can no longer be
// used: unattached past their expiry, attached to an invocation that has ended
// (completed, failed, expired or canceled: nobody can read them any more), or
// belonging to an agent being deleted. Metadata stays as a tombstone; the
// storage counts against the quota no more.
func (s *Store) PurgeAttachments(ctx context.Context, now *time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT a.id FROM attachments a JOIN agents g ON g.id=a.agent_id
        WHERE a.status<>'purged' AND (
          (a.status='pending' AND a.expires_at<=`+dbNow+`)
          OR g.phase IN ('QUIESCING','DELETING','DELETED')
          OR (a.status='attached' AND EXISTS(SELECT 1 FROM platform_operations o
                WHERE o.id=a.operation_id AND o.status IN ('SUCCEEDED','FAILED','CANCELED'))))
        ORDER BY a.id LIMIT $2 FOR UPDATE OF a SKIP LOCKED`, nowArg(now), limit)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if err = purgeAttachments(ctx, tx, ids); err != nil {
		return 0, err
	}
	return len(ids), commit(ctx, tx)
}
