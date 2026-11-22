package controlplane

import (
	"context"
	"regexp"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
)

var declaredDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckAttachmentUpload answers, before the API reads an upload's body, what
// UploadAttachment would answer from the request's headers, the caller's
// rights and the organization's room (v0.1.0 audit, S-09): the name, type and
// lifetime; the scope agent:invoke and an invoke assignment on a live agent
// of the caller's organization; and, unless the key replays a stored answer,
// room for size more bytes under max_attachment_bytes. size is the declared
// Content-Length, or -1. It changes nothing: UploadAttachment checks
// everything again in the transaction that stores the file. Its refusals are
// the upload's, in the upload's order.
func (c *AgentCatalog) CheckAttachmentUpload(ctx context.Context, p Principal, agentID, key string, in AttachmentUpload, size int64) error {
	if p.Kind != "tenant" || !validOrganizationText(agentID, 100) {
		return ErrNotFound
	}
	if size > wire.MaxAttachmentBytes {
		return ErrTooLarge
	}
	if _, err := attachmentTTL(in.TTLSeconds); err != nil {
		return err
	}
	if size == 0 || !wire.ValidAttachmentName(in.Name) || !wire.ValidAttachmentType(in.MediaType) ||
		in.DeclaredSHA256 != "" && !declaredDigest.MatchString(in.DeclaredSHA256) {
		return ErrInput
	}
	if c.transit == nil {
		return ErrTransitKey
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = c.mayInvoke(ctx, tx, p, agentID); err != nil {
		return err
	}
	if !validKey(key) {
		return ErrInput
	}
	var replay bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_http_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation=$3 AND key=$4
        AND expires_at>clock_timestamp())`, p.TenantID, p.ID, "attachment.upload/"+agentID, key).Scan(&replay); err != nil || replay {
		return err
	}
	limits, err := queueLimits(ctx, tx, p.TenantID)
	if err != nil {
		return err
	}
	var used int64
	if err = tx.QueryRow(ctx, `SELECT coalesce(sum(size_bytes),0) FROM attachments WHERE tenant_id=$1 AND status<>'purged'`, p.TenantID).Scan(&used); err != nil {
		return err
	}
	if used+max(size, 1) > limits.MaxAttachmentBytes {
		return ErrStorageQuota
	}
	return nil
}
