package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

// A temporary download link (API conventions, ADR 016) lets the person who
// may read a file or a result fetch it without sending a bearer token, for a
// few minutes. The link is sealed with a key derived from the installation's
// receipt key: it stores nothing, and it shows nothing of what it opens. It
// carries the credential that minted it, narrowed to agent:content:read, and
// one resource. Every download checks that credential and the person's
// rights again, exactly as reading the resource with a bearer would: a
// revoked token, member or assignment opens nothing.

const (
	DefaultLinkTTL = 5 * time.Minute
	MinLinkTTL     = 30 * time.Second
	MaxLinkTTL     = 15 * time.Minute
	linkPrefix     = "dl_"
	maxLinkBytes   = 4096
)

var linkAAD = []byte("agentcapsule.download-link.v1")

// DownloadLink is a path to GET without credentials until ExpiresAt.
type DownloadLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Download is the content a link opens.
type Download struct {
	Name, MediaType, SHA256 string
	Body                    []byte
}

type linkClaims struct {
	Purpose    string                              `json:"purpose"` // attachment or result
	Resource   string                              `json:"resource"`
	Expires    int64                               `json:"expires"` // Unix seconds
	Tenant     string                              `json:"tenant"`
	Principal  string                              `json:"principal"`
	Delegation *delegatedidentity.VerifiedIdentity `json:"delegation,omitempty"`
	Service    string                              `json:"service,omitempty"` // service token ID
}

func linkTTL(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return DefaultLinkTTL, nil
	}
	ttl := time.Duration(seconds) * time.Second
	if seconds < 0 || ttl < MinLinkTTL || ttl > MaxLinkTTL {
		return 0, ErrInput
	}
	return ttl, nil
}

// seal mints a link for p, already authorized for the resource.
func (a *Accounts) seal(p Principal, purpose, resource string, ttl time.Duration, now time.Time) (DownloadLink, error) {
	c := linkClaims{Purpose: purpose, Resource: resource, Expires: now.Add(ttl).Unix(), Tenant: p.TenantID, Principal: p.ID}
	switch {
	case p.delegation != nil:
		v := *p.delegation
		c.Delegation = &v
	case p.service != nil:
		c.Service = p.service.tokenID
	default:
		return DownloadLink{}, ErrForbidden
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return DownloadLink{}, err
	}
	defer clear(plain)
	nonce := make([]byte, a.links.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return DownloadLink{}, err
	}
	sealed := a.links.Seal(nonce, nonce, plain, linkAAD)
	return DownloadLink{URL: "/v1/downloads/" + linkPrefix + base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: time.Unix(c.Expires, 0).UTC()}, nil
}

// open returns the principal a valid, unexpired link stands for, with only
// the scope to read content. Any fault is ErrNotFound: a caller learns
// nothing about why a link opens nothing.
func (a *Accounts) open(token string, now time.Time) (Principal, linkClaims, error) {
	var c linkClaims
	raw, ok := strings.CutPrefix(token, linkPrefix)
	if !ok || len(token) > maxLinkBytes {
		return Principal{}, c, ErrNotFound
	}
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	n := a.links.NonceSize()
	if err != nil || len(sealed) < n+a.links.Overhead() {
		return Principal{}, c, ErrNotFound
	}
	plain, err := a.links.Open(nil, sealed[:n], sealed[n:], linkAAD)
	if err != nil {
		return Principal{}, c, ErrNotFound
	}
	defer clear(plain)
	if json.Unmarshal(plain, &c) != nil || !now.Before(time.Unix(c.Expires, 0)) || c.Tenant == "" || c.Principal == "" {
		return Principal{}, c, ErrNotFound
	}
	read := []string{authorization.ScopeAgentContentRead}
	p := Principal{Kind: "tenant", ID: c.Principal, TenantID: c.Tenant, Scopes: read}
	switch {
	case c.Delegation != nil && c.Service == "":
		v := *c.Delegation
		v.Scopes = read
		p.delegation, p.TokenID = &v, v.TokenID
	case c.Delegation == nil && c.Service != "":
		p.service, p.TokenID = &serviceBinding{tenantID: c.Tenant, tokenID: c.Service, scopes: read}, c.Service
	default:
		return Principal{}, c, ErrNotFound
	}
	if !tenantBound(p) {
		return Principal{}, c, ErrNotFound
	}
	return p, c, nil
}

// readable authorizes p to read content: its credential and membership are
// current and it holds the scope agent:content:read.
func readable(ctx context.Context, tx pgx.Tx, p Principal) error {
	if p.Kind != "tenant" || !slices.Contains(tenantScopes(p), authorization.ScopeAgentContentRead) {
		return ErrNotFound
	}
	_, err := authorizeTenant(ctx, tx, p, authorization.ScopeAgentContentRead)
	return err
}

// mayReadAgentContent: p holds read_content on the agent now.
func mayReadAgentContent(ctx context.Context, tx pgx.Tx, p Principal, agentID string) error {
	perms, err := effectiveAgentPermissions(ctx, tx, p.TenantID, p.ID, agentID)
	if err != nil {
		return err
	}
	if !authorization.CanAccessAssignedAgent(tenantAccess(p), authorization.ReadAgentContent, toPermissions(perms)) {
		return ErrNotFound
	}
	return nil
}

// attachmentForReader is a stored file its sender may read: they uploaded it
// and hold read_content on its agent now.
func attachmentForReader(ctx context.Context, tx pgx.Tx, p Principal, id string) (segmentBinding, Attachment, error) {
	var b segmentBinding
	var hash []byte
	v, err := scanAttachment(tx.QueryRow(ctx, `SELECT `+attachmentColumns+` FROM attachments
        WHERE id=$1 AND tenant_id=$2 AND uploader_principal_id=$3
          AND (status='attached' OR status='pending' AND expires_at>clock_timestamp())`, id, p.TenantID, p.ID))
	if err != nil {
		return b, v, err
	}
	if err = mayReadAgentContent(ctx, tx, p, v.AgentID); err != nil {
		return b, v, err
	}
	err = tx.QueryRow(ctx, `SELECT tenant_id,uploader_principal_id,key_id,segments,size_bytes,sha256 FROM attachments WHERE id=$1 FOR SHARE`, id).
		Scan(&b.Tenant, &b.Uploader, &b.KeyID, &b.Segments, &b.Size, &hash)
	b.ID, b.Agent, b.Hash = id, v.AgentID, hex.EncodeToString(hash)
	return b, v, err
}

// AttachmentLink mints a link to a file for its sender, while they hold
// read_content on its agent and the file is still stored.
func (c *AgentCatalog) AttachmentLink(ctx context.Context, p Principal, id string, ttlSeconds int) (DownloadLink, error) {
	ttl, err := linkTTL(ttlSeconds)
	if err != nil {
		return DownloadLink{}, err
	}
	if p.Kind != "tenant" || !capsuleprotocol.ValidAttachmentID(id) {
		return DownloadLink{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return DownloadLink{}, err
	}
	defer rollback(tx)
	if err = readable(ctx, tx, p); err != nil {
		return DownloadLink{}, err
	}
	if _, _, err = attachmentForReader(ctx, tx, p, id); err != nil {
		return DownloadLink{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return DownloadLink{}, err
	}
	return c.accounts.seal(p, "attachment", id, ttl, time.Now())
}

// ResultLink mints a link to an invocation's result, with the rule of the
// result read: its requester, while they hold read_content.
func (c *AgentCatalog) ResultLink(ctx context.Context, p Principal, operation string, ttlSeconds int) (DownloadLink, error) {
	ttl, err := linkTTL(ttlSeconds)
	if err != nil {
		return DownloadLink{}, err
	}
	if p.Kind != "tenant" || !validOrganizationText(operation, 100) {
		return DownloadLink{}, ErrNotFound
	}
	tx, err := c.accounts.store.begin(ctx)
	if err != nil {
		return DownloadLink{}, err
	}
	defer rollback(tx)
	if err = readable(ctx, tx, p); err != nil {
		return DownloadLink{}, err
	}
	var agentID string
	err = tx.QueryRow(ctx, `SELECT o.agent_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id
        JOIN agents a ON a.id=o.agent_id
        JOIN transit_payloads payload ON payload.id=i.result_payload_id AND payload.kind='instruction_result' AND payload.ref_id=o.id`+rerunJoins+`
        WHERE o.id=$1 AND a.tenant_id=$2 AND o.requested_by_principal_id=$3 AND o.kind='instruction'
          AND (o.status='SUCCEEDED' OR `+lostCondition+`) AND i.result_payload_id IS NOT NULL AND payload.purged_at IS NULL`, operation, p.TenantID, p.ID).Scan(&agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DownloadLink{}, ErrNotFound
	}
	if err != nil {
		return DownloadLink{}, err
	}
	if err = mayReadAgentContent(ctx, tx, p, agentID); err != nil {
		return DownloadLink{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return DownloadLink{}, err
	}
	return c.accounts.seal(p, "result", operation, ttl, time.Now())
}

// OpenDownload returns what a link opens, after checking its seal, its
// expiry, its credential and the person's rights, as of now.
func (c *AgentCatalog) OpenDownload(ctx context.Context, token string) (Download, error) {
	if c.transit == nil {
		return Download{}, ErrTransitKey
	}
	p, claims, err := c.accounts.open(token, time.Now())
	if err != nil {
		return Download{}, err
	}
	var out Download
	switch claims.Purpose {
	case "result":
		out.Body, err = c.instructionResultTenant(ctx, p, claims.Resource)
		out.Name, out.MediaType = "result.json", "application/json"
		if err == nil {
			sum := sha256.Sum256(out.Body)
			out.SHA256 = hex.EncodeToString(sum[:])
		}
	case "attachment":
		out, err = c.transit.attachmentDownload(ctx, p, claims.Resource)
	default:
		err = ErrNotFound
	}
	if errors.Is(err, ErrAuthentication) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrInput) {
		err = ErrNotFound
	}
	return out, err
}

// attachmentDownload decrypts a whole file for its sender and checks it
// against its size and digest.
func (t *Transit) attachmentDownload(ctx context.Context, p Principal, id string) (Download, error) {
	tx, err := t.store.begin(ctx)
	if err != nil {
		return Download{}, err
	}
	defer rollback(tx)
	if err = readable(ctx, tx, p); err != nil {
		return Download{}, err
	}
	b, v, err := attachmentForReader(ctx, tx, p, id)
	if err != nil {
		return Download{}, err
	}
	k, err := t.checkKey(ctx, tx, b.KeyID)
	if err != nil {
		return Download{}, err
	}
	body := make([]byte, 0, b.Size)
	for i := range b.Segments {
		var sealed []byte
		if err = tx.QueryRow(ctx, "SELECT ciphertext FROM attachment_segments WHERE attachment_id=$1 AND idx=$2", id, i).Scan(&sealed); err != nil {
			clear(body)
			if errors.Is(err, pgx.ErrNoRows) {
				return Download{}, ErrTransitPayload
			}
			return Download{}, err
		}
		n := k.cipher.NonceSize()
		if len(sealed) < n+k.cipher.Overhead() {
			clear(body)
			return Download{}, ErrTransitPayload
		}
		b.Index = i
		if body, err = k.cipher.Open(body, sealed[:n], sealed[n:], b.aad()); err != nil {
			clear(body)
			return Download{}, ErrTransitPayload
		}
	}
	sum := sha256.Sum256(body)
	if int64(len(body)) != b.Size || hex.EncodeToString(sum[:]) != b.Hash {
		clear(body)
		return Download{}, ErrTransitPayload
	}
	if err = commit(ctx, tx); err != nil {
		clear(body)
		return Download{}, err
	}
	return Download{Name: v.Name, MediaType: v.MediaType, SHA256: b.Hash, Body: body}, nil
}
