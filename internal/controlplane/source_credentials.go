package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"regexp"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
	"github.com/jackc/pgx/v5"
)

// SourceCredential is the metadata of an organization's read-only forge
// token (ADR 023 §3.1). The secret is write-only: no field, receipt, log or
// audit event ever carries it back.
type SourceCredential struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Host       string     `json:"host"`
	Generation int64      `json:"generation"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
}

type CreateSourceCredentialInput struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Secret string `json:"secret"`
}

// SourceSecret is what the worker needs to fetch with a credential. It holds
// a decrypted token and must stay in the worker's memory.
type SourceSecret struct {
	Kind, Host string
	Secret     string
}

var (
	// ErrSourceCredentialNameTaken: the organization already has a source
	// credential of this name (409 source_credential_name_taken).
	ErrSourceCredentialNameTaken = errors.New("the organization already has a source credential of this name")
	// ErrSourceCredentialDisabled: the credential was disabled; its secret
	// is gone. A build that needs it fails access_denied.
	ErrSourceCredentialDisabled = errors.New("the source credential is disabled")
)

var sourceCredentialName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// validSourceSecret: 1 to 4,096 bytes of visible ASCII, so that it fits an
// HTTP header as it is.
func validSourceSecret(s string) bool {
	if len(s) < 1 || len(s) > 4096 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// validSourceHost: a forge host, a DNS name in lower case with an optional
// port. The API cannot see the workers' rules: the worker refuses a build
// whose credential's host matches none (policy).
func validSourceHost(h string) bool { return len(h) <= 253 && reference.ValidHost(h) }

func (a *Accounts) sealSourceSecret(tenant, id string, generation int64, secret string) []byte {
	nonce := make([]byte, a.sources.NonceSize())
	_, _ = rand.Read(nonce)
	return a.sources.Seal(nonce, nonce, []byte(secret), sourceCredentialAAD(tenant, id, generation))
}

func (a *Accounts) openSourceSecret(tenant, id string, generation int64, sealed []byte) (string, error) {
	n := a.sources.NonceSize()
	if len(sealed) < n {
		return "", ErrInput
	}
	plain, err := a.sources.Open(nil, sealed[:n], sealed[n:], sourceCredentialAAD(tenant, id, generation))
	return string(plain), err
}

// sourceCredentialAAD binds a ciphertext to its organization, credential and
// generation: a ciphertext moved to another row, or kept from an earlier
// generation, does not open.
func sourceCredentialAAD(tenant, id string, generation int64) []byte {
	return binary.BigEndian.AppendUint64([]byte("agentcapsule.source-credential/"+tenant+"/"+id+"/"), uint64(generation))
}

const sourceCredentialColumns = `id,name,kind,host,generation,status,created_at,rotated_at,disabled_at`

func scanSourceCredential(row pgx.Row) (SourceCredential, error) {
	var v SourceCredential
	err := row.Scan(&v.ID, &v.Name, &v.Kind, &v.Host, &v.Generation, &v.Status, &v.CreatedAt, &v.RotatedAt, &v.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func auditSourceCredential(ctx context.Context, tx pgx.Tx, p Principal, id, action string) error {
	var credential *string
	if p.TokenID != "" {
		credential = &p.TokenID
	}
	_, err := tx.Exec(ctx, `INSERT INTO corpus_audit(id,tenant_id,actor_principal_id,credential_id,action,source_credential_id) VALUES($1,$2,$3,$4,$5,$6)`,
		newID("audit"), p.TenantID, p.ID, credential, action, id)
	return err
}

// CreateSourceCredential seals a forge token for the organization. The
// receipt keeps a digest of the secret, never the secret.
func (a *Accounts) CreateSourceCredential(ctx context.Context, p Principal, key string, in CreateSourceCredentialInput) (APIReceipt, error) {
	if !sourceCredentialName.MatchString(in.Name) || (in.Kind != "github" && in.Kind != "gitlab") || !validSourceHost(in.Host) || !validSourceSecret(in.Secret) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageCorpus); err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ Name, Kind, Host, SecretSHA256 string }{in.Name, in.Kind, in.Host, secretDigest(in.Secret)}
	r, err := a.withTenantReceipt(ctx, tx, p, "source_credential.create", key, hashed, func() (int, any, error) {
		id := newID("scr")
		v, err := scanSourceCredential(tx.QueryRow(ctx, `INSERT INTO source_credentials(id,tenant_id,name,kind,host,sealed,created_by)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,name) DO NOTHING RETURNING `+sourceCredentialColumns,
			id, p.TenantID, in.Name, in.Kind, in.Host, a.sealSourceSecret(p.TenantID, id, 1, in.Secret), p.ID))
		if errors.Is(err, ErrNotFound) {
			return 0, nil, ErrSourceCredentialNameTaken
		}
		if err != nil {
			return 0, nil, err
		}
		return 201, v, auditSourceCredential(ctx, tx, p, id, "source_credential.created")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// RotateSourceCredential replaces the secret: a new generation, which the
// next fetch uses. A disabled credential cannot be rotated.
func (a *Accounts) RotateSourceCredential(ctx context.Context, p Principal, id, key, secret string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) || !validSourceSecret(secret) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageCorpus); err != nil {
		return APIReceipt{}, err
	}
	var generation int64
	var status string
	if err = tx.QueryRow(ctx, `SELECT generation,status FROM source_credentials WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id).Scan(&generation, &status); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	hashed := struct{ ID, SecretSHA256 string }{id, secretDigest(secret)}
	r, err := a.withTenantReceipt(ctx, tx, p, "source_credential.rotate", key, hashed, func() (int, any, error) {
		if status != "active" {
			return 0, nil, ErrTransition
		}
		v, err := scanSourceCredential(tx.QueryRow(ctx, `UPDATE source_credentials SET sealed=$3,generation=$4,rotated_at=clock_timestamp()
            WHERE tenant_id=$1 AND id=$2 RETURNING `+sourceCredentialColumns, p.TenantID, id, a.sealSourceSecret(p.TenantID, id, generation+1, secret), generation+1))
		if err != nil {
			return 0, nil, err
		}
		return 200, v, auditSourceCredential(ctx, tx, p, id, "source_credential.rotated")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// DisableSourceCredential erases the secret for good. It is idempotent: a
// credential already disabled answers as it is. A build that needs it then
// fails access_denied; a new credential replaces it.
func (a *Accounts) DisableSourceCredential(ctx context.Context, p Principal, id, key string) (APIReceipt, error) {
	if !validOrganizationText(id, 100) {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageCorpus); err != nil {
		return APIReceipt{}, err
	}
	var status string
	if err = tx.QueryRow(ctx, `SELECT status FROM source_credentials WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, p.TenantID, id).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, ErrNotFound
	} else if err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withTenantReceipt(ctx, tx, p, "source_credential.disable", key, struct{ ID string }{id}, func() (int, any, error) {
		if status == "disabled" {
			v, err := scanSourceCredential(tx.QueryRow(ctx, `SELECT `+sourceCredentialColumns+` FROM source_credentials WHERE tenant_id=$1 AND id=$2`, p.TenantID, id))
			return 200, v, err
		}
		v, err := scanSourceCredential(tx.QueryRow(ctx, `UPDATE source_credentials SET status='disabled',disabled_at=clock_timestamp(),sealed=NULL
            WHERE tenant_id=$1 AND id=$2 RETURNING `+sourceCredentialColumns, p.TenantID, id))
		if err != nil {
			return 0, nil, err
		}
		return 200, v, auditSourceCredential(ctx, tx, p, id, "source_credential.disabled")
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// ListSourceCredentials lists the organization's credentials by identifier,
// metadata only.
func (a *Accounts) ListSourceCredentials(ctx context.Context, p Principal, after string, limit int) ([]SourceCredential, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, authorization.ScopeCorpusManage)
	if err != nil {
		return nil, err
	}
	if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ManageCorpus) {
		return nil, ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT `+sourceCredentialColumns+` FROM source_credentials WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SourceCredential{}
	for rows.Next() {
		v, err := scanSourceCredential(rows)
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

// OpenSourceCredential decrypts an organization's credential for the
// worker, when it fetches a corpus's sources. It needs the installation's
// receipt key, as provider credentials do. A disabled credential, or one of
// a disabled organization, is ErrSourceCredentialDisabled; another
// organization's, or none, ErrNotFound.
func (a *Accounts) OpenSourceCredential(ctx context.Context, tenantID, id string) (SourceSecret, error) {
	if !validOrganizationText(tenantID, 100) || !validOrganizationText(id, 100) {
		return SourceSecret{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return SourceSecret{}, err
	}
	defer rollback(tx)
	var s SourceSecret
	var generation int64
	var active bool
	var sealed []byte
	err = tx.QueryRow(ctx, `SELECT c.kind,c.host,c.generation,c.status='active' AND o.status='active',c.sealed
        FROM source_credentials c JOIN organizations o ON o.id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2 FOR SHARE OF c`, tenantID, id).
		Scan(&s.Kind, &s.Host, &generation, &active, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceSecret{}, ErrNotFound
	}
	if err != nil {
		return SourceSecret{}, err
	}
	if !active {
		return SourceSecret{}, ErrSourceCredentialDisabled
	}
	if s.Secret, err = a.openSourceSecret(tenantID, id, generation, sealed); err != nil {
		return SourceSecret{}, err
	}
	return s, commit(ctx, tx)
}
