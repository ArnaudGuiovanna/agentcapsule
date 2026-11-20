package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
	"github.com/jackc/pgx/v5"
)

type ReviewFile struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type CorpusReview struct {
	Files     []ReviewFile `json:"items"`
	Truncated bool         `json:"truncated"`
}
type CorpusResult struct {
	Digest, UUID string
	Bytes        int64
	Files        map[string][]byte
	Truncated    bool
}

func reviewPath(path string) bool {
	if path == "INDEX.md" || path == "report.json" {
		return true
	}
	parts := strings.Split(path, "/")
	return len(parts) == 3 && parts[0] == "docs" && capsuleprotocol.ValidCorpusMount(parts[1]) && parts[2] == "README.md"
}

// A review segment authenticates its position, contents and tenant even if a
// database backup is corrupted or rows of different builds are exchanged.
func reviewAAD(j CorpusWork, key string, f ReviewFile, index int) []byte {
	aad, _ := json.Marshal([]any{"agentcapsule.corpus-review/v1", j.Tenant, j.ID, key, f.Path, f.Bytes, f.SHA256, index})
	return aad
}
func (t *Transit) writeReviewFile(ctx context.Context, tx pgx.Tx, j CorpusWork, key transitKey, path string, body []byte) error {
	digest := sha256.Sum256(body)
	f := ReviewFile{path, len(body), hex.EncodeToString(digest[:])}
	_, err := tx.Exec(ctx, `INSERT INTO corpus_review_files(build_id,path,bytes,sha256,key_id) VALUES($1,$2,$3,$4,$5)`, j.ID, path, len(body), f.SHA256, t.active)
	if err != nil {
		return err
	}
	for offset, index := 0, 0; offset < len(body); offset, index = offset+capsuleprotocol.AttachmentSegmentBytes, index+1 {
		nonce := make([]byte, key.cipher.NonceSize())
		rand.Read(nonce)
		end := min(offset+capsuleprotocol.AttachmentSegmentBytes, len(body))
		data := key.cipher.Seal(nonce, nonce, body[offset:end], reviewAAD(j, t.active, f, index))
		if _, err = tx.Exec(ctx, `INSERT INTO corpus_review_segments(build_id,path,idx,ciphertext) VALUES($1,$2,$3,$4)`, j.ID, path, index, data); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transit) CompleteCorpusReview(ctx context.Context, j CorpusWork, r CorpusResult) error {
	if t == nil {
		return ErrTransitKey
	}
	if j.Phase != "PACKAGING" || !reference.ValidDigest(r.Digest) || r.Bytes <= 0 || !capsuleprotocol.ValidUUID(r.UUID) || len(r.Files["INDEX.md"]) == 0 || len(r.Files["report.json"]) == 0 {
		return ErrInput
	}
	var total int
	for path, body := range r.Files {
		total += len(body)
		if !reviewPath(path) || len(body) > 1<<20 || total > 8<<20 {
			return ErrInput
		}
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	err = tx.QueryRow(ctx, "SELECT tenant_id FROM corpus_builds"+corpusLease+" FOR UPDATE", j.ID, j.Token, j.Phase).Scan(&j.Tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err = lockOrganizationQuota(ctx, tx, j.Tenant); err != nil {
		return err
	}
	q, _, err := organizationQuotas(ctx, tx, j.Tenant)
	if err != nil {
		return err
	}
	if q.MaxCorpusStorageMiB != nil {
		used, _, err := corpusOccupation(ctx, tx, j.Tenant)
		if err != nil {
			return err
		}
		var pinned bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM corpus_releases WHERE tenant_id=$1 AND digest=$2 AND deprecated_at IS NULL UNION ALL SELECT 1 FROM corpus_builds WHERE tenant_id=$1 AND image_digest=$2 AND state='REVIEW')`, j.Tenant, r.Digest).Scan(&pinned); err != nil {
			return err
		}
		if !pinned && r.Bytes > (*q.MaxCorpusStorageMiB<<20)-used {
			_, err = tx.Exec(ctx, `UPDATE corpus_builds SET state='FAILED',error_code='quota_exceeded',lease_token=NULL,lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1`, j.ID)
			if err != nil {
				return err
			}
			return commit(ctx, tx)
		}
	}
	key, err := t.activeKey(ctx, tx)
	if err != nil {
		return err
	}
	for path, body := range r.Files {
		if err = t.writeReviewFile(ctx, tx, j, key, path, body); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE corpus_builds SET state='REVIEW',image_digest=$4,image_uuid=$5,image_bytes=$6,review_truncated=$7,
 review_at=clock_timestamp(),review_expires_at=clock_timestamp()+interval '30 days',costs=`+corpusCosts+corpusNext+corpusLease, j.ID, j.Token, j.Phase, r.Digest, r.UUID, r.Bytes, r.Truncated)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return commit(ctx, tx)
}

const availableReview = ` AND (b.state='PUBLISHED' OR b.state='REVIEW' AND b.review_expires_at>clock_timestamp())`

func (a *Accounts) CorpusBuildReview(ctx context.Context, p Principal, id string) (CorpusReview, error) {
	return corpusRead(ctx, a, p, authorization.ManageCorpus, func(tx pgx.Tx) (CorpusReview, error) {
		v := CorpusReview{Files: []ReviewFile{}}
		err := tx.QueryRow(ctx, "SELECT b.review_truncated FROM corpus_builds b WHERE b.id=$1 AND b.tenant_id=$2"+availableReview+" FOR SHARE", id, p.TenantID).Scan(&v.Truncated)
		if err != nil {
			return v, corpusRowError(err)
		}
		rows, err := tx.Query(ctx, `SELECT path,bytes,sha256 FROM corpus_review_files WHERE build_id=$1 ORDER BY path`, id)
		if err == nil {
			v.Files, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ReviewFile])
		}
		return v, err
	})
}
func (c *AgentCatalog) ReadCorpusReviewFile(ctx context.Context, p Principal, id, path string) ([]byte, error) {
	if !reviewPath(path) {
		return nil, ErrNotFound
	}
	return corpusRead(ctx, c.accounts, p, authorization.ManageCorpus, func(tx pgx.Tx) ([]byte, error) {
		f := ReviewFile{Path: path}
		var keyID string
		err := tx.QueryRow(ctx, `SELECT f.bytes,f.sha256,f.key_id FROM corpus_builds b JOIN corpus_review_files f ON f.build_id=b.id WHERE b.id=$1 AND b.tenant_id=$2 AND f.path=$3`+availableReview+" FOR SHARE OF b,f", id, p.TenantID, path).Scan(&f.Bytes, &f.SHA256, &keyID)
		if err != nil {
			return nil, corpusRowError(err)
		}
		if c.transit == nil {
			return nil, ErrTransitKey
		}
		k, err := c.transit.checkKey(ctx, tx, keyID)
		if err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT idx,ciphertext FROM corpus_review_segments WHERE build_id=$1 AND path=$2 ORDER BY idx`, id, path)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		body := make([]byte, 0, f.Bytes)
		for index := 0; rows.Next(); index++ {
			var idx int
			var sealed []byte
			if err = rows.Scan(&idx, &sealed); err != nil {
				return nil, err
			}
			n := k.cipher.NonceSize()
			if idx != index || len(sealed) < n+k.cipher.Overhead() || len(body) >= f.Bytes {
				return nil, ErrTransitPayload
			}
			data, err := k.cipher.Open(nil, sealed[:n], sealed[n:], reviewAAD(CorpusWork{ID: id, Tenant: p.TenantID}, keyID, f, idx))
			if err != nil || len(data) != min(capsuleprotocol.AttachmentSegmentBytes, f.Bytes-len(body)) {
				return nil, ErrTransitPayload
			}
			body = append(body, data...)
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		expected, err := hex.DecodeString(f.SHA256)
		if err != nil || len(body) != f.Bytes || !slices.Equal(sum[:], expected) {
			return nil, ErrTransitPayload
		}
		return body, nil
	})
}
