package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// This envelope is deliberately distinct from receiptScope. Its serialized
// fields and version are a storage contract, not an extensible API DTO.
type tenantReceiptAAD struct {
	Domain         string `json:"domain"`
	Version        int    `json:"version"`
	Tenant         string `json:"tenant"`
	Principal      string `json:"principal"`
	Operation      string `json:"operation"`
	Key            string `json:"key"`
	RequestHash    string `json:"request_hash"`
	ResponseStatus int    `json:"response_status"`
}

// withTenantReceipt requires the organization's UPDATE lock and current actor
// AND target authorization. The lock serializes mutation and receipt creation;
// a competing request waits, then rechecks rights before replaying.
func (a *Accounts) withTenantReceipt(ctx context.Context, tx pgx.Tx, p Principal, operation, key string, input any, fn func() (int, any, error)) (APIReceipt, error) {
	if !validKey(key) {
		return APIReceipt{}, ErrInput
	}
	hash, err := requestHash(input)
	if err != nil {
		return APIReceipt{}, err
	}
	aad := func(status int) []byte {
		encoded, _ := json.Marshal(tenantReceiptAAD{Domain: "agentcapsule.tenant-http-receipt", Version: 1, Tenant: p.TenantID, Principal: p.ID, Operation: operation, Key: key, RequestHash: hex.EncodeToString(hash[:]), ResponseStatus: status})
		return encoded
	}
	args := []any{p.TenantID, p.ID, operation, key}
	if _, err = tx.Exec(ctx, `DELETE FROM tenant_http_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation=$3 AND key=$4 AND expires_at<=clock_timestamp()`, args...); err != nil {
		return APIReceipt{}, err
	}
	var original, ciphertext []byte
	var version int
	var result APIReceipt
	err = tx.QueryRow(ctx, `SELECT request_hash,response_status,response_ciphertext,aad_version FROM tenant_http_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation=$3 AND key=$4`, args...).Scan(&original, &result.Status, &ciphertext, &version)
	if err == nil {
		if !bytes.Equal(original, hash[:]) {
			return APIReceipt{}, ErrConflict
		}
		if version != 1 || len(ciphertext) < a.cipher.NonceSize()+a.cipher.Overhead() {
			return APIReceipt{}, errors.New("invalid encrypted tenant receipt")
		}
		plain, err := a.cipher.Open(nil, ciphertext[:a.cipher.NonceSize()], ciphertext[a.cipher.NonceSize():], aad(result.Status))
		if err != nil {
			return APIReceipt{}, errors.New("tenant receipt cannot be decrypted")
		}
		result.Body, result.Replayed = plain, true
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return APIReceipt{}, err
	}
	status, body, err := fn()
	if err != nil {
		return APIReceipt{}, err
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return APIReceipt{}, err
	}
	nonce := make([]byte, a.cipher.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return APIReceipt{}, err
	}
	ciphertext = a.cipher.Seal(nonce, nonce, plain, aad(status))
	_, err = tx.Exec(ctx, `INSERT INTO tenant_http_receipts(tenant_id,principal_id,operation,key,request_hash,response_status,response_ciphertext,aad_version) VALUES($1,$2,$3,$4,$5,$6,$7,1)`, p.TenantID, p.ID, operation, key, hash[:], status, ciphertext)
	return APIReceipt{Status: status, Body: plain}, err
}
