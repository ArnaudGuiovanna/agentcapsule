package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Accounts owns the API receipt-encryption key. The key is operator-managed,
// outside PostgreSQL, and is NOT an agent data-encryption or erasure key.
type Accounts struct {
	store   *Store
	cipher  cipher.AEAD
	keyHash [32]byte
	// Purpose-bound key for LLM provider credentials, derived from the
	// installation key so that no extra operator file is required.
	llm cipher.AEAD
}

func NewAccounts(store *Store, receiptKey []byte) (*Accounts, error) {
	if store == nil || len(receiptKey) != 32 {
		return nil, ErrInput
	}
	block, err := aes.NewCipher(receiptKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, receiptKey)
	mac.Write([]byte("agentcapsule.llm-provider-secret.v1"))
	llmBlock, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	llmAEAD, err := cipher.NewGCM(llmBlock)
	if err != nil {
		return nil, err
	}
	return &Accounts{store: store, cipher: aead, keyHash: sha256.Sum256(receiptKey), llm: llmAEAD}, nil
}

var ErrReceiptKey = errors.New("receipt key does not match this installation")

// InitializeReceiptKey is an explicit installation operation. Losing the key
// file must not silently bind a new key to an existing receipt history.
func (a *Accounts) InitializeReceiptKey(ctx context.Context) error {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610044)"); err != nil {
		return err
	}
	var stored []byte
	err = tx.QueryRow(ctx, "SELECT key_hash FROM api_receipt_key WHERE singleton").Scan(&stored)
	if err == nil {
		if string(stored) != string(a.keyHash[:]) {
			return ErrReceiptKey
		}
		return commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var receipts bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM http_receipts) OR EXISTS(SELECT 1 FROM tenant_http_receipts)").Scan(&receipts); err != nil {
		return err
	}
	if receipts {
		return ErrReceiptKey
	}
	if _, err = tx.Exec(ctx, "INSERT INTO api_receipt_key(singleton,key_hash) VALUES(true,$1)", a.keyHash[:]); err != nil {
		return err
	}
	return commit(ctx, tx)
}
func (a *Accounts) CheckReceiptKey(ctx context.Context) error {
	var stored []byte
	err := a.store.pool.QueryRow(ctx, "SELECT key_hash FROM api_receipt_key WHERE singleton").Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrReceiptKey
	}
	if err != nil {
		return err
	}
	if string(stored) != string(a.keyHash[:]) {
		return ErrReceiptKey
	}
	return nil
}

type User struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateUserInput struct {
	DisplayName string `json:"display_name"`
}
type IssueTokenInput struct {
	ExpiresAt time.Time `json:"expires_at"`
}
type TokenResponse struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
type APIReceipt struct {
	Status   int
	Body     json.RawMessage
	Replayed bool
}

type receiptScope struct{ Kind, Actor, Method, Route, Key string }

func scope(p Principal, method, route, key string) receiptScope {
	return receiptScope{p.Kind, p.ID, method, route, key}
}
func validKey(key string) bool {
	if len(key) < 1 || len(key) > 200 {
		return false
	}
	for _, c := range key {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// withReceipt runs inside the caller's authorized transaction. The receipt and
// protected mutation commit together. An in-flight identical key returns 409
// rather than waiting; a subsequent retry reads the exact committed response.
func (a *Accounts) withReceipt(ctx context.Context, tx pgx.Tx, s receiptScope, input any, fn func() (int, any, error)) (APIReceipt, error) {
	if err := lockHTTPReceipt(ctx, tx, s); err != nil {
		return APIReceipt{}, err
	}
	aad, _ := json.Marshal(s)
	hash, err := requestHash(input)
	if err != nil {
		return APIReceipt{}, err
	}
	args := []any{s.Kind, s.Actor, s.Method, s.Route, s.Key}
	if _, err = tx.Exec(ctx, `DELETE FROM http_receipts WHERE actor_kind=$1 AND actor_id=$2 AND method=$3 AND route=$4 AND key=$5 AND expires_at<=clock_timestamp()`, args...); err != nil {
		return APIReceipt{}, err
	}
	var original, ciphertext []byte
	var result APIReceipt
	err = tx.QueryRow(ctx, `SELECT request_hash,response_status,response_ciphertext FROM http_receipts
        WHERE actor_kind=$1 AND actor_id=$2 AND method=$3 AND route=$4 AND key=$5`, args...).Scan(&original, &result.Status, &ciphertext)
	if err == nil {
		if len(original) != 32 || string(original) != string(hash[:]) {
			return APIReceipt{}, ErrConflict
		}
		if len(ciphertext) < a.cipher.NonceSize()+a.cipher.Overhead() {
			return APIReceipt{}, errors.New("invalid encrypted API receipt")
		}
		plain, err := a.cipher.Open(nil, ciphertext[:a.cipher.NonceSize()], ciphertext[a.cipher.NonceSize():], aad)
		if err != nil {
			return APIReceipt{}, errors.New("API receipt cannot be decrypted")
		}
		result.Body = plain
		result.Replayed = true
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
	_, _ = rand.Read(nonce)
	ciphertext = a.cipher.Seal(nonce, nonce, plain, aad)
	_, err = tx.Exec(ctx, `INSERT INTO http_receipts(actor_kind,actor_id,method,route,key,request_hash,response_status,response_ciphertext)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, s.Kind, s.Actor, s.Method, s.Route, s.Key, hash[:], status, ciphertext)
	return APIReceipt{Status: status, Body: plain}, err
}

func lockHTTPReceipt(ctx context.Context, tx pgx.Tx, s receiptScope) error {
	if !validKey(s.Key) {
		return ErrInput
	}
	b, _ := json.Marshal(s)
	hash := sha256.Sum256(b)
	var locked bool
	if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(hash[:8]))).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return ErrInProgress
	}
	return nil
}

func (a *Accounts) CreateUser(ctx context.Context, p Principal, key string, in CreateUserInput) (APIReceipt, error) {
	if !utf8.ValidString(in.DisplayName) || utf8.RuneCountInString(in.DisplayName) > 100 || strings.TrimSpace(in.DisplayName) == "" || strings.IndexFunc(in.DisplayName, unicode.IsControl) >= 0 {
		return APIReceipt{}, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "service", "user:manage"); err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/users", key), in, func() (int, any, error) {
		var u User
		err := tx.QueryRow(ctx, `INSERT INTO users(id,display_name) VALUES($1,$2)
            RETURNING id,display_name,role,status,created_at`, newID("usr"), in.DisplayName).Scan(&u.ID, &u.DisplayName, &u.Role, &u.Status, &u.CreatedAt)
		return 201, u, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

func (a *Accounts) IssueUserToken(ctx context.Context, p Principal, userID, key string, in IssueTokenInput) (APIReceipt, error) {
	if userID == "" || in.ExpiresAt.IsZero() {
		return APIReceipt{}, ErrInput
	}
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "service", "user:manage"); err != nil {
		return APIReceipt{}, err
	}
	var active bool
	err = tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1 FOR SHARE", userID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
		return APIReceipt{}, ErrNotFound
	}
	if err != nil {
		return APIReceipt{}, err
	}
	r, err := a.withReceipt(ctx, tx, scope(p, "POST", "/v1/users/"+userID+"/tokens", key), in, func() (int, any, error) {
		var allowed bool
		if err := tx.QueryRow(ctx, "SELECT $1::timestamptz>clock_timestamp() AND $1::timestamptz<=clock_timestamp()+interval '365 days'", in.ExpiresAt).Scan(&allowed); err != nil {
			return 0, nil, err
		}
		if !allowed {
			return 0, nil, ErrInput
		}
		r := TokenResponse{ID: newID("tok"), Token: tokenSecret(), ExpiresAt: in.ExpiresAt}
		hash := sha256.Sum256([]byte(r.Token))
		_, err := tx.Exec(ctx, `INSERT INTO api_tokens(id,kind,user_id,token_hash,scopes,expires_at,issued_by_token_id)
            VALUES($1,'user',$2,$3,$4,$5,$6)`, r.ID, userID, hash[:], []string{"agent:own", "inbox:own", "directory:read"}, r.ExpiresAt, p.TokenID)
		return 201, r, err
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

type Profile struct {
	User
	AgentID *string `json:"agent_id,omitempty"`
}

func (a *Accounts) Me(ctx context.Context, p Principal) (Profile, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return Profile{}, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", ""); err != nil {
		return Profile{}, err
	}
	var result Profile
	err = tx.QueryRow(ctx, `SELECT u.id,u.display_name,u.role,u.status,u.created_at,a.id
        FROM users u LEFT JOIN agents a ON a.owner_user_id=u.id WHERE u.id=$1`, p.ID).Scan(&result.ID, &result.DisplayName, &result.Role, &result.Status, &result.CreatedAt, &result.AgentID)
	if err != nil {
		return Profile{}, err
	}
	return result, commit(ctx, tx)
}

func (a *Accounts) ListUsers(ctx context.Context, p Principal, after string, limit int) ([]User, error) {
	if limit < 1 || limit > 200 || len(after) > 100 {
		return nil, ErrInput
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "service", "user:manage"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, "SELECT id,display_name,role,status,created_at FROM users WHERE id>$1 ORDER BY id LIMIT $2", after, limit)
	if err != nil {
		return nil, err
	}
	users := []User{}
	for rows.Next() {
		var u User
		if err = rows.Scan(&u.ID, &u.DisplayName, &u.Role, &u.Status, &u.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return users, commit(ctx, tx)
}

func (s *Store) Ready(ctx context.Context) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	// Includes new schema objects so readiness cannot succeed on an unmigrated DB.
	if _, err = tx.Exec(ctx, "SELECT 1 FROM users,api_tokens,http_receipts,agents LIMIT 0"); err != nil {
		return err
	}
	return checkMigrationLedger(ctx, tx, controlPlaneMigrations)
}
