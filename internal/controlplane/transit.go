package controlplane

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrTransitKey = errors.New("transit key configuration unavailable or mismatched")
var ErrTransitPayload = errors.New("transit payload authentication failed")

const MaxTransitBytes = 512 << 10

type transitKey struct {
	cipher cipher.AEAD
	hash   [32]byte
}

// Transit holds instance transit keys, distinct from API receipt and volume
// keys. It is not a non-rollback authority and cannot erase ciphertext copies
// in backups. Rotation/activation is explicit; ordinary startup creates nothing.
type Transit struct {
	store     *Store
	active    string
	keys      map[string]transitKey
	retention time.Duration
}

// BoundTo prevents attaching a dispatcher to another control-plane store.
func (t *Transit) BoundTo(s *Store) bool { return t != nil && t.store == s }

func NewTransit(s *Store, active string, keys map[string][]byte, retention time.Duration) (*Transit, error) {
	if s == nil || !catalogName(active) || len(keys) < 1 || len(keys) > 16 || retention < time.Microsecond || retention > 30*24*time.Hour {
		return nil, ErrInput
	}
	t := &Transit{store: s, active: active, keys: make(map[string]transitKey), retention: retention}
	for id, key := range keys {
		if !catalogName(id) || len(key) != 32 {
			return nil, ErrTransitKey
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		c, err := cipher.NewGCM(b)
		if err != nil {
			return nil, err
		}
		t.keys[id] = transitKey{c, sha256.Sum256(key)}
	}
	if _, ok := t.keys[active]; !ok {
		return nil, ErrTransitKey
	}
	return t, nil
}

func (t *Transit) checkKey(ctx context.Context, tx pgx.Tx, id string) (transitKey, error) {
	k, ok := t.keys[id]
	if !ok {
		return k, ErrTransitKey
	}
	var hash []byte
	err := tx.QueryRow(ctx, "SELECT key_hash FROM transit_keys WHERE id=$1 FOR SHARE", id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !bytes.Equal(hash, k.hash[:]) {
		return k, ErrTransitKey
	}
	return k, err
}

func (t *Transit) checkCoverage(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, "SELECT DISTINCT key_id FROM transit_payloads WHERE purged_at IS NULL ORDER BY key_id")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = t.checkKey(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// ActivateKeys is an operator-only installation/rotation operation. Existing
// key IDs cannot be rebound, and live payloads require their decryption keys.
// A previously running writer sees the changed active ID and fails closed.
func (t *Transit) ActivateKeys(ctx context.Context) error {
	tx, err := t.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(756610046)"); err != nil {
		return err
	}
	// Exclude writers before inspecting key coverage. Otherwise an old writer
	// could publish a payload under a removed key after this census.
	var current string
	err = tx.QueryRow(ctx, "SELECT active_key_id FROM transit_configuration WHERE singleton FOR UPDATE").Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	ids := make([]string, 0, len(t.keys))
	for id := range t.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		k := t.keys[id]
		if _, err = tx.Exec(ctx, "INSERT INTO transit_keys(id,key_hash) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", id, k.hash[:]); err != nil {
			return err
		}
		if _, err = t.checkKey(ctx, tx, id); err != nil {
			return err
		}
	}
	if err = t.checkCoverage(ctx, tx); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO transit_configuration(singleton,active_key_id) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET active_key_id=excluded.active_key_id", t.active); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func (t *Transit) activeKey(ctx context.Context, tx pgx.Tx) (transitKey, error) {
	var id string
	err := tx.QueryRow(ctx, "SELECT active_key_id FROM transit_configuration WHERE singleton FOR SHARE").Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && id != t.active {
		return transitKey{}, ErrTransitKey
	}
	if err != nil {
		return transitKey{}, err
	}
	return t.checkKey(ctx, tx, id)
}

func (t *Transit) CheckKeys(ctx context.Context) error {
	tx, err := t.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err = t.activeKey(ctx, tx); err != nil {
		return err
	}
	if err = t.checkCoverage(ctx, tx); err != nil {
		return err
	}
	return commit(ctx, tx)
}

type transitParty struct{ Agent, Owner string }
type transitBinding struct {
	Version                    int
	ID, Kind, Reference, KeyID string
	Hash                       []byte
	Parties                    []transitParty
}
type TransitReference struct {
	ID   string
	Hash []byte
}

func transitKind(kind string) bool {
	return kind == "instruction" || kind == "instruction_result" || kind == "request" || kind == "reply" || kind == "owner_message"
}

// put is only used inside the domain transaction that creates its immutable
// operation/request reference. It locks all parties before persisting a body.
func (t *Transit) put(ctx context.Context, tx pgx.Tx, kind, reference string, parties []string, body []byte) (TransitReference, error) {
	return t.putOwned(ctx, tx, kind, reference, parties, nil, body)
}

// putOwned is put with the identity bound to each party. A historical owner
// agent is bound to its owner user. A tenant agent has no owner, so the caller
// supplies the requesting principal: private content belongs to whoever asked,
// not to whoever administers the agent (D-02).
func (t *Transit) putOwned(ctx context.Context, tx pgx.Tx, kind, reference string, parties []string, owners map[string]string, body []byte) (TransitReference, error) {
	if !transitKind(kind) || reference == "" || len(reference) > 100 || len(body) < 1 || len(body) > MaxTransitBytes || len(parties) < 1 || len(parties) > 2 {
		return TransitReference{}, ErrInput
	}
	ids := slices.Clone(parties)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	agents, err := lockAgents(ctx, tx, ids...)
	if err != nil {
		return TransitReference{}, err
	}
	binding := transitBinding{Version: 1, ID: newID("pay"), Kind: kind, Reference: reference, KeyID: t.active}
	for _, id := range ids {
		a, ok := agents[id]
		if !ok {
			return TransitReference{}, ErrNotFound
		}
		if a.Phase != "LIVE" {
			return TransitReference{}, ErrUnavailable
		}
		owner := a.Owner
		if a.Tenant != "" {
			if owner = owners[id]; owner == "" {
				return TransitReference{}, ErrInput
			}
		}
		binding.Parties = append(binding.Parties, transitParty{id, owner})
	}
	k, err := t.activeKey(ctx, tx)
	if err != nil {
		return TransitReference{}, err
	}
	hash := sha256.Sum256(body)
	binding.Hash = hash[:]
	aad, err := json.Marshal(binding)
	if err != nil {
		return TransitReference{}, err
	}
	nonce := make([]byte, k.cipher.NonceSize())
	_, _ = rand.Read(nonce)
	encrypted := k.cipher.Seal(nonce, nonce, body, aad)
	_, err = tx.Exec(ctx, "INSERT INTO transit_payloads(id,kind,ref_id,key_id,content_hash,ciphertext) VALUES($1,$2,$3,$4,$5,$6)", binding.ID, kind, reference, t.active, hash[:], encrypted)
	if err != nil {
		return TransitReference{}, err
	}
	for _, p := range binding.Parties {
		if _, err = tx.Exec(ctx, "INSERT INTO transit_parties(payload_id,agent_id,owner_user_id) VALUES($1,$2,$3)", binding.ID, p.Agent, p.Owner); err != nil {
			return TransitReference{}, err
		}
	}
	return TransitReference{binding.ID, hash[:]}, nil
}

func payloadParties(ctx context.Context, tx pgx.Tx, id string) ([]transitParty, error) {
	rows, err := tx.Query(ctx, "SELECT agent_id,owner_user_id FROM transit_parties WHERE payload_id=$1 ORDER BY agent_id", id)
	if err != nil {
		return nil, err
	}
	var parties []transitParty
	var ids []string
	for rows.Next() {
		var p transitParty
		if err = rows.Scan(&p.Agent, &p.Owner); err != nil {
			rows.Close()
			return nil, err
		}
		parties = append(parties, p)
		ids = append(ids, p.Agent)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(parties) < 1 || len(parties) > 2 {
		return nil, ErrNotFound
	}
	agents, err := lockAgents(ctx, tx, ids...)
	if err != nil {
		return nil, err
	}
	for _, p := range parties {
		a, ok := agents[p.Agent]
		if !ok || a.Phase != "LIVE" {
			return nil, ErrNotFound
		}
		if a.Tenant == "" && a.Owner != p.Owner {
			return nil, ErrNotFound
		}
		// For a tenant agent the bound identity is the requesting principal, which
		// must still be a principal of the same tenant.
		if a.Tenant != "" {
			var known bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals WHERE tenant_id=$1 AND id=$2)`, a.Tenant, p.Owner).Scan(&known); err != nil {
				return nil, err
			}
			if !known {
				return nil, ErrNotFound
			}
		}
	}
	return parties, nil
}

func (t *Transit) read(ctx context.Context, tx pgx.Tx, id string, parties []transitParty) ([]byte, error) {
	binding := transitBinding{Version: 1, ID: id, Parties: parties}
	var encrypted []byte
	err := tx.QueryRow(ctx, `SELECT kind,ref_id,key_id,content_hash,ciphertext FROM transit_payloads WHERE id=$1
        AND purged_at IS NULL AND (purge_after IS NULL OR purge_after>clock_timestamp()) FOR UPDATE`, id).
		Scan(&binding.Kind, &binding.Reference, &binding.KeyID, &binding.Hash, &encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k, err := t.checkKey(ctx, tx, binding.KeyID)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < k.cipher.NonceSize()+k.cipher.Overhead() {
		return nil, ErrTransitPayload
	}
	aad, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	body, err := k.cipher.Open(nil, encrypted[:k.cipher.NonceSize()], encrypted[k.cipher.NonceSize():], aad)
	if err != nil {
		return nil, ErrTransitPayload
	}
	hash := sha256.Sum256(body)
	if !bytes.Equal(hash[:], binding.Hash) {
		clear(body)
		return nil, ErrTransitPayload
	}
	return body, nil
}

// ReadForOwner is a data-plane read, never an administrative privilege. It
// rechecks the token and current parties in the same transaction as decryption.
func (t *Transit) ReadForOwner(ctx context.Context, p Principal, id string) ([]byte, error) {
	tx, err := t.store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err = authorizePrincipal(ctx, tx, p, "user", "agent:own"); err != nil {
		return nil, err
	}
	// A summary may be bound to a peer for revocation without granting that
	// peer's owner read access. The generic reader must preserve this boundary.
	var permitted bool
	err = tx.QueryRow(ctx, `SELECT kind<>'owner_message' OR EXISTS(SELECT 1 FROM owner_messages m
        WHERE m.payload_id=p.id AND m.id=p.ref_id AND m.owner_user_id=$2)
        FROM transit_payloads p WHERE p.id=$1`, id, p.ID).Scan(&permitted)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !permitted {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	parties, err := payloadParties(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(parties, func(a transitParty) bool { return a.Owner == p.ID }) {
		return nil, ErrNotFound
	}
	body, err := t.read(ctx, tx, id, parties)
	if err != nil {
		return nil, err
	}
	if err = commit(ctx, tx); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

func (t *Transit) delivered(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE transit_payloads SET delivered_at=clock_timestamp(),
        purge_after=clock_timestamp()+$2::bigint*interval '1 microsecond' WHERE id=$1 AND delivered_at IS NULL AND purged_at IS NULL`, id, t.retention.Microseconds())
	return err
}

// PurgeExpired clears current SQL ciphertext only. Metadata tombstones remain;
// retaining an old backup/key is outside this operation's erasure guarantees.
func (t *Transit) PurgeExpired(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInput
	}
	tx, err := t.store.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp() WHERE id IN
        (SELECT id FROM transit_payloads WHERE purged_at IS NULL AND purge_after<=clock_timestamp() ORDER BY purge_after,id LIMIT $1 FOR UPDATE SKIP LOCKED)`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), commit(ctx, tx)
}
