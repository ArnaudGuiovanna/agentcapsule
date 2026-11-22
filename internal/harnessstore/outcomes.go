package harnessstore

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore/envelope"
)

// OutcomeFingerprint commits to the same canonical envelope as Apply and its
// durable result. Replayed is deliberately absent: retries and restored copies
// must name the same outcome. Incarnation is an admission constraint, not part
// of the identity of the history that a later incarnation must recover.
func OutcomeFingerprint(store string, event Event, result []byte) (string, [32]byte, error) {
	_, envelope, err := canonical(event)
	if err != nil {
		return "", [32]byte{}, err
	}
	return StoredOutcomeFingerprint(store, event.ID, envelope, result)
}

func StoredOutcomeFingerprint(store, eventID string, hash [32]byte, result []byte) (string, [32]byte, error) {
	return envelope.StoredOutcomeFingerprint(store, eventID, hash, result)
}

// Outcomes reports which of ids this database holds, each with the digest of
// its stored result (StoredOutcomeFingerprint for store). A restore inspects a
// restored image with it: an outcome counts only when its deduplication record
// and its result are present, and Apply commits them with the effects. It
// writes nothing.
func (s *Store) Outcomes(ctx context.Context, store string, ids []string) (map[string][32]byte, error) {
	if store == "" {
		return nil, errors.New("outcome store is required")
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	held := make(map[string][32]byte)
	if len(wanted) == 0 {
		return held, nil
	}
	// One statement reads one consistent snapshot of the inbox.
	rows, err := s.db.QueryContext(ctx, "SELECT event_id, envelope_hash, result FROM capsule_inbox")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var event string
		var envelope, result []byte
		if err = rows.Scan(&event, &envelope, &result); err != nil {
			return nil, err
		}
		if len(envelope) != 32 {
			return nil, errors.New("stored envelope hash is not 32 bytes")
		}
		id, digest, err := StoredOutcomeFingerprint(store, event, [32]byte(envelope), result)
		if err != nil {
			return nil, err
		}
		if wanted[id] {
			held[id] = digest
		}
	}
	return held, rows.Err()
}
