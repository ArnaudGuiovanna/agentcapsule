// Package envelope defines a delivery and the durable fingerprint of its outcome.
package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Subjects must include every participant whose revocation invalidates the work,
// e.g. agent/sender, agent/recipient, request/ID. They are part of the stored hash.
type Event struct {
	ID       string
	Subjects []string
	Body     []byte
}

type Receipt struct {
	Result   []byte
	Replayed bool
}

// StoredOutcomeFingerprint reconstructs a commitment from capsule_inbox data.
// Matching this digest does NOT establish that application effects are present;
// restoration must inspect the actual recovered database as well.
func StoredOutcomeFingerprint(store, eventID string, envelope [32]byte, result []byte) (string, [32]byte, error) {
	if store == "" || eventID == "" {
		return "", [32]byte{}, errors.New("outcome store and event ID are required")
	}
	identity, err := json.Marshal(struct{ Domain, Store, Event string }{"agentcapsule-outcome-id-v1", store, eventID})
	if err != nil {
		return "", [32]byte{}, err
	}
	id := sha256.Sum256(identity)
	if result == nil {
		result = []byte{}
	}
	data, err := json.Marshal(struct {
		Domain, Store, Event string
		Envelope             [32]byte
		Result               []byte
	}{"agentcapsule-outcome-data-v1", store, eventID, envelope, result})
	return "outcome-v1/" + hex.EncodeToString(id[:]), sha256.Sum256(data), err
}
