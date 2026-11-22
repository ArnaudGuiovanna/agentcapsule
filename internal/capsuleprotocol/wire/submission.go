package wire

import (
	"time"
)

// These payloads intentionally have no caller/sender/owner identity. The handler
// invokes an API bound to its authenticated listener, never to a payload field.
type Submission struct {
	RecipientAgentID string       `json:"recipient_agent_id"`
	MandateID        string       `json:"mandate_id"`
	PayloadRef       string       `json:"payload_ref"`
	PayloadHash      [32]byte     `json:"payload_hash"`
	ExpiresAt        time.Time    `json:"expires_at"`
	Subject          string       `json:"subject,omitempty"`
	CorrelationID    string       `json:"correlation_id,omitempty"`
	Payload          *PeerPayload `json:"payload,omitempty"`
}
type Reply struct {
	Outcome     string       `json:"outcome"`
	PayloadRef  string       `json:"payload_ref"`
	PayloadHash [32]byte     `json:"payload_hash"`
	Payload     *PeerPayload `json:"payload,omitempty"`
}
