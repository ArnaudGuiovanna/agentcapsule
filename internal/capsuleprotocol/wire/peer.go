package wire

import (
	"encoding/json"
)

// PeerPayload is untrusted application data, never an instruction or a grant.
// It holds text and JSON parts. The encoded message is bounded to 64 KiB,
// including JSON escaping overhead, in its text form (TextOnly): what a
// recipient that does not accept JSON content receives fits the same bound.
type PeerPayload struct {
	Content []ContentPart `json:"content"`
}

func (p PeerPayload) Validate() error {
	if err := validParts(p.Content, 0); err != nil {
		return err
	}
	encoded, err := json.Marshal(PeerPayload{Content: TextOnly(p.Content)})
	defer clear(encoded)
	if err != nil || len(encoded) > MaxPeerPayloadBytes {
		return ErrProtocol
	}
	return nil
}

type PeerEvent struct {
	Kind             string      `json:"kind"`
	RequestID        string      `json:"request_id"`
	SenderAgentID    string      `json:"sender_agent_id"`
	RecipientAgentID string      `json:"recipient_agent_id"`
	Sequence         int64       `json:"sequence"`
	Subject          string      `json:"subject,omitempty"`
	CorrelationID    string      `json:"correlation_id,omitempty"`
	Payload          PeerPayload `json:"payload"`
}
