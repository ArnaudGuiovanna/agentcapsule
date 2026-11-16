package capsuleprotocol

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
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

// DecodePeerEvent binds the untrusted body to its authenticated fence subjects.
// Strict decoding rejects mandate/operation fields even if a peer inserts them.
func DecodePeerEvent(e harnessstore.Event, agent string) (PeerEvent, error) {
	var p PeerEvent
	if err := decode(bytes.NewReader(e.Body), &p); err != nil {
		return p, err
	}
	if (p.Kind != "request" && p.Kind != "reply") || p.RequestID == "" || len(p.RequestID) > 100 || p.SenderAgentID == "" || p.RecipientAgentID == "" || p.SenderAgentID == p.RecipientAgentID || p.Sequence < 1 {
		return p, ErrProtocol
	}
	target := p.RecipientAgentID
	if p.Kind == "reply" {
		target = p.SenderAgentID
	}
	if target != agent || len(e.Subjects) != 4 {
		return p, ErrProtocol
	}
	for _, subject := range []string{"agent/" + p.SenderAgentID, "agent/" + p.RecipientAgentID, "request/" + p.RequestID, "event/" + e.ID} {
		if !slices.Contains(e.Subjects, subject) {
			return p, ErrProtocol
		}
	}
	return p, p.Payload.Validate()
}
