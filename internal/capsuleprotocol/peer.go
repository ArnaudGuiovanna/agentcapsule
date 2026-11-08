package capsuleprotocol

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// PeerPayload is untrusted application data, never an instruction or a grant.
// The encoded message is bounded to 64 KiB, including JSON escaping overhead.
type PeerPayload struct {
	Content []TextContent `json:"content"`
}

func (p PeerPayload) Validate() error {
	if len(p.Content) < 1 || len(p.Content) > 32 {
		return ErrProtocol
	}
	for _, c := range p.Content {
		if c.Type != "text" || !utf8.ValidString(c.Text) || strings.TrimSpace(c.Text) == "" || strings.ContainsRune(c.Text, 0) {
			return ErrProtocol
		}
	}
	encoded, err := json.Marshal(p)
	defer clear(encoded)
	if err != nil || len(encoded) > 64*1024 {
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
