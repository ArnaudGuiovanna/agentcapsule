package capsuleprotocol

import (
	"bytes"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type PeerPayload = wire.PeerPayload
type PeerEvent = wire.PeerEvent

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
