package wire

// OwnerPost has no owner/caller field. The destination is derived exclusively
// from the authenticated boot. A linked summary refers to a completed outgoing
// request; it does not confer the right to issue another peer request.
type OwnerPost struct {
	RequestID string        `json:"request_id,omitempty"`
	Content   []ContentPart `json:"content"`
}

func (p OwnerPost) Validate() error {
	if len(p.RequestID) > 100 {
		return ErrProtocol
	}
	return (OwnerMessage{Content: p.Content}).Validate()
}

type OwnerPostReceipt struct {
	MessageID string `json:"message_id"`
	Replayed  bool   `json:"replayed"`
}
