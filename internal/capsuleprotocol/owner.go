package capsuleprotocol

import "context"

// OwnerPost has no owner/caller field. The destination is derived exclusively
// from the authenticated boot. A linked summary refers to a completed outgoing
// request; it does not confer the right to issue another peer request.
type OwnerPost struct {
	RequestID string        `json:"request_id,omitempty"`
	Content   []TextContent `json:"content"`
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
type OwnerMessageAPI interface {
	PostOwner(context.Context, string, OwnerPost) (OwnerPostReceipt, error)
}

func (p *PlatformClient) PostOwner(ctx context.Context, key string, input OwnerPost) (OwnerPostReceipt, error) {
	r, err := p.call(ctx, "/v1/owner/messages", &platformRequest{Key: key, OwnerMessage: &input})
	if err != nil {
		return OwnerPostReceipt{}, err
	}
	if r.OwnerReceipt == nil || r.OwnerReceipt.MessageID == "" {
		return OwnerPostReceipt{}, ErrProtocol
	}
	return *r.OwnerReceipt, nil
}
