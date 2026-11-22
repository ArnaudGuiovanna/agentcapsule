package capsuleprotocol

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
)

type OwnerPost = wire.OwnerPost
type OwnerPostReceipt = wire.OwnerPostReceipt

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
