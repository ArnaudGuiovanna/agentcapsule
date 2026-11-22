package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
)

const AttachmentSegmentBytes = wire.AttachmentSegmentBytes
const MaxAttachmentBytes = wire.MaxAttachmentBytes
const MaxInvocationAttachments = wire.MaxInvocationAttachments

type AttachmentRef = wire.AttachmentRef
type AttachmentSegment = wire.AttachmentSegment

func ValidAttachmentName(value string) bool { return wire.ValidAttachmentName(value) }

func ValidAttachmentType(value string) bool { return wire.ValidAttachmentType(value) }

func ValidAttachmentID(value string) bool { return wire.ValidAttachmentID(value) }

type AttachmentRead struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

// AttachmentAPI is optional on a PlatformAPI, like the other bridges.
type AttachmentAPI interface {
	ReadAttachment(context.Context, string, int) (AttachmentSegment, error)
}

func (p *PlatformClient) ReadAttachment(ctx context.Context, id string, index int) (AttachmentSegment, error) {
	r, err := p.call(ctx, "/v1/attachments/read", &platformRequest{Attachment: &AttachmentRead{ID: id, Index: index}})
	if err != nil {
		return AttachmentSegment{}, err
	}
	if r.Segment == nil {
		return AttachmentSegment{}, ErrProtocol
	}
	return *r.Segment, nil
}

// FetchAttachment downloads and verifies a whole file against the reference the
// guest received in its invocation. A wrong size, segment count or digest is a
// protocol error: the bytes are not returned.
func (p *PlatformClient) FetchAttachment(ctx context.Context, ref AttachmentRef) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	want := int((ref.Size + AttachmentSegmentBytes - 1) / AttachmentSegmentBytes)
	var out bytes.Buffer
	for i := 0; i < want; i++ {
		seg, err := p.ReadAttachment(ctx, ref.ID, i)
		if err != nil {
			return nil, err
		}
		if seg.Index != i || seg.Total != want || len(seg.Data) < 1 || len(seg.Data) > AttachmentSegmentBytes || int64(out.Len()+len(seg.Data)) > ref.Size {
			return nil, ErrProtocol
		}
		out.Write(seg.Data)
	}
	sum := sha256.Sum256(out.Bytes())
	if int64(out.Len()) != ref.Size || hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, ErrProtocol
	}
	return out.Bytes(), nil
}
