package wire

import (
	"time"
)

type OwnerMessage struct {
	Content []ContentPart `json:"content"`
}

// Validate accepts 1 to 32 text or JSON parts, at most 32 KiB of text and
// compact JSON in all.
func (m OwnerMessage) Validate() error {
	return validParts(m.Content, MaxMessageContentBytes)
}

type InstructionMandate struct {
	ID               string    `json:"id"`
	MaxAgentRequests int       `json:"max_agent_requests"`
	ExpiresAt        time.Time `json:"expires_at"`
}
type Invocation struct {
	Kind        string             `json:"kind"`
	OperationID string             `json:"operation_id"`
	Mandate     InstructionMandate `json:"mandate"`
	Content     []ContentPart      `json:"content"`
	// Attachments are opaque references to files the requester uploaded for this
	// invocation. The guest reads them through the platform bridge, only while the
	// invocation runs. Absent when there are none.
	Attachments []AttachmentRef `json:"attachments,omitempty"`
}
