package capsuleprotocol

import (
	"bytes"
	"encoding/json"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol/wire"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type ContentPart = wire.ContentPart
type TextContent = wire.TextContent
type JSONValue = wire.JSONValue

const MaxContentParts = wire.MaxContentParts
const MaxMessageContentBytes = wire.MaxMessageContentBytes
const MaxPeerPayloadBytes = wire.MaxPeerPayloadBytes
const MaxJSONDepth = wire.MaxJSONDepth

func HasJSON(parts []ContentPart) bool { return wire.HasJSON(parts) }

func TextOnly(parts []ContentPart) []ContentPart { return wire.TextOnly(parts) }

// eventContent is the part of an event body that holds content, read loosely:
// an invocation's content or a request's or reply's payload.
type eventContent struct {
	Kind    string        `json:"kind"`
	Content []ContentPart `json:"content"`
	Payload struct {
		Content []ContentPart `json:"content"`
	} `json:"payload"`
}

// EventHasJSON reports whether an event body (an invocation, a request or a
// reply) carries a JSON part.
func EventHasJSON(body []byte) bool {
	var e eventContent
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	switch e.Kind {
	case "message.user":
		return HasJSON(e.Content)
	case "request", "reply":
		return HasJSON(e.Payload.Content)
	}
	return false
}

// TextOnlyEvent is the event a harness that does not accept JSON content
// receives: its JSON parts become text parts (TextOnly), and nothing else
// changes. An event without JSON parts is returned as it is, byte for byte.
// The result is deterministic, so a retry carries the same body.
func TextOnlyEvent(e harnessstore.Event) (harnessstore.Event, error) {
	if !EventHasJSON(e.Body) {
		return e, nil
	}
	var kind struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(e.Body, &kind)
	var body []byte
	var err error
	if kind.Kind == "message.user" {
		var in Invocation
		if err = decode(bytes.NewReader(e.Body), &in); err != nil {
			return e, err
		}
		in.Content = TextOnly(in.Content)
		body, err = json.Marshal(in)
	} else {
		var p PeerEvent
		if err = decode(bytes.NewReader(e.Body), &p); err != nil {
			return e, err
		}
		p.Payload.Content = TextOnly(p.Payload.Content)
		body, err = json.Marshal(p)
	}
	if err != nil {
		return e, err
	}
	e.Body = body
	return e, nil
}
