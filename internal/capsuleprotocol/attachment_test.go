package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// attachmentFake serves one in-memory file, optionally corrupted, through the
// real authenticated platform handler.
var attachmentFile = bytes.Repeat([]byte("0123456789abcdef"), (AttachmentSegmentBytes*2+1000)/16)

const attachmentFakeID = "att_0123456789abcdef0123456789abcdef"

func attachmentRef(data []byte) AttachmentRef {
	sum := sha256.Sum256(data)
	return AttachmentRef{ID: attachmentFakeID, Name: "report.txt", MediaType: "text/plain", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

var attachmentFault string

func (a *platformFake) ReadAttachment(_ context.Context, id string, index int) (AttachmentSegment, error) {
	a.calls.Add(1)
	if id != attachmentFakeID {
		return AttachmentSegment{}, &PlatformError{Code: "not_found"}
	}
	total := (len(attachmentFile) + AttachmentSegmentBytes - 1) / AttachmentSegmentBytes
	if index >= total {
		return AttachmentSegment{}, &PlatformError{Code: "not_found"}
	}
	data := append([]byte(nil), attachmentFile[index*AttachmentSegmentBytes:min((index+1)*AttachmentSegmentBytes, len(attachmentFile))]...)
	switch attachmentFault {
	case "flip":
		if index == 1 {
			data[0] ^= 1
		}
	case "reorder":
		if index == 0 {
			index = 1
		}
	case "total":
		total++
	}
	return AttachmentSegment{Index: index, Total: total, Data: data}, nil
}

func TestAttachmentIsFetchedBySegmentsAndVerified(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	attachmentFault = ""
	got, err := c.FetchAttachment(t.Context(), attachmentRef(attachmentFile))
	if err != nil || !bytes.Equal(got, attachmentFile) {
		t.Fatal("whole file not reassembled", err, len(got))
	}
	// A changed byte, a reordered segment or a wrong count is refused, never returned.
	for _, fault := range []string{"flip", "reorder", "total"} {
		attachmentFault = fault
		if got, err = c.FetchAttachment(t.Context(), attachmentRef(attachmentFile)); !errors.Is(err, ErrProtocol) || got != nil {
			t.Fatal("corrupted file accepted", fault, err)
		}
	}
	attachmentFault = ""
	// A reference that does not match the bytes is refused too.
	short := attachmentRef(attachmentFile[:10])
	if _, err = c.FetchAttachment(t.Context(), short); !errors.Is(err, ErrProtocol) {
		t.Fatal("size mismatch accepted", err)
	}
	var pe *PlatformError
	other := attachmentRef(attachmentFile)
	other.ID = "att_ffffffffffffffffffffffffffffffff"
	if _, err = c.FetchAttachment(t.Context(), other); !errors.As(err, &pe) || pe.Code != "not_found" {
		t.Fatal("unknown file", err)
	}
	// Invalid ids and indexes are refused before the adapter.
	calls := api.calls.Load()
	for _, read := range []AttachmentRead{{ID: "../etc/passwd"}, {ID: attachmentFakeID, Index: -1}, {ID: attachmentFakeID, Index: MaxAttachmentBytes / AttachmentSegmentBytes}} {
		if _, err = c.ReadAttachment(t.Context(), read.ID, read.Index); err == nil {
			t.Fatal("invalid read accepted", read)
		}
	}
	if api.calls.Load() != calls {
		t.Fatal("an invalid read reached the adapter")
	}
	// An attachment read cannot ride on another operation.
	b, _ := json.Marshal(platformRequest{Protocol: Version, Identity: host.Identity, Key: "k", Attachment: &AttachmentRead{ID: attachmentFakeID}, LLM: &LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "x"}}}})
	for _, path := range []string{"/v1/llm/complete", "/v1/attachments/read", "/v1/owner/messages"} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+path, bytes.NewReader(b))
		resp, err := c.client.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal("mixed operation accepted", path, resp.StatusCode)
		}
	}
}

func TestAttachmentReferencesAreStrict(t *testing.T) {
	good := attachmentRef([]byte("x"))
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AttachmentRef){
		"id":     func(r *AttachmentRef) { r.ID = "att_XYZ" },
		"slash":  func(r *AttachmentRef) { r.Name = "a/b" },
		"dotdot": func(r *AttachmentRef) { r.Name = ".." },
		"ctrl":   func(r *AttachmentRef) { r.Name = "a\nb" },
		"type":   func(r *AttachmentRef) { r.MediaType = "text/plain; charset=utf-8" },
		"size":   func(r *AttachmentRef) { r.Size = MaxAttachmentBytes + 1 },
		"empty":  func(r *AttachmentRef) { r.Size = 0 },
		"hash":   func(r *AttachmentRef) { r.SHA256 = strings.Repeat("z", 64) },
	} {
		r := good
		mutate(&r)
		if r.Validate() == nil {
			t.Fatal("invalid reference accepted", name)
		}
	}
	envelope := func(refs ...AttachmentRef) harnessstore.Event {
		inv := Invocation{Kind: "message.user", OperationID: "op", Content: []TextContent{{Type: "text", Text: "hi"}}, Attachments: refs,
			Mandate: InstructionMandate{ID: "mdt", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)}}
		b, _ := json.Marshal(inv)
		return harnessstore.Event{ID: "e", Subjects: []string{"agent/a", "event/e"}, Body: b}
	}
	if got, err := DecodeInvocation(envelope(good), "a"); err != nil || len(got.Attachments) != 1 || got.Attachments[0] != good {
		t.Fatal("valid envelope refused", err)
	}
	if _, err := DecodeInvocation(envelope(good, good), "a"); !errors.Is(err, ErrProtocol) {
		t.Fatal("duplicate attachment accepted in an envelope", err)
	}
	many := make([]AttachmentRef, MaxInvocationAttachments+1)
	for i := range many {
		many[i] = good
		many[i].ID = fmt.Sprintf("att_%032x", i)
	}
	if _, err := DecodeInvocation(envelope(many...), "a"); !errors.Is(err, ErrProtocol) {
		t.Fatal("too many attachments accepted", err)
	}
}
