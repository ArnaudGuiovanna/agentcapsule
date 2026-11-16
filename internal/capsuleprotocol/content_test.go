package capsuleprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func jsonPart(raw string) ContentPart { return ContentPart{Type: "json", JSON: JSONValue(raw)} }
func textPart(s string) ContentPart   { return ContentPart{Type: "text", Text: s} }

// A message carries text parts (text/plain) and JSON parts (application/json),
// bounded together as text alone was.
func TestContentPartsCarryStructuredJSON(t *testing.T) {
	ok := OwnerMessage{Content: []ContentPart{textPart("Summarize"), jsonPart(`{"rows": [1, 2, {"a": "b"}]}`), jsonPart(`"a string"`), jsonPart(`42`), jsonPart(`[]`)}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	deep := strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth)
	if err := (OwnerMessage{Content: []ContentPart{jsonPart(deep)}}).Validate(); err != nil {
		t.Fatal("depth at the limit", err)
	}
	// The size of a JSON part is its compact form: spaces do not count.
	spaced := `{"k":` + strings.Repeat(" ", 40<<10) + `"v"}`
	if err := (OwnerMessage{Content: []ContentPart{jsonPart(spaced)}}).Validate(); err != nil {
		t.Fatal("whitespace counted", err)
	}
	for name, bad := range map[string][]ContentPart{
		"null":            {jsonPart(`null`)},
		"spaced null":     {jsonPart(` null `)},
		"empty":           {{Type: "json"}},
		"invalid":         {jsonPart(`{"a":`)},
		"two values":      {jsonPart(`1 2`)},
		"too deep":        {jsonPart("[" + deep + "]")},
		"invalid UTF-8":   {jsonPart("\"\xff\"")},
		"json with text":  {{Type: "json", JSON: JSONValue(`1`), Text: "x"}},
		"text with json":  {{Type: "text", Text: "x", JSON: JSONValue(`1`)}},
		"unknown type":    {{Type: "image", Text: "x"}},
		"too large":       {jsonPart(`"` + strings.Repeat("a", 32<<10) + `"`)},
		"too large mixed": {textPart(strings.Repeat("a", 16<<10)), jsonPart(`"` + strings.Repeat("a", 16<<10) + `"`)},
	} {
		if err := (OwnerMessage{Content: bad}).Validate(); !errors.Is(err, ErrProtocol) {
			t.Error(name, "accepted")
		}
		if err := (PeerPayload{Content: bad}).Validate(); !errors.Is(err, ErrProtocol) && name != "too large" && name != "too large mixed" {
			t.Error(name, "accepted in a peer payload")
		}
	}
	// Strict decoding: a part has no other field.
	var m OwnerMessage
	if err := decode(strings.NewReader(`{"content":[{"type":"json","json":{},"data":1}]}`), &m); !errors.Is(err, ErrProtocol) {
		t.Fatal("unknown part field", err)
	}
	// A text part encodes exactly as before: hashes of stored text content
	// stay the same.
	if b, _ := json.Marshal(textPart("hi")); string(b) != `{"type":"text","text":"hi"}` {
		t.Fatal(string(b))
	}
}

// A harness that does not accept JSON gets each JSON part as a text part
// holding the value's compact form, which its older validation accepts.
func TestTextOnlyGivesJSONPartsAsText(t *testing.T) {
	in := []ContentPart{textPart("a"), jsonPart("{ \"k\" : [1, 2] }")}
	out := TextOnly(in)
	if !reflect.DeepEqual(out, []ContentPart{textPart("a"), textPart(`{"k":[1,2]}`)}) {
		t.Fatal(out)
	}
	if HasJSON(out) || !HasJSON(in) || in[1].Type != "json" {
		t.Fatal("input changed or JSON left")
	}
	plain := []ContentPart{textPart("a")}
	if got := TextOnly(plain); &got[0] != &plain[0] {
		t.Fatal("text-only content was copied")
	}
	// The text form of a peer payload is bounded too: quotes double in it.
	quoted := `[` + strings.Repeat(`"",`, 13<<10) + `""]`
	if err := (PeerPayload{Content: []ContentPart{textPart(quoted[:30<<10])}}).Validate(); err != nil {
		t.Fatal("the same size as text", err)
	}
	if err := (PeerPayload{Content: []ContentPart{jsonPart(quoted)}}).Validate(); !errors.Is(err, ErrProtocol) {
		t.Fatal("a payload whose text form exceeds 64 KiB", err)
	}
	if err := (PeerPayload{Content: TextOnly([]ContentPart{jsonPart(`{"a":"\"quoted\""}`)})}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func invocationWith(t *testing.T, content []ContentPart) harnessstore.Event {
	t.Helper()
	body, err := json.Marshal(Invocation{Kind: "message.user", OperationID: "op_one", Mandate: InstructionMandate{ID: "mdt_one", MaxAgentRequests: 3, ExpiresAt: time.Now().Add(time.Hour)}, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: "instruction", Subjects: []string{"agent/a", "event/instruction"}, Body: body}
}

func TestTextOnlyEventRewritesOnlyContent(t *testing.T) {
	e := invocationWith(t, []ContentPart{textPart("go"), jsonPart(`{"n":1}`)})
	got, err := TextOnlyEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	in, err := DecodeInvocation(got, "a")
	if err != nil || HasJSON(in.Content) || in.Content[1].Text != `{"n":1}` || in.OperationID != "op_one" || in.Mandate.ID != "mdt_one" || got.ID != e.ID {
		t.Fatal(in, err)
	}
	again, _ := TextOnlyEvent(e)
	if !bytes.Equal(again.Body, got.Body) {
		t.Fatal("the text form is not deterministic")
	}
	plain := invocationWith(t, []ContentPart{textPart("go")})
	if same, err := TextOnlyEvent(plain); err != nil || !bytes.Equal(same.Body, plain.Body) {
		t.Fatal("a text-only event changed", err)
	}
	peer := PeerEvent{Kind: "request", RequestID: "r", SenderAgentID: "b", RecipientAgentID: "a", Sequence: 1, Payload: PeerPayload{Content: []ContentPart{jsonPart(`[true]`)}}}
	body, _ := json.Marshal(peer)
	pe := harnessstore.Event{ID: "e1", Subjects: []string{"agent/b", "agent/a", "request/r", "event/e1"}, Body: body}
	if !EventHasJSON(pe.Body) {
		t.Fatal("peer JSON not seen")
	}
	down, err := TextOnlyEvent(pe)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePeerEvent(down, "a")
	if err != nil || !reflect.DeepEqual(decoded.Payload.Content, []ContentPart{textPart(`[true]`)}) || EventHasJSON(down.Body) {
		t.Fatal(decoded, err)
	}
	status := harnessstore.Event{ID: "s", Subjects: []string{"agent/a"}, Body: []byte(`{"kind":"status","RequestID":"r"}`)}
	if same, err := TextOnlyEvent(status); err != nil || !bytes.Equal(same.Body, status.Body) {
		t.Fatal("status changed", err)
	}
}

// JSON content is negotiated: a harness offers it only when it accepts it and
// the client asked for it. A client that does not ask (capsule-init or a worker
// built before it) sees exactly the features it knows.
func TestJSONContentIsNegotiated(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	plain, _ := serverFixture(t, h, g, nil)
	contract, err := plain.Negotiate(t.Context(), []string{Version})
	if err != nil || contract.Supports(ControlContentJSON) {
		t.Fatal("a server that did not opt in offers JSON", contract, err)
	}
	if err = plain.RequireControlContract(t.Context()); err != nil || plain.Accepts(ControlContentJSON) {
		t.Fatal("client records JSON", err)
	}
	if _, err = plain.Invoke(t.Context(), invocationWith(t, []ContentPart{jsonPart(`{}`)})); !errors.Is(err, ErrProtocol) {
		t.Fatal("JSON delivered to a harness that does not accept it", err)
	}
	if r, err := plain.Invoke(t.Context(), invocationWith(t, []ContentPart{textPart("{}")})); err != nil || r.Replayed {
		t.Fatal(r, err)
	}

	accepting, _ := serverFixtureWith(t, h, g, nil, func(s *Server) { s.AcceptJSONContent() })
	if accepting.Accepts(ControlContentJSON) {
		t.Fatal("accepts before negotiation")
	}
	if err = accepting.RequireControlContract(t.Context()); err != nil || !accepting.Accepts(ControlContentJSON) {
		t.Fatal("negotiated JSON not recorded", err)
	}
	if r, err := accepting.Invoke(t.Context(), invocationWith(t, []ContentPart{jsonPart(`{"x":[1]}`)})); err != nil || r.Replayed {
		t.Fatal(r, err)
	}
	// Without the features header, the answer is the profile older clients
	// validate (at most five known features).
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, accepting.endpoint("/v1/capabilities"), nil)
	r.Header.Set(AcceptProtocolHeader, Version)
	resp, err := accepting.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out capabilitiesResponse
	if err = decode(bytes.NewReader(body), &out); err != nil || !reflect.DeepEqual(out.Features, []ControlFeature{ControlHealth, ControlFences, ControlEvents, ControlInvokeText, ControlOutcomes}) {
		t.Fatal("unasked profile", out.Features, err)
	}
	// A fence-only boot never offers it.
	out.Identity.FenceOnly = true
	out.Features = []ControlFeature{ControlHealth, ControlFences, ControlContentJSON}
	if validCapabilities(out) {
		t.Fatal("fence-only boot with JSON content")
	}
}
