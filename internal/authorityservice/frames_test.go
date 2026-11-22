//go:build linux && cgo

package authorityservice

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// A receipt comes back to the service in a request frame (record_fence,
// hold_fences, the activation's steps). Before the v0.1.0 audit a request
// frame was half a response frame, and a receipt past about 80 000 subjects
// fit the answer to scan but no request (S-01). Now a request frame holds
// the largest response, and the largest receipt a scan gives, a page of
// restoreauthority.ScanBytes of the longest subjects, fits both.
func TestRequestFrameHoldsTheLargestReceipt(t *testing.T) {
	if MaxRequest < MaxResponse {
		t.Fatal("a request frame is smaller than a response frame", MaxRequest, MaxResponse)
	}
	// The longest subject a catalogue accepts, of the characters JSON
	// escapes the longest.
	subject := strings.Repeat("\x01", 512)
	encoded, err := json.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	n := min(restoreauthority.ScanPage, restoreauthority.ScanBytes/(len(encoded)+1))
	r := restoreauthority.Receipt{Authority: "restoreauth_" + strings.Repeat("a", 32), Epoch: 1 << 62, Store: strings.Repeat("s", 512),
		Incarnation: 1 << 62, Revision: 1 << 62, Base: 1 << 62, More: true, MAC: make([]byte, 32)}
	for range n {
		r.Subjects = append(r.Subjects, subject)
	}
	result, err := json.Marshal(ReceiptResult{r})
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(Response{Result: result})
	if err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal(LossArgs{Receipt: r, Digest: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(Request{Op: OpHoldActivation, TimeoutMS: int64(MaxTimeout.Milliseconds()), Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if len(response) > MaxResponse || len(request) > MaxRequest {
		t.Fatal("the largest receipt does not fit", len(response), len(request))
	}
	// The short subjects of a real scope fill a page by count, and fit too.
	short := restoreauthority.Receipt{Subjects: make([]string, restoreauthority.ScanPage)}
	for i := range short.Subjects {
		short.Subjects[i] = "event/mbx_" + strings.Repeat("f", 32)
	}
	if b, _ := json.Marshal(ReceiptArgs{short}); len(b) > MaxRequest/4 {
		t.Fatal("a full page of short subjects", len(b))
	}
}
