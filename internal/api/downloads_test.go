package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

func download(t *testing.T, s *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// A temporary download link (API conventions, EVT-04) is bound to the
// person who asked for it and to one resource, works without the bearer for
// a few minutes, is checked again at each use, and leaks nothing in logs.
func TestHTTPTemporaryDownloadLinks(t *testing.T) {
	l, transit, agent, owner, bob := tenantInvocationLab(t)
	var events bytes.Buffer
	l.server.EnableTelemetry(telemetry.NewRegistry(), &events)
	file := []byte("%PDF-1.7 quarterly figures")
	up := httptest.NewRequest("POST", "/v1/agents/"+agent+"/attachments", bytes.NewReader(file))
	up.Header.Set("Authorization", "Bearer "+bob)
	up.Header.Set("Idempotency-Key", "upload")
	up.Header.Set("Content-Type", "application/pdf")
	up.Header.Set("X-Attachment-Name", "q3%20report.pdf")
	w := httptest.NewRecorder()
	l.server.ServeHTTP(w, up)
	var att controlplane.Attachment
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &att) != nil {
		t.Fatal("upload", w.Code, w.Body.String())
	}

	// Only the sender, with read_content, gets a link; nobody else learns the file exists.
	if r := call(t, l.server, "POST", "/v1/attachments/"+att.ID+"/link", owner, "", ""); r.Code != 404 {
		t.Fatal("an administrator got a link to a member's file", r.Code)
	}
	for _, bad := range []string{"?ttl_seconds=5", "?ttl_seconds=3600", "?ttl_seconds=x"} {
		if r := call(t, l.server, "POST", "/v1/attachments/"+att.ID+"/link"+bad, bob, "", ""); r.Code != 400 {
			t.Fatal("ttl accepted", bad, r.Code)
		}
	}
	r := call(t, l.server, "POST", "/v1/attachments/"+att.ID+"/link?ttl_seconds=120", bob, "", "")
	var link controlplane.DownloadLink
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &link) != nil || !strings.HasPrefix(link.URL, "/v1/downloads/dl_") ||
		link.ExpiresAt.Before(time.Now().Add(100*time.Second)) || link.ExpiresAt.After(time.Now().Add(130*time.Second)) {
		t.Fatal("link", r.Code, r.Body.String())
	}
	token := strings.TrimPrefix(link.URL, "/v1/downloads/")
	if strings.Contains(link.URL, att.ID) || strings.Contains(link.URL, agent) {
		t.Fatal("the link shows what it opens")
	}
	got := download(t, l.server, link.URL)
	sum := sha256.Sum256(file)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), file) || got.Header().Get("Content-Type") != "application/pdf" ||
		got.Header().Get("Content-Disposition") != `attachment; filename*=UTF-8''q3%20report.pdf` ||
		got.Header().Get("X-Content-SHA256") != hex.EncodeToString(sum[:]) || got.Header().Get("Referrer-Policy") != "no-referrer" ||
		got.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("download", got.Code, got.Header(), got.Body.String())
	}
	// Single purpose: a link to a file opens nothing else, and a changed link nothing at all.
	tampered := []byte(token)
	tampered[len(tampered)-5] ^= 1
	for _, bad := range []string{"/v1/downloads/" + string(tampered), "/v1/downloads/dl_", "/v1/downloads/" + att.ID} {
		if r := download(t, l.server, bad); r.Code != 404 {
			t.Fatal("opened", bad, r.Code)
		}
	}

	// A result link, read with the same rule as the result itself.
	made := call(t, l.server, "POST", "/v1/agents/"+agent+"/invocations", bob, "with-file",
		`{"content":[{"type":"json","json":{"total":3}}],"attachments":["`+att.ID+`"]}`)
	var inv controlplane.Invocation
	if made.Code != 202 || json.Unmarshal(made.Body.Bytes(), &inv) != nil {
		t.Fatal(made.Code, made.Body.String())
	}
	if r := call(t, l.server, "POST", "/v1/invocations/"+inv.ID+"/result/link", bob, "", ""); r.Code != 404 {
		t.Fatal("a link to a result that does not exist yet", r.Code)
	}
	id, err := l.store.HeadDelivery(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.DispatchMailbox(t.Context(), id, time.Minute, &echoRuntime{}); err != nil {
		t.Fatal(err)
	}
	r = call(t, l.server, "POST", "/v1/invocations/"+inv.ID+"/result/link", bob, "", "")
	var resultLink controlplane.DownloadLink
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &resultLink) != nil {
		t.Fatal("result link", r.Code, r.Body.String())
	}
	got = download(t, l.server, resultLink.URL)
	if got.Code != 200 || got.Header().Get("Content-Type") != "application/json" || !strings.Contains(got.Body.String(), `"json":{"total":3}`) {
		t.Fatal("result download", got.Code, got.Body.String())
	}

	// Bound to bob's current rights: once read_content is gone, his links open nothing.
	var assignments struct {
		Items []controlplane.AgentAssignment `json:"items"`
	}
	if r = call(t, l.server, "GET", "/v1/agents/"+agent+"/assignments", owner, "", ""); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &assignments) != nil || len(assignments.Items) != 1 {
		t.Fatal("assignments", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments/"+assignments.Items[0].ID+"/replace", owner, "narrow", `{"permissions":["read_metadata","invoke"]}`); r.Code != 200 && r.Code != 201 {
		t.Fatal("replace", r.Code, r.Body.String())
	}
	if r = download(t, l.server, resultLink.URL); r.Code != 404 {
		t.Fatal("a link outlived the right it was minted under", r.Code)
	}
	if strings.Contains(events.String(), token) || strings.Contains(events.String(), "dl_") || !strings.Contains(events.String(), `/v1/downloads/{token}`) {
		t.Fatal("the request log", events.String())
	}
}
