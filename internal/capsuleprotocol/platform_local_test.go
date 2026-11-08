//go:build linux

package capsuleprotocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformUnixBridgeBindsKernelPeerAndRemoteIdentity(t *testing.T) {
	remote, host, _, api, _ := platformFixture(t)
	s, err := NewLocalPlatformServer(remote)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign_uid", true: "allowed"}[allow], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "platform.sock")
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			uid := uint32(os.Geteuid())
			if !allow {
				uid++
			}
			go func() { done <- s.Serve(ctx, l, uid) }()
			defer func() {
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
			}()
			local, err := NewLocalPlatformClient(host.Identity, path)
			if err != nil {
				t.Fatal(err)
			}
			err = local.Health(t.Context())
			if !allow {
				var denied *PlatformError
				if !errors.As(err, &denied) || denied.Code != "unauthorized" {
					t.Fatal("kernel peer check bypassed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := local.Submit(t.Context(), "business-key", Submission{RecipientAgentID: "b"})
			if err != nil || r.State != "DELIVERING" {
				t.Fatal(r, err)
			}
			if _, err = local.Reply(t.Context(), r.RequestID, "reply-key", Reply{Outcome: "replied"}); err != nil {
				t.Fatal(err)
			}
			if agents, err := local.Search(t.Context(), []string{"b"}); err != nil || len(agents) != 1 || agents[0] != "b" {
				t.Fatal(agents, err)
			}
			llm, err := local.CompleteLLM(t.Context(), "model-key", LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "via bridge"}}})
			if err != nil || llm.Text != "echo:via bridge" {
				t.Fatal("model call did not cross the local bridge", llm, err)
			}
			attachmentFault = ""
			if file, err := local.FetchAttachment(t.Context(), attachmentRef(attachmentFile)); err != nil || len(file) != len(attachmentFile) {
				t.Fatal("attachment did not cross the local bridge", err)
			}
			if r, err := local.CompleteInvocation(t.Context(), "done-key", InvocationCompletion{OperationID: "op", Outcome: "failed"}); err != nil || r.State != "failed" {
				t.Fatal("completion did not cross the local bridge", r, err)
			}
			if _, err = NewLocalPlatformServer(local); !errors.Is(err, ErrIdentity) {
				t.Fatal("local client re-exported as remote authority", err)
			}
			before := api.calls.Load()
			local.client.identity.Generation++
			if _, err = local.Submit(t.Context(), "stale", Submission{}); !errors.Is(err, ErrIdentity) {
				t.Fatal("foreign generation accepted", err)
			}
			if api.calls.Load() != before {
				t.Fatal("forged caller reached remote API")
			}
		})
	}
	request := httptest.NewRequest("GET", "http://local/v1/health", nil)
	request.Header.Set("X-UID", "1000")
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, request)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("synthetic HTTP/TLS authenticated local request")
	}
}
