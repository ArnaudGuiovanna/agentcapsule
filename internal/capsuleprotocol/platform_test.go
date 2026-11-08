package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type platformFake struct{ calls atomic.Int32 }

func (a *platformFake) Validate(context.Context) error { return nil }
func (a *platformFake) Submit(_ context.Context, key string, _ Submission) (PlatformReceipt, error) {
	a.calls.Add(1)
	if key == "fail" {
		return PlatformReceipt{}, errors.New("private SQL password")
	}
	return PlatformReceipt{RequestID: "request", State: "DELIVERING"}, nil
}
func (a *platformFake) Reply(context.Context, string, string, Reply) (PlatformReceipt, error) {
	a.calls.Add(1)
	return PlatformReceipt{RequestID: "request", State: "REPLIED"}, nil
}
func (a *platformFake) Search(context.Context, []string) ([]string, error) {
	a.calls.Add(1)
	return []string{"b"}, nil
}
func (a *platformFake) PostOwner(context.Context, string, OwnerPost) (OwnerPostReceipt, error) {
	a.calls.Add(1)
	return OwnerPostReceipt{MessageID: "message"}, nil
}

func TestOwnerPostStrictFieldsAndSeparateOperation(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	in := OwnerPost{RequestID: "request", Content: []TextContent{{Type: "text", Text: "summary"}}}
	if r, err := c.PostOwner(t.Context(), "once", in); err != nil || r.MessageID != "message" {
		t.Fatal(r, err)
	}
	if _, err := c.call(t.Context(), "/v1/agent-requests", &platformRequest{Key: "mixed", Submission: &Submission{RecipientAgentID: "b"}, OwnerMessage: &in}); err == nil {
		t.Fatal("mixed owner and submit operations")
	}
	b, _ := json.Marshal(platformRequest{Protocol: Version, Identity: host.Identity, Key: "forged", OwnerMessage: &in})
	b = bytes.Replace(b, []byte(`"content":`), []byte(`"owner_user_id":"foreign","content":`), 1)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+"/v1/owner/messages", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 || api.calls.Load() != 1 {
		t.Fatal("forged owner reached API", resp.StatusCode, api.calls.Load())
	}
}

func platformFixture(t *testing.T) (*PlatformClient, Credentials, Credentials, *platformFake, func(context.Context) (net.Conn, error)) {
	t.Helper()
	h, g, err := NewBootCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	api := &platformFake{}
	handler, err := NewPlatformHandler(h.Identity, api)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeAuthenticated(ctx, l, *h.Platform, handler) }()
	t.Cleanup(func() { cancel(); <-done })
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	client, err := NewPlatformClient(*g.Platform, dial)
	if err != nil {
		t.Fatal(err)
	}
	return client, h, g, api, dial
}

func TestPlatformFixedIdentityAndStrictPayload(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	if err := c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := c.Submit(t.Context(), "one", Submission{RecipientAgentID: "b"})
	if err != nil || r.State != "DELIVERING" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, alter := range []func(*Identity){func(i *Identity) { i.AgentID = "other" }, func(i *Identity) { i.Generation++ }, func(i *Identity) { i.FenceOnly = true }} {
		c.client.identity = host.Identity
		alter(&c.client.identity)
		_, err = c.Submit(t.Context(), "forged", Submission{RecipientAgentID: "b"})
		if !errors.Is(err, ErrIdentity) {
			t.Fatalf("payload identity accepted: %v", err)
		}
	}
	c.client.identity = host.Identity
	if _, err = c.call(t.Context(), "/v1/agent-requests/path-id/reply", &platformRequest{Key: "reply", RequestID: "body-id", Reply: &Reply{Outcome: "declined"}}); err == nil {
		t.Fatal("reply path/body identity mismatch accepted")
	}
	in := platformRequest{Protocol: Version, Identity: host.Identity, Key: "forged-field", Submission: &Submission{RecipientAgentID: "b"}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b[:len(b)-1], []byte(`,"sender_agent_id":"other"}`)...)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+"/v1/agent-requests", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || api.calls.Load() != 1 {
		t.Fatalf("forged payload reached API: status=%d calls=%d", resp.StatusCode, api.calls.Load())
	}
	if _, err = c.Submit(t.Context(), "fail", Submission{}); err == nil || err.Error() != "capsule platform: unavailable" {
		t.Fatalf("private error escaped: %v", err)
	}
}

func TestPlatformAuthorityCannotAuthenticateControlAndForeignClients(t *testing.T) {
	_, host, guest, _, dial := platformFixture(t)
	if bytes.Equal(host.CA, host.Platform.CA) {
		t.Fatal("both channels share an authority")
	}
	// Keep the correct server trust/SNI, but FORCE an invalid client certificate
	// even when its issuer is absent from CertificateRequest.AcceptableCAs.
	_, other, err := NewBootCredentials(Identity{Incarnation: 1, AgentID: "b", Generation: 1, VMID: "fedcba9876543210"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Credentials{"control_client_key": host, "foreign_platform_key": *other.Platform, "server_key": *host.Platform} {
		t.Run(name, func(t *testing.T) {
			cfg, err := guest.Platform.TLS(false)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := tls.X509KeyPair(bad.Certificate, bad.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Certificates = nil
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
			conn, err := dial(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			c := tls.Client(conn, cfg)
			err = c.HandshakeContext(t.Context())
			if err == nil {
				_, err = io.WriteString(c, "GET /v1/health HTTP/1.1\r\nHost: test\r\n\r\n")
				if err == nil {
					var b [1]byte
					_, err = c.Read(b[:])
				}
			}
			if err == nil {
				t.Fatal("invalid client certificate authenticated")
			}
		})
	}
	// A guest platform key has ClientAuth usage, but its separate CA must prevent
	// it from impersonating the host on the control channel.
	control, dialControl := serverFixture(t, host, guest, nil)
	if err = control.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	bad := *guest.Platform
	bad.CA = host.CA
	bad.Channel = "control"
	attacker, err := NewClient(bad, dialControl)
	if err != nil {
		t.Fatal(err)
	}
	if err = attacker.Health(t.Context()); err == nil {
		t.Fatal("guest platform key became host control authority")
	}
}

func (a *platformFake) CompleteLLM(_ context.Context, key string, in LLMRequest) (LLMResult, error) {
	a.calls.Add(1)
	switch key {
	case "budget":
		return LLMResult{}, &PlatformError{Code: "quota_exceeded"}
	case "unknown":
		return LLMResult{}, &PlatformError{Code: "outcome_unknown"}
	case "leak":
		return LLMResult{}, errors.New("sk-live-provider-secret")
	}
	return LLMResult{Text: "echo:" + in.Messages[0].Content, InputTokens: 3, OutputTokens: 2}, nil
}

func TestLLMBridgeCarriesOnlyAnAliasAndTypedOutcomes(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	in := LLMRequest{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "hello"}}, MaxTokens: 64}
	r, err := c.CompleteLLM(t.Context(), "k1", in)
	if err != nil || r.Text != "echo:hello" || r.InputTokens != 3 || r.OutputTokens != 2 {
		t.Fatal(r, err)
	}
	// Typed outcomes cross the bridge; an arbitrary error never does.
	for key, code := range map[string]string{"budget": "quota_exceeded", "unknown": "outcome_unknown", "leak": "unavailable"} {
		_, err = c.CompleteLLM(t.Context(), key, in)
		var pe *PlatformError
		if !errors.As(err, &pe) || pe.Code != code || strings.Contains(err.Error(), "sk-live") {
			t.Fatal(key, err)
		}
	}
	// Invalid requests are refused before the adapter is reached.
	calls := api.calls.Load()
	bad := []LLMRequest{
		{Alias: "", Messages: in.Messages},
		{Alias: "has space", Messages: in.Messages},
		{Alias: "fast"},
		{Alias: "fast", Messages: []LLMMessage{{Role: "tool", Content: "x"}}},
		{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: "  "}}},
		{Alias: "fast", Messages: in.Messages, MaxTokens: MaxLLMOutputCap + 1},
		{Alias: "fast", Messages: []LLMMessage{{Role: "user", Content: strings.Repeat("a", MaxLLMBytes+1)}}},
	}
	for i, b := range bad {
		if _, err = c.CompleteLLM(t.Context(), "bad", b); err == nil {
			t.Fatal("invalid request accepted", i)
		}
	}
	if api.calls.Load() != calls {
		t.Fatal("an invalid request reached the adapter")
	}
	// A payload cannot name a tenant, agent, provider or credential, and the LLM
	// operation cannot be mixed with another one.
	b, _ := json.Marshal(platformRequest{Protocol: Version, Identity: host.Identity, Key: "forged", LLM: &in})
	b = bytes.Replace(b, []byte(`"alias":`), []byte(`"tenant_id":"foreign","provider_secret":"x","alias":`), 1)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+"/v1/llm/complete", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("forged identity fields reached the adapter", resp.StatusCode)
	}
	if _, err = c.call(t.Context(), "/v1/llm/complete", &platformRequest{Key: "mixed", LLM: &in, OwnerMessage: &OwnerPost{Content: []TextContent{{Type: "text", Text: "x"}}}}); err == nil {
		t.Fatal("mixed LLM and owner operations")
	}
	if _, err = c.call(t.Context(), "/v1/owner/messages", &platformRequest{Key: "mixed2", LLM: &in, OwnerMessage: &OwnerPost{Content: []TextContent{{Type: "text", Text: "x"}}}}); err == nil {
		t.Fatal("LLM payload accepted on another route")
	}
}
