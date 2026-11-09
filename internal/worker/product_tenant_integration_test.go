//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/golang-jwt/jwt/v5"
)

const tenantKVMScopes = "org:read member:read member:manage agent:read agent:create agent:assign agent:operate agent:manage agent:delete agent:invoke agent:content:read provider:manage quota:manage usage:read"

// tenantIdentity signs delegated tokens for one organization, as a customer's
// identity provider would. Tokens are short-lived, so each call signs afresh.
type tenantIdentity struct {
	trust delegatedidentity.Trust
	key   ed25519.PrivateKey
	n     atomic.Int64
}

func (i *tenantIdentity) token(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{"iss": i.trust.Issuer, "aud": i.trust.Audience, "sub": subject, "jti": fmt.Sprintf("%s-%d", subject, i.n.Add(1)),
		"iat": now.Unix(), "exp": now.Add(4 * time.Minute).Unix(), "scope": tenantKVMScopes, "role": "platform", "trust_generation": int64(1)}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "primary"
	raw, err := token.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// installTenant creates an organization through the platform API and trusts
// its identity provider, exactly as an operator would.
func (l *productPeerLab) installTenant(t *testing.T) (*tenantIdentity, controlplane.CreateOrganizationResponse, string) {
	t.Helper()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	platform := "acpp_" + base64.RawURLEncoding.EncodeToString(secret)
	if err := l.store.BootstrapPlatformToken(t.Context(), "kvm-platform", platform, time.Hour); err != nil {
		t.Fatal(err)
	}
	var org controlplane.CreateOrganizationResponse
	l.request(platform, "POST", "/v1/organizations", "org", controlplane.CreateOrganizationInput{Name: "KVM Tenant",
		InitialOwner: controlplane.InitialOrganizationOwner{Issuer: "https://idp.example", Subject: "alice", DisplayName: "Alice"}}, 201, &org)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := &tenantIdentity{key: key, trust: delegatedidentity.Trust{TenantID: org.ID, Issuer: "https://idp.example", Audience: "capsule",
		Keys: map[string]ed25519.PublicKey{"primary": pub}, AllowedScopes: strings.Fields(tenantKVMScopes), MaxTTL: 5 * time.Minute}}
	verifier, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{id.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.handler.SetDelegatedIdentityVerifier(verifier)
	r, err := l.store.ChangeDelegationAuthority(t.Context(), controlplane.DelegationChange{OperationID: "kvm-install", Actor: "kvm-operator",
		Action: "install", TenantID: org.ID, Issuer: id.trust.Issuer, Audience: id.trust.Audience, Trust: &id.trust})
	if err != nil {
		t.Fatal(err)
	}
	l.await("tenant clock", false, func() bool {
		var ok bool
		if err := l.db.QueryRow(t.Context(), "SELECT clock_timestamp()>$1::timestamptz+interval '1 second'", r.MinimumIAT).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok && time.Now().After(r.MinimumIAT.Add(time.Second))
	})
	return id, org, platform
}

// raw sends a non-JSON body (an attachment upload).
func (l *productPeerLab) raw(token, path, key string, headers map[string]string, body []byte, code int, out any) {
	l.t.Helper()
	r, err := http.NewRequestWithContext(l.t.Context(), "POST", l.server.URL+path, bytes.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	response, err := l.server.Client().Do(r)
	if err != nil {
		l.t.Fatal("HTTP transport", path, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != code {
		l.t.Fatalf("HTTP POST %s: got %d, want %d", path, response.StatusCode, code)
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		l.t.Fatal("invalid HTTP response shape", path)
	}
}

// A tenant agent in a real encrypted guest receives an invocation with a file,
// acknowledges it "working" (its platform calls cannot run inside the exclusive
// delivery turn), then reads the file and calls its model over the platform
// channel, and posts the answer. Everything enters through the HTTP API.
func TestProductWorkerTenantAsyncInvocationWithFileAndModel(t *testing.T) {
	lab := newProductPeerLab(t)
	var modelCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Messages) != 1 || r.Header.Get("Authorization") != "Bearer kvm-model-secret" {
			http.Error(w, "bad request", 400)
			return
		}
		answer, _ := json.Marshal("model answer to: " + req.Messages[0].Content)
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"content":%s},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`, answer)
	}))
	t.Cleanup(provider.Close)
	svc, err := controlplane.NewLLMService(lab.accounts, llmgateway.New(llmgateway.Config{Timeout: 10 * time.Second, MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err = lab.worker.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}

	id, _, _ := lab.installTenant(t)
	owner := func() string { return id.token(t, "alice") }
	var created controlplane.AgentCreation
	input := controlplane.CreateAgentInput{Name: "tenant-reader", Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"},
		Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}
	lab.request(owner(), "POST", "/v1/agents", "agent", input, 202, &created)
	lab.peers = append(lab.peers, &productPeer{agent: created}) // retired at cleanup
	lab.awaitOperation(owner, created.OperationID)

	var bob controlplane.Member
	lab.request(owner(), "POST", "/v1/members", "bob", controlplane.CreateMemberInput{Issuer: id.trust.Issuer, Subject: "bob", DisplayName: "Bob", Role: "agent_user"}, 201, &bob)
	lab.request(owner(), "POST", "/v1/agents/"+created.AgentID+"/assignments", "assign-bob",
		controlplane.CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
	var p controlplane.LLMProvider
	lab.request(owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "host-model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "kvm-model-secret"}, 201, &p)
	lab.request(owner(), "POST", "/v1/llm/aliases", "alias", controlplane.CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "host"}, 201, nil)
	var wake controlplane.AgentCreation
	lab.request(owner(), "POST", "/v1/agents/"+created.AgentID+"/wake", "wake", map[string]any{}, 202, &wake)
	lab.awaitOperation(owner, wake.OperationID)

	bobToken := func() string { return id.token(t, "bob") }
	file := bytes.Repeat([]byte("kvm attachment line\n"), 30000) // ~600 KB, three segments
	sum := sha256.Sum256(file)
	var attachment controlplane.Attachment
	lab.raw(bobToken(), "/v1/agents/"+created.AgentID+"/attachments", "file", map[string]string{
		"Content-Type": "text/plain", "X-Attachment-Name": "notes.txt", "X-Content-SHA256": hex.EncodeToString(sum[:])}, file, 201, &attachment)
	var inv controlplane.Invocation
	lab.request(bobToken(), "POST", "/v1/agents/"+created.AgentID+"/invocations", "invoke", map[string]any{
		"content": []map[string]string{{"type": "text", "text": "/llm fast summarize the notes"}}, "attachments": []string{attachment.ID}}, 202, &inv)

	lab.await("tenant invocation", true, func() bool {
		var v controlplane.Invocation
		lab.request(bobToken(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	result := string(lab.request(bobToken(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
	if !strings.Contains(result, "notes.txt") || !strings.Contains(result, fmt.Sprintf("%d bytes, sha256 %s", len(file), hex.EncodeToString(sum[:]))) {
		t.Fatal("the guest did not read the exact file")
	}
	if !strings.Contains(result, "model answer to: summarize the notes") || modelCalls.Load() != 1 {
		t.Fatal("the guest did not get its model answer exactly once", modelCalls.Load())
	}
	var deferred, completed bool
	if err = lab.db.QueryRow(t.Context(), "SELECT working_since IS NOT NULL,completion_key IS NOT NULL FROM owner_instructions WHERE operation_id=$1", inv.ID).Scan(&deferred, &completed); err != nil || !deferred || !completed {
		t.Fatal("the answer did not take the asynchronous path", deferred, completed, err)
	}
	var settled int
	if err = lab.db.QueryRow(t.Context(), "SELECT count(*) FROM llm_usage WHERE agent_id=$1 AND state='settled'", created.AgentID).Scan(&settled); err != nil || settled != 1 {
		t.Fatal("model call not metered", settled, err)
	}
	// The file is unreadable once the invocation ended; its bytes are purged.
	lab.await("attachment purge", true, func() bool {
		var state string
		if err := lab.db.QueryRow(t.Context(), "SELECT status FROM attachments WHERE id=$1", attachment.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state == "purged"
	})
}

func (l *productPeerLab) awaitOperation(token func() string, op string) {
	l.t.Helper()
	l.await("operation "+op, true, func() bool {
		var v controlplane.PlatformOperation
		l.request(token(), "GET", "/v1/operations/"+op, "", nil, 200, &v)
		if v.Status == "FAILED" || v.Status == "CANCELED" {
			l.t.Fatal("operation ended badly", v.Kind, v.Status, v.ErrorCode)
		}
		return v.Status == "SUCCEEDED"
	})
}
