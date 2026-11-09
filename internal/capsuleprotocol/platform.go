package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// These payloads intentionally have no caller/sender/owner identity. The handler
// invokes an API bound to its authenticated listener, never to a payload field.
type Submission struct {
	RecipientAgentID string       `json:"recipient_agent_id"`
	MandateID        string       `json:"mandate_id"`
	PayloadRef       string       `json:"payload_ref"`
	PayloadHash      [32]byte     `json:"payload_hash"`
	ExpiresAt        time.Time    `json:"expires_at"`
	Subject          string       `json:"subject,omitempty"`
	CorrelationID    string       `json:"correlation_id,omitempty"`
	Payload          *PeerPayload `json:"payload,omitempty"`
}
type Reply struct {
	Outcome     string       `json:"outcome"`
	PayloadRef  string       `json:"payload_ref"`
	PayloadHash [32]byte     `json:"payload_hash"`
	Payload     *PeerPayload `json:"payload,omitempty"`
}
type PlatformReceipt struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Replayed  bool   `json:"replayed"`
}

type PlatformAPI interface {
	Validate(context.Context) error
	Submit(context.Context, string, Submission) (PlatformReceipt, error)
	Reply(context.Context, string, string, Reply) (PlatformReceipt, error)
	Search(context.Context, []string) ([]string, error)
}

// PlatformError exposes only an enumerated code, never a database/transport error
// string. The trusted adapter translates its domain errors into these codes.
type PlatformError struct{ Code string }

func (e *PlatformError) Error() string { return "capsule platform: " + e.Code }
func safePlatformCode(err error) string {
	var remote *PlatformError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "unauthorized", "not_found", "unavailable", "mandate", "conflict", "expired", "transition", "commit_unknown", "invalid",
			"quota_exceeded", "rate_limited", "rejected", "outcome_unknown", "dialect":
			return remote.Code
		}
	}
	return "unavailable"
}

type platformRequest struct {
	Protocol     string                `json:"protocol"`
	Identity     Identity              `json:"identity"`
	Key          string                `json:"idempotency_key,omitempty"`
	RequestID    string                `json:"request_id,omitempty"`
	Submission   *Submission           `json:"submission,omitempty"`
	Reply        *Reply                `json:"reply,omitempty"`
	Candidates   []string              `json:"candidates,omitempty"`
	OwnerMessage *OwnerPost            `json:"owner_message,omitempty"`
	LLM          *LLMRequest           `json:"llm,omitempty"`
	Attachment   *AttachmentRead       `json:"attachment,omitempty"`
	Completion   *InvocationCompletion `json:"completion,omitempty"`
	Query        *DirectoryQuery       `json:"query,omitempty"`
	Forward      *LLMForward           `json:"forward,omitempty"`
}
type platformResponse struct {
	Protocol     string             `json:"protocol"`
	Identity     Identity           `json:"identity"`
	Receipt      *PlatformReceipt   `json:"receipt,omitempty"`
	Agents       []string           `json:"agents,omitempty"`
	Code         string             `json:"code,omitempty"`
	OwnerReceipt *OwnerPostReceipt  `json:"owner_receipt,omitempty"`
	LLMResult    *LLMResult         `json:"llm_result,omitempty"`
	Segment      *AttachmentSegment `json:"segment,omitempty"`
	Completion   *CompletionReceipt `json:"completion,omitempty"`
	Found        []DirectoryAgent   `json:"found,omitempty"`
	Forwarded    *LLMForwardResult  `json:"forwarded,omitempty"`
}
type platformHandler struct {
	id        Identity
	api       PlatformAPI
	slots     chan struct{}
	localAuth func(*http.Request) bool
}

func NewPlatformHandler(id Identity, api PlatformAPI) (http.Handler, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if api == nil || id.FenceOnly {
		return nil, ErrIdentity
	}
	return &platformHandler{id: id, api: api, slots: make(chan struct{}, 16)}, nil
}

func (p *platformHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out := platformResponse{Protocol: Version, Identity: p.id}
	write := func(status int, code string) {
		out.Code = code
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
	authenticated := r.TLS != nil && len(r.TLS.VerifiedChains) > 0
	if p.localAuth != nil {
		authenticated = p.localAuth(r)
	}
	if !authenticated {
		write(http.StatusUnauthorized, "unauthorized")
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		write(http.StatusServiceUnavailable, "unavailable")
		return
	}
	timeout := 15 * time.Second
	if r.URL.Path == "/v1/llm/complete" || r.URL.Path == "/v1/llm/forward" {
		// Only this route may outlive the server's short write deadline; the
		// listener's other bounds still apply.
		timeout = LLMCallTimeout
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 5*time.Second))
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if r.Method == http.MethodGet && r.URL.Path == "/v1/health" {
		if err := p.api.Validate(ctx); err != nil {
			write(http.StatusForbidden, safePlatformCode(err))
			return
		}
		write(http.StatusOK, "")
		return
	}
	if r.Method != http.MethodPost {
		write(http.StatusNotFound, "not_found")
		return
	}
	var in platformRequest
	if err := decode(http.MaxBytesReader(w, r.Body, MaxMessageBytes), &in); err != nil {
		write(http.StatusBadRequest, "invalid")
		return
	}
	if in.Protocol != Version || in.Identity != p.id {
		write(http.StatusForbidden, "unauthorized")
		return
	}
	var err error
	var receipt PlatformReceipt
	replyID := ""
	if strings.HasPrefix(r.URL.Path, "/v1/agent-requests/") && strings.HasSuffix(r.URL.Path, "/reply") {
		replyID = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/agent-requests/"), "/reply")
		if replyID == "" || strings.Contains(replyID, "/") || len(replyID) > 256 {
			write(http.StatusBadRequest, "invalid")
			return
		}
	}
	if in.Query != nil && r.URL.Path != "/v1/directory/find" || in.Forward != nil && r.URL.Path != "/v1/llm/forward" {
		write(http.StatusBadRequest, "invalid")
		return
	}
	// Validate is performed INSIDE each mutating API transaction, not as an
	// earlier authorization check that could race with generation replacement.
	switch {
	case r.URL.Path == "/v1/directory/find":
		if in.Query == nil || in.OwnerMessage != nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.Reply != nil || in.Submission != nil || in.RequestID != "" || in.Key != "" || in.Candidates != nil || in.Query.Validate() != nil {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(DirectoryAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		out.Found, err = api.FindAgents(ctx, *in.Query)
	case r.URL.Path == "/v1/owner/messages":
		if in.OwnerMessage == nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key == "" || len(in.Key) > 256 || in.OwnerMessage.Validate() != nil {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(OwnerMessageAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		var result OwnerPostReceipt
		result, err = api.PostOwner(ctx, in.Key, *in.OwnerMessage)
		if err == nil {
			out.OwnerReceipt = &result
		}
	case r.URL.Path == "/v1/llm/complete":
		if in.LLM == nil || in.Attachment != nil || in.Completion != nil || in.OwnerMessage != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key == "" || len(in.Key) > 200 || in.LLM.Validate() != nil {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(LLMAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		var result LLMResult
		result, err = api.CompleteLLM(ctx, in.Key, *in.LLM)
		if err == nil {
			out.LLMResult = &result
		}
	case r.URL.Path == "/v1/llm/forward":
		if in.Forward == nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.OwnerMessage != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key == "" || len(in.Key) > 200 || in.Forward.Validate() != nil {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(LLMForwardAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		var result LLMForwardResult
		result, err = api.ForwardLLM(ctx, in.Key, *in.Forward)
		if err == nil {
			out.Forwarded = &result
		}
	case r.URL.Path == "/v1/attachments/read":
		if in.Attachment == nil || in.LLM != nil || in.Completion != nil || in.OwnerMessage != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key != "" ||
			!ValidAttachmentID(in.Attachment.ID) || in.Attachment.Index < 0 || in.Attachment.Index >= MaxAttachmentBytes/AttachmentSegmentBytes {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(AttachmentAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		var segment AttachmentSegment
		segment, err = api.ReadAttachment(ctx, in.Attachment.ID, in.Attachment.Index)
		if err == nil {
			out.Segment = &segment
		}
	case r.URL.Path == "/v1/invocations/complete":
		if in.Completion == nil || in.LLM != nil || in.Attachment != nil || in.OwnerMessage != nil || in.Submission != nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil ||
			in.Key == "" || len(in.Key) > 256 || in.Completion.Validate() != nil {
			write(http.StatusBadRequest, "invalid")
			return
		}
		api, ok := p.api.(InvocationAPI)
		if !ok {
			write(http.StatusServiceUnavailable, "unavailable")
			return
		}
		var result CompletionReceipt
		result, err = api.CompleteInvocation(ctx, in.Key, *in.Completion)
		if err == nil {
			out.Completion = &result
		}
	case r.URL.Path == "/v1/agent-requests":
		if in.OwnerMessage != nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.Submission == nil || in.Reply != nil || in.RequestID != "" || in.Candidates != nil || in.Key == "" || len(in.Key) > 256 {
			write(http.StatusBadRequest, "invalid")
			return
		}
		receipt, err = p.api.Submit(ctx, in.Key, *in.Submission)
		if err == nil {
			out.Receipt = &receipt
		}
	case replyID != "":
		if in.OwnerMessage != nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.Reply == nil || in.Submission != nil || in.RequestID != replyID || in.Candidates != nil || in.Key == "" || len(in.Key) > 256 {
			write(http.StatusBadRequest, "invalid")
			return
		}
		receipt, err = p.api.Reply(ctx, in.RequestID, in.Key, *in.Reply)
		if err == nil {
			out.Receipt = &receipt
		}
	case r.URL.Path == "/v1/directory/search":
		if in.OwnerMessage != nil || in.LLM != nil || in.Attachment != nil || in.Completion != nil || in.Reply != nil || in.Submission != nil || in.RequestID != "" || in.Key != "" || len(in.Candidates) > 100 {
			write(http.StatusBadRequest, "invalid")
			return
		}
		out.Agents, err = p.api.Search(ctx, in.Candidates)
	default:
		write(http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		code := safePlatformCode(err)
		status := http.StatusConflict
		switch code {
		case "unauthorized", "mandate":
			status = http.StatusForbidden
		case "not_found":
			status = http.StatusNotFound
		case "unavailable", "commit_unknown":
			status = http.StatusServiceUnavailable
		case "quota_exceeded", "rate_limited":
			status = http.StatusTooManyRequests
		case "invalid", "dialect":
			status = http.StatusBadRequest
		}
		write(status, code)
		return
	}
	write(http.StatusOK, "")
}

type PlatformClient struct{ client *Client }

func NewPlatformClient(credentials Credentials, dial func(context.Context) (net.Conn, error)) (*PlatformClient, error) {
	if credentials.Channel != "platform" || credentials.Identity.FenceOnly {
		return nil, ErrIdentity
	}
	c, err := NewClient(credentials, dial)
	if err != nil {
		return nil, err
	}
	return &PlatformClient{client: c}, nil
}

func (p *PlatformClient) call(ctx context.Context, path string, in *platformRequest) (platformResponse, error) {
	return p.callWithTimeout(ctx, path, in, 0)
}

// callWithTimeout lets the one long-running operation (a model call) outlive the
// short default without loosening every other bridge method.
func (p *PlatformClient) callWithTimeout(ctx context.Context, path string, in *platformRequest, timeout time.Duration) (platformResponse, error) {
	var body io.Reader
	method := http.MethodGet
	if in != nil {
		in.Protocol = Version
		in.Identity = p.client.identity
		b, err := json.Marshal(in)
		if err != nil || len(b) > MaxMessageBytes {
			return platformResponse{}, ErrProtocol
		}
		body = bytes.NewReader(b)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, p.client.endpoint(path), body)
	if err != nil {
		return platformResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	httpClient := p.client.http
	if timeout > 0 {
		clone := *httpClient
		clone.Timeout = timeout
		httpClient = &clone
	}
	r, err := httpClient.Do(req)
	if err != nil {
		return platformResponse{}, errors.Join(ErrTransport, err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
	if err != nil || len(b) > MaxMessageBytes {
		return platformResponse{}, ErrProtocol
	}
	var out platformResponse
	if err = decode(bytes.NewReader(b), &out); err != nil {
		return out, err
	}
	if out.Protocol != Version || out.Identity != p.client.identity {
		return out, ErrIdentity
	}
	if r.StatusCode != http.StatusOK || out.Code != "" {
		return out, &PlatformError{Code: safePlatformCode(&PlatformError{Code: out.Code})}
	}
	return out, nil
}
func (p *PlatformClient) Health(ctx context.Context) error {
	_, err := p.call(ctx, "/v1/health", nil)
	return err
}
func (p *PlatformClient) Submit(ctx context.Context, key string, input Submission) (PlatformReceipt, error) {
	r, err := p.call(ctx, "/v1/agent-requests", &platformRequest{Key: key, Submission: &input})
	if err != nil {
		return PlatformReceipt{}, err
	}
	if r.Receipt == nil {
		return PlatformReceipt{}, ErrProtocol
	}
	return *r.Receipt, nil
}
func (p *PlatformClient) Reply(ctx context.Context, requestID, key string, input Reply) (PlatformReceipt, error) {
	r, err := p.call(ctx, "/v1/agent-requests/"+url.PathEscape(requestID)+"/reply", &platformRequest{Key: key, RequestID: requestID, Reply: &input})
	if err != nil {
		return PlatformReceipt{}, err
	}
	if r.Receipt == nil {
		return PlatformReceipt{}, ErrProtocol
	}
	return *r.Receipt, nil
}
func (p *PlatformClient) Search(ctx context.Context, candidates []string) ([]string, error) {
	r, err := p.call(ctx, "/v1/directory/search", &platformRequest{Candidates: candidates})
	return r.Agents, err
}
