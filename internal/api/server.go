// Package api exposes the unprivileged owner/service HTTP boundary. VM access
// belongs to the separate worker; HTTP handlers commit durable commands only.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

type Server struct {
	store       *controlplane.Store
	accounts    *controlplane.Accounts
	catalog     *controlplane.AgentCatalog
	mux         *http.ServeMux
	delegations atomic.Pointer[delegatedidentity.Verifier]
}

// NewForHost binds all new agent reservations to the operator-selected host.
// Request bodies cannot select runtime paths, UID ranges or another host.
func NewForHost(store *controlplane.Store, accounts *controlplane.Accounts, host string) (*Server, error) {
	s, err := New(store, accounts)
	if err != nil {
		return nil, err
	}
	s.catalog, err = controlplane.NewAgentCatalog(accounts, host)
	if err != nil {
		return nil, err
	}
	s.mux.HandleFunc("/v1/agents", s.agents)
	s.mux.HandleFunc("/v1/agents/{id}", s.agent)
	s.mux.HandleFunc("/v1/operations/{id}", s.operation)
	s.mux.HandleFunc("/v1/agents/{id}/wake", s.wake)
	s.mux.HandleFunc("/v1/agents/{id}/sleep", s.sleep)
	s.mux.HandleFunc("/v1/agents/{id}/messages", s.instruct)
	s.mux.HandleFunc("/v1/operations/{id}/result", s.instructionResult)
	s.mux.HandleFunc("/v1/agents/{id}/invocations", s.invocations)
	s.mux.HandleFunc("/v1/invocations/{id}", s.invocation)
	s.mux.HandleFunc("/v1/queue", s.queue)
	s.mux.HandleFunc("/v1/queue/limits", s.queueLimits)
	s.mux.HandleFunc("/v1/invocations/{id}/result", s.instructionResult)
	s.mux.HandleFunc("/v1/invocations/{id}/cancel", s.cancelInvocation)
	s.mux.HandleFunc("/v1/agents/{id}/idle-policy", s.idlePolicy)
	s.mux.HandleFunc("/v1/agents/{id}/attachments", s.attachments)
	s.mux.HandleFunc("/v1/attachments/{id}", s.attachment)
	s.mux.HandleFunc("/v1/me/messaging-settings", s.messagingSettings)
	s.mux.HandleFunc("/v1/me/inbox", s.inbox)
	s.mux.HandleFunc("/v1/me/inbox/messages/{id}", s.ownerMessage)
	s.mux.HandleFunc("/v1/me/inbox/requests/{id}/accept", s.acceptRequest)
	s.mux.HandleFunc("/v1/me/inbox/requests/{id}/decline", s.declineRequest)
	s.mux.HandleFunc("/v1/agent-requests/{id}", s.agentRequest)
	s.mux.HandleFunc("/v1/agent-requests/{id}/cancel", s.cancelRequest)
	return s, nil
}

func NewForHostWithTransit(store *controlplane.Store, accounts *controlplane.Accounts, host string, transit *controlplane.Transit) (*Server, error) {
	s, err := NewForHost(store, accounts, host)
	if err != nil {
		return nil, err
	}
	s.catalog, err = controlplane.NewAgentCatalogWithTransit(accounts, host, transit)
	return s, err
}

func New(store *controlplane.Store, accounts *controlplane.Accounts) (*Server, error) {
	if store == nil || accounts == nil {
		return nil, controlplane.ErrInput
	}
	s := &Server{store: store, accounts: accounts, mux: http.NewServeMux()}
	s.mux.HandleFunc("/v1/health/live", s.live)
	s.mux.HandleFunc("/v1/health/ready", s.ready)
	s.mux.HandleFunc("/v1/users", s.users)
	s.mux.HandleFunc("/v1/users/{id}/tokens", s.tokens)
	s.mux.HandleFunc("/v1/me", s.me)
	s.mux.HandleFunc("/v1/members", s.members)
	s.mux.HandleFunc("/v1/members/{id}/role", s.changeMemberRole)
	s.mux.HandleFunc("/v1/members/{id}/revoke", s.revokeMember)
	s.mux.HandleFunc("/v1/agents/{id}/assignments", s.assignments)
	s.mux.HandleFunc("/v1/agents/{id}/assignments/{assignment_id}/revoke", s.revokeAssignment)
	s.mux.HandleFunc("/v1/agents/{id}/assignments/{assignment_id}/replace", s.replaceAssignment)
	s.mux.HandleFunc("/v1/audit", s.audit)
	s.mux.HandleFunc("/v1/llm/providers", s.llmProviders)
	s.mux.HandleFunc("/v1/llm/providers/{id}/rotate", s.rotateLLMProvider)
	s.mux.HandleFunc("/v1/llm/providers/{id}/disable", s.disableLLMProvider)
	s.mux.HandleFunc("/v1/llm/aliases", s.llmAliases)
	s.mux.HandleFunc("/v1/llm/budgets", s.llmBudgets)
	s.mux.HandleFunc("/v1/llm/budgets/{id}/disable", s.disableLLMBudget)
	s.mux.HandleFunc("/v1/llm/usage", s.llmUsage)
	s.mux.HandleFunc("/v1/llm/aliases/{alias}/disable", s.disableLLMAlias)
	s.mux.HandleFunc("/v1/service-accounts", s.serviceAccounts)
	s.mux.HandleFunc("/v1/service-accounts/{id}/disable", s.disableServiceAccount)
	s.mux.HandleFunc("/v1/service-accounts/{id}/tokens", s.serviceTokens)
	s.mux.HandleFunc("/v1/service-accounts/{id}/tokens/{token_id}/revoke", s.revokeServiceToken)
	s.mux.HandleFunc("/v1/teams", s.teams)
	s.mux.HandleFunc("/v1/teams/{id}", s.team)
	s.mux.HandleFunc("/v1/teams/{id}/disable", s.disableTeam)
	s.mux.HandleFunc("/v1/teams/{id}/members", s.teamMembers)
	s.mux.HandleFunc("/v1/teams/{id}/members/{principal_id}/revoke", s.revokeTeamMember)
	s.mux.HandleFunc("/v1/organizations", s.organizations)
	s.mux.HandleFunc("/v1/organizations/current", s.currentOrganization)
	s.mux.HandleFunc("/v1/organizations/{id}", s.organization)
	s.mux.HandleFunc("/v1/organizations/{id}/disable", s.disableOrganization)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "not_found") })
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	w.Header().Set("X-Request-ID", hex.EncodeToString(id))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if path.Clean(r.URL.Path) != r.URL.Path || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") {
		problem(w, 400, "invalid_path")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	if status == 401 {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Code   string `json:"code"`
	}{"about:blank", http.StatusText(status), status, code})
}
func failure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlplane.ErrAuthentication):
		problem(w, 401, "authentication_required")
	case errors.Is(err, controlplane.ErrForbidden):
		problem(w, 403, "forbidden")
	case errors.Is(err, controlplane.ErrNotFound):
		problem(w, 404, "not_found")
	case errors.Is(err, controlplane.ErrInput):
		problem(w, 400, "invalid_request")
	case errors.Is(err, controlplane.ErrConflict):
		problem(w, 422, "idempotency_key_reused")
	case errors.Is(err, controlplane.ErrInProgress):
		problem(w, 409, "idempotency_key_in_progress")
	case errors.Is(err, controlplane.ErrUnavailable):
		problem(w, 409, "agent_unavailable")
	case errors.Is(err, controlplane.ErrTransition):
		problem(w, 409, "invalid_transition")
	case errors.Is(err, controlplane.ErrQueueFull):
		w.Header().Set("Retry-After", "5")
		problem(w, 429, "queue_full")
	case errors.Is(err, controlplane.ErrTooLarge):
		problem(w, 413, "attachment_too_large")
	case errors.Is(err, controlplane.ErrStorageQuota):
		problem(w, 429, "attachment_quota_exceeded")
	case errors.Is(err, controlplane.ErrAttachment):
		problem(w, 409, "attachment_unavailable")
	case errors.Is(err, controlplane.ErrExpired):
		problem(w, 409, "expired")
	case errors.Is(err, controlplane.ErrClosurePending):
		problem(w, 409, "closure_pending")
	case errors.Is(err, controlplane.ErrAgentExists):
		problem(w, 409, "agent_already_exists")
	case errors.Is(err, controlplane.ErrRelease):
		problem(w, 422, "harness_unavailable")
	case errors.Is(err, controlplane.ErrStorageCapacity):
		problem(w, 503, "storage_capacity_unavailable")
	default:
		problem(w, 503, "temporarily_unavailable")
	}
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func receipt(w http.ResponseWriter, r controlplane.APIReceipt, err error) {
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	w.WriteHeader(r.Status)
	_, _ = w.Write(r.Body)
}
func method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, v := range allowed {
		if r.Method == v {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	problem(w, 405, "method_not_allowed")
	return false
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		problem(w, 415, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err = d.Decode(value)
	if err == nil {
		var trailing any
		if e := d.Decode(&trailing); e != io.EOF {
			if e == nil {
				e = controlplane.ErrInput
			}
			err = e
		}
	}
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			problem(w, 413, "request_too_large")
		} else {
			problem(w, 400, "invalid_json")
		}
		return false
	}
	return true
}
func idempotency(w http.ResponseWriter, r *http.Request) (string, bool) {
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" {
		problem(w, 400, "idempotency_key_required")
		return "", false
	}
	return keys[0], true
}
func (s *Server) principal(w http.ResponseWriter, r *http.Request) (controlplane.Principal, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		failure(w, controlplane.ErrAuthentication)
		return controlplane.Principal{}, false
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		failure(w, controlplane.ErrAuthentication)
		return controlplane.Principal{}, false
	}
	var p controlplane.Principal
	var err error
	if strings.HasPrefix(fields[1], "acp_") || strings.HasPrefix(fields[1], "acpp_") || strings.HasPrefix(fields[1], "acps_") {
		p, err = s.store.Authenticate(r.Context(), fields[1])
	} else {
		p, err = s.store.AuthenticateDelegation(r.Context(), s.delegations.Load(), fields[1])
	}
	if err != nil {
		failure(w, err)
		return p, false
	}
	return p, true
}
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "live"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	if err := s.store.Ready(r.Context()); err != nil {
		failure(w, err)
		return
	}
	if err := s.accounts.CheckReceiptKey(r.Context()); err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "ready"})
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				failure(w, controlplane.ErrInput)
				return
			}
			limit = v
		}
		users, err := s.accounts.ListUsers(r.Context(), p, r.URL.Query().Get("after"), limit)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, 200, map[string]any{"items": users})
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var input controlplane.CreateUserInput
	if !decode(w, r, &input) {
		return
	}
	out, err := s.accounts.CreateUser(r.Context(), p, key, input)
	receipt(w, out, err)
}
func (s *Server) tokens(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var input controlplane.IssueTokenInput
	if !decode(w, r, &input) {
		return
	}
	out, err := s.accounts.IssueUserToken(r.Context(), p, r.PathValue("id"), key, input)
	receipt(w, out, err)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.Me(r.Context(), p)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, out)
}
