package api

import (
	"context"
	"net/http"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// auditedRoute is a route whose action an organization's trail records
// (TEN-009): the action, as its event names it, and the path values that
// name its target and its reference.
type auditedRoute struct {
	action, target, reference string
}

// auditedRoutes are the administrative actions of an organization: each
// route here writes an event of its trail when it acts, and a refused
// attempt by one of its members or technical accounts is recorded with
// outcome refused (ADR 014 §10). Reads, invocations and messages are not
// administrative actions. A route of the platform is listed too: an
// organization's member who attempts it is refused, and that attempt is the
// organization's to see. TestEveryAuditedRouteIsServed keeps the list in
// step with the routes.
var auditedRoutes = map[string]auditedRoute{
	"POST /v1/platform/sessions":                                {"platform_credential.created", "", ""},
	"POST /v1/platform/sessions/{id}/revoke":                    {"platform_credential.revoked", "id", ""},
	"POST /v1/pools/{id}/expand":                                {"pool.expanded", "id", ""},
	"POST /v1/applications":                                     {"application.registered", "", ""},
	"POST /v1/applications/{id}/rotate":                         {"application.rotate", "id", ""},
	"POST /v1/applications/{id}/revoke":                         {"application.revoke", "id", ""},
	"POST /v1/assignment-policies/plan":                         {"policy.planned", "", ""},
	"POST /v1/assignment-policies/{id}/apply":                   {"policy.applied", "id", ""},
	"POST /v1/applications/{id}/invitations":                    {"application.invited", "id", ""},
	"PUT /v1/applications/{id}/activations/{activation_id}":     {"application.member_updated", "activation_id", "id"},
	"POST /v1/system-images":                                    {"system_image.approved", "", ""},
	"POST /v1/templates":                                        {"template.published", "", ""},
	"POST /v1/deployment-plans":                                 {"deployment.planned", "", ""},
	"POST /v1/deployment-plans/{id}/apply":                      {"deployment.applied", "id", ""},
	"POST /v1/pools":                                            {"pool.created", "", ""},
	"POST /v1/agents/{id}/resize":                               {"agent.resize_requested", "id", ""},
	"POST /v1/deployments/{id}/rollouts":                        {"rollout.started", "id", ""},
	"POST /v1/rollouts/{id}/resume":                             {"rollout.resumed", "id", ""},
	"POST /v1/agents/{id}/volume-growth":                        {"volume.growth_requested", "id", ""},
	"POST /v1/members":                                          {"member.created", "", ""},
	"POST /v1/members/{id}/role":                                {"member.role_changed", "id", ""},
	"POST /v1/members/{id}/revoke":                              {"member.revoked", "id", ""},
	"POST /v1/teams":                                            {"team.created", "", ""},
	"POST /v1/teams/{id}/disable":                               {"team.disabled", "id", ""},
	"POST /v1/teams/{id}/members":                               {"team.member_added", "id", ""},
	"POST /v1/teams/{id}/members/{principal_id}/revoke":         {"team.member_revoked", "principal_id", "id"},
	"POST /v1/service-accounts":                                 {"service_account.created", "", ""},
	"POST /v1/service-accounts/{id}/disable":                    {"service_account.disabled", "id", ""},
	"POST /v1/service-accounts/{id}/tokens":                     {"token.issued", "id", ""},
	"POST /v1/service-accounts/{id}/tokens/{token_id}/revoke":   {"token.revoked", "id", "token_id"},
	"POST /v1/agents":                                           {"agent.created", "", ""},
	"DELETE /v1/agents/{id}":                                    {"agent.delete_requested", "id", ""},
	"POST /v1/agents/{id}/wake":                                 {"agent.wake_requested", "id", ""},
	"POST /v1/agents/{id}/sleep":                                {"agent.sleep_requested", "id", ""},
	"POST /v1/agents/{id}/idle-policy":                          {"agent.idle_policy_set", "id", ""},
	"POST /v1/agents/{id}/release":                              {"agent.release_changed", "id", ""},
	"PUT /v1/agents/{id}/directory":                             {"agent.directory_changed", "id", ""},
	"PUT /v1/agents/{id}/inbound":                               {"agent.inbound_changed", "id", ""},
	"PUT /v1/agents/{id}/capabilities":                          {"agent.capabilities_changed", "id", ""},
	"POST /v1/agents/{id}/held-requests/{request_id}/accept":    {"agent.request_accepted", "id", "request_id"},
	"POST /v1/agents/{id}/held-requests/{request_id}/decline":   {"agent.request_declined", "id", "request_id"},
	"POST /v1/agents/{id}/attachments":                          {"attachment.uploaded", "id", ""},
	"DELETE /v1/attachments/{id}":                               {"attachment.deleted", "id", ""},
	"POST /v1/agents/{id}/assignments":                          {"assignment.created", "id", ""},
	"POST /v1/agents/{id}/assignments/{assignment_id}/revoke":   {"assignment.revoked", "id", "assignment_id"},
	"POST /v1/agents/{id}/assignments/{assignment_id}/replace":  {"assignment.replaced", "id", "assignment_id"},
	"POST /v1/agents/{id}/assignments/{assignment_id}/reassign": {"assignment.reassigned", "id", "assignment_id"},
	"POST /v1/invocations/{id}/replay":                          {"invocation.replayed", "", "id"},
	"POST /v1/queue/limits":                                     {"queue.limits.set", "", ""},
	"PUT /v1/organizations/current/capabilities":                {"organization.capabilities_changed", "", ""},
	"POST /v1/llm/providers":                                    {"llm.provider.created", "", ""},
	"POST /v1/llm/providers/{id}/rotate":                        {"llm.provider.rotated", "id", ""},
	"POST /v1/llm/providers/{id}/disable":                       {"llm.provider.disabled", "id", ""},
	"POST /v1/llm/aliases":                                      {"llm.alias.created", "", ""},
	"POST /v1/llm/aliases/{alias}/disable":                      {"llm.alias.disabled", "alias", ""},
	"POST /v1/llm/aliases/{alias}/access":                       {"llm.alias.access_set", "alias", ""},
	"POST /v1/llm/aliases/{alias}/prices":                       {"llm.alias.prices_set", "alias", ""},
	"POST /v1/llm/aliases/{alias}/operations":                   {"llm.alias.operations_set", "alias", ""},
	"POST /v1/llm/aliases/{alias}/grants":                       {"llm.alias.grant_created", "alias", ""},
	"POST /v1/llm/aliases/{alias}/grants/{id}/revoke":           {"llm.alias.grant_revoked", "alias", "id"},
	"POST /v1/llm/budgets":                                      {"llm.budget.created", "", ""},
	"POST /v1/llm/budgets/{id}/disable":                         {"llm.budget.disabled", "id", ""},
	"POST /v1/llm/calls/{id}/settle":                            {"llm.usage.settled", "", "id"},
	"POST /v1/llm/calls/{id}/release":                           {"llm.usage.released", "", "id"},
	"POST /v1/organizations":                                    {"organization.created", "", ""},
	"POST /v1/organizations/{id}/disable":                       {"organization.disabled", "id", ""},
	"PUT /v1/organizations/{id}/quotas":                         {"organization.quotas_set", "id", ""},
	"POST /v1/harness-imports":                                  {"harness.import.requested", "", ""},
	"POST /v1/harness-releases/{id}/deprecate":                  {"harness.release.deprecated", "id", ""},
}

// refusedStatuses are the answers that refuse an attempt: authorization
// (403, and 404 for what the caller may not see) and validation (400, 409,
// 413, 415, 422). An unauthenticated request (401) names no organization; a
// method the route does not serve (405) is not an attempt of its action;
// capacity (429) and availability (5xx) refuse no one in particular.
var refusedStatuses = map[int]bool{400: true, 403: true, 404: true, 409: true, 413: true, 415: true, 422: true}

// attemptKey carries, through one request, the principal it authenticated.
type attemptKey struct{}

type attempt struct {
	principal *controlplane.Principal
}

func withAttempt(ctx context.Context) (context.Context, *attempt) {
	a := &attempt{}
	return context.WithValue(ctx, attemptKey{}, a), a
}

func noteAttempt(r *http.Request, p controlplane.Principal) {
	if a, ok := r.Context().Value(attemptKey{}).(*attempt); ok {
		a.principal = &p
	}
}

// recordRefusal adds a refused attempt at an audited route to the trail of
// the organization of the principal that made it. It runs once the answer is
// written, in its own transaction: the refused change rolled back, and the
// answer does not wait for, nor depend on, the record.
func (s *Server) recordRefusal(r *http.Request, w *statusRecorder, a *attempt) {
	if a.principal == nil || a.principal.TenantID == "" || !refusedStatuses[w.status] || w.problem == "" {
		return
	}
	route, ok := auditedRoutes[r.Method+" "+r.Pattern]
	if !ok {
		return
	}
	value := func(name string) string {
		if name == "" {
			return ""
		}
		return r.PathValue(name)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	err := s.accounts.RecordRefusal(ctx, *a.principal, controlplane.RefusedAttempt{Action: route.action, Target: value(route.target),
		Reference: value(route.reference), Reason: w.problem})
	if err != nil && s.telemetry != nil {
		s.telemetry.refusalUnrecorded()
	}
}
