package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// An application's client serves the one organization the platform
// operator approved it for (finding S-10). Another organization cannot
// register it, and its answer tells it nothing of the client: the same
// before and after the client's organization registered it. A member's
// token reaches the application of the organization the client is approved
// for, and withdrawing the approval stops it.
func TestApplicationClientsAreApprovedForOneOrganization(t *testing.T) {
	f := newRBACFixture(t)
	org, other := f.ids["org"], f.second.org.ID
	register := func(actor string, c controlplane.ApplicationConfig) *httptest.ResponseRecorder {
		t.Helper()
		return f.call(t, actor, "POST", "/v1/applications", f.next(), stringify(c))
	}
	refused := func(r *httptest.ResponseRecorder) string {
		t.Helper()
		if r.Code != 403 || problemCode(r) != "application_client_not_approved" {
			t.Fatal("registration of a client not approved for the organization:", r.Code, r.Body.String())
		}
		return r.Body.String()
	}

	cfg := appTestConfig(f.next())
	squat := refused(register("foreign", cfg))
	refused(register("owner", cfg))

	approval := approveAppClient(t, f, org, cfg)
	if approval.OrganizationID != org || approval.Issuer != cfg.Issuer || approval.ClientID != cfg.ClientID || approval.ApprovedBy == "" {
		t.Fatal("approval", approval)
	}
	body := stringify(controlplane.ApplicationClientInput{Issuer: cfg.Issuer, ClientID: cfg.ClientID})
	var again controlplane.ApplicationClient
	f.must(t, "platform", "POST", "/v1/organizations/"+org+"/application-clients", body, 200, &again)
	if again.ID != approval.ID {
		t.Fatal("a repeated approval made another", again, approval)
	}
	if r := f.call(t, "platform", "POST", "/v1/organizations/"+other+"/application-clients", f.next(), body); r.Code != 409 || problemCode(r) != "invalid_transition" {
		t.Fatal("a client approved for two organizations", r.Code, r.Body.String())
	}

	// The other organization gets the same answer whether the client's
	// organization registered it or not: no 409 tells it the client exists.
	if refused(register("foreign", cfg)) != squat {
		t.Fatal("the answer changed once the client was approved elsewhere")
	}
	var app controlplane.IssuedApplication
	if r := register("owner", cfg); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &app) != nil {
		t.Fatal("registration of an approved client", r.Code, r.Body.String())
	}
	if refused(register("foreign", cfg)) != squat {
		t.Fatal("the answer changed once the client was registered elsewhere")
	}
	// A second registration of the client in its own organization is that
	// organization's own conflict.
	twice := cfg
	twice.Name = f.next()
	if r := register("owner", twice); r.Code != 409 || problemCode(r) != "invalid_transition" {
		t.Fatal("a client registered twice in its organization", r.Code, r.Body.String())
	}
	var list struct {
		Items []controlplane.ApplicationClient `json:"items"`
	}
	f.must(t, "platform", "GET", "/v1/organizations/"+org+"/application-clients?limit=200", "", 200, &list)
	listed := false
	for _, c := range list.Items {
		listed = listed || c.ID == approval.ID
	}
	if !listed {
		t.Fatal("approval not listed", list.Items)
	}
	if r := f.call(t, "owner", "GET", "/v1/organizations/"+org+"/application-clients", "", ""); r.Code != 403 {
		t.Fatal("an organization lists the platform's approvals", r.Code)
	}

	// A member of an application signs in; the operator withdraws its
	// client's approval: the application is disabled, its member's and its
	// backend's tokens stop, and its organization cannot take it back.
	v := activationFixture(t, f)
	member := f.static["applicant"]
	current := func(token string) (int, string) {
		t.Helper()
		r := call(t, f.server, "GET", "/v1/organizations/current", token, "", "")
		var out controlplane.CurrentOrganization
		_ = json.Unmarshal(r.Body.Bytes(), &out)
		return r.Code, out.Organization.ID
	}
	if code, got := current(member); code != 200 || got != org {
		t.Fatal("member before the withdrawal", code, got)
	}
	var withdrawn struct {
		ID          string                          `json:"id"`
		Status      string                          `json:"status"`
		Revocations []controlplane.AccessRevocation `json:"revocations"`
	}
	f.must(t, "platform", "POST", "/v1/organizations/"+org+"/application-clients/"+v["approval"]+"/withdraw", "{}", 200, &withdrawn)
	if withdrawn.ID != v["approval"] || withdrawn.Status != "withdrawn" || len(withdrawn.Revocations) != 1 || withdrawn.Revocations[0].Kind != "principal" {
		t.Fatal("withdrawal", withdrawn)
	}
	if code, _ := current(member); code != 401 {
		t.Fatal("a member's token after its client's withdrawal", code)
	}
	if r := call(t, f.server, "GET", "/v1/applications/"+v["app"]+"/activations/"+v["activation"], v["backend"], "", ""); r.Code != 401 {
		t.Fatal("the backend's token after its client's withdrawal", r.Code)
	}
	if r := f.call(t, "platform", "POST", "/v1/organizations/"+org+"/application-clients/"+v["approval"]+"/withdraw", f.next(), "{}"); r.Code != 404 {
		t.Fatal("a withdrawn approval withdrawn again", r.Code, r.Body.String())
	}
	moved := appTestConfig(f.next())
	moved.Issuer = v["issuer"]
	refused(register("owner", moved))

	// The client moves to the other organization, which registers it: a
	// token of the client reaches that organization's application, never
	// the first one's.
	approveAppClient(t, f, other, moved)
	var foreign controlplane.IssuedApplication
	if r := register("foreign", moved); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &foreign) != nil {
		t.Fatal("registration of the moved client", r.Code, r.Body.String())
	}
	second := *f.second
	second.server = f.server
	agent := f.activeAgentOf(t, &second, f.token(t, "foreign"), "moved-client-agent")
	var team controlplane.Team
	f.must(t, "foreign", "POST", "/v1/teams", `{"name":"`+f.next()+`"}`, 201, &team)
	fill := strings.NewReplacer("{app}", foreign.ID, "{team}", team.ID, "{agent}", agent)
	var policy controlplane.AssignmentPolicy
	f.must(t, "foreign", "POST", "/v1/assignment-policies/plan", fill.Replace(appPolicyBody), 201, &policy)
	f.must(t, "foreign", "POST", "/v1/assignment-policies/"+policy.ID+"/apply", "{}", 200, nil)
	invite := strings.NewReplacer("{policy}", policy.ID, "{team}", team.ID, "{expires}", time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"alice@example.test", "carol@example.test").Replace(appInviteBody)
	var invitation controlplane.Invitation
	f.must(t, "foreign", "POST", "/v1/applications/"+foreign.ID+"/invitations", invite, 201, &invitation)
	carol := signAppToken(t, moved.Issuer, "carol", "agentcapsule-api")
	if r := call(t, f.server, "POST", "/v1/applications/"+foreign.ID+"/accept", carol, "carol", stringify(controlplane.AcceptInvitation{Proof: invitation.Proof})); r.Code != 200 {
		t.Fatal("acceptance in the organization the client moved to", r.Code, r.Body.String())
	}
	if code, got := current(carol); code != 200 || got != other {
		t.Fatal("a token of the moved client", code, got)
	}
	if code, _ := current(member); code != 401 {
		t.Fatal("the first organization's member after the move", code)
	}
}
