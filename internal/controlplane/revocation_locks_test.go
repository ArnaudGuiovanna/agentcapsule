package controlplane

import (
	"go/token"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The admission's one row lock (P-07; ADR 001, "Changes after the v0.1.0
// audit"): resolveTenant, resolveService, resolveApp and reserveLLM hold the
// organization's row FOR KEY SHARE, and read the principal, its membership,
// the issuer, the trust, the key, the service token, the application and its
// activation, the provider and the alias without a lock. FOR KEY SHARE conflicts with FOR UPDATE only, not
// with the FOR NO KEY UPDATE a plain UPDATE takes: every statement that
// revokes or changes one of those rows must run in a transaction that holds
// the organization's row FOR UPDATE.

// admissionTables are the tables whose rows an admission reads after its
// organization's row.
var admissionTables = []string{"organizations", "principals", "memberships", "delegation_issuers", "delegation_trusts",
	"delegation_keys", "delegation_revocations", "service_tokens", "llm_providers", "llm_model_aliases", "applications", "app_activations"}

var admissionWrite = regexp.MustCompile(`(?is)\b(?:UPDATE\s+(?:ONLY\s+)?(?:` + strings.Join(admissionTables, "|") + `)\b(?:\s+(?:AS\s+)?[a-z_]+)?\s+SET|DELETE\s+FROM\s+(?:ONLY\s+)?(?:` +
	strings.Join(admissionTables, "|") + `)\b|INSERT\s+INTO\s+delegation_revocations\b)`)

// reviewedWriters are the functions whose statements revoke or change such a
// row, each with where its transaction takes the organization's row FOR
// UPDATE. A new one fails TestEveryRevocationHoldsItsOrganizationsRow until it
// is reviewed and listed here.
var reviewedWriters = map[string]string{
	"ChangeApplication":         "appAdmin: authorizeTenantAdminMutation",
	"ChangeDelegationAuthority": "SELECT status FROM organizations ... FOR UPDATE, before the issuer's anchor",
	"DisableLLMAlias":           "authorizeTenantAdminMutation",
	"DisableLLMProvider":        "authorizeTenantAdminMutation",
	"DisableOrganization":       "SELECT ... FROM organizations ... FOR UPDATE",
	"DisableServiceAccount":     "authorizeIdentityMutation: authorizeTenantAdminMutation",
	"RevokeServiceToken":        "authorizeIdentityMutation: authorizeTenantAdminMutation",
	"RotateLLMProviderSecret":   "authorizeTenantAdminMutation",
	"SetInboundPolicy":          "authorizeTenantAdminMutation",
	"SetLLMAliasAccess":         "authorizeTenantAdminMutation",
	"SetLLMAliasOperations":     "authorizeTenantAdminMutation",
	"SetLLMAliasPrices":         "authorizeTenantAdminMutation",
	"SetLLMAliasRequestPolicy":  "authorizeTenantAdminMutation",
	"SyncActivation":            "authorizeAppSync: organizations FOR UPDATE, or authorizeMemberMutation",
	"WithdrawApplicationClient": "lockClientOrganization: organizations FOR UPDATE",
	"allocateSlots":             "its callers: AcceptInvitation's FOR UPDATE OF o, SyncActivation, retryOne's FOR UPDATE; it writes retry_at, which no admission reads",
	"auditApplication":          "its callers: appAdmin, authorizeTenantAdminMutation (Invite, PlanPolicy, ApplyPolicy, templateMutation), AcceptInvitation's FOR UPDATE OF o, SyncActivation",
	"auditMember":               "its callers: authorizeMemberMutation",
	"auditService":              "its callers: authorizeIdentityMutation",
	"auditTeam":                 "its callers: authorizeTenantAdminMutation",
	"auditTenantAgent":          "its callers: authorizeTenantAdminMutation; a file's upload or deletion changes no row of the organization",
	"capabilityChanged":         "its callers: authorizeTenantAdminMutation",
	"changeMember":              "authorizeMemberMutation",
	"refreshTrustFingerprint":   "its callers: ChangeDelegationAuthority, settleKeys",
	"replaceKeys":               "its caller: ChangeDelegationAuthority",
	"replayBlanket":             "its caller: replayEffect",
	"replayEffect":              "SELECT 1 FROM organizations ... FOR UPDATE, every organization for a blanket",
	"replayTrust":               "its caller: replayEffect",
	"retireKey":                 "its caller: ChangeDelegationAuthority",
	"revokeIssuedServiceTokens": "its caller: changeMember",
	"settleKeys":                "its callers: ChangeDelegationAuthority, replayTrust",
}

func TestEveryRevocationHoldsItsOrganizationsRow(t *testing.T) {
	nodes := packageNodes(parsePackage(t, token.NewFileSet(), "."))
	var writers []string
	for name, list := range nodes {
		for _, n := range list {
			if slices.ContainsFunc(n.literals, admissionWrite.MatchString) && !slices.Contains(writers, name) {
				writers = append(writers, name)
			}
		}
	}
	slices.Sort(writers)
	for _, name := range writers {
		if _, ok := reviewedWriters[name]; !ok {
			t.Errorf("%s revokes or changes a row an admission reads: take the organization's row FOR UPDATE in its transaction, then list it in reviewedWriters", name)
		}
	}
	for name := range reviewedWriters {
		if !slices.Contains(writers, name) {
			t.Errorf("%s no longer writes such a row: remove it from reviewedWriters", name)
		}
	}
	// The replay of a revocation after a failover took no lock before P-07.
	if !slices.ContainsFunc(nodes["replayEffect"][0].literals, regexp.MustCompile(`(?is)FROM organizations\b.*FOR UPDATE`).MatchString) {
		t.Error("replayEffect does not take the organizations' rows FOR UPDATE")
	}
}
