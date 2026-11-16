package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

var testOperator = OperatorCommand{Actor: "local-uid:1000"}

// guardedTrail is the guarded commands' part of the operator's audit, oldest
// first.
func guardedTrail(t *testing.T, s *Store) []OperatorAuditEvent {
	t.Helper()
	events, err := s.ListOperatorAudit(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var trail []OperatorAuditEvent
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Outcome != "" {
			trail = append(trail, events[i])
		}
	}
	return trail
}

// A host past its storage pressure threshold (OPS-03): new agents, which need
// a volume, are refused while its data file system is; imports, which need an
// image, while an image file system is. Nothing is reserved, and both work
// again once the worker records the space back.
func TestStoragePressureRefusesNewVolumesAndImports(t *testing.T) {
	l, c, owner := agentLab(t)
	createTenantAgent(t, c, owner, "before")
	agents := count(t, l.s, "agents")
	if err := l.s.RecordStoragePressure(t.Context(), "local", true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(t.Context(), owner, "create-pressed", tenantAgentInput("pressed")); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("a new volume under data pressure:", err)
	}
	if n := count(t, l.s, "agents"); n != agents {
		t.Fatal("a refused agent was reserved", n, agents)
	}
	if _, err := l.a.RequestHarnessImport(t.Context(), l.platform, "import-1", HarnessImportInput{Reference: pinned("b")}); err != nil {
		t.Fatal("data pressure refused an import:", err)
	}
	if err := l.s.RecordStoragePressure(t.Context(), "local", false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.RequestHarnessImport(t.Context(), l.platform, "import-2", HarnessImportInput{Reference: pinned("c")}); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("an import under image pressure:", err)
	}
	if n := count(t, l.s, "harness_imports"); n != 1 {
		t.Fatal("a refused import was recorded", n)
	}
	// The same key, once space returns, is a new attempt, not a replayed refusal.
	createTenantAgent(t, c, owner, "pressed")
	if err := l.s.RecordStoragePressure(t.Context(), "local", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.RequestHarnessImport(t.Context(), l.platform, "import-2", HarnessImportInput{Reference: pinned("c")}); err != nil {
		t.Fatal("import refused after the pressure ended:", err)
	}

	// The historical owner catalogue reserves volumes too.
	s, _, legacy, _, _, user := catalogLab(t)
	if err := s.RecordStoragePressure(t.Context(), "local", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Reserve(t.Context(), user, "legacy", catalogInput(user.ID)); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("a historical agent under data pressure:", err)
	}
	if err := s.RecordStoragePressure(t.Context(), "bad host!", true, true); !errors.Is(err, ErrInput) {
		t.Fatal("invalid host", err)
	}
}

// Destructive operator commands (API-02, ADR 014): a dry run changes and
// records nothing; each real run is audited with its outcome, refusals
// included.
func TestOperatorCommandsAreDryRunAndAudited(t *testing.T) {
	s, _, p, secret, _ := organizationLab(t)
	dry := OperatorCommand{Actor: testOperator.Actor, DryRun: true}
	out, err := s.RevokeOperatorCredential(t.Context(), dry, "platform", p.TokenID)
	if err != nil || out.Outcome != "done" || !out.DryRun || out.Target != p.TokenID {
		t.Fatal("dry run", out, err)
	}
	if _, err = s.Authenticate(t.Context(), secret); err != nil {
		t.Fatal("a dry run revoked the credential", err)
	}
	if n := count(t, s, "operator_audit"); n != 0 {
		t.Fatal("a dry run was audited", n)
	}
	for _, want := range []string{"done", "unchanged"} {
		if out, err = s.RevokeOperatorCredential(t.Context(), testOperator, "platform", p.TokenID); err != nil || out.Outcome != want || out.DryRun {
			t.Fatal("revocation", want, out, err)
		}
	}
	if _, err = s.Authenticate(t.Context(), secret); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked credential still authenticates", err)
	}
	if out, err = s.RevokeOperatorCredential(t.Context(), testOperator, "platform", "ptok_missing"); !errors.Is(err, ErrNotFound) || out.Outcome != "refused" || out.Reason != "not_found" {
		t.Fatal("unknown credential", out, err)
	}
	if out, err = s.RevokeOperatorCredential(t.Context(), dry, "platform", "ptok_other"); !errors.Is(err, ErrNotFound) || out.Outcome != "refused" {
		t.Fatal("dry refusal", out, err)
	}
	if _, err = s.RevokeOperatorCredential(t.Context(), OperatorCommand{}, "platform", p.TokenID); !errors.Is(err, ErrInput) {
		t.Fatal("a command without an actor", err)
	}
	if _, err = s.AbandonProvisioning(t.Context(), testOperator, "agent_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	trail := guardedTrail(t, s)
	if len(trail) != 4 {
		t.Fatal("operator audit", trail)
	}
	want := []struct{ action, target, outcome, reason string }{
		{"credential.revoked", p.TokenID, "done", ""}, {"credential.revoked", p.TokenID, "unchanged", ""},
		{"credential.revoked", "ptok_missing", "refused", "not_found"}, {"provisioning.abandoned", "agent_missing", "refused", "not_found"}}
	for i, w := range want {
		e := trail[i]
		if e.Actor != testOperator.Actor || e.Action != w.action || e.Target != w.target || e.Outcome != w.outcome || e.Reference != w.reason ||
			e.Changed != (w.outcome == "done") || e.CreatedAt.IsZero() {
			t.Fatal("operator audit event", i, e)
		}
	}
}

// The audit retention (TEN-06, product §7): every event is kept until the
// operator sets one. Then the worker's purge deletes the older events only,
// and records that it did.
func TestAuditRetentionPurgesOnlyOlderEvents(t *testing.T) {
	l, c, owner := agentLab(t)
	old := createTenantAgent(t, c, owner, "old")
	createTenantAgent(t, c, owner, "recent")
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE tenant_agent_audit SET created_at=created_at-interval '40 days' WHERE agent_id=$1", old); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), "UPDATE organization_audit SET created_at=created_at-interval '400 days'"); err != nil {
		t.Fatal(err)
	}
	before := count(t, l.s, "tenant_agent_audit") + count(t, l.s, "organization_audit")
	if days, err := l.s.AuditRetention(t.Context()); err != nil || days != nil {
		t.Fatal("a retention by default", days, err)
	}
	if n, err := l.s.PurgeAudit(t.Context(), 100); err != nil || n != 0 {
		t.Fatal("purged without a retention", n, err)
	}
	thirty := 30
	dry := OperatorCommand{Actor: testOperator.Actor, DryRun: true}
	out, err := l.s.SetAuditRetention(t.Context(), dry, &thirty)
	if err != nil || out.Outcome != "done" || out.Events == nil || *out.Events != 2 || out.Target != "30_days" {
		t.Fatal("dry retention", out, err)
	}
	if days, _ := l.s.AuditRetention(t.Context()); days != nil {
		t.Fatal("a dry run set the retention")
	}
	ten := 10
	if out, err = l.s.SetAuditRetention(t.Context(), testOperator, &ten); !errors.Is(err, ErrInput) || out.Reason != "invalid_input" {
		t.Fatal("a retention under 30 days", out, err)
	}
	if out, err = l.s.SetAuditRetention(t.Context(), testOperator, &thirty); err != nil || out.Outcome != "done" {
		t.Fatal("retention", out, err)
	}
	if out, err = l.s.SetAuditRetention(t.Context(), testOperator, &thirty); err != nil || out.Outcome != "unchanged" {
		t.Fatal("same retention", out, err)
	}
	// One event per table and batch: the second purge takes the rest.
	if n, err := l.s.PurgeAudit(t.Context(), 1); err != nil || n != 2 {
		t.Fatal("purge", n, err)
	}
	if n, err := l.s.PurgeAudit(t.Context(), 100); err != nil || n != 0 {
		t.Fatal("second purge", n, err)
	}
	if after := count(t, l.s, "tenant_agent_audit") + count(t, l.s, "organization_audit"); after != before-2 {
		t.Fatal("purged", before-after, "events, want 2")
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Items {
		if e.Target == old && e.Action == "agent.created" || e.Action == "organization.created" {
			t.Fatal("an event older than the retention remains", e)
		}
	}
	trail := guardedTrail(t, l.s)
	if len(trail) != 4 || trail[3].Action != "audit.purged" || trail[3].Actor != "worker" || trail[3].Target != "2_events" {
		t.Fatal("purge not audited", trail)
	}
	if out, err = l.s.SetAuditRetention(t.Context(), testOperator, nil); err != nil || out.Outcome != "done" || out.Target != "keep_all" {
		t.Fatal("keep all", out, err)
	}
	if days, _ := l.s.AuditRetention(t.Context()); days != nil {
		t.Fatal("retention not cleared", *days)
	}
}

// The invocation backlog (OPS-03): invocations accepted and not delivered,
// and the age of the oldest since its acceptance. One agent's three waiting
// invocations share a single worker job, which says nothing of their wait.
func TestInvocationBacklogCountsWaitingInvocations(t *testing.T) {
	s, c, _, _, owner, e := instructionLab(t)
	if n, age, err := s.InvocationBacklog(t.Context(), "local"); err != nil || n != 0 || age != 0 {
		t.Fatal("empty backlog", n, age, err)
	}
	for _, key := range []string{"one", "two", "three"} {
		if _, err := c.Instruct(t.Context(), owner, e.AgentID, key, privateInstruction(key)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE platform_operations SET created_at=created_at-interval '10 minutes' WHERE kind='instruction' AND id=(SELECT min(id) FROM platform_operations WHERE kind='instruction')"); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscoverWork(t.Context(), "local", 10); err != nil {
		t.Fatal(err)
	}
	n, age, err := s.InvocationBacklog(t.Context(), "local")
	if err != nil || n != 3 || age < 10*time.Minute || age > 11*time.Minute {
		t.Fatal("backlog", n, age, err)
	}
	if stats, err := s.WorkQueue(t.Context(), "local"); err != nil || len(stats) != 1 || stats[0].Jobs != 1 {
		t.Fatal("one job for the agent's head", stats, err)
	}
	if n, _, err = s.InvocationBacklog(t.Context(), "other"); err != nil || n != 0 {
		t.Fatal("another host's backlog", n, err)
	}
}

// A dry run of a delegation change (ADR 014) checks it and records nothing:
// no revocation, no receipt, no audit. The same operation ID then runs for
// real, not as a replay.
func TestDelegationDryRunRecordsNothing(t *testing.T) {
	l := newTenantLab(t, true)
	in := DelegationChange{OperationID: "dry-revoke", Actor: "test-operator", Action: "revoke-token", TenantID: l.org.ID, Issuer: l.trust.Issuer, TokenID: "jti-1", DryRun: true}
	before := count(t, l.s, "delegation_audit")
	r, err := l.s.ChangeDelegationAuthority(t.Context(), in)
	if err != nil || r.Status != "revoked" || r.Replayed {
		t.Fatal("dry run", r, err)
	}
	if count(t, l.s, "delegation_revocations") != 0 || count(t, l.s, "delegation_audit") != before {
		t.Fatal("a dry run recorded the revocation")
	}
	in.DryRun = false
	if r, err = l.s.ChangeDelegationAuthority(t.Context(), in); err != nil || r.Replayed || count(t, l.s, "delegation_revocations") != 1 {
		t.Fatal("the real run after a dry run", r, err)
	}
	in.TenantID = "org_missing"
	in.OperationID, in.DryRun = "dry-missing", true
	if _, err = l.s.ChangeDelegationAuthority(t.Context(), in); !errors.Is(err, ErrNotFound) {
		t.Fatal("a dry run on an unknown organization", err)
	}
}

// The audit export (TEN-06): the organization's events of a time range, with
// the rights of GET /v1/audit, and the retention in force.
func TestAuditExportByRangeWithTheAuditRights(t *testing.T) {
	l, c, owner := agentLab(t)
	first := createTenantAgent(t, c, owner, "first")
	var start time.Time
	if err := l.s.pool.QueryRow(t.Context(), "SELECT clock_timestamp()").Scan(&start); err != nil {
		t.Fatal(err)
	}
	second := createTenantAgent(t, c, owner, "second")
	addMember(t, l, owner, "aud", authorization.Auditor)
	addMember(t, l, owner, "opr", authorization.AgentOperator)
	end := start.Add(time.Hour)
	export, err := l.a.ExportAudit(t.Context(), owner, start, end)
	if err != nil || export.OrganizationID != owner.TenantID || export.RetentionDays != nil || export.ExportedAt.IsZero() {
		t.Fatal("export", export, err)
	}
	targets := map[string]bool{}
	for _, e := range export.Items {
		if e.CreatedAt.Before(start) || !e.CreatedAt.Before(end) {
			t.Fatal("an event out of the range", e)
		}
		targets[e.Target] = true
	}
	if targets[first] || !targets[second] || len(export.Items) < 3 {
		t.Fatal("range", export.Items)
	}
	whole, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	all, err := l.a.ExportAudit(t.Context(), owner, start.Add(-time.Hour), end)
	if err != nil || len(all.Items) != len(whole.Items) {
		t.Fatal("the export and the feed disagree", len(all.Items), len(whole.Items), err)
	}
	if _, err = l.a.ExportAudit(t.Context(), agentPrincipal(t, l, "aud", agentScopes), start, end); err != nil {
		t.Fatal("an auditor cannot export", err)
	}
	for _, p := range []Principal{agentPrincipal(t, l, "opr", agentScopes), agentPrincipal(t, l, "aud", "org:read")} {
		if _, err = l.a.ExportAudit(t.Context(), p, start, end); !errors.Is(err, ErrForbidden) {
			t.Fatal("export without the audit rights", err)
		}
	}
	for _, r := range [][2]time.Time{{end, start}, {start, start}, {start, start.Add(367 * 24 * time.Hour)}, {{}, end}} {
		if _, err = l.a.ExportAudit(t.Context(), owner, r[0], r[1]); !errors.Is(err, ErrInput) {
			t.Fatal("invalid range", r, err)
		}
	}
	days := 400
	if _, err = l.s.SetAuditRetention(t.Context(), testOperator, &days); err != nil {
		t.Fatal(err)
	}
	if export, err = l.a.ExportAudit(t.Context(), owner, start, end); err != nil || export.RetentionDays == nil || *export.RetentionDays != 400 {
		t.Fatal("retention in the export", export.RetentionDays, err)
	}
}
