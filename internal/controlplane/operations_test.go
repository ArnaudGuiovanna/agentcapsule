package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
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

// A stuck reservation of an organization's agent can be abandoned too. Its
// audit stays: the agent is not erased but ends DELETED, its provisioning
// canceled, its reservation freed for the organization's next agent.
func TestAbandonProvisioningRetiresAStuckTenantAgent(t *testing.T) {
	l, c, owner := agentLab(t)
	id := createTenantAgent(t, c, owner, "stuck")
	out, err := l.s.AbandonProvisioning(t.Context(), testOperator, id)
	if err != nil || out.Outcome != "done" {
		t.Fatal("abandon a tenant agent", out, err)
	}
	var phase, status, code string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT a.phase,o.status,o.error_code FROM agents a JOIN platform_operations o ON o.agent_id=a.id
        WHERE a.id=$1 AND o.kind='provision'`, id).Scan(&phase, &status, &code); err != nil {
		t.Fatal(err)
	}
	if phase != "DELETED" || status != "CANCELED" || code != "provisioning_abandoned" {
		t.Fatal("abandoned agent", phase, status, code)
	}
	var left int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM worker_jobs WHERE agent_id=$1)+(SELECT count(*) FROM store_enrollments WHERE agent_id=$1)`, id).Scan(&left); err != nil || left != 0 {
		t.Fatal("work or enrollment left", left, err)
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, e := range page.Items {
		kept = kept || e.Target == id && e.Action == "agent.created"
	}
	if !kept {
		t.Fatal("the organization's audit lost the agent's creation")
	}
	if _, err = l.s.AbandonProvisioning(t.Context(), testOperator, id); !errors.Is(err, ErrTransition) {
		t.Fatal("abandoned twice", err)
	}
	createTenantAgent(t, c, owner, "next")
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

// The retention covers every audit trail of the schema: each table named
// *_audit, and each other table that records who acted, except the
// idempotency receipts, which expire on their own. Each has an index that
// starts with the time the purge selects by, and the purge leaves no event
// older than the retention in any of them.
func TestAuditRetentionCoversEveryAuditTable(t *testing.T) {
	l, c, owner := agentLab(t)
	agent := createTenantAgent(t, c, owner, "audited")
	createProvider(t, l, owner, "audited")
	rows, err := l.s.pool.Query(t.Context(), `SELECT c.relname::text FROM pg_class c
        WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='r' AND c.relname NOT IN ('http_receipts','idempotency_keys')
          AND (c.relname LIKE '%\_audit' OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attname LIKE '%actor%'))
        ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	trails, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(trails) < 2 {
		t.Fatal("audit tables", trails, err)
	}
	at := map[string]string{}
	for _, a := range auditTables {
		at[a.table] = a.at
	}
	for _, table := range trails {
		if at[table] == "" {
			t.Error(table, "is an audit trail the retention leaves out")
			continue
		}
		var indexed bool
		if err = l.s.pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=i.indkey[0]
            WHERE i.indrelid=$1::regclass AND a.attname=$2)`, table, at[table]).Scan(&indexed); err != nil || !indexed {
			t.Error(table, "has no index that starts with", at[table], err)
		}
		delete(at, table)
	}
	if len(at) != 0 {
		t.Error("the retention names tables that are not audit trails", at)
	}
	if t.Failed() {
		t.FailNow()
	}
	// One event at least in each, all of them older than the retention.
	seed := func(query string, args ...any) {
		if _, err := l.s.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(query, err)
		}
	}
	seed(`INSERT INTO teams(id,tenant_id,name) VALUES('team_old',$1,'old')`, owner.TenantID)
	seed(`INSERT INTO tenant_team_audit(id,tenant_id,actor_principal_id,team_id,action,previous_status,next_status,changed)
        VALUES('tta_old',$1,$2,'team_old','team.created','','active',true)`, owner.TenantID, owner.ID)
	seed(`INSERT INTO tenant_member_audit(id,tenant_id,actor_principal_id,target_principal_id,action,previous_role,next_role,changed)
        VALUES('tma_old',$1,$2,$2,'member.created','','owner',true)`, owner.TenantID, owner.ID)
	seed(`INSERT INTO tenant_service_audit(id,tenant_id,actor_principal_id,service_principal_id,action)
        VALUES('tsa_old',$1,$2,$2,'service_account.created')`, owner.TenantID, owner.ID)
	seed(`INSERT INTO queue_audit(id,tenant_id,actor_principal_id,action) VALUES('qa_old',$1,$2,'limits.set')`, owner.TenantID, owner.ID)
	seed(`INSERT INTO capability_audit(id,tenant_id,actor_principal_id,action) VALUES('ca_old',$1,$2,'organization.capabilities_changed')`, owner.TenantID, owner.ID)
	seed(`INSERT INTO platform_audit(id,action,actor,credential_id,changed) SELECT 'pa_old','platform_credential.created','operator',min(id),true FROM platform_credentials`)
	seed(`INSERT INTO harness_audit(id,actor_account,credential_id,action,release_id) SELECT 'ha_old','operator','none','release.deprecated',min(id) FROM harness_releases`)
	seed(`INSERT INTO operator_audit(id,actor,action,target,outcome) VALUES('opa_old','local-uid:0','credential.revoked','none','done')`)
	seed(`INSERT INTO instruction_replays(id,operation_id,agent_id,tenant_id,actor_kind,request_key,previous_reason,expires_at)
        SELECT 'ir_old',id,agent_id,$2,'operator','old','expired',clock_timestamp() FROM platform_operations WHERE agent_id=$1`, agent, owner.TenantID)
	seed(`INSERT INTO tenant_refusal_audit(id,tenant_id,actor_principal_id,action,target,reason) VALUES('tra_old',$1,$2,'team.created',$1,'forbidden')`, owner.TenantID, owner.ID)
	for _, a := range auditTables {
		if count(t, l.s, a.table) == 0 {
			t.Fatal(a.table, "has no event: seed one")
		}
		seed("UPDATE " + a.table + " SET " + a.at + "=" + a.at + "-interval '400 days'")
	}
	thirty := 30
	if out, err := l.s.SetAuditRetention(t.Context(), testOperator, &thirty); err != nil || out.Outcome != "done" {
		t.Fatal("retention", out, err)
	}
	if n, err := l.s.PurgeAudit(t.Context(), 10000); err != nil || n == 0 {
		t.Fatal("purge", n, err)
	}
	for _, a := range auditTables {
		var left int
		if err = l.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM "+a.table+" WHERE "+a.at+" < clock_timestamp()-interval '30 days'").Scan(&left); err != nil || left != 0 {
			t.Error(a.table, "keeps", left, "events older than the retention", err)
		}
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

// An organization's queue limits are an administrative action of its own:
// GET /v1/audit and the export show their change (TEN-009).
func TestAuditShowsQueueLimitChanges(t *testing.T) {
	l, _, owner := agentLab(t)
	if _, err := l.a.SetQueueLimits(t.Context(), owner, "limits", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 20}); err != nil {
		t.Fatal(err)
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range page.Items {
		if e.Action == "queue.limits.set" && e.Actor == owner.ID && e.Target == owner.TenantID {
			found++
		}
	}
	export, err := l.a.ExportAudit(t.Context(), owner, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range export.Items {
		if e.Action == "queue.limits.set" {
			found++
		}
	}
	if found != 2 {
		t.Fatal("the queue limits' change is not in the audit", found, page.Items)
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
