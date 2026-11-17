package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Organization quotas (TEN-007, ADR 021): a typed refusal before any
// reservation, and no excess under concurrency.

func ref[T any](v T) *T { return &v }

// quotaRow sets tenant's quotas as the operator's route stores them.
func quotaRow(t *testing.T, s *Store, tenant string, q OrganizationQuotas) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO organization_quotas(tenant_id,max_agents,max_active_vms,max_vcpus,max_memory_mib,max_storage_mib,updated_by)
        VALUES($1,$2,$3,$4,$5,$6,'test') ON CONFLICT (tenant_id) DO UPDATE SET max_agents=EXCLUDED.max_agents,max_active_vms=EXCLUDED.max_active_vms,
        max_vcpus=EXCLUDED.max_vcpus,max_memory_mib=EXCLUDED.max_memory_mib,max_storage_mib=EXCLUDED.max_storage_mib`,
		tenant, q.MaxAgents, q.MaxActiveVMs, q.MaxVCPUs, q.MaxMemoryMiB, q.MaxStorageMiB); err != nil {
		t.Fatal(err)
	}
}

func quotaRefusal(err error) string {
	var q *OrganizationQuotaError
	if errors.As(err, &q) && errors.Is(err, ErrOrganizationQuota) {
		return q.Quota
	}
	return ""
}

func countWhere(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// reserveAll creates the agents of inputs at once, each with its own key,
// and returns how many were created and the refusals' quotas.
func reserveAll(t *testing.T, c *AgentCatalog, owner Principal, prefix string, inputs []CreateAgentInput) (int, []string) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, len(inputs))
	for i, in := range inputs {
		wg.Go(func() { _, errs[i] = c.Reserve(t.Context(), owner, fmt.Sprintf("%s-%d", prefix, i), in) })
	}
	wg.Wait()
	created, refused := 0, []string{}
	for _, err := range errs {
		if err == nil {
			created++
		} else if q := quotaRefusal(err); q != "" {
			refused = append(refused, q)
		} else {
			t.Fatal("creation failed otherwise", err)
		}
	}
	return created, refused
}

func agentInputs(prefix string, n, vcpus, memory, volume int) []CreateAgentInput {
	out := make([]CreateAgentInput, n)
	for i := range out {
		out[i] = CreateAgentInput{Name: fmt.Sprintf("%s-%d", prefix, i), Harness: HarnessReference{Name: "reference", Version: "1.0.0"},
			Resources: AgentResources{vcpus, memory, volume}}
	}
	return out
}

func allAre(list []string, want string) bool {
	for _, v := range list {
		if v != want {
			return false
		}
	}
	return true
}

// Concurrent creations in one organization never exceed its agents or
// storage quota. A refusal names its quota and reserves nothing: no agent, no
// operation, no enrollment. An agent that alone needs more vCPUs or RAM than
// the organization may run is refused at creation: it could never boot.
func TestConcurrentCreationsNeverExceedTheOrganizationsQuotas(t *testing.T) {
	l, c, owner := agentLab(t)
	org := l.org.ID
	reserved := func() (agents, operations, enrollments int) {
		return countWhere(t, l.s, "SELECT count(*) FROM agents WHERE tenant_id=$1", org),
			countWhere(t, l.s, "SELECT count(*) FROM platform_operations o JOIN agents a ON a.id=o.agent_id WHERE a.tenant_id=$1", org),
			countWhere(t, l.s, "SELECT count(*) FROM store_enrollments e JOIN agents a ON a.id=e.agent_id WHERE a.tenant_id=$1", org)
	}
	quotaRow(t, l.s, org, OrganizationQuotas{MaxAgents: ref(3)})
	created, refused := reserveAll(t, c, owner, "count", agentInputs("count", 8, 1, 256, 256))
	if created != 3 || len(refused) != 5 || !allAre(refused, "max_agents") {
		t.Fatal("the agents quota was exceeded or refused untyped", created, refused)
	}
	if a, o, e := reserved(); a != 3 || o != 3 || e != 3 {
		t.Fatal("a refused creation reserved something", a, o, e)
	}

	// Storage: 3 x 256 MiB are reserved; room for one more 128 MiB volume.
	quotaRow(t, l.s, org, OrganizationQuotas{MaxAgents: ref(100), MaxStorageMiB: ref(int64(1000))})
	created, refused = reserveAll(t, c, owner, "storage", agentInputs("storage", 6, 1, 256, 128))
	if created != 1 || len(refused) != 5 || !allAre(refused, "max_storage_mib") {
		t.Fatal("the storage quota was exceeded or refused untyped", created, refused)
	}
	if a, _, _ := reserved(); a != 4 {
		t.Fatal("storage refusals reserved an agent", a)
	}

	// Alone too large for what the organization may run.
	quotaRow(t, l.s, org, OrganizationQuotas{MaxMemoryMiB: ref(int64(512)), MaxVCPUs: ref(2)})
	for want, in := range map[string]CreateAgentInput{
		"max_memory_mib": agentInputs("ram", 1, 1, 1024, 64)[0],
		"max_vcpus":      agentInputs("cpu", 1, 4, 256, 64)[0],
	} {
		if _, err := c.Reserve(t.Context(), owner, "alone-"+want, in); quotaRefusal(err) != want {
			t.Fatal("an agent that could never boot was created", want, err)
		}
	}
	if _, err := c.Reserve(t.Context(), owner, "fits", agentInputs("fits", 1, 2, 512, 64)[0]); err != nil {
		t.Fatal("an agent that fits was refused", err)
	}

	// Without quotas, as before.
	if _, err := l.s.pool.Exec(t.Context(), "DELETE FROM organization_quotas WHERE tenant_id=$1", org); err != nil {
		t.Fatal(err)
	}
	if created, refused = reserveAll(t, c, owner, "free", agentInputs("free", 3, 8, 8192, 64)); created != 3 {
		t.Fatal("an organization without quotas was limited", refused)
	}
}

// The tenant path of the host's own storage limit (OPS-03): past it, a
// creation is refused before any reservation, whatever the organization's
// quotas.
func TestTenantCreationPastTheHostStorageIsRefusedBeforeAnyReservation(t *testing.T) {
	l, c, owner := agentLab(t)
	if err := l.s.ConfigureHostStorage(t.Context(), "local", 600); err != nil {
		t.Fatal(err)
	}
	created, _ := reserveAll(t, c, owner, "host", agentInputs("host", 2, 1, 256, 256))
	if created != 2 {
		t.Fatal("room for two volumes", created)
	}
	if _, err := c.Reserve(t.Context(), owner, "host-full", agentInputs("full", 1, 1, 256, 256)[0]); !errors.Is(err, ErrStorageCapacity) {
		t.Fatal("the host's storage was overcommitted", err)
	}
	if n := countWhere(t, l.s, "SELECT count(*) FROM agents WHERE tenant_id=$1", l.org.ID); n != 2 {
		t.Fatal("a refused creation reserved an agent", n)
	}
}

// activateTenantAgentOn creates and activates an agent of the lab's
// organization on host, as the worker of that host would.
func activateTenantAgentOn(t *testing.T, l *tenantLab, owner Principal, name, host string) string {
	t.Helper()
	c, err := NewAgentCatalog(l.a, host)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.s.ConfigureHostStorage(t.Context(), host, 4096); err != nil {
		t.Fatal(err)
	}
	r, err := c.Reserve(t.Context(), owner, "activate-"+name, tenantAgentInput(name))
	var created AgentCreation
	if err != nil || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("reserve", err)
	}
	jobs, err := l.s.PendingProvisioning(t.Context(), host, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID == created.AgentID {
			observeTestVolume(t, l.s, e)
			retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
			if err = l.s.ActivateProvisionedAgent(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			return created.AgentID
		}
	}
	t.Fatal("reservation not discoverable")
	return ""
}

// runVM boots agent for work on host, as the worker does: claim, then confirm.
func runVM(t *testing.T, s *Store, agent, host string) Placement {
	t.Helper()
	p, err := s.ClaimPlacement(t.Context(), agent, host, "worker-"+host, time.Minute)
	if err != nil {
		t.Fatal("boot", agent, err)
	}
	p.VMID = fmt.Sprintf("vm-%016x", p.Generation)
	if err = s.ConfirmPlacement(t.Context(), agent, host, "worker-"+host, p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	return p
}

func stopVM(t *testing.T, s *Store, p Placement) {
	t.Helper()
	if err := s.BeginPlacementStop(t.Context(), p.AgentID, p.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.ObservePlacementStopped(t.Context(), p.AgentID, p.HostID, p.Generation, false); err != nil {
		t.Fatal(err)
	}
}

// Concurrent boots of one organization's agents, on one host or two, never
// exceed its active VMs, vCPUs or RAM. The boot's reservation itself is
// refused, typed. A boot only for a barrier is neither refused nor counted,
// and a stop gives the room back.
func TestConcurrentBootsNeverExceedTheOrganizationsQuotas(t *testing.T) {
	l, c, owner := agentLab(t)
	hosts := map[string]string{}
	for i := range 4 {
		hosts[activateTenantAgent(t, l, c, owner, fmt.Sprintf("near-%d", i))] = "local"
	}
	for i := range 3 {
		hosts[activateTenantAgentOn(t, l, owner, fmt.Sprintf("far-%d", i), "far")] = "far"
	}
	// Another organization's running VM counts only for its own.
	other := createTestOrganization(t, l.a, l.platform, "quota-other")
	for _, q := range []string{`INSERT INTO agents(id,tenant_id,discoverable,inbound_mode) VALUES('foreign-vm',$1,false,'manual')`,
		`INSERT INTO agent_specs(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start)
          SELECT 'foreign-vm','foreign',release_id,'local',8,8192,64,false FROM agent_specs WHERE $1<>'' LIMIT 1`,
		`INSERT INTO agent_placements(agent_id,host_id,state,generation,vm_id) SELECT 'foreign-vm','local','RUNNING',1,'vm-foreign' WHERE $1<>''`} {
		if _, err := l.s.pool.Exec(t.Context(), q, other.ID); err != nil {
			t.Fatal(err)
		}
	}
	boot := func() (map[string]Placement, []string) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		started, refused := map[string]Placement{}, []string{}
		for id, host := range hosts {
			wg.Go(func() {
				p, err := l.s.ClaimPlacement(t.Context(), id, host, "worker-"+host, time.Minute)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					started[id] = p
				} else if q := quotaRefusal(err); q != "" {
					refused = append(refused, q)
				} else {
					t.Error("boot failed otherwise", id, err)
				}
			})
		}
		wg.Wait()
		return started, refused
	}
	stopAll := func(started map[string]Placement) {
		for _, p := range started {
			stopVM(t, l.s, p)
		}
	}
	quotaRow(t, l.s, l.org.ID, OrganizationQuotas{MaxActiveVMs: ref(3)})
	started, refused := boot()
	if len(started) != 3 || len(refused) != 4 || !allAre(refused, "max_active_vms") {
		t.Fatal("the active VMs quota was exceeded or refused untyped", len(started), refused)
	}
	if n := countWhere(t, l.s, `SELECT count(*) FROM agent_placements p JOIN agents a ON a.id=p.agent_id
        WHERE a.tenant_id=$1 AND p.state<>'STOPPED'`, l.org.ID); n != 3 {
		t.Fatal("refused boots reserved a VM", n)
	}
	// A barrier boots an agent the quota holds back, and takes no room.
	var held string
	for id := range hosts {
		if _, ok := started[id]; !ok {
			held = id
			break
		}
	}
	fence, err := l.s.ClaimFencePlacement(t.Context(), held, hosts[held], "fencer", time.Minute)
	if err != nil || !fence.FenceOnly {
		t.Fatal("the quota refused a barrier", err)
	}
	stopVM(t, l.s, fence)
	// A stop gives its room back.
	for id, p := range started {
		stopVM(t, l.s, p)
		delete(started, id)
		break
	}
	if _, err = l.s.ClaimPlacement(t.Context(), held, hosts[held], "worker-"+hosts[held], time.Minute); err != nil {
		t.Fatal("a stop did not give its room back", err)
	}
	if p, err := l.s.ClaimPlacement(t.Context(), held, hosts[held], "worker-"+hosts[held], time.Minute); err != nil || p.State != "STARTING" {
		t.Fatal("asking again for its own boot was refused", err)
	}
	stopAll(started)
	stopVM(t, l.s, Placement{AgentID: held, HostID: hosts[held], Generation: placementOf(t, l.s, held).Generation})

	// RAM and vCPUs: each agent has 1 vCPU and 256 MiB.
	quotaRow(t, l.s, l.org.ID, OrganizationQuotas{MaxMemoryMiB: ref(int64(600))})
	started, refused = boot()
	if len(started) != 2 || len(refused) != 5 || !allAre(refused, "max_memory_mib") {
		t.Fatal("the RAM quota was exceeded", len(started), refused)
	}
	stopAll(started)
	quotaRow(t, l.s, l.org.ID, OrganizationQuotas{MaxVCPUs: ref(4)})
	started, refused = boot()
	if len(started) != 4 || len(refused) != 3 || !allAre(refused, "max_vcpus") {
		t.Fatal("the vCPU quota was exceeded", len(started), refused)
	}
}

func placementOf(t *testing.T, s *Store, agent string) Placement {
	t.Helper()
	p, err := scanPlacement(s.pool.QueryRow(t.Context(), `SELECT `+placementColumns+` FROM agent_placements WHERE agent_id=$1`, agent))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Work that needs a VM past its organization's quota waits in its host's
// capacity queue (ADR 017), QUEUED, without holding back other
// organizations' work; within the organization, newer work does not overtake
// older. When the organization's VM stops, its oldest waiter boots.
func TestWorkWaitsForItsOrganizationsQuotaWithoutHoldingBackOthers(t *testing.T) {
	il := newInvocationLab(t)
	il.busy(t)
	busy := runVM(t, il.s, il.agent, "local")
	x1 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "x1")
	x2 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "x2")
	il.foreignAgent(t, "y1")
	quotaRow(t, il.s, il.org.ID, OrganizationQuotas{MaxActiveVMs: ref(1)})
	il.wake(t, x1, "wake-x1")
	il.wake(t, x2, "wake-x2")

	// The host has room; the organization has none, and its one VM computes.
	if d := il.admit(t, x1, []string{il.agent}, 3); d.Admit || d.Quota != "max_active_vms" || len(d.EvictForQuota) != 0 {
		t.Fatal("work booted past its organization's quota, or a computing VM was stopped", d)
	}
	v, err := il.c.GetTenantAgent(t.Context(), il.owner, x1)
	if err != nil || v.State != "QUEUED" || v.QueueReason == nil || *v.QueueReason != "organization_quota" {
		t.Fatal("work waiting for its organization's quota is not shown so", v, err)
	}
	// Another organization's newer work is not held back.
	if d := il.admit(t, "y1", []string{il.agent}, 3); !d.Admit || d.Evict != "" || len(d.EvictForQuota) != 0 {
		t.Fatal("a waiter for its organization's quota held back another organization", d)
	}
	il.taken(t, "y1")
	// Within the organization, newer work waits behind older.
	if d := il.admit(t, x2, []string{il.agent, "y1"}, 2); d.Admit || d.Quota != "max_active_vms" {
		t.Fatal("work booted past its organization's quota", d)
	}
	if got := il.waiters(t); !sameOrder(got, []string{x1, x2}) {
		t.Fatal("waiters not in arrival order", got)
	}
	// The operator's capacity metrics count only work that waits for the host.
	if n, oldest, err := il.s.CapacityQueue(t.Context(), "local"); err != nil || n != 0 || oldest != 0 {
		t.Fatal("waits for a quota counted as waits for the host", n, oldest, err)
	}
	if n, err := il.s.QuotaWaits(t.Context(), "local"); err != nil || n != 2 {
		t.Fatal("waits for a quota", n, err)
	}
	// The organization's VM stops: each pass offers the room to its oldest
	// waiter first, and that waiter boots first.
	if err = il.s.DiscoverWork(t.Context(), "local", 64); err != nil {
		t.Fatal(err)
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE worker_jobs SET available_at=clock_timestamp()+interval '1 hour' WHERE kind='lifecycle'"); err != nil {
		t.Fatal(err)
	}
	stopVM(t, il.s, busy)
	if err = il.s.PromoteCapacityHead(t.Context(), "local"); err != nil {
		t.Fatal(err)
	}
	var x1Now, x2Now bool
	if err = il.s.pool.QueryRow(t.Context(), `SELECT
        coalesce(bool_or(available_at<=clock_timestamp()) FILTER (WHERE agent_id=$1),false),
        coalesce(bool_or(available_at<=clock_timestamp()) FILTER (WHERE agent_id=$2),false) FROM worker_jobs WHERE kind='lifecycle'`, x1, x2).Scan(&x1Now, &x2Now); err != nil {
		t.Fatal(err)
	}
	if !x1Now || x2Now {
		t.Fatal("the organization's oldest waiter was not offered its room, or the wrong one", x1Now, x2Now)
	}
	if d := il.admit(t, x2, []string{"y1"}, 2); d.Admit {
		t.Fatal("newer work overtook its organization's older waiter", d)
	}
	if d := il.admit(t, x1, []string{"y1"}, 2); !d.Admit {
		t.Fatal("the organization's oldest waiter did not get its room", d)
	}
	il.taken(t, x1)
	if got := il.waiters(t); !sameOrder(got, []string{x2}) {
		t.Fatal("waiters", got)
	}
	// Without quotas the organization's work competes for the host only.
	if _, err = il.s.pool.Exec(t.Context(), "DELETE FROM organization_quotas"); err != nil {
		t.Fatal(err)
	}
	if d := il.admit(t, x2, []string{"y1"}, 2); !d.Admit || d.Quota != "" {
		t.Fatal("a removed quota still holds work back", d)
	}
}

// activateWith creates and activates an agent of the lab's organization with
// the given resources.
func activateWith(t *testing.T, l *tenantLab, c *AgentCatalog, owner Principal, name string, r AgentResources) string {
	t.Helper()
	in := tenantAgentInput(name)
	in.Resources = r
	res, err := c.Reserve(t.Context(), owner, "activate-"+name, in)
	var created AgentCreation
	if err != nil || json.Unmarshal(res.Body, &created) != nil {
		t.Fatal("reserve", err)
	}
	jobs, err := l.s.PendingProvisioning(t.Context(), "local", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID == created.AgentID {
			observeTestVolume(t, l.s, e)
			retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
			if err = l.s.ActivateProvisionedAgent(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			return created.AgentID
		}
	}
	t.Fatal("reservation not discoverable")
	return ""
}

// The organization's oldest waiter stops the organization's own VMs on its
// host that are not computing, as work does for a full host (ADR 017): idle
// ones first, the least recently active first, as many as its RAM needs.
// Stopping them frees the host's slots too. It never stops a computing VM;
// when what it may stop is not enough, it waits and stops nothing.
func TestWorkStopsItsOrganizationsIdleVMsForItsQuota(t *testing.T) {
	il := newInvocationLab(t)
	il.busy(t)
	runVM(t, il.s, il.agent, "local")
	i1 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "i1")
	i2 := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "i2")
	big := activateWith(t, il.tenantLab, il.c, il.owner, "big", AgentResources{1, 512, 64})
	runVM(t, il.s, i1, "local")
	runVM(t, il.s, i2, "local")
	il.wake(t, big, "wake-big")
	running := []string{il.agent, i1, i2}

	quotaRow(t, il.s, il.org.ID, OrganizationQuotas{MaxActiveVMs: ref(3)})
	if d := il.admit(t, big, running, 5); !d.Admit || d.Evict != "" || !sameOrder(d.EvictForQuota, []string{i1}) {
		t.Fatal("not the organization's least recently active idle VM", d)
	}
	// A full host: the organization's own stop gives the slot too.
	if d := il.admit(t, big, running, 0); !d.Admit || d.Evict != "" || !sameOrder(d.EvictForQuota, []string{i1}) {
		t.Fatal("a stop for the quota did not count as a free slot", d)
	}
	// 3 x 256 MiB run; big needs 512 MiB of 900: one stop is not enough.
	quotaRow(t, il.s, il.org.ID, OrganizationQuotas{MaxMemoryMiB: ref(int64(900))})
	if d := il.admit(t, big, running, 5); !d.Admit || !sameOrder(d.EvictForQuota, []string{i1, i2}) {
		t.Fatal("not enough of the organization's VMs stopped for its RAM", d)
	}
	// i2 computes now: what may stop is not enough, so nothing stops.
	il.computing(t, i2)
	if d := il.admit(t, big, running, 5); d.Admit || d.Quota != "max_memory_mib" || len(d.EvictForQuota) != 0 {
		t.Fatal("a computing VM was stopped, or a useless stop was made", d)
	}
}

// A change of quotas and a creation that race never leave an agent that alone
// needs more than its organization may run: one of them is refused.
func TestQuotaChangesAndCreationsNeverLeaveAnAgentThatCannotBoot(t *testing.T) {
	l, c, owner := agentLab(t)
	for i := range 6 {
		var wg sync.WaitGroup
		var setErr, createErr error
		wg.Go(func() {
			_, setErr = setQuotas(t, l, fmt.Sprintf("race-%d", i), OrganizationQuotas{MaxMemoryMiB: ref(int64(256))})
		})
		wg.Go(func() {
			_, createErr = c.Reserve(t.Context(), owner, fmt.Sprintf("race-%d", i), agentInputs(fmt.Sprintf("race-%d", i), 1, 1, 512, 64)[0])
		})
		wg.Wait()
		switch {
		case setErr == nil && quotaRefusal(createErr) == "max_memory_mib":
		case createErr == nil && errors.Is(setErr, ErrQuotaBelowAgent):
		default:
			t.Fatal("both or neither took effect", setErr, createErr)
		}
		if _, err := l.s.pool.Exec(t.Context(), "DELETE FROM organization_quotas"); err != nil {
			t.Fatal(err)
		}
		if _, err := l.s.pool.Exec(t.Context(), "UPDATE agents SET phase='DELETED' WHERE tenant_id=$1", l.org.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func setQuotas(t *testing.T, l *tenantLab, key string, q OrganizationQuotas) (APIReceipt, error) {
	t.Helper()
	return l.a.SetOrganizationQuotas(t.Context(), l.platform, l.org.ID, key, q)
}

// The platform operator sets an organization's quotas; the organization reads
// them and its usage, and sees the change in its trail. Its own owner cannot
// raise them. A quota below current usage is accepted and refuses only what
// comes next; one below what an agent alone needs is refused.
func TestThePlatformSetsAnOrganizationsQuotas(t *testing.T) {
	l, c, owner := agentLab(t)
	runVM(t, l.s, activateTenantAgent(t, l, c, owner, "first"), "local")
	activateWith(t, l, c, owner, "second", AgentResources{2, 512, 128})
	// Another organization's agent and VM are not in these numbers (ISO-6).
	other := createTestOrganization(t, l.a, l.platform, "quota-neighbour")
	for _, q := range []string{`INSERT INTO agents(id,tenant_id,discoverable,inbound_mode) VALUES('neighbour-vm',$1,false,'manual')`,
		`INSERT INTO agent_specs(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start)
          SELECT 'neighbour-vm','neighbour',release_id,'local',8,8192,64,false FROM agent_specs WHERE $1<>'' LIMIT 1`,
		`INSERT INTO agent_placements(agent_id,host_id,state,generation,vm_id) SELECT 'neighbour-vm','local','RUNNING',1,'vm-neighbour' WHERE $1<>''`} {
		if _, err := l.s.pool.Exec(t.Context(), q, other.ID); err != nil {
			t.Fatal(err)
		}
	}

	st, err := l.a.OrganizationQuotaStatus(t.Context(), l.platform, l.org.ID)
	want := OrganizationUsage{Agents: 2, StorageMiB: 384, ActiveVMs: 1, VCPUs: 1, MemoryMiB: 256}
	if err != nil || st.Limits != (OrganizationQuotas{}) || st.UpdatedAt != nil || st.Usage != want {
		t.Fatal("no limit by default, and the usage", st, err)
	}
	// The organization's owner holds quota:manage for its own limits, not for these.
	if _, err = l.a.SetOrganizationQuotas(t.Context(), owner, l.org.ID, "owner", OrganizationQuotas{MaxAgents: ref(100)}); !errors.Is(err, ErrForbidden) {
		t.Fatal("an organization set its own quotas", err)
	}
	if _, err = l.a.OrganizationQuotaStatus(t.Context(), owner, l.org.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("an organization read the operator's route", err)
	}
	for _, bad := range []OrganizationQuotas{{MaxAgents: ref(0)}, {MaxActiveVMs: ref(-1)}, {MaxVCPUs: ref(1000001)},
		{MaxMemoryMiB: ref(int64(127))}, {MaxStorageMiB: ref(int64(63))}, {MaxStorageMiB: ref(int64(1) << 41)}} {
		if _, err = setQuotas(t, l, "bad", bad); !errors.Is(err, ErrInput) {
			t.Fatal("an invalid quota was accepted", bad, err)
		}
	}
	// "second" needs 2 vCPUs and 512 MiB: it could never boot under less.
	for name, q := range map[string]OrganizationQuotas{"max_vcpus": {MaxVCPUs: ref(1)}, "max_memory_mib": {MaxMemoryMiB: ref(int64(256))}} {
		var below *QuotaBelowAgentError
		if _, err = setQuotas(t, l, "below-"+name, q); !errors.As(err, &below) || below.Quota != name || !errors.Is(err, ErrQuotaBelowAgent) {
			t.Fatal("a quota below an agent's own need was accepted", name, err)
		}
	}
	// Below current usage: accepted; the next creation is refused.
	q := OrganizationQuotas{MaxAgents: ref(2), MaxActiveVMs: ref(1), MaxVCPUs: ref(2), MaxMemoryMiB: ref(int64(512)), MaxStorageMiB: ref(int64(4096))}
	r, err := setQuotas(t, l, "set", q)
	var got OrganizationQuotas
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &got) != nil || !sameQuotas(got, q) {
		t.Fatal("set", err, string(r.Body))
	}
	if _, err = c.Reserve(t.Context(), owner, "third", tenantAgentInput("third")); quotaRefusal(err) != "max_agents" {
		t.Fatal("a creation past the agents quota", err)
	}
	st, err = l.a.CurrentOrganizationQuotas(t.Context(), owner)
	if err != nil || !sameQuotas(st.Limits, q) || st.UpdatedAt == nil || st.Usage != want || st.OrganizationID != l.org.ID {
		t.Fatal("the organization's view", st, err)
	}
	// A replay changes nothing; the same values under another key are an
	// unchanged act; new values are a change. Only changes show in the trail.
	if r, err = setQuotas(t, l, "set", q); err != nil || !r.Replayed {
		t.Fatal("replay", err)
	}
	if _, err = setQuotas(t, l, "same", q); err != nil {
		t.Fatal(err)
	}
	if _, err = setQuotas(t, l, "none", OrganizationQuotas{}); err != nil {
		t.Fatal(err)
	}
	if n := countWhere(t, l.s, "SELECT count(*) FROM organization_audit WHERE tenant_id=$1 AND action='organization.quotas_set'", l.org.ID); n != 3 {
		t.Fatal("audit rows", n)
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	shown := 0
	for _, e := range page.Items {
		if e.Action == "organization.quotas_set" {
			shown++
		}
	}
	if shown != 2 {
		t.Fatal("the organization's trail does not show each change once", shown)
	}
	if _, err = c.Reserve(t.Context(), owner, "third", tenantAgentInput("third")); err != nil {
		t.Fatal("removed quotas still refuse", err)
	}
	if _, err = l.a.SetOrganizationQuotas(t.Context(), l.platform, "org_missing", "missing", q); !errors.Is(err, ErrNotFound) {
		t.Fatal("quotas of an unknown organization", err)
	}
}
