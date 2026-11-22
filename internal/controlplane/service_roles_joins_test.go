package controlplane

import (
	"slices"
	"testing"
)

// FIX-1: the service roles' analysis sees every table a statement reads: the
// tables of a comma-joined list (FROM a x, b y), and a table joined after one
// without an alias (FROM a JOIN b), whose JOIN it took for the alias. A row
// lock then needs UPDATE on each table it locks, and on no other: FOR SHARE
// OF r,i names harness_releases and system_images, not the tables the same
// function reads elsewhere. Before, it saw only the first table of a list,
// and a lock naming another one fell back to every table read.
func TestTheRoleAnalysisSeesEveryTableAStatementReads(t *testing.T) {
	tables := map[string]bool{}
	for _, table := range []string{"harness_releases", "system_images", "host_system_images", "agents", "organizations", "agent_directory", "worker_jobs"} {
		tables[table] = true
	}
	for _, c := range []struct {
		name     string
		literals []string
		want     []string
	}{
		{"a lock naming the second table of a list", []string{
			`SELECT 1 FROM worker_jobs WHERE id=$1`,
			`SELECT r.id FROM harness_releases r, system_images i WHERE r.id=$1 AND i.id=$2 FOR SHARE OF r,i`},
			[]string{"UPDATE harness_releases", "UPDATE system_images"}},
		{"a list then a join", []string{
			`SELECT r.id FROM harness_releases r,system_images i JOIN host_system_images h USING(kernel_digest) FOR SHARE OF r,i,h`},
			[]string{"UPDATE harness_releases", "UPDATE host_system_images", "UPDATE system_images"}},
		{"a lock of every table read", []string{
			`SELECT 1 FROM agents, organizations o WHERE o.id=$1 FOR UPDATE`},
			[]string{"UPDATE agents", "UPDATE organizations"}},
		{"a join after a table without an alias", []string{
			`SELECT 1 FROM agents JOIN organizations ON organizations.id=agents.tenant_id FOR UPDATE`},
			[]string{"UPDATE agents", "UPDATE organizations"}},
		{"a list in an update", []string{
			`WITH due AS (SELECT agent_id FROM agent_directory LIMIT 1 FOR UPDATE SKIP LOCKED)
        UPDATE agent_directory d SET attempts=1 FROM due, agents a, organizations o WHERE a.id=d.agent_id`},
			[]string{"UPDATE agent_directory", "UPDATE agents", "UPDATE organizations"}},
	} {
		need := map[string]map[string]bool{}
		sqlWrites(c.literals, tables, need)
		if got := flatten(need); !slices.Equal(got, c.want) {
			t.Errorf("%s: derived %v, want %v", c.name, got, c.want)
		}
	}
}
