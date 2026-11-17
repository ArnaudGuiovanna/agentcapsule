//go:build linux && cgo

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// clear-agent-failure (ADR 012) lets a FAILED agent boot again with a new
// restart budget: it removes the agent's failure and the failures that
// spent its budget, says when the agent was not FAILED, names an unknown
// agent, and touches no other agent.
func TestClearAgentFailureCommand(t *testing.T) {
	s, db := operatorDatabase(t)
	ctx := t.Context()
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x46}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(ctx, "failure-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewAgentCatalog(accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	ref := controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}
	if _, err = s.RegisterLocalRelease(ctx, ref, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(ctx, "local", 4096); err != nil {
		t.Fatal(err)
	}
	agents := map[string]string{}
	for _, name := range []string{"failed", "other"} {
		r, err := accounts.CreateUser(ctx, admin, "owner-"+name, controlplane.CreateUserInput{DisplayName: "Owner"})
		var owner controlplane.User
		if err != nil || json.Unmarshal(r.Body, &owner) != nil {
			t.Fatal(err)
		}
		r, err = catalog.Reserve(ctx, admin, "agent-"+name, controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: name, Harness: ref,
			Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 64}})
		var created controlplane.AgentCreation
		if err != nil || json.Unmarshal(r.Body, &created) != nil {
			t.Fatal(name, err)
		}
		agents[name] = created.AgentID
		// Its guest failed five times at boot: the budget is spent.
		for generation := 1; generation <= 5; generation++ {
			if _, err = db.Exec(ctx, "INSERT INTO guest_failures(agent_id,generation,kind) VALUES($1,$2,'boot')", created.AgentID, generation); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.Exec(ctx, "INSERT INTO failed_agents(agent_id,reason,failures) VALUES($1,'boot_failed',5)", created.AgentID); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table, agent string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE agent_id=$1", agent).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, args := range [][]string{{"clear-agent-failure"}, {"clear-agent-failure", "-agent-id", agents["failed"], "extra"}} {
		if out, code := trimmed(t, args...); code != 1 || out != "configuration_required" {
			t.Fatal(args, out, code)
		}
	}
	if count("failed_agents", agents["failed"]) != 1 {
		t.Fatal("a refused command cleared the failure")
	}
	if out, code := trimmed(t, "clear-agent-failure", "-agent-id", agents["failed"]); code != 0 || out != "agent_failure_cleared" {
		t.Fatal("clear", out, code)
	}
	if count("failed_agents", agents["failed"]) != 0 || count("guest_failures", agents["failed"]) != 0 {
		t.Fatal("the agent is still FAILED, or keeps its spent budget")
	}
	if count("failed_agents", agents["other"]) != 1 || count("guest_failures", agents["other"]) != 5 {
		t.Fatal("another agent's failure was cleared")
	}
	if out, code := trimmed(t, "clear-agent-failure", "-agent-id", agents["failed"]); code != 0 || out != "agent_not_failed" {
		t.Fatal("clear again", out, code)
	}
	if out, code := trimmed(t, "clear-agent-failure", "-agent-id", "agt_"+strings.Repeat("0", 32)); code != 1 || out != "clear_agent_failure_rejected_not_found" {
		t.Fatal("unknown agent", out, code)
	}
}
