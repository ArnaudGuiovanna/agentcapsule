package controlplane

import (
	"errors"
	"testing"
)

// The worker names an agent on SLIM by its organization, and lets only
// deliveries between agents wait for the bridge: it reads the kind of the
// next pending delivery.
func TestTheWorkerReadsAnAgentsOrganizationAndNextDelivery(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	tenant, err := il.s.AgentOrganization(ctx, il.agent)
	if err != nil || tenant == "" || tenant != il.owner.TenantID {
		t.Fatal("organization", tenant, err)
	}
	if _, err = il.s.AgentOrganization(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if kind, err := il.s.HeadKind(ctx, il.agent); err != nil || kind != "" {
		t.Fatal("nothing pending", kind, err)
	}
	alice := il.invoker(t, "alice")
	if _, _, err = il.create(t, alice, "k1", "hello"); err != nil {
		t.Fatal(err)
	}
	if kind, err := il.s.HeadKind(ctx, il.agent); err != nil || kind != "instruction" {
		t.Fatal("an invocation is pending", kind, err)
	}
}
