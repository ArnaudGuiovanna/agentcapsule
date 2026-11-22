package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A model call's route is resolved without a row lock (FIX-2): it no longer
// waits for a provider's rotation or disabling in flight, nor makes them
// wait. The reservation is what keeps ADR 011's guarantees: it holds the
// organization's row FOR KEY SHARE, which the change's FOR UPDATE excludes,
// and reads the alias and the provider again (L-08). A route resolved while
// the change was in flight is then never used: a disabled provider refuses
// the call, a rotated credential is resolved again. Until then the
// resolution took FOR SHARE on the alias and the provider on every call,
// which conflicts with the change's plain UPDATEs.
func TestAModelCallResolvesItsRouteWithoutWaitingForAProviderChange(t *testing.T) {
	b := newBudgetLab(t)
	ctx := t.Context()
	tenant := b.owner.TenantID
	other := createProvider(t, b.tenantLab, b.owner, "bp2")
	if _, err := b.a.CreateLLMAlias(ctx, b.owner, "al2", CreateLLMAliasInput{Alias: "slow", ProviderID: other.ID, UpstreamModel: "m",
		InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
		t.Fatal(err)
	}
	var fast string
	if err := b.s.pool.QueryRow(ctx, `SELECT provider_id FROM llm_model_aliases WHERE tenant_id=$1 AND alias='fast'`, tenant).Scan(&fast); err != nil {
		t.Fatal(err)
	}
	amounts := llmAmounts{Operation: LLMChat, Input: 5, Output: 5}
	for _, change := range []struct {
		name, alias, provider string
		statements            []string
		want                  error
	}{
		// DisableLLMProvider's statements, and RotateLLMProviderSecret's.
		{"disable", "slow", other.ID, []string{
			`UPDATE llm_providers SET status='disabled',disabled_at=clock_timestamp(),secret_ciphertext='\x'::bytea WHERE tenant_id=$1 AND id=$2`,
			`UPDATE llm_model_aliases SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND provider_id=$2 AND status='active'`,
		}, ErrNotFound},
		{"rotation", "fast", fast, []string{
			`UPDATE llm_providers SET secret_generation=secret_generation+1,rotated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`,
		}, errLLMRouteChanged},
	} {
		// The change in flight, as its administrator's transaction makes it:
		// the organization's row FOR UPDATE, then plain UPDATEs.
		admin, err := b.s.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, tenant); err != nil {
			t.Fatal(err)
		}
		for _, q := range change.statements {
			if _, err = admin.Exec(ctx, q, tenant, change.provider); err != nil {
				t.Fatal(change.name, q, err)
			}
		}
		short, cancel := context.WithTimeout(ctx, 2*time.Second)
		started := time.Now()
		route, err := b.a.ResolveLLMRoute(short, tenant, change.alias)
		cancel()
		if err != nil {
			rollback(admin)
			t.Fatalf("%s: the resolution waited for the change in flight: %v after %v", change.name, err, time.Since(started))
		}
		// The reservation waits for it, and then refuses the route.
		reserved := make(chan error, 1)
		go func() {
			_, err := b.a.reserveLLM(context.Background(), tenant, b.agent, change.alias, "key-"+change.name, amounts, &route)
			reserved <- err
		}()
		select {
		case err = <-reserved:
			rollback(admin)
			t.Fatal(change.name, ": the reservation did not wait for the change in flight:", err)
		case <-time.After(300 * time.Millisecond):
		}
		if err = admin.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-reserved; !errors.Is(err, change.want) {
			t.Fatal(change.name, ": a route resolved before the change was used:", err)
		}
	}
	if n := b.usageRows(t); n != 0 {
		t.Fatal("a refused route reserved", n)
	}
	// The next call sees the disabled provider at once.
	if _, err := b.a.ResolveLLMRoute(ctx, tenant, "slow"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a disabled provider's alias resolved", err)
	}
}
