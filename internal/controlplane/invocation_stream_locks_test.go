package controlplane

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A chunk's transaction does not take its agent's row (P-11): it commits
// while another transaction holds that row, as a submit, a delivery or a
// completion of the same agent does. It used to wait for them, and they for
// it, at every chunk.
func TestAStreamChunkDoesNotWaitForItsAgentsLock(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "unlocked")
	ctx := t.Context()
	holder, err := il.s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(holder)
	if _, err = lockAgents(ctx, holder, il.agent); err != nil {
		t.Fatal(err)
	}
	append, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := il.tr.AppendOutputStreamFromVM(append, vm, op, 1, deltas(1, "while the agent is locked"), DefaultStreamLimits)
	if err != nil || r.Reason != "" || r.Stored != 1 {
		t.Fatal("a chunk waited for its agent's lock", r, err)
	}
}

// The agent's deletion cancels a working invocation before it purges the
// agent's content: a chunk under way when the deletion begins commits before
// the purge, and is purged with the rest (ADR 022 §5.11, recovery.md: content
// goes in the commit of the deletion request). The deletion here runs while a
// transaction holds the invocation's rows, as a chunk's does, and stores a
// payload of the agent.
func TestADeletionPurgesAChunkCommittedDuringIt(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "deleted")
	ctx := t.Context()
	chunk, err := il.s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(chunk)
	var pid int32
	if err = chunk.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = scanStreamState(chunk.QueryRow(ctx, streamStateSelect+` FOR UPDATE OF i,o`, op, il.agent)); err != nil {
		t.Fatal(err)
	}
	agents, err := streamAgent(ctx, chunk, il.agent)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := il.tr.putChunk(ctx, chunk, op+"/1/1", agents[il.agent], alice.ID, []byte(`[{"type":"delta","seq":1,"text":"x"}]`))
	if err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	go func() {
		_, err := il.c.Delete(ctx, il.owner, il.agent, "delete-while-streaming")
		deleted <- err
	}()
	// The deletion waits for the chunk's transaction.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err = il.s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the deletion did not wait for the chunk")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = commit(ctx, chunk); err != nil {
		t.Fatal(err)
	}
	if err = <-deleted; err != nil {
		t.Fatal(err)
	}
	var purged bool
	if err = il.s.pool.QueryRow(ctx, "SELECT ciphertext IS NULL FROM transit_payloads WHERE id=$1", payload.ID).Scan(&purged); err != nil {
		t.Fatal(err)
	}
	if !purged {
		t.Fatal("a chunk committed during the deletion kept its content")
	}
	if st := il.signal(t, vm, op, 1); st == "" {
		t.Fatal("the stream of a deleted agent stays open")
	}
}

// queryCounter counts the statements a pool sends.
type queryCounter struct{ n atomic.Int32 }

func (c *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}
func (c *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Between two checks of its rights, a subscriber reads what is new in one
// statement (P-11): the same state and frames as the full read, which checks
// the rights again in a dozen. It still reads only the requester's own
// invocation of a live agent.
func TestStreamNewsCostOneStatement(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	bob := il.invoker(t, "bob")
	vm := il.vm(t)
	op := il.workingStream(t, alice, vm, "news")
	il.appendTo(t, vm, op, 1, deltas(1, "one", "two"))
	il.appendTo(t, vm, op, 1, deltas(3, "three"))
	ctx := t.Context()
	cfg := il.s.pool.Config().Copy()
	counter := &queryCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	traced := newStore(pool)
	accounts, err := NewAccounts(traced, []byte("a receipt key nothing here reads"))
	if err != nil {
		t.Fatal(err)
	}
	transit, err := NewTransit(traced, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x73}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewAgentCatalogWithTransit(accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	counter.n.Store(0)
	full, err := catalog.ReadOutputStreamPage(ctx, alice, op, 1, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	fullCost := counter.n.Swap(0)
	news, err := catalog.ReadOutputStreamNews(ctx, alice, op, 1, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	if cost := counter.n.Load(); cost != 1 || fullCost < 5 {
		t.Fatal("statements: news", cost, "full read", fullCost)
	}
	if news.State != full.State || news.Attempt != full.Attempt || news.LastSeq != full.LastSeq || len(news.Chunks) != len(full.Chunks) || len(news.Chunks) != 2 ||
		string(news.Chunks[1].Frames) != string(full.Chunks[1].Frames) || news.Chunks[0].FirstSeq != 1 {
		t.Fatalf("news %+v, full read %+v", news, full)
	}
	if empty, err := catalog.ReadOutputStreamNews(ctx, alice, op, 1, 3, 64); err != nil || len(empty.Chunks) != 0 || empty.LastSeq != 3 {
		t.Fatal("nothing new", empty, err)
	}
	if _, err = catalog.ReadOutputStreamNews(ctx, bob, op, 1, 0, 64); err != ErrNotFound {
		t.Fatal("another principal read the stream", err)
	}
	if _, err = il.c.Delete(ctx, il.owner, il.agent, "delete-news"); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.ReadOutputStreamNews(ctx, alice, op, 1, 0, 64); err != ErrNotFound {
		t.Fatal("the stream of a deleted agent", err)
	}
}
