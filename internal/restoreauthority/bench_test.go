//go:build linux && cgo

package restoreauthority

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The micro-benchmarks of the v0.1.0 audit's S-01, S-15 and P-10
// (docs/adr/006-authority-service.md, "Changes after the v0.1.0 audit").
// They run against the release before the audit too: each measures its own
// release's boot synchronization, and holds through the functions both have.
//
//	go test -run '^$' -bench . -benchtime 20x ./internal/restoreauthority/

// hasScopes reports whether this release records the subjects' scopes.
func hasScopes(b *testing.B, c *Catalog) bool {
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='revocation_scopes'").Scan(&n); err != nil {
		b.Fatal(err)
	}
	return n == 1
}

// revokeElsewhere records n subjects of another organization's store in one
// transaction, as many revocations would have.
func revokeElsewhere(b *testing.B, c *Catalog, n int, store string) {
	scopes := hasScopes(b, c)
	tx, err := c.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	var revision uint64
	if err = tx.QueryRow("SELECT revision FROM authority").Scan(&revision); err != nil {
		b.Fatal(err)
	}
	for i := range n {
		revision++
		subject := fmt.Sprintf("event/%s-%08d", store, i)
		if _, err = tx.Exec("INSERT INTO revocations VALUES(?,?)", subject, revision); err != nil {
			b.Fatal(err)
		}
		if scopes {
			if _, err = tx.Exec("INSERT INTO revocation_scopes VALUES(?,?,?)", subject, store, revision); err != nil {
				b.Fatal(err)
			}
		}
	}
	if _, err = tx.Exec("UPDATE authority SET revision=?", revision); err != nil {
		b.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

// bootSync is the catalogue's part of one boot's synchronization, as the
// worker of each release runs it: before the audit it began every subject of
// PostgreSQL's catalogue, then scanned the whole catalogue; after, it scans
// the store's scope above its acknowledged revision. It returns the number
// of authority calls and of subjects the guest is sent.
func bootSync(b *testing.B, c *Catalog, binding Binding, catalogue []string) (calls, fences int) {
	ctx := b.Context()
	if !hasScopes(b, c) {
		for _, subject := range catalogue {
			if _, err := c.BeginRevocation(ctx, subject); err != nil {
				b.Fatal(err)
			}
			calls++
		}
	}
	for {
		r, err := c.Scan(ctx, binding)
		if err != nil {
			b.Fatal(err)
		}
		fences += len(r.Subjects)
		if err = c.RecordVerifiedFence(ctx, r); err != nil {
			b.Fatal(err)
		}
		calls += 2
		if !r.More {
			return calls, fences
		}
	}
}

// BenchmarkBootSync is the boot of a store with one revocation of its own
// while other organizations' stores hold others: its cost per boot, the
// authority calls and the subjects sent to the guest.
func BenchmarkBootSync(b *testing.B) {
	for _, others := range []int{0, 1000, 10000, 50000} {
		b.Run(fmt.Sprintf("other_subjects=%d", others), func(b *testing.B) {
			c, err := Initialize(b.Context(), b.TempDir()+"/authority", testKeyIdentity)
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			binding, err := c.Register(b.Context(), "store-a", "volume-a")
			if err != nil {
				b.Fatal(err)
			}
			revokeElsewhere(b, c, others, "store-other")
			own := "request/own"
			if hasScopes(b, c) {
				err = c.BeginRevocations(b.Context(), []Scope{{Subject: own, Stores: []string{"store-a"}}})
			} else {
				_, err = c.BeginRevocation(b.Context(), own)
			}
			if err != nil {
				b.Fatal(err)
			}
			// PostgreSQL's catalogue, which the earlier worker began whole.
			catalogue := []string{own}
			for i := range others {
				catalogue = append(catalogue, fmt.Sprintf("event/store-other-%08d", i))
			}
			var calls, fences int
			for b.Loop() {
				// A restored or new incarnation: the store acknowledged nothing.
				b.StopTimer()
				if _, err = c.db.Exec("UPDATE stores SET ack_revision=-1 WHERE id='store-a'"); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				calls, fences = bootSync(b, c, binding, catalogue)
			}
			b.ReportMetric(float64(calls), "authority_calls/boot")
			b.ReportMetric(float64(fences), "guest_fences/boot")
		})
	}
}

// BenchmarkHoldsOnDifferentStores is eight stores' platform calls at once,
// each holding its store's binding for 500 µs, as hold_binding does around
// a VM's platform call. Before the audit every hold kept the single SQLite
// transaction, so they ran one at a time.
func BenchmarkHoldsOnDifferentStores(b *testing.B) {
	c, err := Initialize(b.Context(), b.TempDir()+"/authority", testKeyIdentity)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	const stores = 8
	bindings := make([]Binding, stores)
	for i := range bindings {
		if bindings[i], err = c.Register(b.Context(), fmt.Sprintf("store-%d", i), fmt.Sprintf("volume-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
	for b.Loop() {
		var wg sync.WaitGroup
		for _, binding := range bindings {
			wg.Go(func() {
				if err := c.WithBinding(b.Context(), binding, func() error { time.Sleep(500 * time.Microsecond); return nil }); err != nil {
					b.Error(err)
				}
			})
		}
		wg.Wait()
	}
	b.ReportMetric(stores, "holds/op")
}

// BenchmarkOutcomeDuringAnotherStoresKeyHold is the latency of one
// delivery's outcome record on store b while store a holds its key for
// 100 ms, as a boot's unlock does (up to max_key_hold, 2 minutes).
func BenchmarkOutcomeDuringAnotherStoresKeyHold(b *testing.B) {
	c, err := Initialize(b.Context(), b.TempDir()+"/authority", testKeyIdentity)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	held, err := c.Register(b.Context(), "store-a", "volume-a")
	if err != nil {
		b.Fatal(err)
	}
	other, err := c.Register(b.Context(), "store-b", "volume-b")
	if err != nil {
		b.Fatal(err)
	}
	i := 0
	for b.Loop() {
		b.StopTimer()
		entered, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- c.WithBinding(b.Context(), held, func() error { close(entered); time.Sleep(100 * time.Millisecond); return nil })
		}()
		<-entered
		b.StartTimer()
		i++
		if err := c.RecordOutcome(b.Context(), other, Outcome{ID: fmt.Sprintf("outcome-%d", i), Digest: [32]byte{1}}); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// BenchmarkDeliveryCalls is the authority's part of one delivery: the binding
// check before the guest call and the outcome record after it, on one store.
func BenchmarkDeliveryCalls(b *testing.B) {
	c, err := Initialize(b.Context(), b.TempDir()+"/authority", testKeyIdentity)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	binding, err := c.Register(b.Context(), "store-a", "volume-a")
	if err != nil {
		b.Fatal(err)
	}
	i := 0
	for b.Loop() {
		i++
		if err := c.WithBinding(b.Context(), binding, func() error { return nil }); err != nil {
			b.Fatal(err)
		}
		if err := c.RecordOutcome(b.Context(), binding, Outcome{ID: fmt.Sprintf("outcome-%d", i), Digest: [32]byte{1}}); err != nil {
			b.Fatal(err)
		}
	}
}
