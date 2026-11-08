//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// This fixture uses the actual authenticated server and SQLite transaction.
// Its response proxy can fail the independent authority AFTER the guest commit.
// Host lifecycle/physical isolation is exercised by the separate KVM campaign.
func outcomeClient(t *testing.T, agent string, afterCommit func()) (*capsuleprotocol.Client, *harnessstore.Store) {
	t.Helper()
	h, g, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{AgentID: agent, Incarnation: 1, Generation: 1, VMID: "0123456789abcdef"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	local, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	if err = local.Local(t.Context(), []string{"agent/" + agent}, func(tx harnessstore.SQL) error {
		ctx := t.Context()
		_, err := tx.ExecContext(ctx, "CREATE TABLE effects(id TEXT PRIMARY KEY, value BLOB NOT NULL)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	handler, err := capsuleprotocol.NewServer(g, capsuleprotocol.ShutdownClean, local, func(ctx context.Context, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		_, err := tx.ExecContext(ctx, "INSERT INTO effects VALUES(?,?)", event.ID, event.Body)
		return []byte(`{"durable":true}`), err
	})
	if err != nil {
		t.Fatal(err)
	}
	var fired atomic.Bool
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded := httptest.NewRecorder()
		handler.ServeHTTP(recorded, r)
		if recorded.Code == http.StatusOK && afterCommit != nil && !fired.Swap(true) {
			afterCommit()
		}
		for k, values := range recorded.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(recorded.Body.Bytes())
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, l, g, proxy) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewClient(h, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, local
}

func readOutcomeJournal(t *testing.T, root, store string) map[string][]byte {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(root, "catalog.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(t.Context(), "SELECT id,digest FROM outcomes WHERE store=?", store)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var id string
		var digest []byte
		if err = rows.Scan(&id, &digest); err != nil {
			t.Fatal(err)
		}
		out[id] = digest
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBusinessOutcomeRequiresIndependentCommit(t *testing.T) {
	for _, invoke := range []bool{false, true} {
		for _, fault := range []string{"none", "outage-before", "outage-after", "reserve-before", "reserve-after", "conflict", "wrong-store"} {
			t.Run(fmt.Sprintf("invoke=%t/%s", invoke, fault), func(t *testing.T) {
				b := newBootLab(t)
				keys := b.keys.Provider.(*keyauthority.Files)
				root := filepath.Join(t.TempDir(), "root")
				a, err := restoreauthority.Initialize(t.Context(), root, keys.Identity())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { a.Close() })
				binding, err := a.Register(t.Context(), b.e.AgentID, b.e.VolumeID)
				if err != nil {
					t.Fatal(err)
				}
				b.w.authority = a
				e := harnessstore.Event{ID: "durable-event", Subjects: []string{"agent/" + b.e.AgentID}, Body: []byte("private effect")}
				if invoke {
					e.Subjects = append(e.Subjects, "event/"+e.ID)
					e.Body, err = json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op", Mandate: capsuleprotocol.InstructionMandate{ID: "mandate", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)}, Content: []capsuleprotocol.TextContent{{Type: "text", Text: "private instruction"}}})
					if err != nil {
						t.Fatal(err)
					}
				}
				id, digest, err := harnessstore.OutcomeFingerprint(b.e.AgentID, e, []byte(`{"durable":true}`))
				if err != nil {
					t.Fatal(err)
				}
				faultResult := make(chan error, 1)
				failure := func() {
					var faultErr error
					if fault == "outage-before" || fault == "outage-after" {
						faultErr = a.Close()
					}
					if fault == "reserve-before" || fault == "reserve-after" {
						_, faultErr = a.ReserveIncarnation(t.Context(), binding, "restore")
					}
					faultResult <- faultErr
				}
				if fault == "outage-before" || fault == "reserve-before" {
					failure()
				}
				if fault == "conflict" {
					if err = a.RecordOutcome(t.Context(), binding, restoreauthority.Outcome{ID: id}); err != nil {
						t.Fatal(err)
					}
				}
				clientAgent := b.e.AgentID
				if fault == "wrong-store" {
					clientAgent = "different-agent"
				}
				client, local := outcomeClient(t, clientAgent, func() {
					if fault == "outage-after" || fault == "reserve-after" {
						failure()
					}
				})
				r, err := b.w.deliverToGuest(t.Context(), b.e.AgentID, client, e, invoke)
				if fault == "outage-before" || fault == "outage-after" || fault == "reserve-before" || fault == "reserve-after" {
					select {
					case faultErr := <-faultResult:
						if faultErr != nil {
							t.Fatal("fault injection", faultErr)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("fault not reached")
					}
				}
				wantErr := error(nil)
				switch fault {
				case "outage-before", "outage-after":
					wantErr = restoreauthority.ErrUnavailable
				case "reserve-before", "reserve-after", "wrong-store":
					wantErr = restoreauthority.ErrStale
				case "conflict":
					wantErr = restoreauthority.ErrConflict
				}
				if !errors.Is(err, wantErr) {
					t.Fatal("wrong outcome", err, wantErr)
				}
				if err != nil && (len(r.Result) != 0 || r.Replayed) {
					t.Fatal("unconfirmed result escaped", r)
				}
				wantEffects := 1
				if fault == "outage-before" || fault == "reserve-before" || fault == "wrong-store" {
					wantEffects = 0
				}
				assertEffects := func() {
					t.Helper()
					if err := local.Local(t.Context(), e.Subjects, func(tx harnessstore.SQL) error {
						ctx := t.Context()
						var n int
						if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects").Scan(&n); err != nil {
							return err
						}
						if n != wantEffects {
							return fmt.Errorf("effects=%d want=%d", n, wantEffects)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				assertEffects()
				journal := readOutcomeJournal(t, root, b.e.AgentID)
				if fault != "none" && fault != "conflict" && len(journal) != 0 {
					t.Fatal("failure published root outcome")
				}
				if fault == "none" || fault == "outage-after" {
					if fault == "outage-after" {
						a, err = restoreauthority.Open(t.Context(), root, a.Identity(), keys.Identity())
						if err != nil {
							t.Fatal(err)
						}
						b.w.authority = a
					}
					r, err = b.w.deliverToGuest(t.Context(), b.e.AgentID, client, e, invoke)
					if err != nil || !r.Replayed || string(r.Result) != `{"durable":true}` {
						t.Fatal("durable retry", r, err)
					}
					assertEffects()
					journal = readOutcomeJournal(t, root, b.e.AgentID)
					if len(journal) != 1 || !bytes.Equal(journal[id], digest[:]) {
						t.Fatal("missing/mismatched durable outcome")
					}
				}
			})
		}
	}
}

func TestPlatformIndependentIdentityGuardsSQLPublication(t *testing.T) {
	b := newBootLab(t)
	a := b.withAuthority(t, true)
	api := platformAPI{store: b.w.store, caller: controlplane.VMCaller{AgentID: b.e.AgentID, HostID: b.e.HostID}, authority: a, incarnation: 1}
	// Test the SQL/root portion directly; the physical admission scope is covered
	// by KVM. The production adapter also validates generation/mandate in SQL.
	if _, err := b.db.Exec(t.Context(), "CREATE TABLE publication_probe(n integer)"); err != nil {
		t.Fatal(err)
	}
	publish := func(ctx context.Context) error {
		_, err := b.db.Exec(ctx, "INSERT INTO publication_probe VALUES(1)")
		return err
	}
	if err := api.withIdentity(t.Context(), publish); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- api.withIdentity(t.Context(), func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return publish(ctx)
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("publication failed to enter", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	_, reserveErr := a.ReserveIncarnation(ctx, enrollmentBinding(b.e), "during-publication")
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(reserveErr, context.DeadlineExceeded) {
		t.Fatal("reservation overtook admitted SQL publication", reserveErr)
	}
	if _, err := a.ReserveIncarnation(t.Context(), enrollmentBinding(b.e), "restore"); err != nil {
		t.Fatal(err)
	}
	if err := api.withIdentity(t.Context(), publish); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("obsolete caller published SQL", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := api.withIdentity(t.Context(), publish); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("unavailable root permitted SQL", err)
	}
	var n int
	if err := b.db.QueryRow(t.Context(), "SELECT count(*) FROM publication_probe").Scan(&n); err != nil || n != 2 {
		t.Fatal("unauthorized SQL effect", n, err)
	}
}
