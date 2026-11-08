package harnessstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var sample = Event{ID: "event-1", Subjects: []string{"agent/a", "agent/b", "request/r1"}, Body: []byte("body")}

func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.db.Exec("CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY, n INTEGER NOT NULL); INSERT OR IGNORE INTO effects VALUES (1, 0)"); err != nil {
		t.Fatal(err)
	}
	return s
}

func increment(ctx context.Context, tx SQL) ([]byte, error) {
	_, err := tx.ExecContext(ctx, "UPDATE effects SET n = n + 1 WHERE id = 1")
	return []byte("saved-result"), err
}

func assertCounts(t *testing.T, s *Store, wantEffects, wantMarkers int) {
	t.Helper()
	var effect, marker int
	if err := s.db.QueryRow("SELECT n FROM effects WHERE id = 1").Scan(&effect); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM capsule_inbox").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if effect != wantEffects || marker != wantMarkers {
		t.Fatalf("effect=%d marker=%d, want %d %d", effect, marker, wantEffects, wantMarkers)
	}
}

func TestConcurrentReplayAcrossIndependentConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	stores := []*Store{openTest(t, path), openTest(t, path), openTest(t, path)}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 18)
	for i := range 18 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := stores[i%3].Apply(t.Context(), sample, increment)
			if err == nil && string(r.Result) != "saved-result" {
				err = fmt.Errorf("wrong replay result: %q", r.Result)
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	assertCounts(t, stores[0], 1, 1)
}

func TestRollbackReplayAndEnvelopeConflict(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "agent.db"))
	failure := errors.New("injected after effect SQL, before commit")
	_, err := s.Apply(t.Context(), sample, func(ctx context.Context, tx SQL) ([]byte, error) {
		if _, err := increment(ctx, tx); err != nil {
			return nil, err
		}
		return nil, failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	assertCounts(t, s, 0, 0)
	if _, err := s.Apply(t.Context(), sample, increment); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []Event{
		{ID: sample.ID, Subjects: sample.Subjects, Body: []byte("different")},
		{ID: sample.ID, Subjects: []string{"agent/a", "agent/c"}, Body: sample.Body},
	} {
		if _, err := s.Apply(t.Context(), changed, increment); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected envelope conflict, got %v", err)
		}
	}
	reordered := sample
	reordered.Subjects = []string{"request/r1", "agent/b", "agent/a", "agent/a"}
	r, err := s.Apply(t.Context(), reordered, increment)
	if err != nil || !r.Replayed || string(r.Result) != "saved-result" {
		t.Fatalf("replay=%+v err=%v", r, err)
	}
	assertCounts(t, s, 1, 1)
}

func TestFenceSurvivesReopenAndRejectsEitherParticipant(t *testing.T) {
	for _, subject := range sample.Subjects {
		t.Run(subject, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.db")
			s := openTest(t, path)
			if err := s.Fence(t.Context(), subject); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s = openTest(t, path)
			if _, err := s.Apply(t.Context(), sample, increment); !errors.Is(err, ErrFenced) {
				t.Fatalf("expected fence rejection, got %v", err)
			}
			assertCounts(t, s, 0, 0)
		})
	}
}

func TestInboxInsertFailureRollsBackEffect(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "agent.db"))
	// Fail the marker statement after the mutation SQL has executed.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_marker BEFORE INSERT ON capsule_inbox
BEGIN SELECT RAISE(ABORT, 'injected inbox write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(t.Context(), sample, increment); err == nil {
		t.Fatal("marker failure was acknowledged")
	}
	assertCounts(t, s, 0, 0)
	if _, err := s.db.Exec("DROP TRIGGER reject_marker"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(t.Context(), sample, increment); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, s, 1, 1)
}

func TestFenceWaitsForEffectTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	effectStore, fenceStore := openTest(t, path), openTest(t, path)
	entered, release := make(chan struct{}), make(chan struct{})
	effectDone, fenceDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := effectStore.Apply(t.Context(), sample, func(ctx context.Context, tx SQL) ([]byte, error) {
			result, err := increment(ctx, tx)
			close(entered)
			<-release
			return result, err
		})
		effectDone <- err
	}()
	<-entered
	go func() { fenceDone <- fenceStore.Fence(t.Context(), "agent/a") }()
	// Force an overlap while SQLite holds the effect's write transaction.
	select {
	case err := <-fenceDone:
		close(release)
		<-effectDone
		t.Fatalf("fence returned before the effect transaction ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-effectDone; err != nil {
		t.Fatal(err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatal(err)
	}
	assertCounts(t, effectStore, 1, 1)
	second := sample
	second.ID = "event-2"
	if _, err := effectStore.Apply(t.Context(), second, increment); !errors.Is(err, ErrFenced) {
		t.Fatalf("late effect was not fenced: %v", err)
	}
	assertCounts(t, effectStore, 1, 1)
}

func TestProcessCrashRecovery(t *testing.T) {
	for _, point := range []string{"before-commit", "after-commit", "fence-committed"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.db")
			s := openTest(t, path)
			s.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashChild$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "CAPSULE_CRASH_POINT="+point, "CAPSULE_CRASH_DB="+path)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			line, readErr := bufio.NewReader(stdout).ReadString('\n')
			killErr := cmd.Process.Kill() // real process crash: no defers or SQLite Close
			waitErr := cmd.Wait()
			if readErr != nil || line != "CRASH-READY\n" || killErr != nil || waitErr == nil {
				t.Fatalf("child: line=%q read=%v kill=%v wait=%v stderr=%s", line, readErr, killErr, waitErr, stderr.String())
			}
			s = openTest(t, path)
			switch point {
			case "fence-committed":
				if _, err := s.Apply(t.Context(), sample, increment); !errors.Is(err, ErrFenced) {
					t.Fatalf("lost committed fence: %v", err)
				}
				assertCounts(t, s, 0, 0)
			default:
				wasCommitted := point == "after-commit"
				want := 0
				if wasCommitted {
					want = 1
				}
				assertCounts(t, s, want, want)
				r, err := s.Apply(t.Context(), sample, increment)
				if err != nil || r.Replayed != wasCommitted {
					t.Fatalf("retry after crash: %+v %v", r, err)
				}
				assertCounts(t, s, 1, 1)
			}
		})
	}
}

func TestCrashChild(t *testing.T) {
	point := os.Getenv("CAPSULE_CRASH_POINT")
	if point == "" {
		return
	}
	s, err := Open(context.Background(), os.Getenv("CAPSULE_CRASH_DB"))
	if err != nil {
		t.Fatal(err)
	}
	crashReady := func() {
		fmt.Println("CRASH-READY")
		for {
			time.Sleep(time.Hour)
		}
	}
	if point == "fence-committed" {
		if err := s.Fence(context.Background(), "agent/a"); err != nil {
			t.Fatal(err)
		}
		crashReady()
	}
	_, err = s.Apply(context.Background(), sample, func(ctx context.Context, tx SQL) ([]byte, error) {
		result, err := increment(ctx, tx)
		if err == nil && point == "before-commit" {
			crashReady()
		}
		return result, err
	})
	if err != nil {
		t.Fatal(err)
	}
	// The SQL commit succeeded, but no protocol ACK was sent to the caller.
	crashReady()
}
