//go:build linux

package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

type retryingImportStore struct {
	harnessImportStore
	job      controlplane.ImportJob
	attempts int
	claimErr error
	cancel   context.CancelFunc
	t        *testing.T
}

func (s *retryingImportStore) ClaimHarnessImport(_ context.Context, worker string, lease time.Duration) (controlplane.ImportJob, error) {
	s.t.Helper()
	if worker != "worker-a" || lease != time.Minute {
		s.t.Fatalf("claim used worker %q, lease %v", worker, lease)
	}
	s.attempts++
	switch s.attempts {
	case 1:
		return controlplane.ImportJob{}, s.claimErr
	case 2:
		return s.job, nil
	default:
		s.t.Fatal("unexpected extra claim")
		return controlplane.ImportJob{}, controlplane.ErrNoWork
	}
}

func (s *retryingImportStore) FailHarnessImport(_ context.Context, job controlplane.ImportJob, code string, transient bool, retryAfter time.Duration) (controlplane.HarnessImport, error) {
	s.t.Helper()
	if job != s.job || code != "storage_pressure" || !transient || retryAfter != time.Minute {
		s.t.Fatalf("failed leased job %q with code %q, transient %v, retry %v", job.ID, code, transient, retryAfter)
	}
	s.cancel()
	return controlplane.HarnessImport{}, nil
}

func TestImportLoopRecoversFromAClaimFailureAndRetriesTheLeasedJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	store := retryingImportStore{t: t, cancel: cancel, claimErr: errors.New("claim interrupted"),
		job: controlplane.ImportJob{ID: "import1", Token: "lease2", Attempt: 2, Reference: "registry.example/acme/harness@sha256:" + strings.Repeat("a", 64)}}
	h := HarnessImporter{store: &store, worker: "worker-a", Lease: time.Minute, cache: t.TempDir(),
		Pressure: func(string) error { return controlplane.ErrStoragePressure }}
	var reported []error
	err := h.Run(ctx, time.Millisecond, func(err error) { reported = append(reported, err) })
	if !errors.Is(err, context.Canceled) || store.attempts != 2 || len(reported) != 1 || !errors.Is(reported[0], store.claimErr) {
		t.Fatalf("loop returned %v after %d claims, reported %v", err, store.attempts, reported)
	}
}
