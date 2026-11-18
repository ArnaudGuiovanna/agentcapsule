//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// stuckDeletionBound bounds the deletion of an agent whose harness holds
// its store, from its request to DELETED. The deletion's fence of the
// agent's store is refused when the busy store answers after 5 seconds, or
// at the RPC's 20-second timeout; the stop of the VM takes at most the
// guest's 30-second quiesce and the VMM's forced removal; the restricted
// boot, its fence, the seal, the key's destruction and the volume's
// removal take less than half a minute.
const stuckDeletionBound = 2 * time.Minute

// directoryRecords stands for the Directory behind the publisher: the
// records pushed and not deleted, by CID. The private Directory itself is
// TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord's.
type directoryRecords struct {
	mu      sync.Mutex
	records map[string]bool
}

func (d *directoryRecords) Push(_ context.Context, record []byte) (string, error) {
	sum := sha256.Sum256(record)
	cid := "lab-" + hex.EncodeToString(sum[:16])
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[cid] = true
	return cid, nil
}

func (d *directoryRecords) Delete(_ context.Context, cid string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.records, cid)
	return nil
}

func (d *directoryRecords) holds(cid string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.records[cid]
}

// An owner deletes an agent whose harness never returns from an invocation
// and holds its store (ADR 012, question 7, sub-question 2, option (b)).
// capsule-echo's never-returns behaviour holds the invocation; its first
// attempt ends at the host's timeout and the store stays held. Once the
// deletion is accepted, new work is refused and the agent's Directory
// record is withdrawn; its held invocation is never attempted again. The
// deletion's fence of the agent's store is refused by its guest: the
// worker stops the VM and fences through one restricted boot. Within
// stuckDeletionBound the deletion completes, as
// TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord
// checks it: no VM, no volume, the key revoked and destroyed under the seal
// the authority service holds, no Directory record. The held invocation
// ends canceled (agent_unavailable), and no guest failure is recorded for
// an agent being deleted.
func TestProductWorkerDeletesAnAgentWhoseHarnessNeverAnswers(t *testing.T) {
	l := newRegistryLab(t)
	l.publishBehaviour("1.0.0", "opt/stuck", "never-returns")
	agent := l.create("stuck-deleted", "1.0.0").AgentID
	run := l.runs(1)[agent]
	l.answers(agent, "ordinary", "an ordinary question")
	dir := &directoryRecords{records: map[string]bool{}}
	publisher := &directory.Publisher{Store: l.store, Directory: dir}
	l.request(l.owner(), "PUT", "/v1/agents/"+agent+"/directory", "visible", map[string]any{"visible": true,
		"description": "Holds what it is asked.", "skills": []int{10301}}, 200, nil)
	if _, err := publisher.RunOnce(t.Context()); err != nil {
		t.Fatal("publish", err)
	}
	var entry controlplane.DirectoryEntry
	l.request(l.owner(), "GET", "/v1/agents/"+agent+"/directory", "", nil, 200, &entry)
	if entry.Publication != "published" || entry.RecordCID == nil || !dir.holds(*entry.RecordCID) {
		t.Fatal("the agent's record is not published", entry.Publication, entry.RecordCID)
	}
	cid := *entry.RecordCID
	e, err := l.store.VolumeEnrollment(t.Context(), agent, "local")
	if err != nil {
		t.Fatal(err)
	}
	binding := enrollmentBinding(e)
	volume := filepath.Join(l.root, "volumes", e.VolumeID+".luks")

	t.Log("stage: the harness holds an invocation and its store")
	held := l.invoke(agent, "held", "please never return")
	l.awaitPasses("the held invocation's first attempt", time.Minute, onlyStuckHarness, func() bool {
		var reached bool
		if err := l.db.QueryRow(t.Context(), "SELECT may_have_reached FROM agent_mailboxes WHERE instruction_id=$1", held).Scan(&reached); err != nil {
			t.Fatal(err)
		}
		return reached
	})
	var attempts int
	var state string
	if err = l.db.QueryRow(t.Context(), "SELECT attempts,delivery_state FROM agent_mailboxes WHERE instruction_id=$1", held).Scan(&attempts, &state); err != nil ||
		attempts != 1 || state != "PENDING" {
		t.Fatal("the held invocation before the deletion", attempts, state, err)
	}

	t.Log("stage: the owner deletes the agent: new work refused, the Directory record withdrawn")
	start := time.Now()
	var deletion controlplane.AgentCreation
	l.request(l.owner(), "DELETE", "/v1/agents/"+agent, "delete", nil, 202, &deletion)
	invoke := map[string]any{"content": []map[string]string{{"type": "text", "text": "after the deletion"}}}
	if got := l.statusOf(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "after-delete", invoke); got/100 != 4 {
		t.Fatal("an invocation was admitted after the deletion", got)
	}
	if _, err = publisher.RunOnce(t.Context()); err != nil {
		t.Fatal("publish", err)
	}
	if dir.holds(cid) {
		t.Fatal("the deleted agent's record is still in the Directory")
	}

	t.Log("stage: the deletion stops the VM whose guest refuses its fence, and completes")
	// The held invocation's delivery is refused for an agent being deleted
	// (ErrUnavailable) until the deletion cancels it; any other failure, a
	// refused fence that stopped nothing among them, fails the test.
	l.awaitPasses("the deletion of an agent whose harness holds its store", stuckDeletionBound, onlyProductUnavailable, func() bool {
		var op controlplane.PlatformOperation
		l.request(l.owner(), "GET", "/v1/operations/"+deletion.OperationID, "", nil, 200, &op)
		if op.Status == "FAILED" || op.Status == "CANCELED" {
			t.Fatal("the deletion ended badly", op.Status, op.ErrorCode)
		}
		return op.Status == "SUCCEEDED"
	})
	t.Log("the deletion completed after", time.Since(start))
	var phase string
	if err = l.db.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id=$1", agent).Scan(&phase); err != nil || phase != "DELETED" {
		t.Fatal("the deletion did not include the physical cleanup", phase, err)
	}
	var status, code, delivery string
	if err = l.db.QueryRow(t.Context(), `SELECT o.status,coalesce(o.error_code,''),m.delivery_state FROM platform_operations o
        JOIN agent_mailboxes m ON m.instruction_id=o.id WHERE o.id=$1`, held).Scan(&status, &code, &delivery); err != nil ||
		status != "CANCELED" || code != "agent_unavailable" || delivery != "CANCELED" {
		t.Fatal("the held invocation", status, code, delivery, err)
	}
	if got := l.guestFailures(agent); len(got) != 0 {
		t.Fatal("guest failures recorded for an agent being deleted", got)
	}
	// One restricted boot fenced the store after the stop.
	if g := l.placementGeneration(agent); g != run.Generation+1 {
		t.Fatal("boots after the stop", g, run.Generation)
	}
	l.runs(0)
	if sameProcess(run.PID, run.StartTicks) {
		t.Fatal("the VMM whose guest held its store survived")
	}
	if _, err = os.Lstat(volume); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the deleted agent's volume file remains", err)
	}
	if err = l.keys.WithKey(t.Context(), agent, e.VolumeID, func([]byte) error { t.Error("the deleted key was delivered"); return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the key was not revoked", err)
	}
	if err = l.keys.Ensure(t.Context(), agent, e.VolumeID); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the deleted key could be created again", err)
	}
	if _, err = l.worker.authority.Lookup(t.Context(), agent); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal("the authority service does not hold the store sealed", err)
	}
	stale := binding
	stale.Incarnation++
	if err = l.worker.authority.DestroyKey(t.Context(), stale); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the service destroyed a key under another binding than the sealed one", err)
	}
	if _, err = publisher.RunOnce(t.Context()); err != nil {
		t.Fatal("publish", err)
	}
	if dir.holds(cid) {
		t.Fatal("the deleted agent's record came back to the Directory")
	}
}
