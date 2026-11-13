//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// outcomeOf is the restore authority's ID of an invocation's outcome: its
// event ID is its mailbox ID.
func (l *registryLab) outcomeOf(agentID, invocationID string) string {
	l.t.Helper()
	var mailbox string
	if err := l.db.QueryRow(l.t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", invocationID).Scan(&mailbox); err != nil {
		l.t.Fatal(err)
	}
	id, _, err := harnessstore.StoredOutcomeFingerprint(agentID, mailbox, [32]byte{}, nil)
	if err != nil {
		l.t.Fatal(err)
	}
	return id
}

// An agent restored on its own host from an archive (REC-02, ADR 003). It
// answers one invocation, is archived on demand, then answers two more. The
// restore stops twice, like a crash, and resumes each time. It installs
// exactly the archive's bytes, boots the image restricted at the new
// incarnation, declares lost exactly the two invocations after the archive,
// maps each to its invocation, and puts the agent back in service. The two
// invocations are then lost, with their old results readable, and run again
// under the same IDs: they complete with lost_at set, at the new
// incarnation, and the restore authority records each rerun. The agent then
// answers a new invocation from a VM of the new incarnation, and the old
// incarnation's fence receipt, identity and placement observation are
// refused.
func TestProductWorkerRestoresAgentFromArchive(t *testing.T) {
	l := newRegistryLab(t)
	l.publish("1.0.0", "opt/echo")
	agent := l.create("restored", "1.0.0").AgentID
	before := l.invoke(agent, "before-archive", "written before the archive")
	l.await("invocation before the archive", true, func() bool { return l.answered(before, "written before the archive") })

	t.Log("stage: archive the volume on demand, then two invocations after the archive")
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archiveID := "arc_" + strings.Repeat("5", 32)
	manifest, err := l.worker.CaptureArchive(t.Context(), agent, archiveID, archives)
	if err != nil {
		t.Fatal(err)
	}
	after := []string{l.invoke(agent, "after-archive-1", "lost in the restore, one"), l.invoke(agent, "after-archive-2", "lost in the restore, two")}
	l.await("invocations after the archive", true, func() bool {
		return l.answered(after[0], "lost in the restore, one") && l.answered(after[1], "lost in the restore, two")
	})
	oldRun := l.runs(1)[agent]
	e, err := l.store.VolumeEnrollment(t.Context(), agent, "local")
	if err != nil || e.Incarnation != 1 || oldRun.Incarnation != 1 || manifest.Binding.Incarnation != 1 {
		t.Fatal("incarnation before the restore", e.Incarnation, oldRun.Incarnation, err)
	}
	oldBinding := enrollmentBinding(e)
	oldReceipt, err := l.worker.authority.Scan(t.Context(), oldBinding)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("stage: restore from the archive, stopped after the install and after the activation")
	restoreID := "rst_" + strings.Repeat("6", 32)
	stopped := errors.New("stopped like a crash")
	stops := map[string]bool{controlplane.RestoreReconciling: true, controlplane.RestoreActivated: true}
	installed := false
	l.worker.afterRestoreStep = func(step string) error {
		if step == controlplane.RestoreReconciling && !installed {
			// Before the restricted boot: the volume holds the archive's bytes.
			plan, err := l.store.VolumeRestoreTarget(t.Context(), restoreID, "local")
			if err != nil {
				return err
			}
			err = l.worker.host.WithStoppedVolume(t.Context(), agent, plan.Placement.Generation, plan.Device, plan.Inode, func(r io.Reader) error {
				h := sha256.New()
				if _, err := io.Copy(h, r); err != nil {
					return err
				}
				if !bytes.Equal(h.Sum(nil), manifest.Digest[:]) {
					return errors.New("the installed volume is not the archive")
				}
				return nil
			})
			if err != nil {
				return err
			}
			installed = true
		}
		if stops[step] {
			delete(stops, step)
			return stopped
		}
		return nil
	}
	var result VolumeRestoreResult
	for attempt := 0; ; attempt++ {
		result, err = l.worker.RestoreFromArchive(t.Context(), restoreID, agent, archiveID, archives)
		if err == nil {
			break
		}
		if !errors.Is(err, stopped) || attempt == 2 {
			t.Fatal("restore", err)
		}
		e, err := l.store.VolumeEnrollment(t.Context(), agent, "local")
		if err != nil || e.Stage != "RESTORING" || e.Incarnation != 2 {
			t.Fatal("a stopped restore put the volume back in service", e.Stage, e.Incarnation, err)
		}
		runs, err := l.worker.Reconcile(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if run, ok := runs[agent]; ok && (!run.FenceOnly || run.Incarnation != 2) {
			t.Fatal("a VM other than the restricted boot of the new incarnation runs", run)
		}
	}
	if !installed || len(stops) != 0 {
		t.Fatal("the restore did not pass both stops", installed, stops)
	}

	t.Log("stage: the losses are exactly the invocations after the archive")
	got := []string{}
	for _, loss := range result.Losses {
		if loss.Incarnation != 2 || loss.MailboxID == "" {
			t.Fatal("loss", loss)
		}
		got = append(got, loss.InvocationID)
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(after))
	if result.Incarnation != 2 || !slices.Equal(got, want) {
		t.Fatal("declared losses", got, want)
	}
	for invocation, status := range map[string]restoreauthority.Status{before: restoreauthority.StatusConfirmed,
		after[0]: restoreauthority.StatusLost, after[1]: restoreauthority.StatusLost} {
		if got, _, err := l.worker.authority.OutcomeStatus(t.Context(), l.outcomeOf(agent, invocation)); err != nil || got != status {
			t.Fatal("outcome status", invocation, got, err)
		}
	}
	if e, err = l.store.VolumeEnrollment(t.Context(), agent, "local"); err != nil || e.Stage != "READY" || e.Incarnation != 2 || !e.Initialized {
		t.Fatal("volume after the restore", e, err)
	}
	l.runs(0)

	t.Log("stage: the lost invocations are lost, then run again under the same IDs")
	texts := map[string]string{after[0]: "lost in the restore, one", after[1]: "lost in the restore, two"}
	for _, loss := range result.Losses {
		if loss.Rerun != controlplane.RerunQueued || loss.SkipReason != "" {
			t.Fatal("the rerun of a lost invocation is not queued", loss)
		}
	}
	lostAt := map[string]time.Time{}
	for _, id := range after {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
		if v.State != "lost" || v.LostAt == nil || v.CompletedAt != nil || !v.ResultAvailable || v.ErrorCode != "" {
			t.Fatal("a lost invocation before its rerun", id, v.State, v.ErrorCode, v.LostAt, v.CompletedAt)
		}
		lostAt[id] = *v.LostAt
		// The result the restored database still holds stays readable.
		if body := string(l.request(l.user(), "GET", "/v1/invocations/"+id+"/result", "", nil, 200, nil)); !strings.Contains(body, texts[id]) {
			t.Fatal("the result of a lost invocation is not readable")
		}
	}
	var listed struct {
		Items []controlplane.Invocation `json:"items"`
	}
	l.request(l.user(), "GET", "/v1/agents/"+agent+"/invocations?state=lost", "", nil, 200, &listed)
	lost := []string{}
	for _, v := range listed.Items {
		lost = append(lost, v.ID)
	}
	slices.Sort(lost)
	if !slices.Equal(lost, want) {
		t.Fatal("the lost filter", lost, want)
	}
	l.await("reruns of the lost invocations", true, func() bool {
		for _, id := range after {
			var v controlplane.Invocation
			l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
			if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
				t.Fatal("a rerun ended without an answer", id, v.State, v.ErrorCode)
			}
			if v.State != "completed" {
				return false
			}
		}
		return true
	})
	for _, id := range after {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+id, "", nil, 200, &v)
		if v.LostAt == nil || !v.LostAt.Equal(lostAt[id]) || v.CompletedAt == nil || !v.CompletedAt.After(*v.LostAt) || !v.ResultAvailable {
			t.Fatal("a completed rerun", id, v.LostAt, v.CompletedAt)
		}
		if !l.answered(id, texts[id]) {
			t.Fatal("the rerun's answer")
		}
		if got, _, err := l.worker.authority.OutcomeStatus(t.Context(), l.outcomeOf(agent, id)); err != nil || got != restoreauthority.StatusRerunConfirmed {
			t.Fatal("the authority did not record the rerun", id, got, err)
		}
	}
	if got, _, err := l.worker.authority.OutcomeStatus(t.Context(), l.outcomeOf(agent, before)); err != nil || got != restoreauthority.StatusConfirmed {
		t.Fatal("an outcome the archive held", got, err)
	}
	l.request(l.user(), "GET", "/v1/agents/"+agent+"/invocations?state=lost", "", nil, 200, &listed)
	if len(listed.Items) != 0 {
		t.Fatal("lost invocations after the reruns", len(listed.Items))
	}
	if run := l.runs(1)[agent]; run.Incarnation != 2 {
		t.Fatal("the reruns did not run at the new incarnation", run)
	}

	t.Log("stage: the agent answers at the new incarnation; the old one is refused")
	l.answers(agent, "after-restore", "answered at the new incarnation")
	run := l.runs(1)[agent]
	if run.Incarnation != 2 || run.Generation <= oldRun.Generation {
		t.Fatal("the agent did not answer from the new incarnation", run)
	}
	if err = l.worker.authority.RecordVerifiedFence(t.Context(), oldReceipt); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the old incarnation's fence receipt was recorded", err)
	}
	if err = l.worker.authority.WithBinding(t.Context(), oldBinding, func() error { return nil }); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the old incarnation is still admitted", err)
	}
	if err = l.store.ObservePlacementControl(t.Context(), controlplane.PlacementControlObservation{AgentID: agent, HostID: "local", VMID: run.ID,
		Generation: run.Generation, Incarnation: 1, Compatible: true}); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal("the old incarnation's control contract was observed", err)
	}
}
