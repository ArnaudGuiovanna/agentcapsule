//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

func TestProductVolumeGrowthKVM(t *testing.T) {
	l := newRegistryLab(t)
	ctx := t.Context()
	l.publish("1.0.0", "opt/echo")
	agent := l.create("grown", "1.0.0").AgentID
	before := l.invoke(agent, "before-growth", "survives growth")
	l.await("invocation before growth", true, func() bool { return l.answered(before, "survives growth") })
	outcome := l.outcomeOf(agent, before)
	readGuestOutcome := func() [32]byte {
		client, err := l.worker.host.Control(ctx, agent)
		if err != nil {
			t.Fatal(err)
		}
		contents, err := client.Outcomes(ctx, []string{outcome})
		if err != nil {
			t.Fatal(err)
		}
		digest, ok := contents[outcome]
		if !ok {
			t.Fatal("pre-growth sentinel absent from guest volume")
		}
		return digest
	}
	sentinel := readGuestOutcome()
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := l.store.VolumeEnrollment(ctx, agent, "local")
	if err != nil {
		t.Fatal(err)
	}
	var g controlplane.VolumeGrowth
	in := controlplane.GrowthInput{SizeMiB: 192}
	request := "/v1/agents/" + agent + "/volume-growth"
	l.request(l.owner(), "POST", request, "grow", in, 202, &g)
	if g.Stage != "pending" || g.Previous != 128 || g.Target != 192 {
		t.Fatal(g)
	}
	status := "/v1/volume-growth/" + g.ID
	for _, want := range []string{"capturing", "restoring"} {
		if err := l.worker.GrowthPass(ctx, archives); err != nil {
			t.Fatal(err)
		}
		l.request(l.owner(), "GET", status, "", nil, 200, &g)
		if g.Stage != want {
			t.Fatalf("expected %s: %+v", want, g)
		}
	}
	stopped := errors.New("test interruption after copying the archive")
	l.worker.afterRestoreStep = func(step string) error {
		if step == controlplane.RestoreReconciling {
			return stopped
		}
		return nil
	}
	if err := l.worker.GrowthPass(ctx, archives); !errors.Is(err, stopped) {
		t.Fatalf("expected interruption, got %v", err)
	}
	l.worker.afterRestoreStep = nil
	if err := l.worker.GrowthPass(ctx, archives); err != nil {
		t.Fatal(err)
	}
	l.request(l.owner(), "GET", status, "", nil, 200, &g)
	grown, err := l.store.VolumeEnrollment(ctx, agent, "local")
	if err != nil || g.Stage != "succeeded" || grown.VolumeID != original.VolumeID || grown.Stage != "READY" || grown.Incarnation != original.Incarnation+1 || grown.Resources.DataVolumeMiB != 192 {
		t.Fatal(g, grown, err)
	}
	losses, err := l.store.VolumeRestoreLosses(ctx, g.RestoreID)
	if err != nil || len(losses) != 0 {
		t.Fatal(losses, err)
	}
	f, manifest, err := archives.Open(ctx, g.ArchiveID, l.worker.authority)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if manifest.Size != 128<<20 || manifest.Binding != enrollmentBinding(original) {
		t.Fatal(manifest)
	}
	var replay controlplane.VolumeGrowth
	l.request(l.owner(), "POST", request, "grow", in, 202, &replay)
	if replay.ID != g.ID {
		t.Fatal("duplicate growth", replay.ID, g.ID)
	}
	after := l.invoke(agent, "after-growth", "written after growth")
	l.await("invocation after growth", true, func() bool { return l.answered(after, "written after growth") })
	if readGuestOutcome() != sentinel {
		t.Fatal("private guest outcome changed after growth")
	}
	t.Logf("volume %s grew %d -> %d MiB, independently authenticated archive restored into incarnation %d with zero lost outcomes", grown.VolumeID, g.Previous, g.Target, grown.Incarnation)
}
