//go:build linux

package worker

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

var (
	// ErrNewerArchive refuses to restore an archive older than another archive
	// of the agent on this host: the newer one may hold outcomes that the
	// restore would otherwise declare lost (the model's repair comes first).
	ErrNewerArchive = errors.New("a newer archive of the agent is available on this host")
	// ErrRestoreArchive refuses an archive that is not of the agent's volume.
	ErrRestoreArchive = errors.New("the archive is not of the agent's current volume")
)

// VolumeRestoreResult is a finished restore: the agent's volume is READY at
// Incarnation, and Losses are the outcomes it lacks, declared lost.
type VolumeRestoreResult struct {
	RestoreID, AgentID, ArchiveID string
	Incarnation                   uint64
	Losses                        []controlplane.RestoreLoss
}

// restoreHost is what a restore needs from the host. The product uses the
// Firecracker host (productRestoreHost); tests replace it where KVM is needed.
type restoreHost struct {
	// barrier holds the agent's exclusive admission on the host.
	barrier func(ctx context.Context, id string, fn func(context.Context) error) error
	// retire leaves the agent with no VM and its placement STOPPED.
	retire func(ctx context.Context, id string) error
	// probe checks, before the agent stops, that its harness reports the
	// outcomes its store holds: the restricted boot runs the same harness.
	probe func(ctx context.Context, id string) error
	// install writes the authenticated archive into the agent's volume.
	install func(ctx context.Context, plan controlplane.VolumeRestorePlan, image io.Reader, a restoreauthority.Archive) error
	// boot starts the restricted boot of the installed image and returns its
	// authenticated control.
	boot func(ctx context.Context, id string) (runtime.VMRun, *capsuleprotocol.Client, error)
	// relocate creates the volume file of an agent that moves here from a
	// lost host, and registers it on this host: the same volume ID, size and
	// key, an empty container. It returns the file's identity. Repeating it
	// returns the same file. The agent's barrier needs it registered.
	relocate func(ctx context.Context, e controlplane.Enrollment) (device, inode uint64, err error)
	// after runs once each step is durable; tests stop the restore there.
	after func(step string) error
}

func (w *Placements) productRestoreHost() restoreHost {
	return restoreHost{
		barrier: w.host.WithBarrier,
		retire:  w.retireForRestore,
		probe:   w.probeRestoreHarness,
		install: func(ctx context.Context, plan controlplane.VolumeRestorePlan, image io.Reader, a restoreauthority.Archive) error {
			return w.host.InstallVolume(ctx, plan.Restore.AgentID, plan.Placement.Generation, plan.Device, plan.Inode, image, a.Size, a.Digest)
		},
		relocate: w.relocateVolume,
		boot: func(ctx context.Context, id string) (runtime.VMRun, *capsuleprotocol.Client, error) {
			run, err := w.start(ctx, id, true)
			if errors.Is(err, runtime.ErrCapacity) {
				if err = w.makeBarrierCapacity(ctx, id); err != nil {
					return run, nil, err
				}
				run, err = w.start(ctx, id, true)
			}
			if err != nil {
				return run, nil, err
			}
			c, err := w.host.Control(ctx, id)
			return run, c, err
		},
		after: w.afterRestoreStep,
	}
}

// relocateVolume creates, as provisioning does, the volume file of an agent
// that moves here from a lost host (ADR 020): a container of its volume ID
// and size, formatted with its key, which the key authority holds under the
// store's current binding. It registers it on this host with the agent's
// harness. The archive's bytes replace it at the install. Nothing boots it
// before its restore moves the agent here.
func (w *Placements) relocateVolume(ctx context.Context, e controlplane.Enrollment) (uint64, uint64, error) {
	p := w.provisioning
	if p == nil {
		return 0, 0, controlplane.ErrInput
	}
	harness, err := w.resolveHarness(ctx, e)
	if err != nil {
		return 0, 0, err
	}
	// The incarnation the authority holds now: the lost host's, or the one a
	// begun restore reserved. A sealed store is refused here.
	binding, err := w.authority.Lookup(ctx, e.AgentID)
	if err != nil {
		return 0, 0, err
	}
	if binding.Volume != e.VolumeID {
		return 0, 0, restoreauthority.ErrStale
	}
	var volume volumestore.Container
	err = w.authority.HoldKey(ctx, binding, func(ctx context.Context, key []byte) error {
		var err error
		volume, err = p.volumes.Prepare(ctx, volumestore.Spec{AgentID: e.AgentID, VolumeID: e.VolumeID, SizeMiB: int64(e.Resources.DataVolumeMiB)}, key)
		return err
	})
	if err != nil {
		return 0, 0, err
	}
	registration := runtime.ProvisionedAgent{ID: e.AgentID, Volume: volume.Path, Device: volume.Device, Inode: volume.Inode,
		Resources: runtime.VMResources{VCPUs: e.Resources.VCPUs, MemoryMiB: e.Resources.MemoryMiB, VolumeMiB: e.Resources.DataVolumeMiB}, Harness: harness}
	if err = w.host.RegisterProvisioned(ctx, registration, p.config.FirstUID, p.config.LastUID); err != nil {
		return 0, 0, err
	}
	return volume.Device, volume.Inode, nil
}

// arriveForRestore records the volume file of an agent whose relocation is
// pending, before the install: arriveBeforeBarrier created it. It does
// nothing for an agent whose volume is here.
func (w *Placements) arriveForRestore(ctx context.Context, h restoreHost, plan controlplane.VolumeRestorePlan) error {
	if plan.RelocatedFrom == "" {
		return nil
	}
	if h.relocate == nil {
		return controlplane.ErrInput
	}
	device, inode, err := h.relocate(ctx, plan.Enrollment)
	if err != nil {
		return err
	}
	return w.store.RecordRelocatedVolume(ctx, plan.Restore.ID, w.hostID, device, inode)
}

// arriveBeforeBarrier creates and registers the volume file of an agent
// that moves here, or whose relocation is pending, before the restore takes
// the agent's barrier on this host: the host admits a barrier only for an
// agent it knows. An agent whose volume is here needs nothing.
func (w *Placements) arriveBeforeBarrier(ctx context.Context, h restoreHost, restoreID, agentID string) error {
	plan, err := w.store.VolumeRestoreTarget(ctx, restoreID, w.hostID)
	var e controlplane.Enrollment
	switch {
	case err == nil && plan.RelocatedFrom == "":
		return nil
	case err == nil:
		e = plan.Enrollment
	case errors.Is(err, controlplane.ErrNotFound):
		if _, err = w.store.VolumeEnrollment(ctx, agentID, w.hostID); err == nil {
			return nil
		}
		if !errors.Is(err, controlplane.ErrStoreEnrollment) && !errors.Is(err, controlplane.ErrPlacement) {
			return err
		}
		if e, _, err = w.store.TakenOverEnrollment(ctx, agentID, w.hostID); err != nil {
			return err
		}
	default:
		return err
	}
	if h.relocate == nil {
		return controlplane.ErrInput
	}
	_, _, err = h.relocate(ctx, e)
	return err
}

// retireForRestore runs under the agent's barrier. Reconciliation already
// retires a VM of an older incarnation: its adoption fails. A VM of this
// restore's restricted boot is quiesced, anything else is stopped, and the
// host's watermark then excludes every older attempt.
func (w *Placements) retireForRestore(ctx context.Context, id string) error {
	runs, err := w.Reconcile(ctx)
	if err != nil {
		return err
	}
	p, err := w.placement(ctx, id)
	if err != nil {
		return err
	}
	if run, ok := runs[id]; ok && p.State == "RUNNING" && run.Generation == p.Generation && run.ID == p.VMID {
		if err = w.quiesceStop(ctx, id, p.Generation); err != nil {
			return err
		}
	} else if p.State != "STOPPED" {
		if err = w.stop(ctx, id, p.Generation, true); err != nil {
			return err
		}
	}
	return w.host.Retire(ctx, id, p.Generation)
}

// probeRestoreHarness asks the agent's running VM which control features its
// harness offers. A sleeping agent boots restricted for the question, and that
// boot is removed after.
func (w *Placements) probeRestoreHarness(ctx context.Context, id string) (result error) {
	runs, err := w.Reconcile(ctx)
	if err != nil {
		return err
	}
	if _, running := runs[id]; !running {
		run, err := w.start(ctx, id, true)
		if errors.Is(err, runtime.ErrCapacity) {
			if err = w.makeBarrierCapacity(ctx, id); err != nil {
				return err
			}
			run, err = w.start(ctx, id, true)
		}
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			result = errors.Join(result, w.quiesceStop(cleanup, id, run.Generation))
		}()
	}
	client, err := w.host.Control(ctx, id)
	if err != nil {
		return err
	}
	return requireOutcomes(ctx, client)
}

func requireOutcomes(ctx context.Context, client *capsuleprotocol.Client) error {
	contract, err := client.Negotiate(ctx, []string{capsuleprotocol.Version})
	if err != nil {
		return err
	}
	if !contract.Supports(capsuleprotocol.ControlOutcomes) {
		return capsuleprotocol.ErrUnsupportedProtocol // this harness cannot be inspected
	}
	return nil
}

func (w *Placements) placement(ctx context.Context, id string) (controlplane.Placement, error) {
	placements, err := w.store.Placements(ctx, w.hostID)
	if err != nil {
		return controlplane.Placement{}, err
	}
	for _, p := range placements {
		if p.AgentID == id {
			return p, nil
		}
	}
	return controlplane.Placement{}, controlplane.ErrPlacement
}

// RestoreFromArchive restores one agent of this host from one of its archives
// into a new incarnation, following the restore model (REC-02, ADR 003). It is
// a trusted operator operation, recorded in PostgreSQL under restoreID before
// anything stops. Steps:
//  1. The volume goes out of service at the next incarnation (SQL), and the
//     restore authority reserves that incarnation.
//  2. The agent's VMs are retired.
//  3. The archive, authenticated and hashed, is written into the volume.
//  4. A restricted boot opens the image at the new incarnation: no delivery,
//     no platform channel. The worker fences it with every revocation, then
//     the restore authority activates it: it inspects the outcomes that the
//     image holds, asks for a repair, declares each acknowledged outcome
//     still missing lost for this incarnation, and only then publishes.
//  5. The restricted boot is retired; the losses are copied into PostgreSQL
//     and the volume is READY again, in one transaction.
//
// A crash at any step leaves the volume RESTORING: nothing boots it for
// ordinary work. Calling it again with the same restoreID resumes from the
// last durable step; a new restoreID replaces an unfinished restore that has
// not activated. The agent wakes on its next delivery.
//
// While the authorities are unavailable (the authority service is away, or
// in degraded mode waits for the standby), the restore pauses: paused, when
// not nil, receives the error, then the restore resumes from its last
// durable step once they answer, until ctx ends (ADR 006 §4). A refusal
// ends it.
func (w *Placements) RestoreFromArchive(ctx context.Context, restoreID, agentID, archiveID string, archives *volumearchive.Store, paused func(error)) (VolumeRestoreResult, error) {
	if w.provisioning == nil || w.authority == nil || archives == nil {
		return VolumeRestoreResult{}, controlplane.ErrInput
	}
	for _, check := range []func() error{
		func() error { return restoreauthority.CheckSeparation(w.provisioning.runtimeRoot, archives.Root()) },
		func() error { return w.authority.SeparateFrom(archives.Root()) },
	} {
		if err := check(); err != nil {
			return VolumeRestoreResult{}, err
		}
	}
	return w.restorePausing(ctx, w.productRestoreHost(), restoreID, agentID, archiveID, archives, paused)
}

// restorePause bounds the wait between two attempts of a paused restore.
var restorePause = struct{ first, max time.Duration }{time.Second, 30 * time.Second}

// restorePausing runs the restore, and runs it again with the same ID
// whenever it stopped on unavailable authorities: every step can be
// repeated, and each attempt resumes from the last durable one.
func (w *Placements) restorePausing(ctx context.Context, h restoreHost, restoreID, agentID, archiveID string, archives *volumearchive.Store, paused func(error)) (VolumeRestoreResult, error) {
	wait := restorePause.first
	for {
		result, err := w.restore(ctx, h, restoreID, agentID, archiveID, archives)
		if err == nil || !errors.Is(err, restoreauthority.ErrUnavailable) || ctx.Err() != nil {
			return result, err
		}
		if paused != nil {
			paused(err)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		wait = min(2*wait, restorePause.max)
	}
}

// RestorePauses is the vocabulary of RestorePause.
func RestorePauses() []string { return []string{"waits_for_replica", "authority_unavailable"} }

// RestorePause says why a restore paused: the authority service waits for
// the standby in degraded mode, or the authorities do not answer.
func RestorePause(err error) string {
	if errors.Is(err, restoreauthority.ErrWaitsForReplica) {
		return "waits_for_replica"
	}
	return "authority_unavailable"
}

func (w *Placements) restore(ctx context.Context, h restoreHost, restoreID, agentID, archiveID string, archives *volumearchive.Store) (VolumeRestoreResult, error) {
	var result VolumeRestoreResult
	if w.authority == nil || archives == nil || !controlplane.ValidRestoreID(restoreID) || !volumearchive.ValidID(archiveID) || agentID == "" {
		return result, controlplane.ErrInput
	}
	if err := w.arriveBeforeBarrier(ctx, h, restoreID, agentID); err != nil {
		return result, err
	}
	err := h.barrier(ctx, agentID, func(ctx context.Context) error {
		plan, err := w.beginRestore(ctx, h, restoreID, agentID, archiveID, archives)
		if err != nil {
			return err
		}
		for {
			r := plan.Restore
			switch r.Step {
			case controlplane.RestoreDraining:
				err = w.drainForRestore(ctx, h, plan)
			case controlplane.RestoreInstalling:
				err = w.installRestore(ctx, h, plan, archives)
			case controlplane.RestoreReconciling:
				err = w.activateRestore(ctx, h, plan, archives)
			case controlplane.RestoreActivated:
				err = w.completeRestore(ctx, h, plan)
			case controlplane.RestoreSucceeded:
				losses, err := w.store.VolumeRestoreLosses(ctx, r.ID)
				result = VolumeRestoreResult{RestoreID: r.ID, AgentID: r.AgentID, ArchiveID: r.ArchiveID, Incarnation: r.Incarnation, Losses: losses}
				return err
			default:
				return controlplane.ErrRestore // superseded by a later restore
			}
			if err != nil {
				return err
			}
			if plan, err = w.store.VolumeRestoreTarget(ctx, restoreID, w.hostID); err != nil {
				return err
			}
			if h.after != nil {
				if err = h.after(plan.Restore.Step); err != nil {
					return err
				}
			}
		}
	})
	return result, err
}

// beginRestore resumes a recorded restore, or checks the archive and the
// harness before the agent is taken out of service. A restore that replaces
// an unfinished one first completes that one's reservation in the restore
// authority, so that both stores move together, one incarnation at a time.
func (w *Placements) beginRestore(ctx context.Context, h restoreHost, restoreID, agentID, archiveID string, archives *volumearchive.Store) (controlplane.VolumeRestorePlan, error) {
	plan, err := w.store.VolumeRestoreTarget(ctx, restoreID, w.hostID)
	if err == nil {
		if plan.Restore.AgentID != agentID || plan.Restore.ArchiveID != archiveID {
			return plan, controlplane.ErrConflict
		}
		return plan, nil
	}
	if !errors.Is(err, controlplane.ErrNotFound) {
		return plan, err
	}
	// An agent of a lost host that this host took over (ADR 020): the
	// restore moves it here. Its harness cannot be asked before: its VMs went
	// with the lost host, and its volume is not here yet. The restricted boot
	// asks it, as for any restore.
	e, err := w.store.VolumeEnrollment(ctx, agentID, w.hostID)
	relocating := false
	if errors.Is(err, controlplane.ErrStoreEnrollment) || errors.Is(err, controlplane.ErrPlacement) {
		var lost string
		if e, lost, err = w.store.TakenOverEnrollment(ctx, agentID, w.hostID); err == nil {
			relocating = lost != ""
		}
	}
	if err != nil {
		return plan, err
	}
	if err = checkRestoreArchive(ctx, archives, archiveID, e, w.authority); err != nil {
		return plan, err
	}
	if err = w.newerArchive(ctx, agentID, archiveID, archives); err != nil {
		return plan, err
	}
	// A catalogue that cannot declare a loss (version 1) could never activate
	// the image: refuse now rather than after the agent stops.
	if _, err = w.authority.Losses(ctx, agentID); err != nil {
		return plan, err
	}
	open, err := w.store.OpenVolumeRestore(ctx, agentID)
	if err != nil {
		return plan, err
	}
	if open != nil {
		if open.Step == controlplane.RestoreActivated {
			return plan, controlplane.ErrRestore // finish it: it declared its losses
		}
		previous := restoreauthority.Binding{Store: agentID, Volume: open.VolumeID, Incarnation: open.FromIncarnation}
		if _, err = w.authority.ReserveIncarnation(ctx, previous, open.ID); err != nil {
			return plan, err
		}
	} else if !relocating {
		if err = h.probe(ctx, agentID); err != nil {
			return plan, err
		}
	}
	return w.store.BeginVolumeRestore(ctx, restoreID, agentID, w.hostID, archiveID)
}

// checkRestoreArchive authenticates the archive and hashes its bytes, then
// checks that it is of this agent's volume and of its size.
func checkRestoreArchive(ctx context.Context, archives *volumearchive.Store, archiveID string, e controlplane.Enrollment, authority volumearchive.Authority) error {
	f, a, err := archives.Open(ctx, archiveID, authority)
	if err != nil {
		return err
	}
	f.Close()
	return archiveFits(a, e)
}

func archiveFits(a restoreauthority.Archive, e controlplane.Enrollment) error {
	if a.Binding.Store != e.AgentID || a.Binding.Volume != e.VolumeID || a.Binding.Incarnation > e.Incarnation ||
		a.Size != int64(e.Resources.DataVolumeMiB)<<20 {
		return ErrRestoreArchive
	}
	return nil
}

// newerArchive is the coordinator's repair: an archive can hold the outcomes
// that another lacks only by being newer. It refuses when the agent has a
// kept archive on this host captured after archiveID, that is still present.
// An archive that PostgreSQL does not record, such as one taken on demand, is
// the operator's explicit choice and has none.
func (w *Placements) newerArchive(ctx context.Context, agentID, archiveID string, archives *volumearchive.Store) error {
	newer, err := w.store.NewerVolumeArchives(ctx, agentID, w.hostID, archiveID)
	if err != nil {
		return err
	}
	for _, id := range newer {
		if m, err := archives.Manifest(id); err == nil && m.Binding.Store == agentID {
			return ErrNewerArchive
		}
	}
	return nil
}

// drainForRestore is the model's beginRestore then retire: the authority
// reserves the incarnation that SQL already holds, so the old incarnation can
// record no outcome, then the agent's VMs are retired.
func (w *Placements) drainForRestore(ctx context.Context, h restoreHost, plan controlplane.VolumeRestorePlan) error {
	r := plan.Restore
	previous := restoreauthority.Binding{Store: r.AgentID, Volume: r.VolumeID, Incarnation: r.FromIncarnation}
	next, err := w.authority.ReserveIncarnation(ctx, previous, r.ID)
	if err != nil {
		return err
	}
	if next.Incarnation != r.Incarnation {
		return restoreauthority.ErrStale
	}
	// A relocated agent's volume is created once its incarnation is
	// reserved: the key authority holds its key under that incarnation.
	if err = w.arriveForRestore(ctx, h, plan); err != nil {
		return err
	}
	if err = h.retire(ctx, r.AgentID); err != nil {
		return err
	}
	return w.store.AdvanceVolumeRestore(ctx, r.ID, w.hostID, controlplane.RestoreDraining, controlplane.RestoreInstalling)
}

// installRestore is the model's install. A crash in the copy leaves a partial
// image, which nothing boots; the copy is redone from the immutable archive.
func (w *Placements) installRestore(ctx context.Context, h restoreHost, plan controlplane.VolumeRestorePlan, archives *volumearchive.Store) error {
	r := plan.Restore
	if err := w.arriveForRestore(ctx, h, plan); err != nil {
		return err
	}
	if err := h.retire(ctx, r.AgentID); err != nil {
		return err
	}
	// Retirement may have moved the placement's generation.
	plan, err := w.store.VolumeRestoreTarget(ctx, r.ID, w.hostID)
	if err != nil {
		return err
	}
	f, a, err := archives.Open(ctx, r.ArchiveID, w.authority)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = archiveFits(a, plan.Enrollment); err != nil {
		return err
	}
	if err = h.install(ctx, plan, f, a); err != nil {
		return err
	}
	return w.store.AdvanceVolumeRestore(ctx, r.ID, w.hostID, controlplane.RestoreInstalling, controlplane.RestoreReconciling)
}

// activateRestore is the model's launchRestore, then repairHistory or
// declareLoss, then activate. Each attempt starts a fresh restricted boot.
func (w *Placements) activateRestore(ctx context.Context, h restoreHost, plan controlplane.VolumeRestorePlan, archives *volumearchive.Store) (result error) {
	r := plan.Restore
	if err := h.retire(ctx, r.AgentID); err != nil {
		return err
	}
	run, client, err := h.boot(ctx, r.AgentID)
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			// Release the slot; the next attempt boots again.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			result = errors.Join(result, h.retire(cleanup, r.AgentID))
		}
	}()
	if err = requireOutcomes(ctx, client); err != nil {
		return err
	}
	e, err := w.store.VolumeEnrollment(ctx, r.AgentID, w.hostID)
	if err != nil {
		return err
	}
	if e.Incarnation != r.Incarnation || client.Identity().Incarnation != r.Incarnation || !client.Identity().FenceOnly {
		return restoreauthority.ErrStale
	}
	receipt, err := w.synchronizeAuthority(ctx, e, client)
	if err != nil {
		return err
	}
	inspect := func(recorded []restoreauthority.Outcome) ([]string, error) {
		ids := make([]string, len(recorded))
		for i, o := range recorded {
			ids[i] = o.ID
		}
		held, err := client.Outcomes(ctx, ids)
		if err != nil {
			return nil, err
		}
		missing := []string{}
		for _, o := range recorded {
			if digest, ok := held[o.ID]; !ok || digest != o.Digest {
				missing = append(missing, o.ID)
			}
		}
		return missing, nil
	}
	_, err = w.authority.ActivateRestored(ctx, receipt, restoreauthority.Activation{
		Inspect: inspect,
		Repair: func([]restoreauthority.Outcome) error {
			return w.newerArchive(ctx, r.AgentID, r.ArchiveID, archives)
		},
		Publish: func(ctx context.Context) error {
			return w.store.ActivateVolumeRestore(ctx, r.ID, w.hostID, run.Generation, run.ID)
		},
	})
	return err
}

// completeRestore retires the restricted boot, then copies the losses
// declared for the restore's incarnation, queues or skips the rerun of each
// lost invocation, and puts the volume back in service, in one transaction.
func (w *Placements) completeRestore(ctx context.Context, h restoreHost, plan controlplane.VolumeRestorePlan) error {
	r := plan.Restore
	if err := h.retire(ctx, r.AgentID); err != nil {
		return err
	}
	losses, err := w.authority.Losses(ctx, r.AgentID)
	if err != nil {
		return err
	}
	// The volume was RESTORING since the reservation, so no rerun can be
	// recorded yet. A recorded one is passed on all the same: it is not due.
	declared := make([]controlplane.DeclaredLoss, 0, len(losses))
	for _, l := range losses {
		if l.Incarnation == r.Incarnation {
			declared = append(declared, controlplane.DeclaredLoss{OutcomeID: l.ID, RerunRecorded: l.Rerun})
		}
	}
	slices.SortFunc(declared, func(a, b controlplane.DeclaredLoss) int { return strings.Compare(a.OutcomeID, b.OutcomeID) })
	_, err = w.store.CompleteVolumeRestore(ctx, r.ID, w.hostID, declared)
	return err
}

var restoreFailures = []string{"archive", "newer_archive", "busy", "authority", "unsupported_harness", "state", "error"}

// RestoreFailures is the vocabulary of RestoreFailure.
func RestoreFailures() []string { return slices.Clone(restoreFailures) }

// RestoreFailure classifies why a restore stopped: the archive is missing,
// inconsistent or not the agent's; a newer archive is available; the host or
// the agent was busy; an authority refused; the agent's harness cannot be
// inspected; the agent or the restore is not in a state that allows it; or
// any other error. Every one leaves the agent out of service until the
// restore is resumed, except a refusal before the agent was stopped.
func RestoreFailure(err error) string {
	switch {
	case errors.Is(err, volumearchive.ErrArchive), errors.Is(err, ErrRestoreArchive), errors.Is(err, runtime.ErrVolumeImage), errors.Is(err, ErrArchiveUnavailable):
		return "archive"
	case errors.Is(err, ErrNewerArchive):
		return "newer_archive"
	case errors.Is(err, runtime.ErrVolumeBusy), errors.Is(err, runtime.ErrAdmissionBusy), errors.Is(err, controlplane.ErrPlacementBusy),
		errors.Is(err, runtime.ErrCapacity):
		return "busy"
	case errors.Is(err, restoreauthority.ErrStale), errors.Is(err, restoreauthority.ErrSealed), errors.Is(err, restoreauthority.ErrUnavailable),
		errors.Is(err, restoreauthority.ErrConflict), errors.Is(err, restoreauthority.ErrHistory), errors.Is(err, restoreauthority.ErrInput):
		return "authority"
	case errors.Is(err, capsuleprotocol.ErrUnsupportedProtocol), errors.Is(err, capsuleprotocol.ErrCapabilitiesUnavailable):
		return "unsupported_harness"
	case errors.Is(err, controlplane.ErrRestore), errors.Is(err, controlplane.ErrStoreEnrollment), errors.Is(err, controlplane.ErrConflict),
		errors.Is(err, controlplane.ErrPlacement), errors.Is(err, controlplane.ErrNotFound), errors.Is(err, controlplane.ErrHostLost),
		errors.Is(err, controlplane.ErrRelease), errors.Is(err, ErrNotTakenOver):
		return "state"
	}
	return "error"
}
