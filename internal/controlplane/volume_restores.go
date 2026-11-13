package controlplane

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

// ErrRestore refuses a restore step in the current state: another restore is
// unfinished, the agent is not LIVE, or the step does not follow the last one.
var ErrRestore = errors.New("volume restore is not possible in this state")

var restoreIDPattern = regexp.MustCompile(`^rst_[0-9a-f]{32}$`)

// ValidRestoreID checks the stable restore identifier chosen by the operator.
// Reuse it only to resume the same restore.
func ValidRestoreID(id string) bool { return restoreIDPattern.MatchString(id) }

// Restore steps (migration 0029), in order.
const (
	RestoreDraining    = "DRAINING"
	RestoreInstalling  = "INSTALLING"
	RestoreReconciling = "RECONCILING"
	RestoreActivated   = "ACTIVATED"
	RestoreSucceeded   = "SUCCEEDED"
	RestoreSuperseded  = "SUPERSEDED"
)

// VolumeRestore is the durable record of one restore of an agent's volume
// from one of its archives, into a new incarnation (REC-02, ADR 003).
type VolumeRestore struct {
	ID, AgentID, HostID, VolumeID, ArchiveID string
	FromIncarnation, Incarnation             uint64
	Step                                     string
	StartedAt                                time.Time
	ActivatedAt, CompletedAt                 *time.Time
}

// Open is true until the restore succeeds or another one replaces it.
func (r VolumeRestore) Open() bool { return r.Step != RestoreSucceeded && r.Step != RestoreSuperseded }

// VolumeRestorePlan is a restore with what its next step needs: the agent's
// enrollment, its placement and the registered volume. It is a SQL
// precondition, not physical proof.
type VolumeRestorePlan struct {
	Restore       VolumeRestore
	Enrollment    Enrollment
	Placement     Placement
	Device, Inode uint64
}

// RestoreLoss is a loss that a restore copied from the restore authority.
// MailboxID is empty when the outcome matches no delivery this database knows:
// it lost that work too. InvocationID is set for an owner instruction. Rerun
// is the restore's decision for that invocation (RerunQueued, or RerunSkipped
// with SkipReason), or empty when it made none: the invocation's delivery was
// still open, it was canceled, or the authority had recorded its rerun.
type RestoreLoss struct {
	OutcomeID, MailboxID, InvocationID string
	Incarnation                        uint64
	DeclaredAt                         time.Time
	Rerun, SkipReason                  string
}

const restoreColumns = `restore_id,agent_id,host_id,volume_id,archive_id,from_incarnation,incarnation,step,started_at,activated_at,completed_at`

func scanRestore(row pgx.Row) (VolumeRestore, error) {
	var r VolumeRestore
	var from, incarnation int64
	err := row.Scan(&r.ID, &r.AgentID, &r.HostID, &r.VolumeID, &r.ArchiveID, &from, &incarnation, &r.Step, &r.StartedAt, &r.ActivatedAt, &r.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	r.FromIncarnation, r.Incarnation = uint64(from), uint64(incarnation)
	return r, err
}

// restoreInstalled reports whether the open restore of e's incarnation has
// installed its image: only then may the image boot, restricted.
func restoreInstalled(ctx context.Context, tx pgx.Tx, e Enrollment) (bool, error) {
	var installed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM volume_restores WHERE agent_id=$1 AND volume_id=$2
        AND incarnation=$3 AND step=$4)`, e.AgentID, e.VolumeID, int64(e.Incarnation), RestoreReconciling).Scan(&installed)
	return installed, err
}

// restorePlan reads a restore and, under the agent's lock, its plan. An open
// restore must hold the volume RESTORING at its incarnation, on its host.
func restorePlan(ctx context.Context, tx pgx.Tx, restoreID, host string) (VolumeRestorePlan, agent, error) {
	var plan VolumeRestorePlan
	r, err := scanRestore(tx.QueryRow(ctx, `SELECT `+restoreColumns+` FROM volume_restores WHERE restore_id=$1`, restoreID))
	if err != nil {
		return plan, agent{}, err
	}
	if r.HostID != host {
		return plan, agent{}, ErrPlacement
	}
	a, p, err := placementLock(ctx, tx, r.AgentID, host)
	if err != nil {
		return plan, a, err
	}
	// The row may have moved while the agent's lock was awaited.
	if r, err = scanRestore(tx.QueryRow(ctx, `SELECT `+restoreColumns+` FROM volume_restores WHERE restore_id=$1`, restoreID)); err != nil {
		return plan, a, err
	}
	e, err := enrollment(ctx, tx, r.AgentID, host)
	if err != nil {
		return plan, a, err
	}
	if r.Open() && (e.Stage != "RESTORING" || e.Incarnation != r.Incarnation || e.VolumeID != r.VolumeID) {
		return plan, a, ErrStoreEnrollment
	}
	var device, inode string
	if err = tx.QueryRow(ctx, "SELECT volume_device,volume_inode FROM store_enrollments WHERE agent_id=$1", r.AgentID).Scan(&device, &inode); err != nil {
		return plan, a, err
	}
	if plan.Device, err = strconv.ParseUint(device, 16, 64); err != nil {
		return plan, a, ErrStoreEnrollment
	}
	if plan.Inode, err = strconv.ParseUint(inode, 16, 64); err != nil || plan.Inode == 0 {
		return plan, a, ErrStoreEnrollment
	}
	plan.Restore, plan.Enrollment, plan.Placement = r, e, p
	return plan, a, nil
}

// OpenVolumeRestore returns the agent's unfinished restore, if any.
func (s *Store) OpenVolumeRestore(ctx context.Context, agentID string) (*VolumeRestore, error) {
	r, err := scanRestore(s.pool.QueryRow(ctx, `SELECT `+restoreColumns+` FROM volume_restores
        WHERE agent_id=$1 AND step NOT IN ($2,$3)`, agentID, RestoreSucceeded, RestoreSuperseded))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// BeginVolumeRestore records a restore of the agent from archiveID before
// anything stops, and in the same transaction takes its volume out of
// service: the volume becomes RESTORING at the next incarnation, so no
// ordinary boot, adoption, delivery or archive uses it any more, and every
// check of the old incarnation fails. The agent must be LIVE with a READY,
// initialized volume, or hold an unfinished restore that has not activated
// yet: this restore then supersedes it, one incarnation further. Repeating it
// with the same restore ID returns the recorded restore, whatever its step.
// The worker reserves the same incarnation in the restore authority next.
func (s *Store) BeginVolumeRestore(ctx context.Context, restoreID, agentID, host, archiveID string) (VolumeRestorePlan, error) {
	var plan VolumeRestorePlan
	if !ValidRestoreID(restoreID) || !archiveIDPattern.MatchString(archiveID) || agentID == "" || host == "" {
		return plan, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return plan, err
	}
	defer rollback(tx)
	a, _, err := placementLock(ctx, tx, agentID, host)
	if err != nil {
		return plan, err
	}
	existing, err := scanRestore(tx.QueryRow(ctx, `SELECT `+restoreColumns+` FROM volume_restores WHERE restore_id=$1`, restoreID))
	if err == nil {
		if existing.AgentID != agentID || existing.ArchiveID != archiveID {
			return plan, ErrConflict
		}
		plan, _, err = restorePlan(ctx, tx, restoreID, host)
		return plan, err
	}
	if !errors.Is(err, ErrNotFound) {
		return plan, err
	}
	if a.Phase != "LIVE" {
		return plan, ErrRestore
	}
	e, err := enrollment(ctx, tx, agentID, host)
	if err != nil {
		return plan, err
	}
	switch e.Stage {
	case "READY":
		if !e.Initialized {
			return plan, ErrStoreEnrollment
		}
	case "RESTORING":
		tag, err := tx.Exec(ctx, `UPDATE volume_restores SET step=$2,completed_at=clock_timestamp()
            WHERE agent_id=$1 AND incarnation=$3 AND step IN ($4,$5,$6)`, agentID, RestoreSuperseded, int64(e.Incarnation),
			RestoreDraining, RestoreInstalling, RestoreReconciling)
		if err != nil {
			return plan, err
		}
		if tag.RowsAffected() != 1 {
			return plan, ErrRestore // an activated restore is finished, not replaced
		}
	default:
		return plan, ErrStoreEnrollment
	}
	if _, err = tx.Exec(ctx, `INSERT INTO volume_restores(restore_id,agent_id,host_id,volume_id,archive_id,from_incarnation,incarnation)
        VALUES($1,$2,$3,$4,$5,$6::bigint,$6::bigint+1)`, restoreID, agentID, host, e.VolumeID, archiveID, int64(e.Incarnation)); err != nil {
		return plan, err
	}
	if _, err = tx.Exec(ctx, `UPDATE store_enrollments SET stage='RESTORING',incarnation=incarnation+1 WHERE agent_id=$1`, agentID); err != nil {
		return plan, err
	}
	if plan, _, err = restorePlan(ctx, tx, restoreID, host); err != nil {
		return plan, err
	}
	return plan, commit(ctx, tx)
}

// VolumeRestoreTarget rereads a restore and its plan, to resume it.
func (s *Store) VolumeRestoreTarget(ctx context.Context, restoreID, host string) (VolumeRestorePlan, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return VolumeRestorePlan{}, err
	}
	defer rollback(tx)
	plan, _, err := restorePlan(ctx, tx, restoreID, host)
	return plan, err
}

// AdvanceVolumeRestore records that the worker finished a host step: the
// agent's VMs are retired (DRAINING to INSTALLING), or the archive is
// installed (INSTALLING to RECONCILING). Both need the agent's placement
// STOPPED. Repeating a recorded step succeeds.
func (s *Store) AdvanceVolumeRestore(ctx context.Context, restoreID, host, from, to string) error {
	if !(from == RestoreDraining && to == RestoreInstalling) && !(from == RestoreInstalling && to == RestoreReconciling) {
		return ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	plan, a, err := restorePlan(ctx, tx, restoreID, host)
	if err != nil {
		return err
	}
	switch plan.Restore.Step {
	case to:
		return nil
	case from:
	default:
		return ErrRestore
	}
	if (a.Phase != "LIVE" && a.Phase != "QUIESCING") || plan.Placement.State != "STOPPED" {
		return ErrRestore
	}
	if _, err = tx.Exec(ctx, "UPDATE volume_restores SET step=$2 WHERE restore_id=$1", restoreID, to); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// ActivateVolumeRestore is the publication that the restore authority runs
// inside its activation (Catalog.Activate), once every acknowledged outcome
// the image lacks is declared lost for its incarnation. It checks the
// physical precondition: the inspected restricted boot is the agent's current
// placement, and the image recorded its initialization. The volume stays
// RESTORING until CompleteVolumeRestore. Repeating it succeeds.
func (s *Store) ActivateVolumeRestore(ctx context.Context, restoreID, host string, generation uint64, vmID string) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	plan, a, err := restorePlan(ctx, tx, restoreID, host)
	if err != nil {
		return err
	}
	switch plan.Restore.Step {
	case RestoreActivated, RestoreSucceeded:
		return nil
	case RestoreReconciling:
	default:
		return ErrRestore
	}
	p := plan.Placement
	if (a.Phase != "LIVE" && a.Phase != "QUIESCING") || !plan.Enrollment.Initialized {
		return ErrRestore
	}
	if p.State != "RUNNING" || !p.FenceOnly || p.Generation != generation || p.VMID != vmID || vmID == "" {
		return ErrPlacement
	}
	if _, err = tx.Exec(ctx, "UPDATE volume_restores SET step=$2,activated_at=clock_timestamp() WHERE restore_id=$1", restoreID, RestoreActivated); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// outcomeID is the restore authority's identifier of the outcome of event
// eventID delivered to agentID (harnessstore.StoredOutcomeFingerprint).
func outcomeID(agentID, eventID string) (string, error) {
	id, _, err := harnessstore.StoredOutcomeFingerprint(agentID, eventID, [32]byte{}, nil)
	return id, err
}

// CompleteVolumeRestore ends an activated restore once its restricted boot
// is retired. In one transaction, it copies the losses that the restore
// authority declared for the restore's incarnation, decides the rerun of each
// lost invocation (scheduleReruns), and puts the volume back in service:
// READY at that incarnation. Each loss is mapped to the delivery whose
// outcome it is, by computing the outcome ID of each of the agent's
// mailboxes; an owner instruction's mailbox gives its invocation. Repeating
// it after success returns the recorded losses and ignores declared: it
// decides nothing again.
func (s *Store) CompleteVolumeRestore(ctx context.Context, restoreID, host string, declared []DeclaredLoss) ([]RestoreLoss, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	plan, a, err := restorePlan(ctx, tx, restoreID, host)
	if err != nil {
		return nil, err
	}
	r := plan.Restore
	switch r.Step {
	case RestoreSucceeded:
		return restoreLosses(ctx, tx, restoreID)
	case RestoreActivated:
	default:
		return nil, ErrRestore
	}
	if (a.Phase != "LIVE" && a.Phase != "QUIESCING") || plan.Placement.State != "STOPPED" {
		return nil, ErrRestore
	}
	deliveries := map[string][2]string{}
	if len(declared) > 0 {
		rows, err := tx.Query(ctx, "SELECT id,coalesce(instruction_id,'') FROM agent_mailboxes WHERE dest_agent_id=$1", r.AgentID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var mailbox, invocation string
			if err = rows.Scan(&mailbox, &invocation); err != nil {
				rows.Close()
				return nil, err
			}
			id, err := outcomeID(r.AgentID, mailbox)
			if err != nil {
				rows.Close()
				return nil, err
			}
			deliveries[id] = [2]string{mailbox, invocation}
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return nil, err
		}
	}
	recorded := map[string]bool{}
	for _, l := range declared {
		d := deliveries[l.OutcomeID]
		if _, err = tx.Exec(ctx, `INSERT INTO volume_restore_losses(restore_id,incarnation,outcome_id,mailbox_id,invocation_id)
            VALUES($1,$2,$3,nullif($4,''),nullif($5,'')) ON CONFLICT DO NOTHING`, restoreID, int64(r.Incarnation), l.OutcomeID, d[0], d[1]); err != nil {
			return nil, err
		}
		recorded[l.OutcomeID] = recorded[l.OutcomeID] || l.RerunRecorded
	}
	if err = scheduleReruns(ctx, tx, restoreID, a, recorded); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1", r.AgentID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE volume_restores SET step=$2,completed_at=clock_timestamp() WHERE restore_id=$1", restoreID, RestoreSucceeded); err != nil {
		return nil, err
	}
	losses, err := restoreLosses(ctx, tx, restoreID)
	if err != nil {
		return nil, err
	}
	return losses, commit(ctx, tx)
}

func restoreLosses(ctx context.Context, tx pgx.Tx, restoreID string) ([]RestoreLoss, error) {
	rows, err := tx.Query(ctx, `SELECT l.outcome_id,coalesce(l.mailbox_id,''),coalesce(l.invocation_id,''),l.incarnation,l.declared_at,
            coalesce(r.state,''),coalesce(r.skip_reason,'')
        FROM volume_restore_losses l LEFT JOIN invocation_reruns r ON (r.restore_id,r.outcome_id)=(l.restore_id,l.outcome_id)
        WHERE l.restore_id=$1 ORDER BY l.outcome_id`, restoreID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	losses := make([]RestoreLoss, 0)
	for rows.Next() {
		var l RestoreLoss
		var incarnation int64
		if err = rows.Scan(&l.OutcomeID, &l.MailboxID, &l.InvocationID, &incarnation, &l.DeclaredAt, &l.Rerun, &l.SkipReason); err != nil {
			return nil, err
		}
		l.Incarnation = uint64(incarnation)
		losses = append(losses, l)
	}
	return losses, rows.Err()
}

// VolumeRestoreLosses lists the losses a restore copied, by outcome ID.
func (s *Store) VolumeRestoreLosses(ctx context.Context, restoreID string) ([]RestoreLoss, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	return restoreLosses(ctx, tx, restoreID)
}

// NewerVolumeArchives lists the agent's archives on host, kept and published,
// that were captured after archiveID. An archive that PostgreSQL does not
// record, such as one taken on demand, has none.
func (s *Store) NewerVolumeArchives(ctx context.Context, agentID, host, archiveID string) ([]string, error) {
	return s.archiveIDs(ctx, `SELECT n.archive_id FROM volume_archives n JOIN volume_archives o ON o.agent_id=n.agent_id AND o.host_id=n.host_id
        WHERE n.agent_id=$1 AND n.host_id=$2 AND o.archive_id=$3 AND n.archive_id<>o.archive_id
        AND n.captured_at IS NOT NULL AND n.removed_at IS NULL AND o.captured_at IS NOT NULL AND n.captured_at>o.captured_at
        ORDER BY n.captured_at DESC,n.archive_id`, agentID, host, archiveID)
}
