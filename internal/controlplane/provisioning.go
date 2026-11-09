package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var ErrStoreEnrollment = errors.New("store enrollment is not ready or no longer current")

// Enrollment is trusted worker input. The volume identity is allocated in the
// reservation transaction and survives retries. Incarnation identifies the
// installed storage image independently of process boot generations. New
// enrollment starts at 1; only a future restore coordinator may replace it.
type Enrollment struct {
	Incarnation                                                  uint64
	AgentID, OperationID, VolumeID, HostID, Stage, HarnessDigest string
	// HarnessSource is "local-approved" (the host's built-in image) or "oci"
	// (a registry package, whose harness.ext4 has RootfsDigest).
	HarnessSource, RootfsDigest string
	Resources                   AgentResources
	AutoStart                   bool
	Initialized                 bool
}

// ProvisionedVolume is the trusted worker's observation after actual encrypted
// container creation, durable sync and host registration. Filesystem readiness
// is recorded separately after the guest opens and initializes/checks its image.
// SQL cannot establish those physical facts; this is not a public API payload.
type ProvisionedVolume struct {
	AgentID, OperationID, VolumeID, HostID string
	Device, Inode                          uint64
}

type EnrollmentFence struct {
	Incarnation                              uint64
	AgentID, VolumeID, HostID, VMID, Subject string
	Generation                               uint64
}

type EnrollmentBoot struct {
	Incarnation                     uint64
	AgentID, VolumeID, HostID, VMID string
	Generation                      uint64
}

// VolumeBootPlan is read from current authority immediately before key delivery.
// It is not an ordinary placement confirmation and carries no key. The trusted
// host must still hold the physical volume lock, authenticate this boot's peer,
// and confirm the placement after readiness. No SQL lock crosses that RPC.
type VolumeBootPlan struct {
	Enrollment                Enrollment
	Initialize                bool
	AcknowledgeInitialization bool
	UncleanStop               bool
}

func (s *Store) PrepareVolumeBoot(ctx context.Context, proof VMCaller, worker string) (VolumeBootPlan, error) {
	var result VolumeBootPlan
	if worker == "" || proof.Generation == 0 || proof.VMID == "" {
		return result, ErrPlacement
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return result, err
	}
	if p.State != "STARTING" || p.Generation != proof.Generation || p.WorkerID != worker {
		return result, ErrPlacement
	}
	// The projected LeaseValid value may have been evaluated before waiting for
	// FOR UPDATE. Read the database clock again after owning both row locks.
	var live bool
	if err = tx.QueryRow(ctx, "SELECT lease_until>clock_timestamp() FROM agent_placements WHERE agent_id=$1", proof.AgentID).Scan(&live); err != nil {
		return result, err
	}
	if !live {
		return result, ErrPlacement
	}
	e, err := enrollment(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return result, err
	}
	if p.FenceOnly {
		if a.Phase == "PROVISIONING" && e.Stage == "FENCING" {
			return VolumeBootPlan{Enrollment: e, Initialize: !e.Initialized, AcknowledgeInitialization: !e.Initialized, UncleanStop: p.UncleanStop}, nil
		}
		if (a.Phase == "LIVE" || a.Phase == "QUIESCING") && e.Stage == "READY" {
			return VolumeBootPlan{Enrollment: e, AcknowledgeInitialization: a.Phase == "LIVE" && !e.Initialized, UncleanStop: p.UncleanStop}, nil
		}
		return result, ErrStoreEnrollment
	}
	if a.Phase != "LIVE" || e.Stage != "READY" || !e.Initialized {
		return result, ErrStoreEnrollment
	}
	return VolumeBootPlan{Enrollment: e, UncleanStop: p.UncleanStop}, nil
}

// VolumeEnrollment reads the installed identity for boot/adoption. It never
// registers a new store or changes the independent authority.
func (s *Store) VolumeEnrollment(ctx context.Context, id, host string) (Enrollment, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return Enrollment{}, err
	}
	defer rollback(tx)
	if _, err = lockAgents(ctx, tx, id); err != nil {
		return Enrollment{}, err
	}
	return enrollment(ctx, tx, id, host)
}

func publishRevocation(ctx context.Context, tx pgx.Tx, subject string) error {
	_, err := tx.Exec(ctx, "INSERT INTO revocation_catalogue(subject) VALUES($1) ON CONFLICT DO NOTHING", subject)
	return err
}

// RevocationSubjects returns durable, already-authorized intents. No SQL lock
// crosses the worker's subsequent independent-authority or guest RPC operation.
func (s *Store) RevocationSubjects(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT subject FROM revocation_catalogue ORDER BY subject")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subjects []string
	for rows.Next() {
		var subject string
		if err = rows.Scan(&subject); err != nil {
			return nil, err
		}
		subjects = append(subjects, subject)
	}
	return subjects, rows.Err()
}

const enrollmentColumns = `e.agent_id,e.operation_id,e.volume_id,x.host_id,e.stage,r.artifact_digest,r.source,coalesce(r.rootfs_digest,''),e.incarnation,
    x.vcpus,x.memory_mib,x.volume_mib,x.auto_start,
    EXISTS(SELECT 1 FROM store_initializations i WHERE i.agent_id=e.agent_id AND i.volume_id=e.volume_id AND i.incarnation=e.incarnation)`

func scanEnrollment(row pgx.Row) (Enrollment, error) {
	var e Enrollment
	err := row.Scan(&e.AgentID, &e.OperationID, &e.VolumeID, &e.HostID, &e.Stage, &e.HarnessDigest, &e.HarnessSource, &e.RootfsDigest, &e.Incarnation,
		&e.Resources.VCPUs, &e.Resources.MemoryMiB, &e.Resources.DataVolumeMiB, &e.AutoStart, &e.Initialized)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrStoreEnrollment
	}
	return e, err
}

// The caller holds the agent row, acquired before any placement lock. Every
// enrollment mutation uses that common serialization domain.
func enrollment(ctx context.Context, tx pgx.Tx, id, host string) (Enrollment, error) {
	e, err := scanEnrollment(tx.QueryRow(ctx, `SELECT `+enrollmentColumns+`
        FROM store_enrollments e JOIN agent_specs x ON x.agent_id=e.agent_id
        JOIN harness_releases r ON r.id=x.release_id WHERE e.agent_id=$1`, id))
	if err == nil && e.HostID != host {
		err = ErrStoreEnrollment
	}
	return e, err
}

// PendingProvisioning discovers durable operations; it does not acquire a
// physical volume lock. Concurrent workers must serialize actual installation
// on the host, independently of SQL leases or this observation.
func (s *Store) PendingProvisioning(ctx context.Context, host string, limit int) ([]Enrollment, error) {
	if !catalogName(host) || limit < 1 || limit > 200 {
		return nil, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT `+enrollmentColumns+`
        FROM store_enrollments e JOIN agent_specs x ON x.agent_id=e.agent_id
        JOIN harness_releases r ON r.id=x.release_id JOIN agents a ON a.id=e.agent_id
        JOIN platform_operations o ON o.id=e.operation_id
        WHERE x.host_id=$1 AND a.phase='PROVISIONING' AND e.stage<>'READY'
        AND o.kind='provision' AND o.status IN ('PENDING','RUNNING')
        ORDER BY o.created_at,o.id LIMIT $2`, host, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Enrollment, 0)
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// ProvisioningTarget revalidates a queued job against its durable reservation.
// READY is an exact replay after a lost activation/queue ACK; the worker must
// return without creating, starting or reactivating anything in that case.
func (s *Store) ProvisioningTarget(ctx context.Context, id, host, operation string) (Enrollment, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return Enrollment{}, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return Enrollment{}, err
	}
	e, err := enrollment(ctx, tx, id, host)
	if err != nil {
		return e, err
	}
	if e.OperationID != operation || (e.Stage != "READY" && agents[id].Phase != "PROVISIONING") {
		return Enrollment{}, ErrStoreEnrollment
	}
	return e, nil
}

func (s *Store) RecordProvisionedVolume(ctx context.Context, proof ProvisionedVolume) error {
	if proof.Inode == 0 || proof.VolumeID == "" || proof.OperationID == "" {
		return ErrStoreEnrollment
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, proof.AgentID)
	if err != nil {
		return err
	}
	e, err := enrollment(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if e.OperationID != proof.OperationID || e.VolumeID != proof.VolumeID {
		return ErrStoreEnrollment
	}
	device, inode := fmt.Sprintf("%016x", proof.Device), fmt.Sprintf("%016x", proof.Inode)
	if e.Stage != "INSTALLING" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT volume_device=$2 AND volume_inode=$3
            FROM store_enrollments WHERE agent_id=$1`, proof.AgentID, device, inode).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrStoreEnrollment
		}
		// Replay only observes the original registration; it never resets READY
		// or grants authority to a later phase of the agent's life.
		return nil
	}
	if agents[proof.AgentID].Phase != "PROVISIONING" {
		return ErrStoreEnrollment
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_placements(agent_id,host_id) VALUES($1,$2)
        ON CONFLICT(agent_id) DO NOTHING`, proof.AgentID, proof.HostID); err != nil {
		return err
	}
	_, p, err := placementLock(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if p.Generation != 0 || p.State != "STOPPED" {
		return ErrStoreEnrollment
	}
	if _, err = tx.Exec(ctx, `UPDATE store_enrollments SET stage='FENCING',volume_device=$2,volume_inode=$3
        WHERE agent_id=$1`, proof.AgentID, device, inode); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE platform_operations SET status='RUNNING'
        WHERE id=$1 AND agent_id=$2 AND host_id=$3 AND kind='provision' AND status IN ('PENDING','RUNNING')`,
		proof.OperationID, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStoreEnrollment
	}
	return commit(ctx, tx)
}

func (s *Store) EnrollmentPendingFences(ctx context.Context, id, host, volume string) ([]string, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	e, err := enrollment(ctx, tx, id, host)
	if err != nil {
		return nil, err
	}
	if agents[id].Phase != "PROVISIONING" || e.Stage != "FENCING" || e.VolumeID != volume {
		return nil, ErrStoreEnrollment
	}
	rows, err := tx.Query(ctx, `SELECT c.subject FROM revocation_catalogue c WHERE NOT EXISTS
        (SELECT 1 FROM store_enrollment_receipts r WHERE r.agent_id=$1 AND r.volume_id=$2 AND r.incarnation=$3 AND r.subject=c.subject)
        ORDER BY c.subject`, id, volume, e.Incarnation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var subject string
		if err = rows.Scan(&subject); err != nil {
			return nil, err
		}
		result = append(result, subject)
	}
	return result, rows.Err()
}

// RecordEnrollmentInitialized follows a fixed-identity authenticated guest
// readiness report for this volume. The worker may authorize first-time format
// only while PROVISIONING, FENCING and !Initialized. Subsequent boots must open
// and validate the existing filesystem without any fallback to formatting.
// A pre-existing READY enrollment can gain this receipt only from a restricted
// validation boot; migration never fabricates an observation of its filesystem.
func (s *Store) RecordEnrollmentInitialized(ctx context.Context, proof EnrollmentBoot) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	e, err := enrollment(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if !((a.Phase == "PROVISIONING" && e.Stage == "FENCING") || (a.Phase == "LIVE" && e.Stage == "READY")) ||
		e.VolumeID != proof.VolumeID || e.Incarnation != proof.Incarnation || p.State != "RUNNING" || !p.FenceOnly ||
		proof.Generation == 0 || proof.VMID == "" || p.Generation != proof.Generation || p.VMID != proof.VMID {
		return ErrStoreEnrollment
	}
	if _, err = tx.Exec(ctx, `INSERT INTO store_initializations(agent_id,volume_id,boot_generation,boot_vm_id,incarnation)
        VALUES($1,$2,$3,$4,$5) ON CONFLICT(agent_id) DO NOTHING`, proof.AgentID, proof.VolumeID, proof.Generation, proof.VMID, proof.Incarnation); err != nil {
		return err
	}
	return commit(ctx, tx)
}

func ordinaryStoreReady(ctx context.Context, tx pgx.Tx, id string) error {
	var missing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM store_enrollments e WHERE e.agent_id=$1
        AND NOT EXISTS(SELECT 1 FROM store_initializations i WHERE i.agent_id=e.agent_id AND i.volume_id=e.volume_id AND i.incarnation=e.incarnation))`, id).Scan(&missing); err != nil {
		return err
	}
	if missing {
		return ErrStoreEnrollment
	}
	return nil
}

// RecordEnrollmentFence follows an authenticated guest ACK, after its local
// durable fence commit. A lost ACK is retried; an old boot response is refused
// even when a receipt with the same subject already exists.
func (s *Store) RecordEnrollmentFence(ctx context.Context, proof EnrollmentFence) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	e, err := enrollment(ctx, tx, proof.AgentID, proof.HostID)
	if err != nil {
		return err
	}
	if a.Phase != "PROVISIONING" || e.Stage != "FENCING" || !e.Initialized || e.VolumeID != proof.VolumeID || e.Incarnation != proof.Incarnation ||
		p.State != "RUNNING" || !p.FenceOnly || proof.Generation == 0 || proof.VMID == "" ||
		p.Generation != proof.Generation || p.VMID != proof.VMID {
		return ErrStoreEnrollment
	}
	tag, err := tx.Exec(ctx, `INSERT INTO store_enrollment_receipts(agent_id,volume_id,subject,boot_generation,boot_vm_id,incarnation)
        SELECT $1,$2,subject,$4,$5,$6 FROM revocation_catalogue WHERE subject=$3
        ON CONFLICT DO NOTHING`, proof.AgentID, proof.VolumeID, proof.Subject, proof.Generation, proof.VMID, proof.Incarnation)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var recorded bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM store_enrollment_receipts
            WHERE agent_id=$1 AND volume_id=$2 AND subject=$3 AND incarnation=$4)`, proof.AgentID, proof.VolumeID, proof.Subject, proof.Incarnation).Scan(&recorded); err != nil {
			return err
		}
		if !recorded {
			return ErrStoreEnrollment
		}
	}
	return commit(ctx, tx)
}

// ActivateProvisionedAgent is the only product path from PROVISIONING to LIVE.
// It checks the CURRENT catalogue while excluding all new revocation intents,
// requires physical retirement of the restricted boot (observed separately),
// and commits readiness with the operation result. No host/RPC work runs here.
func (s *Store) ActivateProvisionedAgent(ctx context.Context, wanted Enrollment) error {
	tx, err := s.beginCensus(ctx, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, wanted.AgentID, wanted.HostID)
	if err != nil {
		return err
	}
	e, err := enrollment(ctx, tx, wanted.AgentID, wanted.HostID)
	if err != nil {
		return err
	}
	if e.VolumeID != wanted.VolumeID || e.OperationID != wanted.OperationID || e.Incarnation != wanted.Incarnation {
		return ErrStoreEnrollment
	}
	if !e.Initialized {
		return ErrStoreEnrollment
	}
	if e.Stage == "READY" {
		return nil // Exact replay cannot resurrect or otherwise change this agent.
	}
	if a.Phase != "PROVISIONING" || e.Stage != "FENCING" || p.State != "STOPPED" {
		return ErrStoreEnrollment
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM revocation_catalogue c WHERE NOT EXISTS
        (SELECT 1 FROM store_enrollment_receipts r WHERE r.agent_id=$1 AND r.volume_id=$2 AND r.incarnation=$3 AND r.subject=c.subject))`,
		e.AgentID, e.VolumeID, e.Incarnation).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrPendingFences
	}
	if _, err = tx.Exec(ctx, "UPDATE agents SET phase='LIVE' WHERE id=$1", e.AgentID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1", e.AgentID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp()
        WHERE id=$1 AND agent_id=$2 AND host_id=$3 AND kind='provision' AND status='RUNNING'`,
		e.OperationID, e.AgentID, e.HostID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStoreEnrollment
	}
	if e.AutoStart {
		var seq int64
		if err = tx.QueryRow(ctx, `UPDATE agent_specs SET next_operation_seq=next_operation_seq+1
            WHERE agent_id=$1 RETURNING next_operation_seq`, e.AgentID).Scan(&seq); err != nil {
			return err
		}
		// A tenant agent has no owner user: its follow-up wake inherits the
		// requester of the provisioning operation instead.
		if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,owner_user_id,requested_by_principal_id,agent_id,host_id,seq,kind)
            SELECT $1,nullif($2::text,''),requested_by_principal_id,$3,$4,$5,'wake' FROM platform_operations WHERE id=$6`,
			newID("op"), a.Owner, e.AgentID, e.HostID, seq, e.OperationID); err != nil {
			return err
		}
	}
	return commit(ctx, tx)
}
