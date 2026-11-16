package controlplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrHostLost refuses work on a host that another host took over (ADR 020):
// its worker gets no job, and no agent is reserved on it.
var ErrHostLost = errors.New("this host was lost and another host took it over")

// maxTakeoverChain bounds the hosts a takeover chain may pass through: a host
// lost, then the host that took it over lost in turn, and so on.
const maxTakeoverChain = 64

// HostTakeover is the record that HostID took over LostHostID after a
// disaster (REC-03, ADR 020). It is final.
type HostTakeover struct {
	LostHostID, HostID string
	TakenOverAt        time.Time
}

// TakeOverHost records, once and for good, that host takes over the agents
// of lost: the operator fenced lost, which never serves again. From the
// commit, lost's worker gets no work and no agent is reserved on lost; each
// of its agents moves to host when a restore from one of its archives begins
// there (BeginVolumeRestore). Nothing else moves here. Repeating it returns
// the record. Refused when lost is unknown (ErrNotFound), already taken over
// by another host (ErrConflict), or when host is itself lost (ErrHostLost).
func (s *Store) TakeOverHost(ctx context.Context, lost, host string) (HostTakeover, error) {
	var t HostTakeover
	if !catalogName(lost) || !catalogName(host) || lost == host {
		return t, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return t, err
	}
	defer rollback(tx)
	// FOR UPDATE waits for every transaction that holds the lost host's queue
	// (lockWorkerHost): a job claimed before the takeover commits first.
	var known int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM (SELECT 1 FROM worker_hosts WHERE host_id=$1 FOR UPDATE) h", lost).Scan(&known); err != nil {
		return t, err
	}
	if known != 1 {
		return t, ErrNotFound
	}
	if err = lockWorkerHost(ctx, tx, host); err != nil {
		return t, err
	}
	err = tx.QueryRow(ctx, "SELECT lost_host_id,host_id,taken_over_at FROM host_takeovers WHERE lost_host_id=$1", lost).Scan(&t.LostHostID, &t.HostID, &t.TakenOverAt)
	if err == nil {
		if t.HostID != host {
			return t, ErrConflict
		}
		return t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return t, err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO host_takeovers(lost_host_id,host_id) VALUES($1,$2)
        RETURNING lost_host_id,host_id,taken_over_at`, lost, host).Scan(&t.LostHostID, &t.HostID, &t.TakenOverAt); err != nil {
		return t, err
	}
	return t, commit(ctx, tx)
}

// HostTakeoverOf returns the takeover of a lost host, with HostID the live
// host at the end of its chain: the host that takes its agents now. A host
// that is not lost gives ErrNotFound.
func (s *Store) HostTakeoverOf(ctx context.Context, lost string) (HostTakeover, error) {
	var t HostTakeover
	if !catalogName(lost) {
		return t, ErrInput
	}
	err := s.pool.QueryRow(ctx, `WITH RECURSIVE chain(successor,depth) AS (
          SELECT host_id,1 FROM host_takeovers WHERE lost_host_id=$1
          UNION ALL
          SELECT t.host_id,c.depth+1 FROM chain c JOIN host_takeovers t ON t.lost_host_id=c.successor WHERE c.depth<$2)
        SELECT h.lost_host_id,(SELECT successor FROM chain ORDER BY depth DESC LIMIT 1),h.taken_over_at
        FROM host_takeovers h WHERE h.lost_host_id=$1`, lost, maxTakeoverChain).Scan(&t.LostHostID, &t.HostID, &t.TakenOverAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// takenOverBy returns the lost host of the agent's placement when the chain
// of its takeovers ends at host; ErrPlacement otherwise. The caller holds the
// agent's lock.
func takenOverBy(ctx context.Context, tx pgx.Tx, agentID, host string) (string, error) {
	var lost string
	err := tx.QueryRow(ctx, `WITH RECURSIVE chain(lost,successor,depth) AS (
          SELECT t.lost_host_id,t.host_id,1 FROM host_takeovers t JOIN agent_placements p ON p.host_id=t.lost_host_id WHERE p.agent_id=$1
          UNION ALL
          SELECT c.lost,t.host_id,c.depth+1 FROM chain c JOIN host_takeovers t ON t.lost_host_id=c.successor WHERE c.depth<$3)
        SELECT lost FROM chain WHERE successor=$2 AND NOT EXISTS(SELECT 1 FROM host_takeovers WHERE lost_host_id=$2)`,
		agentID, host, maxTakeoverChain).Scan(&lost)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPlacement
	}
	return lost, err
}

// relocateAgent moves an agent from its lost host to host, in the
// transaction that begins its restore there. Its VMs went with the lost host:
// its placement is STOPPED on host, without a renewal or an observed control
// contract. Its specification and its unfinished operations name host, and
// its jobs move to host's queue, in their order, without a lease. Its volume
// is the lost host's until the new host creates it (RecordRelocatedVolume).
func relocateAgent(ctx context.Context, tx pgx.Tx, agentID, from, host string) error {
	if err := lockWorkerHost(ctx, tx, host); err != nil {
		return err
	}
	type job struct {
		kind, object string
		available    time.Time
		failures     int
	}
	rows, err := tx.Query(ctx, `SELECT kind,object_id,available_at,failures FROM worker_jobs
        WHERE host_id=$1 AND agent_id=$2 ORDER BY ticket FOR UPDATE`, from, agentID)
	if err != nil {
		return err
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.kind, &j.object, &j.available, &j.failures); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM worker_jobs WHERE host_id=$1 AND agent_id=$2", from, agentID); err != nil {
		return err
	}
	for _, j := range jobs {
		n, err := nextWorkTicket(ctx, tx, host)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO worker_jobs(host_id,kind,object_id,agent_id,ticket,available_at,failures)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (host_id,kind,object_id) DO NOTHING`, host, j.kind, j.object, agentID, n, j.available, j.failures); err != nil {
			return err
		}
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`UPDATE agent_placements SET host_id=$2,state='STOPPED',worker_id='',lease_until=NULL,vm_id='',fence_only=false,unclean_stop=false
            WHERE agent_id=$1`, []any{agentID, host}},
		{"DELETE FROM placement_renewals WHERE agent_id=$1", []any{agentID}},
		{"DELETE FROM placement_control_contracts WHERE agent_id=$1", []any{agentID}},
		{"UPDATE agent_specs SET host_id=$2 WHERE agent_id=$1", []any{agentID, host}},
		{"UPDATE platform_operations SET host_id=$2 WHERE agent_id=$1 AND status IN ('PENDING','RUNNING')", []any{agentID, host}},
	} {
		if _, err = tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return nil
}

// RecordRelocatedVolume records the identity of the volume file that host
// created for a relocated agent, before the archive is installed into it: the
// restore is DRAINING or INSTALLING, its placement STOPPED, and the agent's
// relocation pending. The file is a new one, of the same volume ID and key.
// Repeating it with the recorded identity succeeds.
func (s *Store) RecordRelocatedVolume(ctx context.Context, restoreID, host string, device, inode uint64) error {
	if !ValidRestoreID(restoreID) || inode == 0 {
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
	if plan.RelocatedFrom == "" {
		if plan.Device == device && plan.Inode == inode {
			return nil
		}
		return ErrStoreEnrollment
	}
	r := plan.Restore
	if (r.Step != RestoreDraining && r.Step != RestoreInstalling) || (a.Phase != "LIVE" && a.Phase != "QUIESCING") || plan.Placement.State != "STOPPED" {
		return ErrRestore
	}
	d, i := fmt.Sprintf("%016x", device), fmt.Sprintf("%016x", inode)
	if _, err = tx.Exec(ctx, "UPDATE store_enrollments SET volume_device=$2,volume_inode=$3 WHERE agent_id=$1", r.AgentID, d, i); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE volume_relocations SET volume_device=$2,volume_inode=$3,recorded_at=clock_timestamp()
        WHERE agent_id=$1 AND recorded_at IS NULL`, r.AgentID, d, i); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// LostHostAgent is an agent that was on a lost host, as its takeover sees
// it (ADR 020): where it is now, its newest restore, and its archives.
type LostHostAgent struct {
	AgentID, Phase string
	// HostID is the agent's host now: the lost host, or the host its
	// restore moved it to.
	HostID string
	// Stage and Incarnation are its volume's, when it has one.
	Stage       string
	Incarnation uint64
	Sealed      bool
	// Restore is its newest restore that was not superseded; nil when none.
	Restore *VolumeRestore
	// Archives are its published captures, on any host, newest first.
	Archives []VolumeArchive
}

// LostHostAgents lists the agents that are on the lost host, or that a
// restore moved off it, except deleted ones, by agent ID.
func (s *Store) LostHostAgents(ctx context.Context, lost string) ([]LostHostAgent, error) {
	if !catalogName(lost) {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id,a.phase,coalesce(p.host_id,x.host_id),coalesce(e.stage,''),coalesce(e.incarnation,0),
          EXISTS(SELECT 1 FROM store_seals z WHERE z.agent_id=a.id)
        FROM agents a LEFT JOIN agent_specs x ON x.agent_id=a.id LEFT JOIN agent_placements p ON p.agent_id=a.id
        LEFT JOIN store_enrollments e ON e.agent_id=a.id
        WHERE a.phase<>'DELETED' AND (x.host_id=$1 OR p.host_id=$1
          OR EXISTS(SELECT 1 FROM volume_relocations l WHERE l.agent_id=a.id AND l.from_host_id=$1))
        ORDER BY a.id`, lost)
	if err != nil {
		return nil, err
	}
	agents := make([]LostHostAgent, 0)
	for rows.Next() {
		var a LostHostAgent
		var incarnation int64
		if err = rows.Scan(&a.AgentID, &a.Phase, &a.HostID, &a.Stage, &incarnation, &a.Sealed); err != nil {
			rows.Close()
			return nil, err
		}
		a.Incarnation = uint64(incarnation)
		agents = append(agents, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for i := range agents {
		a := &agents[i]
		r, err := scanRestore(s.pool.QueryRow(ctx, `SELECT `+restoreColumns+` FROM volume_restores
            WHERE agent_id=$1 AND step<>$2 ORDER BY incarnation DESC LIMIT 1`, a.AgentID, RestoreSuperseded))
		if err == nil {
			a.Restore = &r
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		all, err := s.VolumeArchives(ctx, a.AgentID)
		if err != nil {
			return nil, err
		}
		a.Archives = make([]VolumeArchive, 0, len(all))
		for _, v := range all {
			if v.CapturedAt != nil {
				a.Archives = append(a.Archives, v)
			}
		}
		// Newest capture first: VolumeArchives orders by start.
		slices.SortStableFunc(a.Archives, func(x, y VolumeArchive) int { return y.CapturedAt.Compare(*x.CapturedAt) })
	}
	return agents, nil
}
