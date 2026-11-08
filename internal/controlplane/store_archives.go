package controlplane

import (
	"context"
	"strconv"
)

// StoreArchivePlan is a SQL precondition, not physical proof. The host must
// separately check the registered inode and exclude every writer during capture.
type StoreArchivePlan struct {
	Enrollment    Enrollment
	Placement     Placement
	Device, Inode uint64
}

func (s *Store) StoreArchiveTarget(ctx context.Context, id, host string) (StoreArchivePlan, error) {
	var plan StoreArchivePlan
	tx, err := s.begin(ctx)
	if err != nil {
		return plan, err
	}
	defer rollback(tx)
	a, p, err := placementLock(ctx, tx, id, host)
	if err != nil {
		return plan, err
	}
	if a.Phase != "LIVE" || p.State != "STOPPED" || p.UncleanStop {
		return plan, ErrPlacement
	}
	e, err := enrollment(ctx, tx, id, host)
	if err != nil {
		return plan, err
	}
	if e.Stage != "READY" || !e.Initialized {
		return plan, ErrStoreEnrollment
	}
	var device, inode string
	if err = tx.QueryRow(ctx, "SELECT volume_device,volume_inode FROM store_enrollments WHERE agent_id=$1", id).Scan(&device, &inode); err != nil {
		return plan, err
	}
	plan.Device, err = strconv.ParseUint(device, 16, 64)
	if err != nil {
		return plan, ErrStoreEnrollment
	}
	plan.Inode, err = strconv.ParseUint(inode, 16, 64)
	if err != nil || plan.Inode == 0 {
		return plan, ErrStoreEnrollment
	}
	plan.Enrollment, plan.Placement = e, p
	return plan, nil
}
