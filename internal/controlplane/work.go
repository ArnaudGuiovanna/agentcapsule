package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/workqueue"
	"github.com/jackc/pgx/v5"
)

type WorkerJob = workqueue.WorkerJob
type WorkKindStats = workqueue.WorkKindStats

var ErrNoWork = workqueue.ErrNoWork
var ErrWorkLeaseLost = workqueue.ErrWorkLeaseLost

func lockWorkerHost(ctx context.Context, tx pgx.Tx, host string) error {
	return workqueue.LockHost(ctx, tx, host)
}
