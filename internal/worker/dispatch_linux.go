//go:build linux

package worker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type DispatchOptions struct {
	Batch int
	// Concurrency bounds the jobs of a pass that run at once (S-02): jobs of
	// different agents run side by side, each agent's own jobs one after the
	// other in the order they were claimed. Zero means one at a time.
	Concurrency                                   int
	WorkLease, DeliveryLease, RetryBase, RetryMax time.Duration
	// Retention is how long finished records are kept (P-04); zero means
	// controlplane.DefaultFinishedRetention.
	Retention time.Duration
}

// MaxDispatchConcurrency bounds DispatchOptions.Concurrency.
const MaxDispatchConcurrency = 64

func (o DispatchOptions) valid() bool {
	return o.Batch >= 1 && o.Batch <= 256 && o.Concurrency >= 0 && o.Concurrency <= MaxDispatchConcurrency && o.WorkLease >= time.Microsecond && o.WorkLease <= 24*time.Hour && o.DeliveryLease >= time.Microsecond && o.DeliveryLease <= 24*time.Hour && o.RetryBase >= time.Microsecond && o.RetryMax >= o.RetryBase && o.RetryMax <= 24*time.Hour &&
		(o.Retention == 0 || o.Retention >= controlplane.MinFinishedRetention && o.Retention <= controlplane.MaxFinishedRetention)
}
func (o DispatchOptions) backoff(failures int) time.Duration {
	d := o.RetryBase
	for i := 0; i < failures && d < o.RetryMax; i++ {
		if d > o.RetryMax/2 {
			return o.RetryMax
		}
		d *= 2
	}
	return d
}

// DispatchPass processes bounded, durable jobs. Queue leases coordinate workers;
// business leases, immutable envelopes and SQL/host fences remain authoritative.
// ClaimWork moves a job to the tail, so new work and retries cannot monopolize it.
func (w *Placements) DispatchPass(ctx context.Context, o DispatchOptions, attemptTimeout time.Duration) error {
	_, err := w.dispatchPass(ctx, o, attemptTimeout)
	return err
}

// dispatchPass is DispatchPass, and reports whether it claimed a full batch
// of jobs: more work may wait, and the next pass may start at once (P-01).
func (w *Placements) dispatchPass(ctx context.Context, o DispatchOptions, attemptTimeout time.Duration) (bool, error) {
	if !o.valid() || attemptTimeout <= 0 {
		return false, errors.New("invalid dispatch options")
	}
	// Scheduling runs first so what it produces is discovered in this same pass.
	// Both steps use the database clock and are safe to repeat after a crash.
	var result error
	{
		step, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, releaseErr := w.store.ReleaseDueInstructions(step, nil, o.Batch)
		_, idleErr := w.store.ScheduleIdleSleeps(step, w.hostID, nil, o.Batch)
		// A disabled organization's VMs go to sleep (docs/api/organizations.md).
		_, suspendErr := w.store.ScheduleSuspensionSleeps(step, w.hostID, o.Batch)
		idleErr = errors.Join(idleErr, suspendErr)
		_, workErr := w.store.ExpireWorkingInvocations(step, nil, o.Batch)
		// A slot freed by a sleep, a deletion or a crash goes to the oldest
		// work waiting for capacity (ADR 017).
		queueErr := w.store.PromoteCapacityHead(step, w.hostID)
		result = errors.Join(releaseErr, idleErr, workErr, queueErr)
		cancel()
	}
	step, cancel := context.WithTimeout(ctx, attemptTimeout)
	err := w.store.DiscoverWork(step, w.hostID, o.Batch*4)
	cancel()
	if err != nil {
		return false, errors.Join(result, err)
	}
	{
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, receiptErr := w.store.PurgeExpiredReceipts(purge, min(o.Batch*4, 1000))
		result = errors.Join(result, receiptErr)
		cancel()
	}
	if transit := w.transit.Load(); transit != nil {
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, purgeErr := transit.PurgeExpired(purge, min(o.Batch*4, 1000))
		result = errors.Join(result, purgeErr)
		cancel()
	}
	{
		// The chunks of output streams go soon after their outcome (ADR 022).
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, chunkErr := w.store.PurgeStreamChunks(purge, nil, w.streamRetention(), min(o.Batch*4, 1000))
		result = errors.Join(result, chunkErr)
		cancel()
	}
	{
		// After the transit purge: an attachment goes once its invocation's own
		// content has gone, or when it expired unused.
		purge, cancel := context.WithTimeout(ctx, attemptTimeout)
		_, attachmentErr := w.store.PurgeAttachments(purge, nil, min(o.Batch*4, 1000))
		result = errors.Join(result, attachmentErr)
		cancel()
	}
	result = errors.Join(result, w.purgeAudit(ctx, attemptTimeout))
	result = errors.Join(result, w.purgeFinished(ctx, o, attemptTimeout))
	if w.provisioning != nil {
		step, cancel := context.WithTimeout(ctx, attemptTimeout)
		result = errors.Join(result, w.rolloutPass(step))
		cancel()
	}
	claimed, err := w.runJobs(ctx, o, attemptTimeout)
	return claimed == o.Batch, errors.Join(result, err)
}

// runJobs claims at most o.Batch jobs and runs up to o.Concurrency of them
// at once. A job of an agent that already has one running joins that agent's
// chain and runs after it, in the same slot: an agent's jobs keep their
// order, a delivery's FIFO and leases stay PostgreSQL's (ADR 007, 017), and
// a slow guest on one agent holds one slot, never the others (S-02). It
// returns how many jobs it claimed.
func (w *Placements) runJobs(ctx context.Context, o DispatchOptions, attemptTimeout time.Duration) (int, error) {
	slots := make(chan struct{}, max(o.Concurrency, 1))
	var (
		mu     sync.Mutex
		result error
		wg     sync.WaitGroup
		count  int
	)
	chains := map[string][]claimedJob{}
	report := func(err error) {
		mu.Lock()
		result = errors.Join(result, err)
		mu.Unlock()
	}
	// next takes agent's next job, or ends its chain.
	next := func(agent string) (claimedJob, bool) {
		mu.Lock()
		defer mu.Unlock()
		chain := chains[agent]
		if len(chain) == 0 {
			delete(chains, agent)
			return claimedJob{}, false
		}
		chains[agent] = chain[1:]
		return chain[0], true
	}
	for range o.Batch {
		if ctx.Err() != nil {
			report(ctx.Err())
			break
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			report(ctx.Err())
		}
		if ctx.Err() != nil {
			break
		}
		claim, cancel := context.WithTimeout(ctx, attemptTimeout)
		job, err := w.store.ClaimWork(claim, w.hostID, o.WorkLease)
		if errors.Is(err, controlplane.ErrNoWork) {
			if w.provisioning != nil {
				report(w.warmDeployment(claim))
			}
			cancel()
			<-slots
			break
		}
		cancel()
		if err != nil {
			report(err)
			<-slots
			break
		}
		count++
		if w.afterWorkClaim != nil {
			w.afterWorkClaim(job)
		}
		claimed := claimedJob{job: job, at: time.Now()}
		mu.Lock()
		chain, running := chains[job.AgentID]
		claimed.chained = running
		chains[job.AgentID] = append(chain, claimed)
		mu.Unlock()
		if running {
			<-slots // the agent's running chain takes it in its own slot
			continue
		}
		wg.Add(1)
		go func(agent string) {
			defer wg.Done()
			defer func() { <-slots }()
			for {
				c, ok := next(agent)
				if !ok {
					return
				}
				report(w.runJob(ctx, c, o, attemptTimeout))
			}
		}(job.AgentID)
	}
	wg.Wait()
	return count, result
}

// claimedJob is a job, when this process claimed it, and whether it waited
// behind its agent's earlier jobs.
type claimedJob struct {
	job     controlplane.WorkerJob
	at      time.Time
	chained bool
}

// runJob executes one claimed job and completes or retries it. A job that
// waited behind its agent's earlier jobs until its work lease could end
// before its attempt is left for that lease to expire and its next claim.
func (w *Placements) runJob(ctx context.Context, c claimedJob, o DispatchOptions, attemptTimeout time.Duration) error {
	job := c.job
	if c.chained && time.Since(c.at)+attemptTimeout > o.WorkLease {
		return nil
	}
	attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
	// The API request behind the job, for its event and its span.
	origin := w.jobOrigin(attempt, job)
	traced, span := w.startJob(attempt, job, origin)
	err := w.executeWork(traced, job, o.DeliveryLease)
	endJob(span, err)
	w.countJob(job.Kind, err)
	w.logJob(job, origin, err)
	if err == nil && w.afterWork != nil {
		w.afterWork(job)
	}
	cancel()
	finish, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer finishCancel()
	if err == nil {
		return w.store.CompleteWork(finish, job)
	}
	return errors.Join(err, w.store.RetryWorkWithCapacity(finish, job, o.backoff(job.Failures), errors.Is(err, runtime.ErrCapacity)))
}

// Replenish at most one VM after ordinary work. A warm boot may use a free
// slot, but it has no delivery or operation that justifies evicting a VM.
func (w *Placements) warmDeployment(ctx context.Context) error {
	id, err := w.store.NextWarmAgent(ctx, w.hostID)
	if errors.Is(err, controlplane.ErrNoWork) {
		return nil
	}
	if err != nil {
		return err
	}
	err = w.host.WithBarrier(ctx, id, func(ctx context.Context) error {
		_, err := w.startWithClaim(ctx, id, false, func(ctx context.Context) (controlplane.Placement, error) {
			return w.store.ClaimWarmPlacement(ctx, id, w.hostID, w.workerID, w.lease)
		})
		return err
	})
	if errors.Is(err, controlplane.ErrNoWork) || errors.Is(err, controlplane.ErrOrganizationQuota) || errors.Is(err, runtime.ErrCapacity) {
		return nil
	}
	return err
}

// auditPurgeEvery spaces the purges of the audit trail: its retention is
// counted in days.
const auditPurgeEvery = 10 * time.Minute

// purgeAudit deletes, at most every auditPurgeEvery, a batch of the audit
// events older than the retention the operator set (TEN-06); none without
// one. A full batch is followed by another at the next pass.
func (w *Placements) purgeAudit(ctx context.Context, timeout time.Duration) error {
	last := time.Unix(0, w.auditPurgedAt.Load())
	if time.Since(last) < auditPurgeEvery {
		return nil
	}
	purge, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	n, err := w.store.PurgeAudit(purge, 1000)
	if err == nil && n == 0 {
		w.auditPurgedAt.Store(time.Now().UnixNano())
	}
	return err
}

func (w *Placements) executeWork(ctx context.Context, j controlplane.WorkerJob, deliveryLease time.Duration) error {
	switch j.Kind {
	case "provision":
		return w.provision(ctx, j)
	case "lifecycle":
		return w.lifecycleOperation(ctx, j)
	case "resume":
		return w.resume(ctx, j)
	case "delivery":
		var runtime controlplane.InstructionRuntime = w
		if w.deliveries != nil {
			runtime = w.deliveries
		}
		var err error
		if transit := w.transit.Load(); transit != nil {
			err = transit.DispatchMailbox(ctx, j.ID, deliveryLease, runtime)
		} else {
			err = w.store.DispatchMailbox(ctx, j.ID, deliveryLease, runtime)
		}
		if errors.Is(err, controlplane.ErrNoDelivery) {
			return nil
		}
		return err
	case "closure":
		return w.store.ReconcileRequestClosure(ctx, j.ID, w)
	case "deletion":
		if err := w.store.ReconcileRevocation(ctx, j.ID, w); err != nil {
			return err
		}
		return w.RemoveDeletedStore(ctx, j.ID)
	case "expiration":
		err := w.store.RequestExpiration(ctx, j.ID)
		if errors.Is(err, controlplane.ErrTransition) {
			return nil
		}
		if err != nil && !errors.Is(err, controlplane.ErrClosurePending) {
			return err
		}
		return w.store.ReconcileRequestClosure(ctx, j.ID, w)
	default:
		return errors.New("unknown worker job kind")
	}
}
