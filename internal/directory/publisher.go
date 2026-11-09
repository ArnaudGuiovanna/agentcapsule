package directory

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// Store is the publisher's view of PostgreSQL (controlplane.Store).
type Store interface {
	ClaimDirectoryWork(ctx context.Context, limit int, lease time.Duration) ([]controlplane.DirectoryWork, error)
	RecordDirectoryPublished(ctx context.Context, w controlplane.DirectoryWork, cid string) error
	RecordDirectoryUnpublished(ctx context.Context, w controlplane.DirectoryWork, reason string) error
	RecordDirectoryRetired(ctx context.Context, agentID, cid string) error
	DeferDirectoryWork(ctx context.Context, agentID string, delay time.Duration) error
}

// Directory is the publisher's view of the Directory (Client).
type Directory interface {
	Push(ctx context.Context, record []byte) (string, error)
	Delete(ctx context.Context, cid string) error
}

// Publisher brings the Directory to each agent's revision. Every step is
// recorded in PostgreSQL before the next one: a new record is recorded before
// the old one is deleted, so a crash leaves at worst a record to delete again,
// never a published record the platform does not know. Pushing and deleting
// are idempotent, so a step interrupted anywhere is simply done again.
type Publisher struct {
	Store     Store
	Directory Directory
	Batch     int           // work items per claim (default 16)
	Lease     time.Duration // time to finish one claim (default 1 minute)
	Timeout   time.Duration // per Directory call (default 10 seconds)
}

func (p *Publisher) batch() int {
	if p.Batch > 0 {
		return p.Batch
	}
	return 16
}

func (p *Publisher) lease() time.Duration {
	if p.Lease > 0 {
		return p.Lease
	}
	return time.Minute
}

func (p *Publisher) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 10 * time.Second
}

// backoff grows from 5 seconds to 5 minutes with the number of attempts.
func backoff(attempt int64) time.Duration {
	d := 5 * time.Second
	for i := int64(1); i < attempt && d < 5*time.Minute; i++ {
		d *= 2
	}
	return min(d, 5*time.Minute)
}

// RunOnce processes one batch and returns how many items it took. An error is
// returned only when PostgreSQL could not be read; a Directory outage defers
// the items concerned.
func (p *Publisher) RunOnce(ctx context.Context) (int, error) {
	work, err := p.Store.ClaimDirectoryWork(ctx, p.batch(), p.lease())
	if err != nil {
		return 0, err
	}
	for _, w := range work {
		if err = p.process(ctx, w); err != nil {
			delay := time.Second // another step won the race: retry soon
			if !errors.Is(err, controlplane.ErrConflict) {
				delay = backoff(w.Attempt)
			}
			if deferErr := p.Store.DeferDirectoryWork(ctx, w.AgentID, delay); deferErr != nil {
				return len(work), deferErr
			}
		}
	}
	return len(work), nil
}

// Run publishes until ctx ends, polling every interval and at once again
// while work remains. report receives errors that end a round.
func (p *Publisher) Run(ctx context.Context, interval time.Duration, report func(error)) {
	for {
		n, err := p.RunOnce(ctx)
		if err != nil && ctx.Err() == nil && report != nil {
			report(err)
		}
		if n == p.batch() && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (p *Publisher) call(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	return fn(ctx)
}

func (p *Publisher) retire(ctx context.Context, agent, cid string) error {
	if err := p.call(ctx, func(ctx context.Context) error { return p.Directory.Delete(ctx, cid) }); err != nil {
		return err
	}
	return p.Store.RecordDirectoryRetired(ctx, agent, cid)
}

func (p *Publisher) process(ctx context.Context, w controlplane.DirectoryWork) error {
	if w.RetiredCID != "" {
		if err := p.retire(ctx, w.AgentID, w.RetiredCID); err != nil {
			return err
		}
		w.RetiredCID = ""
	}
	if w.Revision == w.PublishedRevision {
		return nil // only a retired record was left
	}
	if !w.Publish {
		if err := p.Store.RecordDirectoryUnpublished(ctx, w, ""); err != nil {
			return err
		}
		if w.PublishedCID != "" {
			return p.retire(ctx, w.AgentID, w.PublishedCID)
		}
		return nil
	}
	record, err := Record(RecordInput{Tenant: w.TenantID, Agent: w.AgentID, Revision: w.Revision, Description: w.Description,
		Skills: w.Skills, Domains: w.Domains, CreatedAt: w.CreatedAt})
	if err != nil {
		return err
	}
	var cid string
	err = p.call(ctx, func(ctx context.Context) (err error) { cid, err = p.Directory.Push(ctx, record); return err })
	var invalid *InvalidRecordError
	if errors.As(err, &invalid) {
		// The description cannot be published: withdraw the previous record
		// too, rather than keep showing what the organization replaced.
		if err = p.Store.RecordDirectoryUnpublished(ctx, w, invalid.Message); err != nil {
			return err
		}
		if w.PublishedCID != "" {
			return p.retire(ctx, w.AgentID, w.PublishedCID)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err = p.Store.RecordDirectoryPublished(ctx, w, cid); err != nil {
		return err
	}
	if w.PublishedCID != "" && w.PublishedCID != cid {
		return p.retire(ctx, w.AgentID, w.PublishedCID)
	}
	return nil
}
