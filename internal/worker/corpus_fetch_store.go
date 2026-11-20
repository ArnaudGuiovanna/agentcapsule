package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
)

// A worker claims downloads for its host. Source and image data stay out of
// the database. Only drive descriptors and the lease token cross this boundary.
type corpusFetchStore struct {
	store         *controlplane.Store
	host, builder string
}

func (db corpusFetchStore) ClaimCorpusFetch(ctx context.Context, worker string, lease time.Duration) (CorpusFetchJob, error) {
	j, err := db.store.ClaimCorpusWork(ctx, db.host, worker, db.builder, true, lease)
	if err != nil {
		return CorpusFetchJob{}, err
	}
	job := CorpusFetchJob{BuildID: j.ID, TenantID: j.Tenant, CredentialID: j.CredentialID, Source: j.Source, Ref: j.Ref, Commit: j.Commit, Attempt: j.Attempt, Token: j.Token, Phase: CorpusFetchSource}
	if j.Phase == "FETCHING_LFS" {
		job.Phase = CorpusFetchLFS
		err = json.Unmarshal(j.Pointers, &job.Pointers)
	}
	return job, err
}
func (j CorpusFetchJob) work() controlplane.CorpusWork {
	phase := "FETCHING"
	if j.Phase == CorpusFetchLFS {
		phase = "FETCHING_LFS"
	}
	return controlplane.CorpusWork{ID: j.BuildID, Token: j.Token, Phase: phase}
}
func (db corpusFetchStore) PinCorpusCommit(ctx context.Context, j CorpusFetchJob, sha string) error {
	return db.store.PinCorpusCommit(ctx, j.work(), sha)
}
func (db corpusFetchStore) CompleteCorpusSource(ctx context.Context, j CorpusFetchJob, a corpussource.Archive) error {
	return db.store.CompleteCorpusDownload(ctx, j.work(), a)
}
func (db corpusFetchStore) CompleteCorpusLFS(ctx context.Context, j CorpusFetchJob, d corpussource.LFSDrive) error {
	return db.store.CompleteCorpusDownload(ctx, j.work(), d)
}
func (db corpusFetchStore) FailCorpusFetch(ctx context.Context, j CorpusFetchJob, code string, final bool, delay time.Duration) error {
	return db.store.FailCorpusWork(ctx, j.work(), code, final, delay)
}
