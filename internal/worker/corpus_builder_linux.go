//go:build linux

package worker

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

const corpusSchema = "agentcapsule.corpus-builder/v1"

type corpusGuest struct {
	w           *Placements
	source      *CorpusSources
	harness     controlplane.HarnessReference
	resources   controlplane.AgentResources
	catalog     *controlplane.AgentCatalog
	transit     *controlplane.Transit
	inspection  sandbox.Options
	evictions   *telemetry.Counter
	runtimeRoot string
	telemetry   *CorpusTelemetry
}

func (c ServiceConfig) OpenCorpusBuilder(w *Placements, tr *controlplane.Transit, metrics *CorpusTelemetry) (*corpusGuest, error) {
	if c.Corpus == nil || c.Corpus.Builder == nil {
		return nil, nil
	}
	if tr == nil || w.corpusCache == nil {
		return nil, controlplane.ErrInput
	}
	source, err := c.corpusSources()
	if err != nil {
		return nil, err
	}
	sb, err := c.inspection(sandbox.AsRoot())
	if err != nil {
		return nil, err
	}
	acc, err := c.openBridgeAccounts(w.store)
	if err != nil {
		return nil, err
	}
	catalog, err := controlplane.NewAgentCatalogWithTransit(acc, w.hostID, tr)
	if err != nil {
		return nil, err
	}
	b := c.Corpus.Builder
	g := &corpusGuest{runtimeRoot: c.Root, telemetry: metrics, w: w, source: source, harness: b.Harness, resources: controlplane.AgentResources{VCPUs: cmp.Or(b.VCPUs, 2), MemoryMiB: cmp.Or(b.MemoryMiB, 4096), DataVolumeMiB: cmp.Or(b.VolumeMiB, 2048)}, catalog: catalog, transit: tr, inspection: sb}
	if g.resources.VCPUs < 1 || g.resources.VCPUs > 8 || g.resources.MemoryMiB < 128 || g.resources.MemoryMiB > 8192 || g.resources.DataVolumeMiB < 64 || g.resources.DataVolumeMiB > 32768 {
		return nil, ErrCorpusConfiguration
	}
	return g, nil
}
func (g *corpusGuest) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	w, source := g.w, g.source
	var err error
	var nextGC time.Time
	for ctx.Err() == nil {
		if _, err = w.store.ExpireCorpusBuilds(ctx); err != nil {
			report(err)
		}
		worked, err := g.one(ctx)
		if err != nil {
			report(err)
		}
		if worked && err == nil {
			continue
		}
		if time.Now().After(nextGC) {
			gc := GarbageCollection{Store: w.store, HostID: w.hostID, RuntimeRoot: g.runtimeRoot, CorpusCache: source.Cache, CorpusStaging: source.Staging}
			var summary GarbageReport
			summary, err = gc.Run(ctx, false)
			if g.evictions != nil && summary.Corpora != nil {
				g.evictions.Add(float64(len(summary.Corpora.Unused)))
			}
			if err != nil {
				report(err)
			}
			nextGC = time.Now().Add(time.Hour)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	return ctx.Err()
}
func (g corpusGuest) one(ctx context.Context) (bool, error) {
	j, err := g.w.store.ClaimCorpusWork(ctx, g.w.hostID, g.w.workerID, g.harness.Name+"@"+g.harness.Version, false, 30*time.Minute)
	if errors.Is(err, controlplane.ErrNoWork) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	code, err := g.phase(ctx, j)
	if err == nil || ctx.Err() != nil || errors.Is(err, controlplane.ErrLeaseLost) {
		return true, err
	}
	if code == "" {
		if storeErr := g.w.store.FailCorpusWork(ctx, j, "unavailable", j.Attempt >= MaxCorpusFetchAttempts, backoff(j.Attempt)); storeErr != nil {
			return true, storeErr
		}
		return true, err
	}
	return true, g.w.store.FailCorpusWork(ctx, j, code, true, 0)
}

func (g corpusGuest) phase(ctx context.Context, j controlplane.CorpusWork) (string, error) {
	agent, digest, ready, err := g.w.store.EnsureCorpusBuilder(ctx, j, g.harness, g.resources)
	if err != nil {
		if errors.Is(err, controlplane.ErrRelease) || errors.Is(err, controlplane.ErrStorageCapacity) {
			return "unavailable", err
		}
		return "", err
	}
	if !ready {
		return "", g.w.store.WaitCorpusWork(ctx, j, time.Second)
	}
	uuid, err := corpuspkg.ImageUUID(j.Corpus, j.Commit, digest)
	if err != nil {
		return "invalid_image", err
	}
	dir := filepath.Join(g.source.Staging, j.ID)
	output := filepath.Join(dir, "output.ext4")
	size := int64(g.source.MaxImageMiB) << 20
	phase := map[string]string{"SCANNING": "scan", "CONVERTING": "convert", "PACKAGING": "package"}[j.Phase]
	in := map[string]any{"schema": corpusSchema, "phase": phase, "build_id": j.ID}
	switch j.Phase {
	case "SCANNING":
		in["source"], in["name"], in["builder"], in["commit"], in["path"] = j.SourceDrive, j.Name, j.Builder, j.Commit, j.Path
		if j.Cursor != "" {
			in["cursor"] = j.Cursor
		}
	case "CONVERTING":
		in["source"] = j.SourceDrive
		if len(j.LFSDrive) > 0 {
			var lfs corpussource.LFSDrive
			if err = json.Unmarshal(j.LFSDrive, &lfs); err != nil {
				return "integrity", err
			}
			in["lfs"] = corpussource.Archive{Bytes: lfs.Bytes, SHA256: lfs.SHA256}
		}
	case "PACKAGING":
		in["uuid"], in["output"] = uuid, map[string]int64{"bytes": size}
	default:
		return "builder_failed", controlplane.ErrInput
	}
	if j.InvocationID == "" {
		if err = g.prepareDrives(ctx, j, agent, output, size); err != nil {
			return "unavailable", err
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "builder_failed", err
	}
	result, done, err := g.catalog.CorpusInvocation(ctx, j, raw)
	if err != nil {
		if done {
			return "builder_failed", err
		}
		return "", err
	}
	if !done {
		return "", g.w.store.WaitCorpusWork(ctx, j, time.Second)
	}
	var message capsuleprotocol.OwnerMessage
	if strictCorpusJSON(result, &message) != nil || message.Validate() != nil || len(message.Content) != 1 || message.Content[0].Type != "json" {
		return "builder_failed", controlplane.ErrInput
	}
	content := []byte(message.Content[0].JSON)
	g.telemetry.Phase(strings.ToLower(j.Phase), j.PhaseStarted)
	switch phase {
	case "scan":
		return g.scan(ctx, j, content)
	case "convert":
		var v struct {
			Schema, Phase string
			Files         map[string]int `json:"files"`
			Tokens        *int64         `json:"tokens"`
		}
		if strictCorpusJSON(content, &v) != nil || v.Schema != corpusSchema || v.Phase != phase || v.Tokens == nil || *v.Tokens < 0 || !validFileCounts(v.Files, "converted", "cached", "skipped", "failed") {
			return "builder_failed", controlplane.ErrInput
		}
		return "", g.w.store.FinishCorpusConversion(ctx, j, v.Files)
	default:
		var v struct {
			Schema, Phase string
			ImageBytes    int64  `json:"image_bytes"`
			Documents     *int   `json:"documents"`
			Tokens        *int64 `json:"tokens"`
			IndexTokens   *int64 `json:"index_tokens"`
		}
		if strictCorpusJSON(content, &v) != nil || v.Schema != corpusSchema || v.Phase != phase || v.Documents == nil || *v.Documents < 0 || v.Tokens == nil || *v.Tokens < 0 || v.IndexTokens == nil || *v.IndexTokens < 0 {
			return "builder_failed", controlplane.ErrInput
		}
		if v.ImageBytes <= 0 || v.ImageBytes > size {
			return "invalid_image", controlplane.ErrInput
		}
		if err = g.stopGuest(ctx, agent); err != nil {
			return "", err
		}
		if err = g.w.host.SetBuildDrives(ctx, agent, nil); err != nil {
			return "", err
		}
		return g.finishImage(ctx, j, uuid, digest, output, v.ImageBytes)
	}
}

// The guest is the sole writer until stopped. The host only reads the output
// after that point, including on a retry following a worker interruption.
func (g corpusGuest) stopGuest(ctx context.Context, agent string) error {
	runs, err := g.w.reconcileAgent(ctx, agent)
	if err != nil {
		return err
	}
	if run, ok := runs[agent]; ok {
		return g.w.stop(ctx, agent, run.Generation, false)
	}
	return nil
}
func (g corpusGuest) prepareDrives(ctx context.Context, j controlplane.CorpusWork, agent, output string, size int64) error {
	if err := g.stopGuest(ctx, agent); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = controlplane.ErrInput
	}
	if err == nil && st.Size() != size {
		err = f.Truncate(size)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	drives := runtime.BuildDrives{Source: filepath.Join(filepath.Dir(output), CorpusSourceFile), Output: output}
	if len(j.LFSDrive) > 0 {
		drives.LFS = filepath.Join(filepath.Dir(output), corpussource.LFSFile)
	}
	return g.w.host.SetBuildDrives(ctx, agent, &drives)
}
func strictCorpusJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return controlplane.ErrInput
	}
	return nil
}
func validFileCounts(counts map[string]int, names ...string) bool {
	if len(counts) != len(names) {
		return false
	}
	for _, n := range names {
		v, ok := counts[n]
		if !ok || v < 0 {
			return false
		}
	}
	return true
}
func (g corpusGuest) scan(ctx context.Context, j controlplane.CorpusWork, raw []byte) (string, error) {
	var v struct {
		Schema, Phase, Manifest string
		Errors                  []string
		Files                   map[string]int
		Bytes                   *int64
		Kinds                   map[string]int
		Estimate                map[string]int
		Aliases                 []string
		LFS                     []corpussource.Pointer
		Next                    string `json:"next_cursor"`
	}
	if strictCorpusJSON(raw, &v) != nil || v.Schema != corpusSchema || v.Phase != "scan" || len(v.Errors) > 16 {
		return "builder_failed", controlplane.ErrInput
	}
	if v.Manifest == "invalid" {
		return "invalid_manifest", controlplane.ErrInput
	}
	if v.Manifest != "valid" || v.Bytes == nil || *v.Bytes < 0 || !validFileCounts(v.Files, "total", "included", "skipped") || !validFileCounts(v.Estimate, "llm_calls", "input_tokens", "audio_seconds", "pages") || v.LFS == nil || len(v.LFS) > 256 {
		return "builder_failed", controlplane.ErrInput
	}
	if v.Next != "" {
		before, _ := strconv.Atoi(j.Cursor)
		after, err := strconv.Atoi(v.Next)
		if err != nil || after <= before || len(v.LFS) == 0 || strconv.Itoa(after) != v.Next {
			return "builder_failed", controlplane.ErrInput
		}
	}
	var pointers []corpussource.Pointer
	if err := json.Unmarshal(j.Pointers, &pointers); err != nil {
		return "integrity", err
	}
	pointers = append(pointers, v.LFS...)
	if len(pointers) > g.source.Limits.LFSObjects {
		return "too_large", corpussource.ErrTooLarge
	}
	var total int64
	seen := map[string]bool{}
	for _, p := range pointers {
		if len(p.OID) != 64 || strings.Trim(p.OID, "0123456789abcdef") != "" || p.Size < 0 || seen[p.OID] {
			return "builder_failed", controlplane.ErrInput
		}
		if p.Size > g.source.Limits.LFSBytes-total {
			return "too_large", corpussource.ErrTooLarge
		}
		total += p.Size
		seen[p.OID] = true
	}
	return "", g.w.store.FinishCorpusScan(ctx, j, pointers, v.Files, v.Estimate, v.Next, len(pointers) > 0)
}

func (g *corpusGuest) Observe(reg *telemetry.Registry) {
	outcomes := reg.Counter("agentcapsule_worker_corpus_builds_total", "Corpus builds by outcome.", telemetry.Label{Name: "outcome", Values: []string{"review", "canceled", "expired", "policy", "not_found", "access_denied", "integrity", "too_large", "invalid_manifest", "builder_failed", "invalid_image", "timeout", "unavailable", "storage_pressure", "quota_exceeded"}})
	cacheBytes := reg.Gauge("agentcapsule_worker_corpus_cache_bytes", "Bytes of packages retained in the corpus image cache.")
	g.evictions = reg.Counter("agentcapsule_worker_corpus_evictions_total", "Corpus packages evicted by the worker.")
	var mu sync.Mutex
	previous := map[string]int64{}
	reg.Collect(func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		counts, err := g.w.store.CorpusBuildOutcomes(ctx, g.w.hostID)
		if err != nil {
			return err
		}
		for outcome, n := range counts {
			if delta := n - previous[outcome]; delta > 0 {
				outcomes.Add(float64(delta), outcome)
			}
			previous[outcome] = n
		}
		size, _, err := treeUsage(filepath.Join(g.source.Cache, "sha256"))
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		if err == nil {
			cacheBytes.Set(float64(size))
		}
		return err
	})
}
