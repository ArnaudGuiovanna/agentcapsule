//go:build linux

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

const enricherSchema = "agentcapsule.corpus-enricher/v1"

func (g corpusGuest) enrichOne(ctx context.Context) (bool, error) {
	w, err := g.w.store.ClaimCorpusExtension(ctx, g.w.hostID)
	if errors.Is(err, controlplane.ErrNoWork) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	code, err := g.enrichment(ctx, w)
	if code == "" || ctx.Err() != nil || errors.Is(err, controlplane.ErrLeaseLost) {
		return true, err
	}
	return true, g.w.store.SettleCorpusExtension(ctx, w, nil, code)
}

func (g corpusGuest) enrichment(ctx context.Context, w controlplane.CorpusExtensionWork) (string, error) {
	agent, ready, err := g.w.store.EnsureCorpusEnricher(ctx, w, g.resources)
	if err != nil {
		if errors.Is(err, controlplane.ErrRelease) || errors.Is(err, controlplane.ErrStorageCapacity) {
			return "unavailable", err
		}
		return "", err
	}
	if !ready {
		return "", g.w.store.SettleCorpusExtension(ctx, w, nil, "")
	}
	sum := sha256.Sum256([]byte(enricherSchema + "\x00" + w.Name + "\x00" + w.BaseDigest + "\x00" + w.HarnessDigest))
	uuid, err := corpuspkg.ImageUUID(w.Corpus, w.Commit, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		return "invalid_image", err
	}
	size := int64(g.source.MaxImageMiB) << 20
	dir := filepath.Join(g.source.Staging, w.ID)
	output := filepath.Join(dir, "output.ext4")
	if w.InvocationID == "" {
		if err = g.stopGuest(ctx, agent); err != nil {
			return "", err
		}
		if err = os.MkdirAll(dir, 0700); err != nil {
			return "unavailable", err
		}
		// A failed prior invocation may leave data in unallocated ext4 blocks.
		if err = os.Remove(output); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "unavailable", err
		}
		if err = prepareCorpusOutput(output, size); err != nil {
			return "unavailable", err
		}
		err = g.w.corpusCache.withLock(ctx, func() error {
			base, err := g.w.corpusCache.image(ctx, controlplane.BootCorpus{Digest: w.BaseDigest, UUID: w.BaseUUID, Mount: "base"})
			if err != nil {
				return err
			}
			return g.w.host.SetEnrichmentDrives(ctx, agent, base, output)
		})
		if err != nil {
			return "unavailable", err
		}
	}
	raw, err := json.Marshal(map[string]any{"schema": enricherSchema, "build_id": w.Build, "name": w.Name, "mount": "/corpus/base", "uuid": uuid, "output": map[string]int64{"bytes": size}})
	if err != nil {
		return "enricher_failed", err
	}
	result, done, err := g.catalog.CorpusExtensionInvocation(ctx, w, raw)
	if err != nil {
		if done {
			return "enricher_failed", err
		}
		return "", err
	}
	if !done {
		return "", g.w.store.SettleCorpusExtension(ctx, w, nil, "")
	}
	if err = g.stopGuest(ctx, agent); err != nil {
		return "", err
	}
	if err = g.w.host.SetEnrichmentDrives(ctx, agent, runtime.CorpusImage{}, ""); err != nil {
		return "", err
	}
	var msg capsuleprotocol.OwnerMessage
	var reply struct {
		Schema     string `json:"schema"`
		ImageBytes int64  `json:"image_bytes"`
	}
	if strictCorpusJSON(result, &msg) != nil || msg.Validate() != nil || len(msg.Content) != 1 || msg.Content[0].Type != "json" || strictCorpusJSON([]byte(msg.Content[0].JSON), &reply) != nil || reply.Schema != enricherSchema || reply.ImageBytes <= 0 || reply.ImageBytes > size {
		return "enricher_failed", controlplane.ErrInput
	}
	job := controlplane.CorpusWork{ID: w.Build, Commit: w.Commit, Name: w.Name, Builder: w.HarnessName + "@" + w.HarnessVersion}
	return g.finishImage(ctx, job, uuid, w.HarnessDigest, output, reply.ImageBytes, &w)
}
