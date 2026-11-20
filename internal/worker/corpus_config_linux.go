//go:build linux

package worker

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
)

// ServiceCorpus is the worker's corpus section (ADR 023 §3.2). This file
// reads all its keys, so that the configuration refuses only what it does
// not know; the source rules, the staging directory and the fetch limits are
// the corpus fetcher's (corpus_fetch.go). The image cache, the image limit
// and the builder belong to the builder and to publication.
type ServiceCorpus struct {
	// Cache holds the verified images; default <root>/corpora.
	Cache string `json:"cache,omitempty"`
	// Staging holds each build's downloads and output drive; default
	// <root>/corpus-staging.
	Staging string `json:"staging,omitempty"`
	// MaxArchiveMiB bounds one archive (default 2,048).
	MaxArchiveMiB int `json:"max_archive_mib,omitempty"`
	// MaxLFSMiB and MaxLFSObjects bound the LFS objects of one build
	// (default 20,480 and 10,000).
	MaxLFSMiB     int `json:"max_lfs_mib,omitempty"`
	MaxLFSObjects int `json:"max_lfs_objects,omitempty"`
	// MaxImageMiB bounds the output drive, so one image (default 16,384).
	MaxImageMiB int `json:"max_image_mib,omitempty"`
	// Builder is the builder agent's harness release and resources.
	Builder *ServiceCorpusBuilder `json:"builder,omitempty"`
	Sources ServiceCorpusSources  `json:"sources"`
}

// ServiceCorpusBuilder is corpus.builder.
type ServiceCorpusBuilder struct {
	Harness   controlplane.HarnessReference `json:"harness"`
	VCPUs     int                           `json:"vcpus,omitempty"`
	MemoryMiB int                           `json:"memory_mib,omitempty"`
	VolumeMiB int                           `json:"volume_mib,omitempty"`
}

// ServiceCorpusSources is corpus.sources: the forges a build may fetch from,
// and the internal forge addresses the operator allows, in the syntax of
// llm.allowed_internal_providers ("host:port" or an internal CIDR prefix).
type ServiceCorpusSources struct {
	Rules                []corpussource.Rule `json:"rules"`
	AllowedInternalHosts []string            `json:"allowed_internal_hosts,omitempty"`
}

var (
	// ErrCorpusConfiguration: the corpus section is invalid.
	ErrCorpusConfiguration = errors.New("invalid corpus configuration")
	// ErrCorpusNeedsLLM: the corpus section needs the llm section, whose
	// receipt key opens the source credentials, as it opens the provider
	// credentials; the builder's inference goes through its gateway too.
	ErrCorpusNeedsLLM = errors.New("the corpus section needs the llm section")
	// ErrClearTextCorpusSource: a corpus source rule is local, so it fetches
	// over plain HTTP; production refuses it, as it refuses a local
	// registry rule.
	ErrClearTextCorpusSource = errors.New("a local corpus source rule uses plain HTTP; production refuses it")
)

// CorpusSources is the validated source side of the corpus section.
type CorpusSources struct {
	Fetcher *corpussource.Fetcher
	Limits  corpussource.Limits
	// Staging is the absolute directory of the builds' downloads; Cache,
	// that of the verified images.
	Staging, Cache string
	// MaxImageMiB bounds a build's output drive.
	MaxImageMiB int
}

// OpenCorpusSources validates the corpus section and returns its source
// fetcher, or nil without the section. It creates the staging directory,
// private to the worker.
func (c ServiceConfig) OpenCorpusSources() (*CorpusSources, error) {
	out, err := c.corpusSources()
	if out == nil || err != nil {
		return nil, err
	}
	if err = os.MkdirAll(out.Staging, 0o700); err != nil {
		return nil, err
	}
	return out, os.Chmod(out.Staging, 0o700)
}

// OpenCorpusFetcher connects the configured forge client to leased build work.
func (c ServiceConfig) OpenCorpusFetcher(store *controlplane.Store, worker string) (*CorpusFetcher, error) {
	sources, err := c.OpenCorpusSources()
	if err != nil || sources == nil {
		return nil, err
	}
	if c.Corpus.Builder == nil {
		return nil, nil
	}
	harness := c.Corpus.Builder.Harness
	if harness.Name == "" || harness.Version == "" {
		return nil, ErrCorpusConfiguration
	}
	accounts, err := c.openBridgeAccounts(store)
	if err != nil {
		return nil, err
	}
	return NewCorpusFetcher(corpusFetchStore{store, c.HostID, harness.Name + "@" + harness.Version}, sources.Fetcher, accounts, sources.Staging, worker)
}

// corpusSources validates the corpus section and changes nothing.
func (c ServiceConfig) corpusSources() (*CorpusSources, error) {
	k := c.Corpus
	if k == nil {
		return nil, nil
	}
	if c.LLM == nil {
		return nil, ErrCorpusNeedsLLM
	}
	out := &CorpusSources{
		Staging: cmp.Or(k.Staging, filepath.Join(c.Root, "corpus-staging")),
		Cache:   cmp.Or(k.Cache, filepath.Join(c.Root, "corpora")),
		Limits: corpussource.Limits{
			ArchiveBytes: int64(cmp.Or(k.MaxArchiveMiB, 2048)) << 20,
			LFSBytes:     int64(cmp.Or(k.MaxLFSMiB, 20480)) << 20,
			LFSObjects:   cmp.Or(k.MaxLFSObjects, 10000),
		},
		MaxImageMiB: cmp.Or(k.MaxImageMiB, 16384),
	}
	switch {
	case !filepath.IsAbs(out.Staging) || !filepath.IsAbs(out.Cache) || filepath.Clean(out.Staging) != out.Staging || filepath.Clean(out.Cache) != out.Cache:
		return nil, fmt.Errorf("%w: cache and staging must be absolute, clean paths", ErrCorpusConfiguration)
	case k.MaxArchiveMiB < 0 || k.MaxArchiveMiB > 64<<10, k.MaxLFSMiB < 0 || k.MaxLFSMiB > 1<<20, k.MaxLFSObjects < 0 || k.MaxLFSObjects > 1_000_000,
		k.MaxImageMiB < 0 || k.MaxImageMiB > 1<<20:
		return nil, fmt.Errorf("%w: a limit is out of range", ErrCorpusConfiguration)
	}
	f, err := corpussource.New(corpussource.Policy{Rules: k.Sources.Rules, AllowedInternalHosts: k.Sources.AllowedInternalHosts}, out.Limits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorpusConfiguration, err)
	}
	out.Fetcher = f
	return out, nil
}

// corpusCheck is the preflight of the corpus section: valid, and over
// HTTPS in production.
func (c ServiceConfig) corpusCheck(mode operatorconfig.Mode) preflight.Result {
	const check = "corpus_sources"
	if _, err := c.corpusSources(); err != nil {
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the corpus section is invalid",
			Fix: "an llm section, absolute paths, limits in range and valid source rules (docs/worker.md#corpus-sources)"}
	}
	switch err := c.CheckProductionTransport(); {
	case !errors.Is(err, ErrClearTextCorpusSource):
		return preflight.Result{Check: check, Status: preflight.OK, Detail: "every corpus source rule uses HTTPS"}
	case mode == operatorconfig.Production:
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "a corpus source rule is local: plain HTTP",
			Fix: "serve the forge over HTTPS and allow its address in corpus.sources.allowed_internal_hosts; drop \"local\""}
	}
	return preflight.Result{Check: check, Status: preflight.Warn, Detail: "a corpus source rule is local: plain HTTP (development)",
		Fix: "drop \"local\" in production"}
}
