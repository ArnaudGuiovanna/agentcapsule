//go:build linux

package worker

import (
	"context"
	"errors"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// DefaultStoragePressure is the used share of a file system past which the
// host takes no new volume and no new harness image (OPS-03, ADR 014). It is
// the level of the critical disk alert: the last fifth stays for the sparse
// volumes of the existing agents to grow into.
const DefaultStoragePressure = 0.80

// StoragePressure watches the file system of the volumes (Data, the runtime
// root) and the one of the harness images (Images, the registry's cache)
// against Threshold. The worker records both in PostgreSQL at each
// maintenance pass, so that the API refuses new agents and imports before
// reserving anything; provisioning and imports check again before they
// write.
type StoragePressure struct {
	Data, Images string
	Threshold    float64
	// usedRatio reads a file system's used share; tests replace it.
	usedRatio func(string) (float64, error)
}

func diskUsedRatio(path string) (float64, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, err
	}
	if fs.Blocks == 0 {
		return 0, nil
	}
	return 1 - float64(fs.Bavail)/float64(fs.Blocks), nil
}

func (p *StoragePressure) ratio(path string) (float64, error) {
	if p.usedRatio != nil {
		return p.usedRatio(path)
	}
	return diskUsedRatio(path)
}

// Refuse returns controlplane.ErrStoragePressure when the file system of path
// is past the threshold, or when it cannot be read.
func (p *StoragePressure) Refuse(path string) error {
	r, err := p.ratio(path)
	if err != nil {
		return errors.Join(controlplane.ErrStoragePressure, err)
	}
	if r >= p.Threshold {
		return controlplane.ErrStoragePressure
	}
	return nil
}

func (p *StoragePressure) valid() bool {
	return p != nil && p.Data != "" && p.Images != "" && p.Threshold >= 0.5 && p.Threshold <= 0.95
}

// EnableStoragePressure makes maintenance record the host's storage pressure
// and provisioning refuse a new volume under it. With a registry, it serves
// the image file system's used share and whether each file system is past
// the threshold (OPS-03).
func (w *Placements) EnableStoragePressure(p *StoragePressure, registry *telemetry.Registry) error {
	if !p.valid() || !w.pressure.CompareAndSwap(nil, p) {
		return controlplane.ErrInput
	}
	if registry == nil {
		return nil
	}
	images := registry.Gauge("agentcapsule_worker_image_disk_used_ratio", "Used share of the file system holding the harness images (0 to 1).")
	pressed := registry.Gauge("agentcapsule_worker_storage_pressure", "1 while a file system (data, images) is past the storage pressure threshold: new agents or imports are refused.",
		telemetry.Label{Name: "filesystem", Values: []string{"data", "images"}})
	registry.Collect(func(context.Context) error {
		var result error
		for _, fs := range []struct{ name, path string }{{"data", p.Data}, {"images", p.Images}} {
			r, err := p.ratio(fs.path)
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
			if fs.name == "images" {
				images.Set(r)
			}
			pressed.Set(map[bool]float64{false: 0, true: 1}[r >= p.Threshold], fs.name)
		}
		return result
	})
	return nil
}

// recordStoragePressure tells PostgreSQL whether each file system is past
// the threshold. A file system that cannot be read counts as pressed.
func (w *Placements) recordStoragePressure(ctx context.Context, timeout time.Duration) error {
	p := w.pressure.Load()
	if p == nil {
		return nil
	}
	data, images := p.Refuse(p.Data) != nil, p.Refuse(p.Images) != nil
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return w.store.RecordStoragePressure(ctx, w.hostID, data, images)
}
