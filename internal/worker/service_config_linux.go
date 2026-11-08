//go:build linux

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type ServiceImage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ServiceKeyAuthority struct {
	Root     string `json:"root"`
	Identity string `json:"identity"`
}

// ServiceConfig is trusted operator input; the DSN is provided separately through
// AGENTCAPSULE_DATABASE_URL. Provisioning requires an explicit key authority and
// a dedicated UID range; without them it maintains preprovisioned placements.
type ServiceConfig struct {
	Version          int                  `json:"version"`
	HostID           string               `json:"host_id"`
	Root             string               `json:"root"`
	Firecracker      ServiceImage         `json:"firecracker"`
	Jailer           ServiceImage         `json:"jailer"`
	Kernel           ServiceImage         `json:"kernel"`
	Initrd           ServiceImage         `json:"initrd"`
	MaxActive        int                  `json:"max_active"`
	BootTimeout      string               `json:"boot_timeout"`
	BootLease        string               `json:"boot_lease"`
	PollInterval     string               `json:"poll_interval"`
	AttemptTimeout   string               `json:"attempt_timeout"`
	DispatchBatch    int                  `json:"dispatch_batch"`
	WorkLease        string               `json:"work_lease"`
	DeliveryLease    string               `json:"delivery_lease"`
	RetryBase        string               `json:"retry_base"`
	RetryMax         string               `json:"retry_max"`
	RestoreAuthority *ServiceKeyAuthority `json:"restore_authority,omitempty"`
	KeyAuthority     *ServiceKeyAuthority `json:"key_authority,omitempty"`
	Provisioning     *ProvisioningConfig  `json:"provisioning,omitempty"`
	Transit          *ServiceTransit      `json:"transit,omitempty"`
	LLM              *ServiceLLM          `json:"llm,omitempty"`
}

// OpenVolumeKeys never initializes an authority. Its public identity must have
// been pinned after explicit administrative setup, outside the runtime root.
func (c ServiceConfig) OpenVolumeKeys() (*keyauthority.Files, error) {
	if c.KeyAuthority == nil || !filepath.IsAbs(c.KeyAuthority.Root) {
		return nil, keyauthority.ErrInput
	}
	keys, err := keyauthority.Open(c.KeyAuthority.Root, c.KeyAuthority.Identity)
	if err != nil {
		return nil, err
	}
	if err = keys.SeparateFrom(c.Root); err != nil {
		return nil, err
	}
	return keys, nil
}

// OpenRestoreAuthority opens only explicitly initialized, pinned state outside
// the restored data root. Startup never creates a replacement catalogue.
func (c ServiceConfig) OpenRestoreAuthority(ctx context.Context, keys *keyauthority.Files) (*restoreauthority.Catalog, error) {
	if c.RestoreAuthority == nil || keys == nil || !filepath.IsAbs(c.RestoreAuthority.Root) {
		return nil, restoreauthority.ErrInput
	}
	root, err := restoreauthority.Open(ctx, c.RestoreAuthority.Root, c.RestoreAuthority.Identity, keys.Identity())
	if err != nil {
		return nil, err
	}
	if err = root.SeparateFrom(c.Root); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func LoadServiceConfig(path string) (ServiceConfig, error) {
	var c ServiceConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return c, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return c, err
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 || s.Size() > 65536 {
		return c, errors.New("worker configuration must be a bounded root-owned regular file without group/other write access")
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing worker configuration data")
	}
	return c, nil
}

func (c ServiceConfig) Settings() (runtime.FirecrackerOptions, time.Duration, MaintenanceOptions, error) {
	var r runtime.FirecrackerOptions
	var m MaintenanceOptions
	invalid := errors.New("invalid worker configuration")
	if c.Version != 1 || c.HostID == "" {
		return r, 0, m, invalid
	}
	if (c.KeyAuthority != nil) != (c.RestoreAuthority != nil) || (c.Provisioning != nil && (c.KeyAuthority == nil || !c.Provisioning.valid())) {
		return r, 0, m, invalid
	}
	boot, err := time.ParseDuration(c.BootTimeout)
	if err != nil || boot <= 0 {
		return r, 0, m, invalid
	}
	lease, err := time.ParseDuration(c.BootLease)
	if err != nil || lease <= boot || lease > 24*time.Hour {
		return r, 0, m, invalid
	}
	m.Interval, err = time.ParseDuration(c.PollInterval)
	if err != nil || m.Interval <= 0 || m.Interval > time.Minute {
		return r, 0, m, invalid
	}
	m.AttemptTimeout, err = time.ParseDuration(c.AttemptTimeout)
	if err != nil || m.AttemptTimeout <= boot {
		return r, 0, m, invalid
	}
	batch := c.DispatchBatch
	if batch == 0 {
		batch = 16
	}
	d := &DispatchOptions{Batch: batch}
	m.Dispatch = d
	for _, value := range []struct {
		text, fallback string
		out            *time.Duration
	}{
		{c.WorkLease, "2m", &d.WorkLease}, {c.DeliveryLease, "30s", &d.DeliveryLease},
		{c.RetryBase, "1s", &d.RetryBase}, {c.RetryMax, "30s", &d.RetryMax},
	} {
		s := value.text
		if s == "" {
			s = value.fallback
		}
		*value.out, err = time.ParseDuration(s)
		if err != nil {
			return r, 0, m, invalid
		}
	}
	if !d.valid() || d.WorkLease < m.AttemptTimeout+30*time.Second {
		return r, 0, m, invalid
	}
	r = runtime.FirecrackerOptions{Root: c.Root, Firecracker: c.Firecracker.Path, FirecrackerSHA256: c.Firecracker.SHA256,
		Jailer: c.Jailer.Path, JailerSHA256: c.Jailer.SHA256, Kernel: c.Kernel.Path, KernelSHA256: c.Kernel.SHA256,
		Initrd: c.Initrd.Path, InitrdSHA256: c.Initrd.SHA256, MaxActive: c.MaxActive, BootTimeout: boot, AuthenticatedControl: true}
	return r, lease, m, nil
}
