//go:build linux

package worker

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

type ServiceImage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ServiceKeyAuthority struct {
	Root     string `json:"root"`
	Identity string `json:"identity"`
}

// ServiceAuthorityReplica links both authorities to their replica on the
// standby (ADR 005, option a): each of their writes returns only once the
// replica holds it. Certificate and Key are this host's side of the mutual
// TLS link; ReplicaCertificate pins the standby's. Without this section the
// authorities are standalone and give no protection against the host's loss;
// once a snapshot armed them, the worker refuses to start without it.
type ServiceAuthorityReplica struct {
	Address            string `json:"address"`
	Certificate        string `json:"certificate"`
	Key                string `json:"key"`
	ReplicaCertificate string `json:"replica_certificate"`
}

func (r *ServiceAuthorityReplica) valid() bool {
	if r == nil {
		return true
	}
	if _, port, err := net.SplitHostPort(r.Address); err != nil || port == "" {
		return false
	}
	for _, path := range []string{r.Certificate, r.Key, r.ReplicaCertificate} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	return true
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
	RestoreAuthority *ServiceKeyAuthority     `json:"restore_authority,omitempty"`
	KeyAuthority     *ServiceKeyAuthority     `json:"key_authority,omitempty"`
	AuthorityReplica *ServiceAuthorityReplica `json:"authority_replica,omitempty"`
	Provisioning     *ProvisioningConfig  `json:"provisioning,omitempty"`
	Transit          *ServiceTransit      `json:"transit,omitempty"`
	LLM              *ServiceLLM          `json:"llm,omitempty"`
	Registry         *ServiceRegistry     `json:"registry,omitempty"`
	Directory        *ServiceDirectory    `json:"directory,omitempty"`
	SLIM             *ServiceSLIM         `json:"slim,omitempty"`
	// MetricsListen serves Prometheus metrics at /metrics on a loopback
	// address (OPS-02); none when empty.
	MetricsListen string `json:"metrics_listen,omitempty"`
	// Archives makes maintenance archive each agent's encrypted volume about
	// once a day (REC-02, ADR 004); none when absent.
	Archives *ServiceArchives `json:"archives,omitempty"`
}

// ServiceArchives configures the nightly volume archives. Root is a private
// directory outside the runtime and both authorities. Every bounds the age of
// each agent's newest archive (default 24h, 1h to 7 days). During the last
// SleepWindow before it (default Every/12, at most Every/2), a sleeping agent
// is captured; at Every, a running agent is stopped for its capture. Keep
// archives are kept per agent (default 7, 1 to 365). PerPass bounds the
// captures of a maintenance pass (default 1, at most 8). Timeout bounds one
// capture (default 30m, 1m to 6h, below Every).
type ServiceArchives struct {
	Root        string `json:"root"`
	Every       string `json:"every,omitempty"`
	SleepWindow string `json:"sleep_window,omitempty"`
	Keep        int    `json:"keep,omitempty"`
	PerPass     int    `json:"per_pass,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
}

// archives validates the archives section without touching its root; nil
// without the section. Capturing needs provisioning and both authorities.
func (c ServiceConfig) archives() (*Archives, error) {
	s := c.Archives
	if s == nil {
		return nil, nil
	}
	invalid := errors.New("invalid archive configuration")
	if c.Provisioning == nil || c.KeyAuthority == nil || c.RestoreAuthority == nil ||
		!filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || c.Root == "" {
		return nil, invalid
	}
	for _, root := range []string{c.Root, c.KeyAuthority.Root, c.RestoreAuthority.Root} {
		if restoreauthority.CheckSeparation(root, s.Root) != nil {
			return nil, invalid
		}
	}
	duration := func(text string, fallback, low, high time.Duration) (time.Duration, bool) {
		if text == "" {
			return fallback, true
		}
		d, err := time.ParseDuration(text)
		return d, err == nil && d >= low && d <= high
	}
	a := &Archives{Keep: cmp.Or(s.Keep, 7), PerPass: cmp.Or(s.PerPass, 1)}
	var ok [3]bool
	a.Every, ok[0] = duration(s.Every, 24*time.Hour, time.Hour, 7*24*time.Hour)
	a.SleepWindow, ok[1] = duration(s.SleepWindow, a.Every/12, 0, a.Every/2)
	a.Timeout, ok[2] = duration(s.Timeout, 30*time.Minute, time.Minute, min(6*time.Hour, a.Every-time.Second))
	if ok != [3]bool{true, true, true} || a.Keep < 1 || a.Keep > 365 || a.PerPass < 1 || a.PerPass > 8 {
		return nil, invalid
	}
	return a, nil
}

// OpenArchives opens the archive root, creating it private when absent, and
// returns the archives for MaintenanceOptions; nil without the section.
func (c ServiceConfig) OpenArchives() (*Archives, error) {
	a, err := c.archives()
	if a == nil || err != nil {
		return nil, err
	}
	if a.Store, err = volumearchive.New(c.Archives.Root); err != nil {
		return nil, err
	}
	return a, nil
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
// With authority_replica, it links both authorities to the replica: keys
// becomes journaled through the catalogue, one stream for both. Without it,
// both stay standalone, unless a snapshot armed them: then it refuses
// (ErrReplicaRequired). It does not contact the replica: the first
// operation does.
func (c ServiceConfig) OpenRestoreAuthority(ctx context.Context, keys *keyauthority.Files) (*restoreauthority.Catalog, error) {
	if c.RestoreAuthority == nil || keys == nil || !filepath.IsAbs(c.RestoreAuthority.Root) || !c.AuthorityReplica.valid() {
		return nil, restoreauthority.ErrInput
	}
	root, err := restoreauthority.Open(ctx, c.RestoreAuthority.Root, c.RestoreAuthority.Identity, keys.Identity())
	if err != nil {
		return nil, err
	}
	if err = root.SeparateFrom(c.Root); err == nil {
		err = c.replicate(ctx, root, keys)
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func (c ServiceConfig) replicate(ctx context.Context, root *restoreauthority.Catalog, keys *keyauthority.Files) error {
	state, err := root.Replication(ctx)
	if err != nil {
		return err
	}
	keysArmed, err := keys.Replicated()
	if err != nil {
		return err
	}
	if keysArmed != state.Armed {
		return restoreauthority.ErrUnavailable // armed by halves: take the snapshot again
	}
	r := c.AuthorityReplica
	if r == nil {
		if state.Armed {
			return restoreauthority.ErrReplicaRequired
		}
		return nil // standalone: no protection against the host's loss
	}
	if !state.Armed {
		return restoreauthority.ErrNotArmed
	}
	config, err := authoritylog.TLSFiles{Certificate: r.Certificate, Key: r.Key, PeerCertificate: r.ReplicaCertificate,
		RestoreAuthority: root.Identity(), KeyAuthority: keys.Identity()}.ClientTLS()
	if err != nil {
		return errors.Join(ErrAuthorityReplicaConfiguration, err)
	}
	client, err := authoritylog.NewClient(r.Address, config)
	if err != nil {
		return errors.Join(ErrAuthorityReplicaConfiguration, err)
	}
	if err = root.Replicate(ctx, client); err != nil {
		return err
	}
	keys.SetJournal(root)
	return nil
}

// ErrAuthorityReplicaConfiguration marks unusable TLS files for the replica.
var ErrAuthorityReplicaConfiguration = errors.New("invalid authority replica configuration")

// AuthorityFailure names why the authorities did not open, for the worker's
// exit code.
func AuthorityFailure(err error) string {
	switch {
	case errors.Is(err, restoreauthority.ErrReplicaRequired):
		return "authority_replica_required"
	case errors.Is(err, restoreauthority.ErrNotArmed):
		return "authority_replica_not_armed"
	case errors.Is(err, ErrAuthorityReplicaConfiguration):
		return "authority_replica_configuration_invalid"
	}
	return "restore_authority_unavailable"
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
	if c.AuthorityReplica != nil && (c.KeyAuthority == nil || !c.AuthorityReplica.valid()) {
		return r, 0, m, invalid
	}
	if _, err := c.archives(); err != nil {
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
