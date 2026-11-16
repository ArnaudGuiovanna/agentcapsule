//go:build linux

package worker

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

type ServiceImage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ServiceAuthority reaches the authority service, which owns both
// authorities (docs/adr/006-authority-service.md): its worker socket, and
// the identities of the two authorities it must hold. The worker never opens
// their directories.
type ServiceAuthority struct {
	Socket             string `json:"socket"`
	RestoreAuthorityID string `json:"restore_authority_id"`
	KeyAuthorityID     string `json:"key_authority_id"`
}

func (a *ServiceAuthority) valid() bool {
	return a != nil && filepath.IsAbs(a.Socket) && filepath.Clean(a.Socket) == a.Socket && len(a.Socket) <= 100 &&
		authoritylog.ValidID(a.RestoreAuthorityID, "restoreauth_") && authoritylog.ValidID(a.KeyAuthorityID, "keyauth_")
}

// ErrAuthorityServiceRequired refuses a configuration that still names the
// authorities' directories or their replica: they belong to the authority
// service, and a worker that opened them would write behind it.
var ErrAuthorityServiceRequired = errors.New("key_authority, restore_authority and authority_replica moved to the authority service: use the authority section")

// ServiceConfig is trusted operator input; the DSN is provided separately through
// AGENTCAPSULE_DATABASE_URL. Provisioning requires an explicit key authority and
// a dedicated UID range; without them it maintains preprovisioned placements.
type ServiceConfig struct {
	Version        int          `json:"version"`
	HostID         string       `json:"host_id"`
	Root           string       `json:"root"`
	Firecracker    ServiceImage `json:"firecracker"`
	Jailer         ServiceImage `json:"jailer"`
	Kernel         ServiceImage `json:"kernel"`
	Initrd         ServiceImage `json:"initrd"`
	MaxActive      int          `json:"max_active"`
	BootTimeout    string       `json:"boot_timeout"`
	BootLease      string       `json:"boot_lease"`
	PollInterval   string       `json:"poll_interval"`
	AttemptTimeout string       `json:"attempt_timeout"`
	DispatchBatch  int          `json:"dispatch_batch"`
	WorkLease      string       `json:"work_lease"`
	DeliveryLease  string       `json:"delivery_lease"`
	RetryBase      string       `json:"retry_base"`
	RetryMax       string       `json:"retry_max"`
	// Authority reaches the authority service; none on a laboratory host
	// without authorities.
	Authority *ServiceAuthority `json:"authority,omitempty"`
	// The sections of a worker that opened the authorities itself, before
	// the authority service: refused (ErrAuthorityServiceRequired).
	OldRestoreAuthority json.RawMessage     `json:"restore_authority,omitempty"`
	OldKeyAuthority     json.RawMessage     `json:"key_authority,omitempty"`
	OldAuthorityReplica json.RawMessage     `json:"authority_replica,omitempty"`
	Provisioning        *ProvisioningConfig `json:"provisioning,omitempty"`
	Transit             *ServiceTransit     `json:"transit,omitempty"`
	LLM                 *ServiceLLM         `json:"llm,omitempty"`
	Registry            *ServiceRegistry    `json:"registry,omitempty"`
	Directory           *ServiceDirectory   `json:"directory,omitempty"`
	SLIM                *ServiceSLIM        `json:"slim,omitempty"`
	// MetricsListen serves Prometheus metrics at /metrics on a loopback
	// address (OPS-02); none when empty.
	MetricsListen string `json:"metrics_listen,omitempty"`
	// Archives makes maintenance archive each agent's encrypted volume about
	// once a day (REC-02, ADR 004); none when absent.
	Archives *ServiceArchives `json:"archives,omitempty"`
	// DriveLimits caps the disk I/O of each VM (CAP-03, ADR 012). Every
	// number left out or zero takes its default (runtime.DefaultDriveLimits).
	DriveLimits *runtime.DriveLimits `json:"drive_limits,omitempty"`
	// RestartBudget bounds the failed boots and crashes of each agent's
	// guest (CAP-03, ADR 012); see ServiceRestartBudget.
	RestartBudget *ServiceRestartBudget `json:"restart_budget,omitempty"`
}

// ServiceRestartBudget: an agent whose guest fails to boot or crashes
// Failures times within Window is FAILED until it is woken or cleared.
// Defaults: 5 failures in 1h. Failures from 1 to 100, Window from 1m to 24h.
type ServiceRestartBudget struct {
	Failures int    `json:"failures,omitempty"`
	Window   string `json:"window,omitempty"`
}

// Restarts returns the configured restart budget, or the default without the
// section.
func (c ServiceConfig) Restarts() (controlplane.RestartBudget, error) {
	b := controlplane.DefaultRestartBudget
	if r := c.RestartBudget; r != nil {
		b.Failures = cmp.Or(r.Failures, b.Failures)
		if r.Window != "" {
			window, err := time.ParseDuration(r.Window)
			if err != nil {
				return b, errors.New("invalid restart budget")
			}
			b.Window = window
		}
	}
	if !b.Valid() {
		return b, errors.New("invalid restart budget")
	}
	return b, nil
}

// driveLimits returns the configured ceilings, each zero number taking its
// default.
func (c ServiceConfig) driveLimits() (runtime.DriveLimits, error) {
	l := runtime.DefaultDriveLimits
	if d := c.DriveLimits; d != nil {
		l.Volume.BandwidthMiBPerSecond = cmp.Or(d.Volume.BandwidthMiBPerSecond, l.Volume.BandwidthMiBPerSecond)
		l.Volume.IOPS = cmp.Or(d.Volume.IOPS, l.Volume.IOPS)
		l.Harness.BandwidthMiBPerSecond = cmp.Or(d.Harness.BandwidthMiBPerSecond, l.Harness.BandwidthMiBPerSecond)
		l.Harness.IOPS = cmp.Or(d.Harness.IOPS, l.Harness.IOPS)
	}
	return l, l.Validate()
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
// without the section. Capturing needs provisioning and the authorities.
// The root is checked against the runtime here, and against the
// authorities' directories once the service gives them, at each capture.
func (c ServiceConfig) archives() (*Archives, error) {
	s := c.Archives
	if s == nil {
		return nil, nil
	}
	invalid := errors.New("invalid archive configuration")
	if c.Provisioning == nil || c.Authority == nil ||
		!filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || c.Root == "" {
		return nil, invalid
	}
	if restoreauthority.CheckSeparation(c.Root, s.Root) != nil {
		return nil, invalid
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

// OpenAuthority returns the client of the authority service's worker
// socket, pinning both identities; nil without the authority section. It
// does not connect: WaitForAuthority does.
func (c ServiceConfig) OpenAuthority() (*authorityclient.Client, error) {
	if c.Authority == nil {
		return nil, nil
	}
	if !c.Authority.valid() {
		return nil, restoreauthority.ErrInput
	}
	return authorityclient.New(c.Authority.Socket, authorityservice.RoleWorker, c.Authority.RestoreAuthorityID, c.Authority.KeyAuthorityID)
}

// WaitForAuthority waits until the authority service answers, then checks
// that root lies outside both authorities' directories. A service that does
// not answer yet is waited for while ctx lasts, and waiting receives each
// failed attempt; a service that holds another installation's authorities,
// or speaks an older protocol, is refused at once.
func WaitForAuthority(ctx context.Context, a *authorityclient.Client, root string, waiting func(error)) error {
	delay := 100 * time.Millisecond
	for {
		_, err := a.Status(ctx)
		if err == nil {
			return a.SeparateFrom(root)
		}
		if errors.Is(err, authorityservice.ErrIdentity) || errors.Is(err, authorityservice.ErrProtocol) ||
			errors.Is(err, authorityservice.ErrRole) || ctx.Err() != nil {
			return err
		}
		if waiting != nil {
			waiting(err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		delay = min(2*delay, 5*time.Second)
	}
}

// AuthorityFailure names why the worker did not reach the authorities, for
// its exit code.
func AuthorityFailure(err error) string {
	switch {
	case errors.Is(err, ErrAuthorityServiceRequired):
		return "authority_service_required"
	case errors.Is(err, authorityservice.ErrIdentity):
		return "authority_identity_mismatch"
	case errors.Is(err, authorityservice.ErrRole):
		return "authority_socket_role_mismatch"
	case errors.Is(err, authorityservice.ErrProtocol):
		return "authority_protocol_unsupported"
	case errors.Is(err, restoreauthority.ErrInput):
		return "authority_domain_overlap"
	}
	return "authority_service_unavailable"
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
	return decodeServiceConfig(io.LimitReader(f, 65537))
}

// decodeServiceConfig reads one configuration object, refusing unknown
// fields and trailing data.
func decodeServiceConfig(r io.Reader) (ServiceConfig, error) {
	var c ServiceConfig
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
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
	if c.OldKeyAuthority != nil || c.OldRestoreAuthority != nil || c.OldAuthorityReplica != nil {
		return r, 0, m, ErrAuthorityServiceRequired
	}
	if (c.Authority != nil && !c.Authority.valid()) || (c.Provisioning != nil && (c.Authority == nil || !c.Provisioning.valid())) {
		return r, 0, m, invalid
	}
	if _, err := c.archives(); err != nil {
		return r, 0, m, invalid
	}
	if _, err := c.Restarts(); err != nil {
		return r, 0, m, invalid
	}
	drives, err := c.driveLimits()
	if err != nil {
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
		Initrd: c.Initrd.Path, InitrdSHA256: c.Initrd.SHA256, MaxActive: c.MaxActive, BootTimeout: boot, DriveLimits: drives, AuthenticatedControl: true}
	return r, lease, m, nil
}
