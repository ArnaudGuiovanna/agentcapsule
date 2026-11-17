//go:build linux

package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// DirectoryClientName is the client certificate's common name that the
// shipped Directory edge admits (deploy/interop/haproxy.cfg).
const DirectoryClientName = "agentcapsule-control-plane"

// ErrClearTextRegistry: a registry rule is local, so it fetches over plain
// HTTP; production refuses it (docs/adr/010-transport-security-and-preflight.md).
var ErrClearTextRegistry = errors.New("a local registry rule uses plain HTTP; production refuses it")

// CheckProductionTransport refuses what production does not allow in this
// configuration: a local registry rule, which downloads over plain HTTP and
// would send its credentials in clear.
func (c ServiceConfig) CheckProductionTransport() error {
	if c.Registry == nil {
		return nil
	}
	for _, r := range c.Registry.Rules {
		if r.Local {
			return ErrClearTextRegistry
		}
	}
	return nil
}

// PreflightArtifacts are the pinned runtime files, each with the copy the
// worker keeps under its runtime root.
func (c ServiceConfig) PreflightArtifacts() []preflight.Artifact {
	var out []preflight.Artifact
	for _, a := range []struct {
		name  string
		image ServiceImage
	}{{"firecracker", c.Firecracker}, {"jailer", c.Jailer}, {"kernel", c.Kernel}, {"initrd", c.Initrd}} {
		pinned := ""
		if filepath.IsAbs(c.Root) {
			pinned = filepath.Join(c.Root, "bin", a.name)
		}
		out = append(out, preflight.Artifact{Name: a.name, Path: a.image.Path, SHA256: a.image.SHA256, Pinned: pinned})
	}
	return out
}

// MandatoryPreflight is what the worker checks at every start (RUN-012): KVM,
// the kernel, cgroups, namespaces, the runtime file system and its free space
// (DEP-3: a failure from 95% used), and the pinned artifacts. It does not open
// the database or the network.
func (c ServiceConfig) MandatoryPreflight(ctx context.Context, h preflight.Host) []preflight.Result {
	return preflight.Mandatory(ctx, h, c.Root, c.PreflightArtifacts())
}

// Preflight runs every check of this configuration on h, for an operator
// preparing or verifying a host (agentcapsule-worker -preflight). The runtime
// disk is judged at the operator's levels (a failure from 80% used), stricter
// than at start.
func (c ServiceConfig) Preflight(ctx context.Context, h preflight.Host, mode operatorconfig.Mode, dsn string) []preflight.Result {
	out := c.MandatoryPreflight(ctx, h)
	for i, r := range out {
		if r.Check == "disk_runtime" {
			out[i] = preflight.Disk(h, "runtime", c.Root)
		}
	}
	out = append(out, preflight.Clock(h))
	if c.Archives != nil {
		out = append(out, preflight.Disk(h, "archives", c.Archives.Root))
	}
	out = append(out, c.authorityChecks(ctx)...)
	if c.MetricsListen != "" {
		out = append(out, preflight.Listen("metrics_listen", c.MetricsListen, true))
	}
	if c.Directory != nil {
		out = append(out, c.directoryChecks(ctx, h)...)
	}
	if c.Registry != nil {
		switch err := c.CheckProductionTransport(); {
		case err == nil:
			out = append(out, preflight.Result{Check: "registry", Status: preflight.OK, Detail: "every registry rule uses HTTPS"})
		case mode == operatorconfig.Production:
			out = append(out, preflight.Result{Check: "registry", Status: preflight.Fail, Detail: "a registry rule is local: plain HTTP",
				Fix: "serve the registry over HTTPS with a public name and drop \"local\""})
		default:
			out = append(out, preflight.Result{Check: "registry", Status: preflight.Warn, Detail: "a registry rule is local: plain HTTP (development)",
				Fix: "drop \"local\" in production"})
		}
		out = append(out, c.inspectionCheck(ctx, sandbox.AsRoot()))
	}
	return append(out, preflight.Database(ctx, mode, dsn))
}

// authorityChecks: the authority service answers on the worker socket with
// the pinned identities, and the runtime root and the archives lie outside
// both authorities' directories, which it gives, so that a restore of the
// data never brings back their keys. Its status reads no database. The
// directories and the link to the standby are the service's (ADR 006).
func (c ServiceConfig) authorityChecks(ctx context.Context) []preflight.Result {
	if c.Authority == nil {
		return nil
	}
	const check = "authority"
	client, err := c.OpenAuthority()
	if err != nil {
		return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: "the authority section is invalid",
			Fix: "an absolute socket path and both identities, as in runtime/worker/config.example.json"}}
	}
	defer client.Close()
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := client.Status(probe)
	switch {
	case errors.Is(err, authorityservice.ErrIdentity):
		return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: "the service on " + c.Authority.Socket + " holds other authorities than the pinned ones",
			Fix: "pin the identities of /etc/agentcapsule/authority.json in the authority section"}}
	case errors.Is(err, authorityservice.ErrRole):
		return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: c.Authority.Socket + " is not the service's worker socket",
			Fix: "use the service's worker_socket"}}
	case err != nil:
		return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: "the authority service does not answer on " + c.Authority.Socket,
			Fix: "start agentcapsule-authority (docs/recovery.md, Install the authority service)"}}
	}
	roots := []struct{ name, path string }{{"runtime root", c.Root}}
	if c.Archives != nil {
		roots = append(roots, struct{ name, path string }{"archives", c.Archives.Root})
	}
	for _, r := range roots {
		if client.SeparateFrom(r.path) != nil {
			return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: "the " + r.name + " (" + r.path + ") overlaps an authority directory",
				Fix: "keep the runtime root and the archives outside both authorities (ADR 005)"}}
		}
	}
	switch status.Mode {
	case restoreauthority.ModeDegraded:
		return []preflight.Result{{Check: check, Status: preflight.Warn, Detail: "the authority service runs in degraded mode, without its standby",
			Fix: "bring the standby back (docs/recovery.md, Degraded mode)"}}
	case restoreauthority.ModeWaiting:
		return []preflight.Result{{Check: check, Status: preflight.Warn, Detail: "the authority service waits for its standby and runs nothing",
			Fix: "start agentcapsule-authority serve on the standby, or check the address and the firewall"}}
	case restoreauthority.ModeStandalone:
		return []preflight.Result{{Check: check, Status: preflight.OK,
			Detail: "the authority service answers with the pinned identities; standalone: no replica, no protection against the host's loss"}}
	}
	return []preflight.Result{{Check: check, Status: preflight.OK, Detail: "the authority service answers with the pinned identities, synchronous with its standby"}}
}

func (c ServiceConfig) directoryChecks(ctx context.Context, h preflight.Host) []preflight.Result {
	d := c.Directory
	out := []preflight.Result{preflight.Certificate(h, "directory_certificate", d.Cert, d.Key, x509.ExtKeyUsageClientAuth, "", DirectoryClientName)}
	ca, err := readPublic(d.CA, 64<<10)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return append(out, preflight.Result{Check: "directory_ca", Status: preflight.Fail, Detail: d.CA + " holds no CA certificate",
			Fix: "install the Directory CA (directory-ca.pem of make-certs.sh)"})
	}
	if out[0].Status == preflight.Fail {
		return out
	}
	pair, err := operatorconfig.LoadCertificate(d.Cert, d.Key, x509.ExtKeyUsageClientAuth, h.Now())
	if err != nil {
		return out
	}
	// The client of internal/directory: the edge's name is the address's host.
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"}}
	return append(out, preflight.MutualTLS(ctx, "directory_edge", d.Address, config))
}

// inspectionCheck: debugfs, which inspects each downloaded image, runs
// confined here (package sandbox), as the configured inspection UID when the
// worker is root.
func (c ServiceConfig) inspectionCheck(ctx context.Context, asRoot bool) preflight.Result {
	const check = "registry_inspection"
	sb, err := c.inspection(asRoot)
	if err != nil {
		detail, _, _ := strings.Cut(strings.TrimPrefix(err.Error(), ErrInspectionUID.Error()+": "), "\n")
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "registry.inspection_uid is missing or not reserved: " + detail,
			Fix: "set registry.inspection_uid to a UID (and GID) reserved for image inspection: not 0 or 65535, below 2147483647, " +
				"outside the provisioning range, no account's or group's"}
	}
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = harnesspkg.CheckInspection(probe, sb); err != nil {
		detail, _, _ := strings.Cut(err.Error(), "\n")
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "debugfs cannot run confined: " + detail,
			Fix: "install e2fsprogs; use a kernel with mount_setattr (5.12), and user namespaces when the worker is not root; " +
				"run the worker as root of the host, not of a container's user namespace"}
	}
	detail := "debugfs runs confined as this account, in a user namespace (not root)"
	if asRoot {
		detail = "debugfs runs confined as UID and GID " + strconv.FormatUint(uint64(sb.UID), 10)
	}
	return preflight.Result{Check: check, Status: preflight.OK, Detail: detail}
}
