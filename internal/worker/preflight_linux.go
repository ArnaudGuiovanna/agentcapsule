//go:build linux

package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
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
// the kernel, cgroups, namespaces, the runtime file system and the pinned
// artifacts. It does not open the database or the network.
func (c ServiceConfig) MandatoryPreflight(ctx context.Context, h preflight.Host) []preflight.Result {
	return preflight.Mandatory(ctx, h, c.Root, c.PreflightArtifacts())
}

// Preflight runs every check of this configuration on h, for an operator
// preparing or verifying a host (agentcapsule-worker -preflight).
func (c ServiceConfig) Preflight(ctx context.Context, h preflight.Host, mode operatorconfig.Mode, dsn string) []preflight.Result {
	out := c.MandatoryPreflight(ctx, h)
	out = append(out, preflight.Clock(h), preflight.Disk(h, "runtime", c.Root))
	if c.Archives != nil {
		out = append(out, preflight.Disk(h, "archives", c.Archives.Root))
	}
	out = append(out, c.authorityChecks()...)
	if c.MetricsListen != "" {
		out = append(out, preflight.Listen("metrics_listen", c.MetricsListen, true))
	}
	if c.Directory != nil {
		out = append(out, c.directoryChecks(ctx, h)...)
	}
	if c.AuthorityReplica != nil {
		out = append(out, c.replicaChecks(ctx, h)...)
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
	}
	return append(out, preflight.Database(ctx, mode, dsn))
}

// authorityChecks: each authority directory exists, is this user's with mode
// 0700, and lies outside the runtime root, the archives and the other
// authority, so that a restore of the data never brings back its keys.
func (c ServiceConfig) authorityChecks() []preflight.Result {
	type dir struct{ name, path string }
	var authorities, all []dir
	if c.KeyAuthority != nil {
		authorities = append(authorities, dir{"key_authority", c.KeyAuthority.Root})
	}
	if c.RestoreAuthority != nil {
		authorities = append(authorities, dir{"restore_authority", c.RestoreAuthority.Root})
	}
	all = append(all, authorities...)
	all = append(all, dir{"runtime root", c.Root})
	if c.Archives != nil {
		all = append(all, dir{"archives", c.Archives.Root})
	}
	var out []preflight.Result
	for _, a := range authorities {
		check := a.name
		init := map[string]string{"key_authority": "agentcapsule-admin init-key-authority", "restore_authority": "agentcapsule-admin init-restore-authority"}[a.name]
		st, err := os.Lstat(a.path)
		if err != nil {
			out = append(out, preflight.Result{Check: check, Status: preflight.Fail, Detail: a.path + " does not exist", Fix: "initialize it with " + init})
			continue
		}
		if !st.IsDir() || st.Mode().Perm() != 0o700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			out = append(out, preflight.Result{Check: check, Status: preflight.Fail, Detail: a.path + " is not a directory of this user with mode 0700",
				Fix: "chown it to the worker's user and chmod 0700"})
			continue
		}
		overlap := ""
		for _, other := range all {
			if other.path == a.path && other.name == a.name {
				continue
			}
			if restoreauthority.CheckSeparation(a.path, other.path) != nil {
				overlap = other.name + " (" + other.path + ")"
				break
			}
		}
		if overlap != "" {
			out = append(out, preflight.Result{Check: check, Status: preflight.Fail, Detail: a.path + " overlaps the " + overlap,
				Fix: "keep each authority in its own directory, outside the runtime root, the archives and the other authority (ADR 005)"})
			continue
		}
		out = append(out, preflight.Result{Check: check, Status: preflight.OK, Detail: a.path + " is private and separate from the data and the other authority"})
	}
	return out
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

func (c ServiceConfig) replicaChecks(ctx context.Context, h preflight.Host) []preflight.Result {
	r := c.AuthorityReplica
	const check = "authority_replica_tls"
	if c.KeyAuthority == nil || c.RestoreAuthority == nil || !r.valid() {
		return []preflight.Result{{Check: check, Status: preflight.Fail, Detail: "authority_replica is incomplete", Fix: "see docs/worker.md, Replica of the authorities"}}
	}
	files := authoritylog.TLSFiles{Certificate: r.Certificate, Key: r.Key, PeerCertificate: r.ReplicaCertificate,
		RestoreAuthority: c.RestoreAuthority.Identity, KeyAuthority: c.KeyAuthority.Identity}
	if _, err := files.ClientTLS(); err != nil {
		return []preflight.Result{{Check: check, Status: preflight.Fail,
			Detail: "the link's certificates do not match this host's authorities, or a file is unreadable",
			Fix:    "regenerate them with agentcapsule-authority certificate (the key 0600, owned by the worker's user), and pin the standby's"}}
	}
	result := preflight.Result{Check: check, Status: preflight.OK, Detail: "certificates of both sides pinned to this host's authorities"}
	for _, path := range []string{r.Certificate, r.ReplicaCertificate} {
		b, _ := os.ReadFile(path)
		block, _ := pem.Decode(b)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if left := cert.NotAfter.Sub(h.Now()); left < 30*24*time.Hour {
			result = preflight.Result{Check: check, Status: preflight.Warn, Detail: fmt.Sprintf("%s expires on %s", path, cert.NotAfter.UTC().Format(time.DateOnly)),
				Fix: "generate new link certificates (docs/recovery.md)"}
			if left <= 0 {
				result.Status = preflight.Fail
			}
		}
	}
	return []preflight.Result{result, preflight.Reachable(ctx, "authority_replica", r.Address, "start agentcapsule-authority serve on the standby, or check the address and the firewall")}
}
