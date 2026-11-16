//go:build linux

package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
)

func TestProductionRefusesALocalRegistryRule(t *testing.T) {
	c := ServiceConfig{}
	if c.CheckProductionTransport() != nil {
		t.Fatal("no registry refused")
	}
	c.Registry = &ServiceRegistry{Rules: []RegistryRule{{Rule: ociregistry.Rule{Host: "ghcr.io", Repositories: []string{"acme/"}}}}}
	if c.CheckProductionTransport() != nil {
		t.Fatal("HTTPS registry refused")
	}
	c.Registry.Rules = append(c.Registry.Rules, RegistryRule{Rule: ociregistry.Rule{Host: "registry.lan:5000", Repositories: []string{"acme/"}, Local: true}})
	if !errors.Is(c.CheckProductionTransport(), ErrClearTextRegistry) {
		t.Fatal("local rule accepted")
	}
}

func TestPreflightArtifactsNameThePinnedCopies(t *testing.T) {
	c := ServiceConfig{Root: "/var/lib/agentcapsule/host", Firecracker: ServiceImage{"/opt/fc", "a"}, Jailer: ServiceImage{"/opt/j", "b"},
		Kernel: ServiceImage{"/opt/k", "c"}, Initrd: ServiceImage{"/opt/i", "d"}}
	got := c.PreflightArtifacts()
	want := []preflight.Artifact{{Name: "firecracker", Path: "/opt/fc", SHA256: "a", Pinned: "/var/lib/agentcapsule/host/bin/firecracker"},
		{Name: "jailer", Path: "/opt/j", SHA256: "b", Pinned: "/var/lib/agentcapsule/host/bin/jailer"}, {Name: "kernel", Path: "/opt/k", SHA256: "c", Pinned: "/var/lib/agentcapsule/host/bin/kernel"},
		{Name: "initrd", Path: "/opt/i", SHA256: "d", Pinned: "/var/lib/agentcapsule/host/bin/initrd"}}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(got[i], want[i])
		}
	}
}

func result(t *testing.T, results []preflight.Result, check string) preflight.Result {
	t.Helper()
	for _, r := range results {
		if r.Check == check {
			return r
		}
	}
	t.Fatalf("no %s check in %+v", check, results)
	return preflight.Result{}
}

func clientCertificate(t *testing.T, dir, cn string) (string, string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Directory CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	ca, _ = x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	paths := []string{filepath.Join(dir, "directory-ca.pem"), filepath.Join(dir, "directory.crt"), filepath.Join(dir, "directory.key")}
	for i, b := range [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})} {
		mode := os.FileMode(0o644)
		if i == 2 {
			mode = 0o600
		}
		if err = os.WriteFile(paths[i], b, mode); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1], paths[2]
}

// The full set on a fake host: the Directory's files, its absent edge, the
// metrics port, a local registry rule and a clear-text database, each with
// its answer for the mode.
func TestPreflightOfAConfiguration(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	h := preflight.Host{Root: dir, Stat: os.Stat, Release: func() (string, error) { return "6.1.0", nil },
		KVM: func(string, []preflight.KVMCapability) (int, []preflight.KVMCapability, error) { return 12, nil, nil },
		Statfs: func(string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{Type: 0xEF53, Blocks: 100, Bfree: 90, Bavail: 90, Bsize: 4096}, nil
		},
		ClockSynchronized: func() (bool, error) { return true, nil },
		Version:           func(context.Context, string) (string, error) { return "", errors.New("absent") }, Now: time.Now}
	ca, cert, key := clientCertificate(t, dir, "some-other-workload")
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	edge := free.Addr().String()
	free.Close()
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	c := ServiceConfig{Root: filepath.Join(dir, "runtime"), MetricsListen: busy.Addr().String(),
		Directory: &ServiceDirectory{Address: edge, CA: ca, Cert: cert, Key: key},
		Registry:  &ServiceRegistry{Rules: []RegistryRule{{Rule: ociregistry.Rule{Host: "registry.lan:5000", Local: true}}}}}
	results := c.Preflight(t.Context(), h, operatorconfig.Production, "host=127.0.0.1 port=1 dbname=x")
	for check, want := range map[string]preflight.Status{"kvm": preflight.Fail, "artifact_firecracker": preflight.Fail, "kernel": preflight.OK,
		"clock": preflight.OK, "disk_runtime": preflight.OK, "metrics_listen": preflight.Fail, "directory_certificate": preflight.Fail,
		"registry": preflight.Fail, "postgresql": preflight.Fail} {
		if r := result(t, results, check); r.Status != want {
			t.Errorf("%s: %s %q", check, r.Status, r.Detail)
		}
	}
	// The right name: the files pass, the edge does not answer (a warning).
	ca, cert, key = clientCertificate(t, dir, DirectoryClientName)
	c.Directory = &ServiceDirectory{Address: edge, CA: ca, Cert: cert, Key: key}
	results = c.Preflight(t.Context(), h, operatorconfig.Development, "host=127.0.0.1 port=1 dbname=x connect_timeout=1")
	for check, want := range map[string]preflight.Status{"directory_certificate": preflight.OK, "directory_edge": preflight.Warn,
		"registry": preflight.Warn, "postgresql": preflight.Fail} {
		if r := result(t, results, check); r.Status != want {
			t.Errorf("development %s: %s %q", check, r.Status, r.Detail)
		}
	}
}
