//go:build linux

package preflight

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// fakeHost is a host whose system paths live under a temporary root and
// whose kernel answers are given by the test. By default every answer is
// that of a good host.
func fakeHost(t *testing.T) (Host, string) {
	t.Helper()
	root := t.TempDir()
	return Host{
		Root:    root,
		Stat:    os.Stat,
		Release: func() (string, error) { return "6.1.0-28-amd64", nil },
		KVM: func(string, []KVMCapability) (int, []KVMCapability, error) {
			return kvmAPIVersion, nil, nil
		},
		Statfs: func(string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{Type: 0xEF53, Blocks: 1000, Bfree: 600, Bavail: 550, Bsize: 4096}, nil
		},
		ClockSynchronized: func() (bool, error) { return true, nil },
		Version: func(context.Context, string) (string, error) {
			return "Firecracker v" + FirecrackerVersion + "\nJailer v" + FirecrackerVersion + "\n", nil
		},
		Now: time.Now,
	}, root
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, r Result, status Status, detail string) {
	t.Helper()
	if r.Status != status || !strings.Contains(r.Detail, detail) {
		t.Fatalf("%s: got %s %q, want %s with %q", r.Check, r.Status, r.Detail, status, detail)
	}
	if status != OK && r.Fix == "" {
		t.Fatalf("%s: %s without a fix", r.Check, status)
	}
}

func TestKVMDevice(t *testing.T) {
	h, root := fakeHost(t)
	expect(t, KVM(h), Fail, "/dev/kvm is missing")
	write(t, filepath.Join(root, "dev/kvm"), "")
	expect(t, KVM(h), Fail, "not a character device")
	os.Remove(filepath.Join(root, "dev/kvm"))
	if err := os.Symlink("/dev/null", filepath.Join(root, "dev/kvm")); err != nil {
		t.Fatal(err)
	}
	expect(t, KVM(h), Fail, "device 1:3, not KVM")
	h.Stat = kvmDevice(h.Stat)
	expect(t, KVM(h), OK, "KVM API 12")
	h.KVM = func(string, []KVMCapability) (int, []KVMCapability, error) { return 0, nil, os.ErrPermission }
	expect(t, KVM(h), Fail, "cannot be opened read-write")
	h.KVM = func(string, []KVMCapability) (int, []KVMCapability, error) { return 11, nil, nil }
	expect(t, KVM(h), Fail, "KVM API version 11")
	h.KVM = func(_ string, c []KVMCapability) (int, []KVMCapability, error) { return 12, c[1:3], nil }
	expect(t, KVM(h), Fail, "KVM lacks KVM_CAP_IOEVENTFD, KVM_CAP_IRQFD")
}

// kvmDevice makes stat describe <root>/dev/kvm as the KVM character device
// (10:232), which a test cannot create without root.
func kvmDevice(stat func(string) (os.FileInfo, error)) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		if strings.HasSuffix(path, "/dev/kvm") {
			return fakeDevice{}, nil
		}
		return stat(path)
	}
}

type fakeDevice struct{}

func (fakeDevice) Name() string       { return "kvm" }
func (fakeDevice) Size() int64        { return 0 }
func (fakeDevice) Mode() os.FileMode  { return os.ModeDevice | os.ModeCharDevice | 0o660 }
func (fakeDevice) ModTime() time.Time { return time.Time{} }
func (fakeDevice) IsDir() bool        { return false }
func (fakeDevice) Sys() any           { return &syscall.Stat_t{Rdev: 10<<8 | 232} }

// The real probe: a device that is not KVM answers no KVM ioctl; where this
// machine's user may open /dev/kvm, the real device answers too.
func TestKVMProbe(t *testing.T) {
	if _, _, err := probeKVM("/dev/null", FirecrackerCapabilities); err == nil {
		t.Fatal("/dev/null answered the KVM ioctl")
	}
	if _, _, err := probeKVM(filepath.Join(t.TempDir(), "kvm"), FirecrackerCapabilities); err == nil {
		t.Fatal("a missing device opened")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Log("/dev/kvm cannot be opened here: only the refusals were checked")
		return
	}
	f.Close()
	api, missing, err := probeKVM("/dev/kvm", FirecrackerCapabilities)
	if err != nil || api != kvmAPIVersion || len(missing) != 0 {
		t.Fatal(api, missing, err)
	}
	if _, missing, _ = probeKVM("/dev/kvm", []KVMCapability{{"none", 1 << 30}}); len(missing) != 1 {
		t.Fatal("an unknown capability reported present")
	}
}

func TestKernelVersion(t *testing.T) {
	h, _ := fakeHost(t)
	for release, want := range map[string]Status{"4.19.0": Fail, "5.10.209": Fail, "5.13.0": Fail, "5.15.0-91-generic": Warn,
		"6.1.0-28-amd64": OK, "6.18.58.1-microsoft-standard-WSL2": OK, "6.8.0-45-generic": Warn, "linux": Fail, "6": Fail} {
		h.Release = func() (string, error) { return release, nil }
		if r := Kernel(h); r.Status != want || (want != OK && r.Fix == "") {
			t.Errorf("%s: %s %q", release, r.Status, r.Detail)
		}
	}
	h.Release = func() (string, error) { return "", errors.New("no uname") }
	expect(t, Kernel(h), Fail, "cannot be read")
}

func TestCgroups(t *testing.T) {
	h, root := fakeHost(t)
	group := filepath.Join(root, "sys/fs/cgroup")
	h.Statfs = func(string) (syscall.Statfs_t, error) { return syscall.Statfs_t{Type: 0x27e0eb}, nil } // cgroup v1
	expect(t, Cgroups(h), Fail, "not a cgroup v2 hierarchy")
	h.Statfs = func(string) (syscall.Statfs_t, error) { return syscall.Statfs_t{Type: 0x63677270}, nil }
	expect(t, Cgroups(h), Fail, "cgroup.controllers cannot be read")
	write(t, filepath.Join(group, "cgroup.controllers"), "cpuset cpu io pids\n")
	write(t, filepath.Join(group, "cgroup.subtree_control"), "cpu memory pids\n")
	expect(t, Cgroups(h), Fail, "offers no memory controller")
	write(t, filepath.Join(group, "cgroup.controllers"), "cpuset cpu io memory hugetlb pids rdma\n")
	write(t, filepath.Join(group, "cgroup.subtree_control"), "memory\n")
	expect(t, Cgroups(h), Fail, "does not delegate cpu, pids")
	write(t, filepath.Join(group, "cgroup.subtree_control"), "cpu memory pids\n")
	expect(t, Cgroups(h), OK, "cgroup v2")
}

func TestNamespacesAndClock(t *testing.T) {
	h, root := fakeHost(t)
	expect(t, Namespaces(h), Fail, "no mnt, pid, net namespace")
	for _, ns := range []string{"mnt", "pid"} {
		write(t, filepath.Join(root, "proc/self/ns", ns), "")
	}
	expect(t, Namespaces(h), Fail, "no net namespace")
	write(t, filepath.Join(root, "proc/self/ns/net"), "")
	expect(t, Namespaces(h), OK, "network namespaces")

	expect(t, Clock(h), OK, "synchronized")
	h.ClockSynchronized = func() (bool, error) { return false, nil }
	expect(t, Clock(h), Fail, "not synchronized")
	h.ClockSynchronized = func() (bool, error) { return false, syscall.EPERM }
	expect(t, Clock(h), Fail, "cannot be read")
	// The real call reads the state without changing it.
	if _, err := clockSynchronized(); err != nil {
		t.Fatal("adjtimex read:", err)
	}
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestArtifacts(t *testing.T) {
	h, _ := fakeHost(t)
	dir := t.TempDir()
	kernel := []byte("\x7fELF kernel")
	write(t, filepath.Join(dir, "vmlinux"), string(kernel))
	write(t, filepath.Join(dir, "initrd"), "initrd")
	write(t, filepath.Join(dir, "firecracker"), "firecracker")
	write(t, filepath.Join(dir, "pinned-jailer"), "jailer")
	artifacts := []Artifact{
		{"firecracker", filepath.Join(dir, "firecracker"), digest([]byte("firecracker")), ""},
		// The source is gone; the copy under the runtime root stands in.
		{"jailer", filepath.Join(dir, "jailer"), digest([]byte("jailer")), filepath.Join(dir, "pinned-jailer")},
		{"kernel", filepath.Join(dir, "vmlinux"), digest(kernel), ""},
		{"initrd", filepath.Join(dir, "initrd"), digest([]byte("initrd")), ""},
	}
	for _, r := range Artifacts(t.Context(), h, artifacts) {
		expect(t, r, OK, "matches its SHA-256")
	}
	bad := append([]Artifact(nil), artifacts...)
	bad[0].SHA256 = digest([]byte("another build"))
	bad[1].Pinned = ""
	bad[2] = Artifact{"kernel", filepath.Join(dir, "initrd"), digest([]byte("initrd")), ""}
	bad[3].SHA256 = ""
	results := Artifacts(t.Context(), h, bad)
	expect(t, results[0], Fail, "the configuration pins")
	expect(t, results[1], Fail, "cannot be read")
	expect(t, results[2], Fail, "not an ELF kernel image")
	expect(t, results[3], Fail, "no SHA-256")
	h.Version = func(context.Context, string) (string, error) { return "Firecracker v1.16.0\n", nil }
	expect(t, Artifacts(t.Context(), h, artifacts[:1])[0], Fail, "does not report Firecracker v"+FirecrackerVersion)
	h.Version = func(context.Context, string) (string, error) { return "", errors.New("exec format error") }
	expect(t, Artifacts(t.Context(), h, artifacts[1:2])[0], Fail, "does not report Jailer v"+FirecrackerVersion)
	// The real runner executes the binary with --version only.
	script := filepath.Join(dir, "fake-firecracker")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n[ \"$1\" = --version ] && echo \"Firecracker v"+FirecrackerVersion+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := version(t.Context(), script); err != nil || !strings.Contains(out, "Firecracker v"+FirecrackerVersion) {
		t.Fatal(out, err)
	}
}

// The version checked is the release the repository builds.
func TestFirecrackerVersionIsThePinnedRelease(t *testing.T) {
	b, err := os.ReadFile("../../runtime/firecracker/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct{ Version string }
	if err = json.Unmarshal(b, &m); err != nil || m.Version != FirecrackerVersion {
		t.Fatalf("manifest %q, preflight %q", m.Version, FirecrackerVersion)
	}
}

func TestRuntimeFileSystemAndDisk(t *testing.T) {
	h, _ := fakeHost(t)
	root := filepath.Join(t.TempDir(), "not", "yet", "created")
	fs := func(kind int64, flags int64) {
		h.Statfs = func(path string) (syscall.Statfs_t, error) {
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("statfs of a missing path", path)
			}
			return syscall.Statfs_t{Type: kind, Flags: flags}, nil
		}
	}
	fs(0xEF53, 0)
	expect(t, RuntimeFileSystem(h, root), OK, "ext4")
	expect(t, RuntimeFileSystem(h, "relative/root"), Fail, "not an absolute path")
	fs(0x01021994, 0)
	expect(t, RuntimeFileSystem(h, root), Fail, "tmpfs: volumes would be lost")
	fs(0x6969, 0)
	expect(t, RuntimeFileSystem(h, root), Fail, "nfs")
	fs(0x58465342, stNodev)
	expect(t, RuntimeFileSystem(h, root), Fail, "nodev")
	fs(0x58465342, stNoexec)
	expect(t, RuntimeFileSystem(h, root), Fail, "noexec")
	fs(0x58465342, stRdonly)
	expect(t, RuntimeFileSystem(h, root), Fail, "read-only")
	fs(0x12345678, 0)
	expect(t, RuntimeFileSystem(h, root), Warn, "not qualified")

	usage := func(used uint64) {
		h.Statfs = func(string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{Blocks: 1000, Bfree: 1000 - used, Bavail: 1000 - used, Bsize: 1 << 20}, nil
		}
	}
	usage(500)
	expect(t, Disk(h, "runtime", root), OK, "50% used")
	usage(750)
	expect(t, Disk(h, "runtime", root), Warn, "75% used")
	usage(850)
	expect(t, Disk(h, "runtime", root), Fail, "85% used")
}

func TestMandatoryOnAGoodFakeHost(t *testing.T) {
	h, root := fakeHost(t)
	h.Stat = kvmDevice(h.Stat)
	write(t, filepath.Join(root, "sys/fs/cgroup/cgroup.controllers"), "cpu memory pids\n")
	write(t, filepath.Join(root, "sys/fs/cgroup/cgroup.subtree_control"), "cpu memory pids\n")
	for _, ns := range []string{"mnt", "pid", "net"} {
		write(t, filepath.Join(root, "proc/self/ns", ns), "")
	}
	h.Statfs = func(path string) (syscall.Statfs_t, error) {
		if strings.HasSuffix(path, "sys/fs/cgroup") {
			return syscall.Statfs_t{Type: 0x63677270}, nil
		}
		return syscall.Statfs_t{Type: 0xEF53}, nil
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "vmlinux"), "\x7fELF")
	results := Mandatory(t.Context(), h, filepath.Join(dir, "runtime"), []Artifact{{"kernel", filepath.Join(dir, "vmlinux"), digest([]byte("\x7fELF")), ""}})
	if Failed(results) || len(results) != 6 {
		t.Fatalf("%+v", results)
	}
	var out bytes.Buffer
	if err := Write(&out, results); err != nil || !strings.HasSuffix(out.String(), "preflight_passed\n") {
		t.Fatal(out.String(), err)
	}
	h.Release = func() (string, error) { return "5.4.0", nil }
	results = Mandatory(t.Context(), h, filepath.Join(dir, "runtime"), nil)
	out.Reset()
	if !Failed(results) || Write(&out, results) != nil || !strings.Contains(out.String(), "fail kernel: kernel 5.4.0 is older than 5.14\n     fix: upgrade") ||
		!strings.HasSuffix(out.String(), "preflight_failed\n") {
		t.Fatal(out.String())
	}
}

type pki struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
}

func authority(t *testing.T, name string) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour * 24 * 365), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = x509.ParseCertificate(der)
	return pki{key, c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue writes a leaf signed by ca into dir and returns its files.
func (ca pki) issue(t *testing.T, dir, cn string, usage x509.ExtKeyUsage, lifetime time.Duration) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, c, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestCertificateChecks(t *testing.T) {
	h, _ := fakeHost(t)
	ca := authority(t, "Test CA")
	dir := t.TempDir()
	cert, key := ca.issue(t, dir, "server", x509.ExtKeyUsageServerAuth, 90*24*time.Hour)
	expect(t, Certificate(h, "api_tls", cert, key, x509.ExtKeyUsageServerAuth, "localhost", ""), OK, "covers localhost")
	expect(t, Certificate(h, "api_tls", cert, key, x509.ExtKeyUsageServerAuth, "api.example", ""), Fail, "does not cover api.example")
	expect(t, Certificate(h, "api_tls", cert, key, x509.ExtKeyUsageClientAuth, "", ""), Fail, "not issued for this role")
	soon, soonKey := ca.issue(t, dir, "soon", x509.ExtKeyUsageServerAuth, 10*24*time.Hour)
	expect(t, Certificate(h, "api_tls", soon, soonKey, x509.ExtKeyUsageServerAuth, "", ""), Warn, "valid until")
	h.Now = func() time.Time { return time.Now().Add(100 * 24 * time.Hour) }
	expect(t, Certificate(h, "api_tls", cert, key, x509.ExtKeyUsageServerAuth, "", ""), Fail, "has expired")
	h.Now = time.Now
	expect(t, Certificate(h, "api_tls", cert, soonKey, x509.ExtKeyUsageServerAuth, "", ""), Fail, "the key is not the key")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, Certificate(h, "api_tls", cert, key, x509.ExtKeyUsageServerAuth, "", ""), Fail, "cannot be used")
	client, clientKey := ca.issue(t, dir, "some-other-workload", x509.ExtKeyUsageClientAuth, 90*24*time.Hour)
	expect(t, Certificate(h, "directory_tls", client, clientKey, x509.ExtKeyUsageClientAuth, "", "agentcapsule-control-plane"), Fail, "admits \"agentcapsule-control-plane\" only")
	client, clientKey = ca.issue(t, dir, "agentcapsule-control-plane", x509.ExtKeyUsageClientAuth, 90*24*time.Hour)
	expect(t, Certificate(h, "directory_tls", client, clientKey, x509.ExtKeyUsageClientAuth, "", "agentcapsule-control-plane"), OK, "valid until")
}

func TestListen(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busy := l.Addr().String()
	expect(t, Listen("api_listen", busy, false), Fail, "already in use")
	l.Close()
	expect(t, Listen("api_listen", busy, false), OK, "is free")
	expect(t, Listen("metrics_listen", "0.0.0.0:0", true), Fail, "not a loopback address")
	expect(t, Listen("api_listen", "nonsense", false), Fail, "not host:port")
}

// A peer that admits only the client certificates of its authority: the
// right certificate passes; a foreign authority, a server signed by another
// CA, and a closed port each give their answer.
func TestMutualTLSProbe(t *testing.T) {
	ca, other := authority(t, "Directory CA"), authority(t, "Rogue CA")
	dir := t.TempDir()
	serverCert, serverKey := ca.issue(t, filepath.Join(dir, "server"), "edge", x509.ExtKeyUsageServerAuth, 24*time.Hour)
	pair, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	clients.AddCert(ca.cert)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: clients,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if c.(*tls.Conn).Handshake() == nil {
					time.Sleep(2 * time.Second) // admitted: the client speaks first
				}
			}()
		}
	}()
	address := l.Addr().String()
	config := func(signer pki) *tls.Config {
		cert, key := signer.issue(t, filepath.Join(dir, signer.cert.Subject.CommonName), "agentcapsule-control-plane", x509.ExtKeyUsageClientAuth, 24*time.Hour)
		p, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.cert)
		return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{p}, MinVersion: tls.VersionTLS12}
	}
	expect(t, MutualTLS(t.Context(), "directory_edge", address, config(ca)), OK, "admits this client over TLS 1.3")
	expect(t, MutualTLS(t.Context(), "directory_edge", address, config(other)), Fail, "")
	wrongRoots := config(ca)
	wrongRoots.RootCAs = x509.NewCertPool()
	wrongRoots.RootCAs.AddCert(other.cert)
	expect(t, MutualTLS(t.Context(), "directory_edge", address, wrongRoots), Fail, "the configured CA did not sign")
	wrongName := config(ca)
	wrongName.ServerName = "directory.example"
	expect(t, MutualTLS(t.Context(), "directory_edge", address, wrongName), Fail, "for another name")
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := free.Addr().String()
	free.Close()
	expect(t, MutualTLS(t.Context(), "directory_edge", closed, config(ca)), Warn, "does not answer")
}

func TestDatabaseRefusesBeforeConnecting(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	expect(t, Database(t.Context(), operatorconfig.Production, ""), Fail, "is empty")
	expect(t, Database(t.Context(), operatorconfig.Production, "host=db.internal sslmode=bogus"), Fail, "does not parse")
	// Production refuses clear text without connecting: nothing listens here.
	expect(t, Database(t.Context(), operatorconfig.Production, "host=127.0.0.1 port=1 dbname=x"), Fail, "may use clear text")
	expect(t, Database(t.Context(), operatorconfig.Development, "host=127.0.0.1 port=1 dbname=x connect_timeout=2"), Fail, "cannot be reached")
	expect(t, Database(t.Context(), operatorconfig.Production, "host="+t.TempDir()+" dbname=x"), Fail, "cannot be reached")
}

// Against the campaign's PostgreSQL, over its Unix socket.
func TestDatabaseOverAUnixSocket(t *testing.T) {
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL missing")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	expect(t, Database(t.Context(), operatorconfig.Production, dsn), OK, "over a Unix socket")
}

func TestModeResult(t *testing.T) {
	t.Setenv(operatorconfig.ModeVariable, "")
	if m, r := Mode(); m != operatorconfig.Production || r.Status != OK {
		t.Fatal(m, r)
	}
	t.Setenv(operatorconfig.ModeVariable, "development")
	if m, r := Mode(); m != operatorconfig.Development || r.Status != Warn {
		t.Fatal(m, r)
	}
	t.Setenv(operatorconfig.ModeVariable, "prod")
	if _, r := Mode(); r.Status != Fail || r.Fix == "" {
		t.Fatal(r)
	}
}
