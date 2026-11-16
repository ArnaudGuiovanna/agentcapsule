//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// command runs the entry point and returns what it printed and its code.
func command(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := run(args)
	os.Stdout, os.Stderr = stdout, stderr
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func certificate(t *testing.T, dir string, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "api"}, NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, keyFile := filepath.Join(dir, "api.crt"), filepath.Join(dir, "api.key")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, keyFile
}

// Production refuses every configuration that would serve or connect in
// clear text, before it opens the database: these runs have none.
func TestProductionRefusesClearText(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	receipt := filepath.Join(dir, "receipt.key")
	if err := os.WriteFile(receipt, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := certificate(t, dir, time.Now().Add(24*time.Hour))
	base := []string{"-receipt-key-file", receipt, "-host-id", "local"}
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "host=127.0.0.1 port=1 dbname=agentcapsule")
	for _, c := range []struct {
		mode string
		args []string
		want string
	}{
		{"", []string{"-listen", "127.0.0.1:0"}, "tls_required_in_production"},
		{"production", []string{"-listen", "0.0.0.0:0"}, "tls_required_in_production"},
		{"", []string{"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key}, "database_tls_required_in_production"},
		{"", []string{"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key, "-tls-server-name", "api.example"}, "tls_certificate_does_not_cover_server_name"},
		{"", []string{"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", receipt}, "tls_files_invalid"},
		{"", []string{"-listen", "127.0.0.1:0", "-tls-server-name", "api.example"}, "configuration_required"},
		{"development", []string{"-listen", "0.0.0.0:0"}, "tls_required_for_non_loopback_listener"},
		{"staging", []string{"-listen", "127.0.0.1:0"}, "mode_invalid"},
	} {
		t.Setenv("AGENTCAPSULE_MODE", c.mode)
		out, code := command(t, append(append([]string{}, base...), c.args...)...)
		if code == 0 || !strings.HasSuffix(out, c.want+"\n") {
			t.Errorf("%q %v: %d %q, want %s", c.mode, c.args, code, out, c.want)
		}
		if c.mode == "development" && !strings.HasPrefix(out, "development_mode_clear_text_allowed_never_use_in_production\n") {
			t.Errorf("development mode not announced: %q", out)
		}
	}
	expired, expiredKey := certificate(t, t.TempDir(), time.Now().Add(-time.Hour))
	t.Setenv("AGENTCAPSULE_MODE", "")
	if out, _ := command(t, append(base, "-listen", "127.0.0.1:0", "-tls-cert", expired, "-tls-key", expiredKey)...); out != "tls_certificate_expired_or_not_yet_valid\n" {
		t.Error("expired certificate:", out)
	}
}

// The preflight of the API's configuration: what fails, and what to fix.
func TestPreflightOfTheAPI(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	receipt := filepath.Join(dir, "receipt.key")
	if err := os.WriteFile(receipt, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	t.Setenv("AGENTCAPSULE_MODE", "")
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "host=127.0.0.1 port=1 dbname=agentcapsule")
	out, code := command(t, "-preflight", "-receipt-key-file", receipt, "-host-id", "local", "-listen", busy.Addr().String())
	for _, want := range []string{"ok   mode: production", "fail api_certificate: no -tls-cert", "fail api_listen: " + busy.Addr().String() + " is already in use",
		"fail receipt_key:", "fail postgresql: the connection may use clear text", "     fix: use a Unix socket", "preflight_failed\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code != 1 || strings.Contains(out, "port=1") {
		t.Fatal(code, out)
	}
}
