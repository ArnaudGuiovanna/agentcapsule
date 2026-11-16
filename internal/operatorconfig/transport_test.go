//go:build linux

package operatorconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModeFromEnvironment(t *testing.T) {
	for value, want := range map[string]Mode{"": Production, "production": Production, "development": Development} {
		t.Setenv(ModeVariable, value)
		if got, err := ModeFromEnvironment(); err != nil || got != want {
			t.Fatalf("%q: %q %v", value, got, err)
		}
	}
	for _, value := range []string{"dev", "Production", "test", " development"} {
		t.Setenv(ModeVariable, value)
		if _, err := ModeFromEnvironment(); !errors.Is(err, ErrMode) {
			t.Fatalf("%q accepted", value)
		}
	}
}

// Production accepts a Unix socket or verified TLS to every host the string
// can reach; anything that may fall back to clear text or skip the server's
// name is refused. The check reads the connection string as pgx does.
func TestDatabaseURLRefusesClearTextAndUnverifiedTLS(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT", "PGPORT", "PGSERVICEFILE", "PGSERVICE"} {
		t.Setenv(name, "")
	}
	ca := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(ca, testCertificatePEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	accepted := []string{
		"host=/run/postgresql dbname=agentcapsule",
		"host=/run/postgresql sslmode=disable dbname=agentcapsule",
		"postgres://agentcapsule@db.internal:5432/agentcapsule?sslmode=verify-full&sslrootcert=" + ca,
		"host=db.internal sslmode=verify-full sslrootcert=" + ca,
		"host=db.internal,db2.internal sslmode=verify-full sslrootcert=" + ca,
		"host=127.0.0.1 sslmode=verify-full sslrootcert=" + ca,
		"host=db.internal sslrootcert=system",
	}
	for _, dsn := range accepted {
		if err := CheckDatabaseURL(dsn); err != nil {
			t.Errorf("%q refused: %v", dsn, err)
		}
	}
	refused := []string{
		"host=127.0.0.1 dbname=agentcapsule",                    // prefer: falls back to clear text
		"host=db.internal sslmode=disable",                      // clear text
		"host=db.internal sslmode=allow",                        // clear text first
		"host=db.internal sslmode=prefer",                       // may fall back to clear text
		"host=db.internal sslmode=require",                      // no server verification
		"host=db.internal sslmode=verify-ca sslrootcert=" + ca,  // no name verification
		"host=/run/postgresql,db.internal sslmode=require",      // one host unverified
		"postgres://agentcapsule@db.internal:5432/agentcapsule", // the default, prefer
	}
	for _, dsn := range refused {
		if err := CheckDatabaseURL(dsn); !errors.Is(err, ErrDatabaseClearText) {
			t.Errorf("%q not refused as clear text: %v", dsn, err)
		}
	}
	for _, dsn := range []string{"host=db.internal sslmode=verify-full sslrootcert=/nonexistent/ca.pem", "postgres://h:notaport/db", "sslmode=bogus host=x"} {
		err := CheckDatabaseURL(dsn)
		if !errors.Is(err, ErrDatabaseURL) {
			t.Errorf("%q: %v", dsn, err)
		}
		if err != nil && strings.Contains(err.Error(), "notaport") {
			t.Error("the error quotes the connection string")
		}
	}
	// The environment counts, as it does for the connection itself.
	t.Setenv("PGSSLMODE", "disable")
	if err := CheckDatabaseURL("host=db.internal"); !errors.Is(err, ErrDatabaseClearText) {
		t.Error("PGSSLMODE=disable accepted", err)
	}
}

func TestDatabaseURLFromTheEnvironmentByMode(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT"} {
		t.Setenv(name, "")
	}
	t.Setenv(DatabaseVariable, "")
	if _, code := DatabaseURL(Production); code != "database_configuration_required" {
		t.Fatal(code)
	}
	t.Setenv(DatabaseVariable, "host=127.0.0.1 dbname=agentcapsule")
	if _, code := DatabaseURL(Production); code != "database_tls_required_in_production" {
		t.Fatal(code)
	}
	if dsn, code := DatabaseURL(Development); code != "" || dsn != "host=127.0.0.1 dbname=agentcapsule" {
		t.Fatal(dsn, code)
	}
	t.Setenv(DatabaseVariable, "host=/run/postgresql dbname=agentcapsule")
	if _, code := DatabaseURL(Production); code != "" {
		t.Fatal(code)
	}
	t.Setenv(DatabaseVariable, "host=db.internal sslmode=bogus")
	if _, code := DatabaseURL(Production); code != "database_configuration_invalid" {
		t.Fatal(code)
	}
}

type testCert struct {
	template *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	keyPEM   []byte
}

func newTestCert(t *testing.T, modify func(*x509.Certificate)) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "api.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"api.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if modify != nil {
		modify(c)
	}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c.Raw = der
	return testCert{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})}
}

func testCertificatePEM(t *testing.T) []byte { return newTestCert(t, nil).certPEM }

// write puts a certificate (0644) and its key (0600) in dir.
func (c testCert) write(t *testing.T, dir string) (string, string) {
	t.Helper()
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, content := range map[string][]byte{cert: c.certPEM, key: c.keyPEM} {
		_ = os.Remove(path)
		mode := os.FileMode(0o644)
		if path == key {
			mode = 0o600
		}
		if err := os.WriteFile(path, content, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

func TestServerCertificateFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := newTestCert(t, nil)
	cert, key := good.write(t, dir)
	if _, err := LoadServerCertificate(cert, key, "api.example", time.Now()); err != nil {
		t.Fatal("valid certificate refused:", err)
	}
	if _, err := LoadServerCertificate(cert, key, "", time.Now()); err != nil {
		t.Fatal("no name to check:", err)
	}
	for name, c := range map[string]struct {
		files func() (string, string)
		name  string
		now   time.Time
		want  error
	}{
		"wrong name": {func() (string, string) { return cert, key }, "other.example", time.Now(), ErrTLSName},
		"expired":    {func() (string, string) { return cert, key }, "", time.Now().Add(91 * 24 * time.Hour), ErrTLSValidity},
		"not yet":    {func() (string, string) { return cert, key }, "", time.Now().Add(-2 * time.Hour), ErrTLSValidity},
		"other key": {func() (string, string) {
			d := t.TempDir()
			c2, _ := good.write(t, d)
			_, k2 := newTestCert(t, nil).write(t, t.TempDir())
			return c2, k2
		}, "", time.Now(), ErrTLSKeyMismatch},
		"client only": {func() (string, string) {
			return newTestCert(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }).write(t, t.TempDir())
		}, "", time.Now(), ErrTLSUsage},
		"readable key": {func() (string, string) {
			d := t.TempDir()
			c2, k2 := good.write(t, d)
			if err := os.Chmod(k2, 0o640); err != nil {
				t.Fatal(err)
			}
			return c2, k2
		}, "", time.Now(), ErrTLSFiles},
		"writable certificate": {func() (string, string) {
			d := t.TempDir()
			c2, k2 := good.write(t, d)
			if err := os.Chmod(c2, 0o666); err != nil {
				t.Fatal(err)
			}
			return c2, k2
		}, "", time.Now(), ErrTLSFiles},
		"symlinked key": {func() (string, string) {
			d := t.TempDir()
			link := filepath.Join(d, "link.key")
			if err := os.Symlink(key, link); err != nil {
				t.Fatal(err)
			}
			return cert, link
		}, "", time.Now(), ErrTLSFiles},
		"relative path": {func() (string, string) { return "tls.crt", key }, "", time.Now(), ErrTLSFiles},
		"not a certificate": {func() (string, string) {
			d := t.TempDir()
			c2, k2 := good.write(t, d)
			if err := os.WriteFile(c2, []byte("not PEM"), 0o644); err != nil {
				t.Fatal(err)
			}
			return c2, k2
		}, "", time.Now(), ErrTLSFiles},
		"not a key": {func() (string, string) {
			d := t.TempDir()
			c2, k2 := good.write(t, d)
			if err := os.WriteFile(k2, good.certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			return c2, k2
		}, "", time.Now(), ErrTLSFiles},
	} {
		c2, k2 := c.files()
		if _, err := LoadServerCertificate(c2, k2, c.name, c.now); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// A served certificate: TLS 1.2 at least, no clear text, and a reload that
// replaces the certificate for new connections or keeps the old one when the
// new files are wrong.
func TestServerCertificateServesTLSAndReloads(t *testing.T) {
	dir := t.TempDir()
	first := newTestCert(t, nil)
	cert, key := first.write(t, dir)
	served, err := NewServerCertificate(cert, key, "api.example")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }),
		TLSConfig: served.TLSConfig(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { server.Close() })
	address := l.Addr().String()

	serial := func(c tls.Config) (*big.Int, error) {
		c.ServerName = "api.example"
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &c)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber, nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(first.certPEM)
	got, err := serial(tls.Config{RootCAs: pool})
	if err != nil || got.Cmp(first.template.SerialNumber) != 0 {
		t.Fatal("handshake", err)
	}
	if _, err = serial(tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11, MinVersion: tls.VersionTLS10}); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
	// Clear text: the server answers no route, only a refusal.
	r, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + address + "/")
	if err == nil {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest || string(body) == "ok" {
			t.Fatal("clear text served", r.StatusCode)
		}
	}

	second := newTestCert(t, nil)
	second.write(t, dir)
	if err = served.Reload(); err != nil {
		t.Fatal("reload", err)
	}
	pool.AppendCertsFromPEM(second.certPEM)
	if got, err = serial(tls.Config{RootCAs: pool}); err != nil || got.Cmp(second.template.SerialNumber) != 0 {
		t.Fatal("reload not served", err)
	}
	// A broken renewal keeps the certificate in service.
	if err = os.WriteFile(key, newTestCert(t, nil).keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = served.Reload(); !errors.Is(err, ErrTLSKeyMismatch) {
		t.Fatal("mismatched reload accepted", err)
	}
	if got, err = serial(tls.Config{RootCAs: pool}); err != nil || got.Cmp(second.template.SerialNumber) != 0 {
		t.Fatal("old certificate dropped after a failed reload", err)
	}
	if !served.NotAfter().Equal(second.template.NotAfter.Truncate(time.Second)) {
		t.Fatal("NotAfter", served.NotAfter(), second.template.NotAfter)
	}
}
