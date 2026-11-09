//go:build linux

package worker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeDirectoryIdentity(t *testing.T) (ca, cert, key string) {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Directory CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agentcapsule-control-plane"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &clientKey.PublicKey, caKey)
	keyDER, _ := x509.MarshalECPrivateKey(clientKey)
	files := map[string][]byte{
		"ca.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"client.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"client.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
}

func TestDirectoryConfigNeedsAPrivateKeyAndAnEdge(t *testing.T) {
	if c, _, err := (ServiceConfig{}).OpenDirectory(); c != nil || err != nil {
		t.Fatal("a host without Directory", err)
	}
	ca, cert, key := writeDirectoryIdentity(t)
	good := ServiceDirectory{Address: "127.0.0.1:8443", CA: ca, Cert: cert, Key: key}
	c, every, err := (ServiceConfig{Directory: &good}).OpenDirectory()
	if err != nil || c == nil || every != 5*time.Second {
		t.Fatal("valid configuration refused", err)
	}
	_ = c.Close()
	slow := good
	slow.PublishInterval = "30s"
	if c, every, err = (ServiceConfig{Directory: &slow}).OpenDirectory(); err != nil || every != 30*time.Second {
		t.Fatal("interval", every, err)
	}
	_ = c.Close()

	shared := filepath.Join(t.TempDir(), "shared.key")
	raw, _ := os.ReadFile(key)
	if err = os.WriteFile(shared, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.pem")
	if err = os.Symlink(ca, link); err != nil {
		t.Fatal(err)
	}
	for label, mutate := range map[string]func(*ServiceDirectory){
		"key readable by others": func(d *ServiceDirectory) { d.Key = shared },
		"relative key":           func(d *ServiceDirectory) { d.Key = "client.key" },
		"missing certificate":    func(d *ServiceDirectory) { d.Cert = filepath.Join(filepath.Dir(cert), "none.crt") },
		"CA through a symlink":   func(d *ServiceDirectory) { d.CA = link },
		"missing CA":             func(d *ServiceDirectory) { d.CA = ca + ".missing" },
		"no port":                func(d *ServiceDirectory) { d.Address = "127.0.0.1" },
		"no address":             func(d *ServiceDirectory) { d.Address = "" },
		"interval too short":     func(d *ServiceDirectory) { d.PublishInterval = "100ms" },
		"interval not a time":    func(d *ServiceDirectory) { d.PublishInterval = "often" },
		"certificate and key do not match": func(d *ServiceDirectory) {
			_, otherCert, _ := writeDirectoryIdentity(t)
			d.Cert = otherCert
		},
	} {
		d := good
		mutate(&d)
		if c, _, err := (ServiceConfig{Directory: &d}).OpenDirectory(); !errors.Is(err, ErrDirectoryConfig) || c != nil {
			t.Fatal(label, "accepted", err)
		}
	}
}
