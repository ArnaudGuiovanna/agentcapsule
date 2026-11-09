//go:build linux

package worker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

func writeCredentials(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRegistryCredentialsComeFromAPrivateFile(t *testing.T) {
	good := `{"username":"ci-bot","password":"test-password-not-a-secret"}` // gitleaks:allow
	user, password, err := readRegistryCredentials(writeCredentials(t, good, 0o600))
	if err != nil || user != "ci-bot" || password != "test-password-not-a-secret" { // gitleaks:allow
		t.Fatal("valid credentials refused", err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err = os.Symlink(writeCredentials(t, good, 0o600), link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"readable by others": writeCredentials(t, good, 0o644),
		"symlink":            link,
		"relative path":      "registry.json",
		"unknown field":      writeCredentials(t, `{"username":"u","password":"p","token":"x"}`, 0o600),
		"second document":    writeCredentials(t, good+`{}`, 0o600),
		"no password":        writeCredentials(t, `{"username":"u"}`, 0o600),
		"empty":              writeCredentials(t, ``, 0o600),
		"too large":          writeCredentials(t, `{"username":"u","password":"`+string(bytes.Repeat([]byte("x"), 5000))+`"}`, 0o600),
	} {
		if _, _, err := readRegistryCredentials(path); !errors.Is(err, ErrRegistryCredentials) {
			t.Fatal("accepted:", name, err)
		}
	}
}

func TestRegistryRulesDecodeWithACredentialsFile(t *testing.T) {
	raw := `{"rules":[{"host":"ghcr.io","repositories":["acme/"],"blob_hosts":["pkg-containers.githubusercontent.com"],"credentials_file":"/etc/agentcapsule/ghcr.json"}]}`
	var r ServiceRegistry
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	rule := r.Rules[0]
	if rule.Host != "ghcr.io" || len(rule.BlobHosts) != 1 || rule.CredentialsFile != "/etc/agentcapsule/ghcr.json" || rule.Username != "" {
		t.Fatalf("%+v", rule)
	}
	// Secrets are never accepted inline in the configuration.
	for _, inline := range []string{`"username":"u"`, `"password":"p"`, `"Username":"u"`} {
		bad := `{"rules":[{"host":"ghcr.io","repositories":["acme/"],` + inline + `}]}`
		d := json.NewDecoder(bytes.NewReader([]byte(bad)))
		d.DisallowUnknownFields()
		var r ServiceRegistry
		if err := d.Decode(&r); err == nil {
			t.Fatal("inline credential field accepted", inline)
		}
	}
}

func TestPublisherKeysComeFromProtectedFiles(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	good := writeCredentials(t, pub, 0o644) // public: readable by all, writable by its owner only
	k, err := readPublisherKey(good)
	if err != nil || !strings.HasPrefix(k.ID, "sha256:") {
		t.Fatal("a protected public key was refused", err)
	}
	link := filepath.Join(t.TempDir(), "link.pub")
	if err = os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	for name, path := range map[string]string{
		"group writable": writeCredentials(t, pub, 0o664),
		"symlink":        link,
		"relative":       "key.pub",
		"private key":    writeCredentials(t, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})), 0o600),
		"not a key":      writeCredentials(t, "ssh-ed25519 AAAA", 0o644),
	} {
		if _, err := readPublisherKey(path); !errors.Is(err, ErrPublisherKey) {
			t.Fatal("publisher key accepted:", name, err)
		}
	}
	// Strict mode: a rule that trusts no key makes the configuration invalid.
	c := ServiceConfig{Root: t.TempDir(), Registry: &ServiceRegistry{RequireSignatures: true,
		Rules: []RegistryRule{{Rule: ociregistry.Rule{Host: "ghcr.io", Repositories: []string{"acme/"}}}}}}
	if _, err = c.OpenRegistry(nil, "w"); err == nil {
		t.Fatal("strict mode accepted a rule without publisher keys")
	}
}
