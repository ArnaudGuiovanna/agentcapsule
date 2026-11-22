//go:build linux

package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
)

// L-16: the shipped example, which the installer writes for a new host,
// trusts no publisher key (the project's packages are not signed): its rule
// says allow_unsigned, so a production worker starts, and warns.
func TestTheShippedExampleOptsOutOfSignaturesExplicitly(t *testing.T) {
	text, err := os.ReadFile("../../runtime/worker/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeServiceConfig(strings.NewReader(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Registry.Rules {
		if len(r.PublisherKeys) == 0 && !r.AllowUnsigned {
			t.Errorf("the example's rule for %s trusts no key and does not say allow_unsigned", r.Host)
		}
	}
	if r := c.registrySignatures(operatorconfig.Production); r.Status != preflight.Warn {
		t.Errorf("the example in production: %s %q", r.Status, r.Detail)
	}
}

// publisherKeyFile writes a publisher's public key as an operator installs
// it, and returns its path.
func publisherKeyFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	return writeCredentials(t, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), 0o644)
}

// registryConfig is a worker configuration whose registry section is the
// JSON rules, decoded as LoadServiceConfig decodes it.
func registryConfig(t *testing.T, rules string) ServiceConfig {
	t.Helper()
	c := ServiceConfig{Root: filepath.Join(t.TempDir(), "runtime"), Registry: &ServiceRegistry{}}
	d := json.NewDecoder(strings.NewReader(`{"rules":` + rules + `}`))
	d.DisallowUnknownFields()
	if err := d.Decode(c.Registry); err != nil {
		t.Fatal(err)
	}
	return c
}

// L-16: in production, a registry rule without publisher keys makes the
// configuration invalid unless it says "allow_unsigned": true, an explicit
// opt-out per rule, which the preflight reports as a warning naming the
// rule; a signed rule passes. Development keeps the behaviour from before:
// a rule without keys imports unsigned packages, and the preflight warns.
func TestProductionRegistryRequiresSignaturesByDefault(t *testing.T) {
	key := publisherKeyFile(t)
	signed := `[{"host":"ghcr.io","repositories":["acme/"],"publisher_keys":["` + key + `"]}]`
	unsigned := `[{"host":"ghcr.io","repositories":["acme/"]}]`
	optedOut := `[{"host":"ghcr.io","repositories":["acme/"]},{"host":"registry.example","repositories":["lab/"],"allow_unsigned":true}]`
	h := preflight.Host{Root: t.TempDir(), Stat: os.Stat, Release: func() (string, error) { return "6.1.0", nil },
		KVM: func(string, []preflight.KVMCapability) (int, []preflight.KVMCapability, error) { return 12, nil, nil },
		Statfs: func(string) (syscall.Statfs_t, error) {
			return syscall.Statfs_t{Type: 0xEF53, Blocks: 100, Bfree: 90, Bavail: 90, Bsize: 4096}, nil
		},
		ClockSynchronized: func() (bool, error) { return true, nil },
		Version:           func(context.Context, string) (string, error) { return "", errors.New("absent") }, Now: time.Now}
	for _, c := range []struct {
		name, rules string
		mode        operatorconfig.Mode
		want        preflight.Status
		names       string
	}{
		{"production, signed", signed, operatorconfig.Production, preflight.OK, ""},
		{"production, unsigned", unsigned, operatorconfig.Production, preflight.Fail, "ghcr.io"},
		{"production, one opted out", strings.Replace(optedOut, `{"host":"ghcr.io","repositories":["acme/"]}`,
			`{"host":"ghcr.io","repositories":["acme/"],"publisher_keys":["`+key+`"]}`, 1), operatorconfig.Production, preflight.Warn, "registry.example"},
		{"development, unsigned", unsigned, operatorconfig.Development, preflight.Warn, "ghcr.io"},
	} {
		cfg := registryConfig(t, c.rules)
		r := result(t, cfg.Preflight(t.Context(), h, c.mode, "host=127.0.0.1 port=1 dbname=x connect_timeout=1"), "registry_signatures")
		if r.Status != c.want || !strings.Contains(r.Detail, c.names) {
			t.Errorf("%s: %s %q", c.name, r.Status, r.Detail)
		}
		// The worker refuses to open what the preflight fails; past the
		// policy, a missing store is the next refusal.
		_, err := cfg.OpenRegistry(nil, "w", c.mode == operatorconfig.Production)
		if c.want == preflight.Fail && !errors.Is(err, ociregistry.ErrUnsigned) || c.want != preflight.Fail && !errors.Is(err, controlplane.ErrInput) {
			t.Errorf("%s: OpenRegistry: %v", c.name, err)
		}
		if got := cfg.UnsignedRegistryRules(); (c.names == "") != (len(got) == 0) || c.names != "" && !slices.Contains(got, c.names) {
			t.Errorf("%s: rules that import unsigned packages: %v", c.name, got)
		}
	}
}
