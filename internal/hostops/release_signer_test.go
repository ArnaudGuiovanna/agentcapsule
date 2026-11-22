package hostops

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// signingCertificate is a certificate like Fulcio's, with environment in the
// deployment environment extension when it is not empty.
func signingCertificate(t *testing.T, environment string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sigstore"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute)}
	trigger, _ := asn1.MarshalWithParams("push", "utf8")
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}, Value: trigger}}
	if environment != "" {
		value, err := asn1.MarshalWithParams(environment, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: environmentOID, Value: value})
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func bundleWith(der []byte, chain bool) []byte {
	raw := base64.StdEncoding.EncodeToString(der)
	material := map[string]any{"certificate": map[string]string{"rawBytes": raw}}
	if chain {
		material = map[string]any{"x509CertificateChain": map[string]any{"certificates": []map[string]string{{"rawBytes": raw}}}}
	}
	b, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": material})
	return b
}

func TestCosignVerificationBindsTheSigningRun(t *testing.T) {
	args := cosignVerification("b.json", "v1.2.3")
	want := map[string]string{
		"--bundle":                                 "b.json",
		"--certificate-identity":                   "https://github.com/ArnaudGuiovanna/agentcapsule/.github/workflows/release.yml@refs/tags/v1.2.3",
		"--certificate-oidc-issuer":                "https://token.actions.githubusercontent.com",
		"--certificate-github-workflow-trigger":    "push",
		"--certificate-github-workflow-repository": "ArnaudGuiovanna/agentcapsule",
		"--certificate-github-workflow-ref":        "refs/tags/v1.2.3",
	}
	if args[0] != "verify-blob" {
		t.Fatalf("command: %v", args)
	}
	for flag, value := range want {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] != value {
			t.Errorf("%s: %v", flag, args)
		}
	}
}

func TestSigningEnvironmentReadsTheCertificate(t *testing.T) {
	for _, chain := range []bool{false, true} {
		got, err := signingEnvironment(bundleWith(signingCertificate(t, "release"), chain))
		if err != nil || got != "release" {
			t.Fatalf("chain %v: %q, %v", chain, got, err)
		}
	}
	if got, err := signingEnvironment(bundleWith(signingCertificate(t, ""), false)); err != nil || got != "" {
		t.Fatalf("no environment: %q, %v", got, err)
	}
	for name, bundle := range map[string][]byte{
		"not json":       []byte("{"),
		"no certificate": []byte(`{"verificationMaterial":{}}`),
		"not base64":     []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"%%%"}}}`),
		"not a cert":     []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"AAAA"}}}`),
	} {
		if _, err := signingEnvironment(bundle); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckSigningEnvironmentRequiresTheReleaseEnvironment(t *testing.T) {
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("0000  agentcapsule-linux-amd64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	write := func(environment string) string {
		path := filepath.Join(dir, "bundle-"+environment+".json")
		if err := os.WriteFile(path, bundleWith(signingCertificate(t, environment), false), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := checkSigningEnvironment(write("release"), sums, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	for _, environment := range []string{"", "staging"} {
		err := checkSigningEnvironment(write(environment), sums, "v1.2.3")
		if err == nil || !strings.Contains(err.Error(), "protected release environment") {
			t.Fatalf("%q: %v", environment, err)
		}
	}
	// A release signed before the environment existed passes by its digest,
	// for its own tag only.
	content, _ := os.ReadFile(sums)
	digest := sha256.Sum256(content)
	signedBeforeEnvironment["v1.2.3"] = hex.EncodeToString(digest[:])
	defer delete(signedBeforeEnvironment, "v1.2.3")
	if err := checkSigningEnvironment(write(""), sums, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if err := checkSigningEnvironment(write(""), sums, "v1.2.4"); err == nil {
		t.Fatal("a pinned digest passed for another tag")
	}
}

func TestPinnedReleasesSignedBeforeTheEnvironment(t *testing.T) {
	// The two published releases, by the digest of their SHA256SUMS.
	if len(signedBeforeEnvironment) != 2 || signedBeforeEnvironment["v0.0.1"] == "" || signedBeforeEnvironment["v0.1.0"] == "" {
		t.Fatalf("pins: %v", signedBeforeEnvironment)
	}
	for _, file := range []string{"host.py", "../../install.sh"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for version, digest := range signedBeforeEnvironment {
			if !bytes.Contains(source, []byte(digest)) || !bytes.Contains(source, []byte(version)) {
				t.Errorf("%s does not pin %s at %s", file, version, digest)
			}
		}
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"v0.0.1", "v0.1.0-dev.2", "v0.1.0-dev.10", "v0.1.0-rc.1", "v0.1.0", "v0.1.1", "v0.10.0", "v1.0.0-alpha",
		"v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta", "v1.0.0"}
	for i := range ordered {
		for j := range ordered {
			c, err := compareVersions(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if err != nil || c != want {
				t.Fatalf("%s vs %s: %d, %v", ordered[i], ordered[j], c, err)
			}
		}
	}
	for _, bad := range []string{"1.0.0", "v1.0", "v01.0.0", "v1.0.0-01", "v1.0.0-a..b"} {
		if _, err := compareVersions(bad, "v1.0.0"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestSelfUpdateRefusesAnOlderReleaseUnlessAllowed(t *testing.T) {
	config := t.TempDir()
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", config)
	previous := Version
	defer func() { Version = previous }()
	run := func(args ...string) error {
		var out, errOut bytes.Buffer
		return selfUpdate(context.Background(), append([]string{"update"}, args...), &out, &errOut)
	}
	offline := t.TempDir() // empty: an update that passes the floor fails on its first file
	// The running release is the floor.
	Version = "v0.3.0"
	if err := run("--to", "v0.2.0", "--offline", offline); err == nil || !strings.Contains(err.Error(), "--allow-older") {
		t.Fatalf("older than the running release: %v", err)
	}
	if err := run("--to", "v0.2.0", "--offline", offline, "--allow-older"); err == nil || strings.Contains(err.Error(), "--allow-older") {
		t.Fatalf("--allow-older: %v", err)
	}
	// So is the highest recorded release, also for a development build.
	if err := recordHighest("v0.4.0", "v0.3.0"); err != nil {
		t.Fatal(err)
	}
	Version = "development"
	if err := run("--to", "v0.3.5", "--offline", offline); err == nil || !strings.Contains(err.Error(), "v0.4.0") {
		t.Fatalf("older than the recorded release: %v", err)
	}
	if err := run("--to", "v0.4.0", "--offline", offline); err == nil || strings.Contains(err.Error(), "--allow-older") {
		t.Fatalf("the recorded release itself: %v", err)
	}
	// The record only goes up.
	if err := recordHighest("v0.3.9", "v0.4.0"); err != nil {
		t.Fatal(err)
	}
	if got, err := highestRecord(); err != nil || got != "v0.4.0" {
		t.Fatalf("record: %q, %v", got, err)
	}
	if err := recordHighest("v0.5.0-rc.1", "v0.4.0"); err != nil {
		t.Fatal(err)
	}
	if got, _ := highestRecord(); got != "v0.5.0-rc.1" {
		t.Fatalf("record: %q", got)
	}
	// A damaged record stops the update.
	if err := os.WriteFile(filepath.Join(config, "self-update.json"), []byte(`{"highest":"latest"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("--to", "v9.0.0", "--offline", offline); err == nil || !strings.Contains(err.Error(), "not a valid record") {
		t.Fatalf("damaged record: %v", err)
	}
}
