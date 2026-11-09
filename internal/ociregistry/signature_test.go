package ociregistry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
)

func publisher(t *testing.T, key crypto.Signer) PublisherKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePublisherKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecdsaKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBundlesVerifyOnlyForTheirPackageAndKey(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"p256": ecdsaKey(t, elliptic.P256()), "p384": ecdsaKey(t, elliptic.P384()),
		"p521": ecdsaKey(t, elliptic.P521()), "ed25519": ed, "rsa": rsaKey} {
		b, err := SignBundle(digest, key)
		if err != nil {
			t.Fatal(name, err)
		}
		pub := publisher(t, key)
		if signer, err := VerifyBundle(b, digest, []PublisherKey{publisher(t, ecdsaKey(t, elliptic.P256())), pub}); err != nil || signer != pub.ID {
			t.Fatal("valid signature refused", name, err)
		}
		if _, err = VerifyBundle(b, "sha256:"+strings.Repeat("cd", 32), []PublisherKey{pub}); !errors.Is(err, ErrSignature) {
			t.Fatal("a signature verified for another package", name, err)
		}
		if _, err = VerifyBundle(b, digest, []PublisherKey{publisher(t, ecdsaKey(t, elliptic.P256()))}); !errors.Is(err, ErrSignature) {
			t.Fatal("a signature verified with an untrusted key", name, err)
		}
	}

	key := ecdsaKey(t, elliptic.P256())
	trusted := []PublisherKey{publisher(t, key)}
	good, _ := SignBundle(digest, key)
	var b map[string]any
	_ = json.Unmarshal(good, &b)
	forge := func(mutate func(map[string]any)) []byte {
		var c map[string]any
		_ = json.Unmarshal(good, &c)
		mutate(c)
		raw, _ := json.Marshal(c)
		return raw
	}
	statement := func(predicate, payloadType string) []byte {
		st, _ := json.Marshal(map[string]any{"_type": inTotoStatementV1, "predicateType": predicate, "predicate": map[string]any{},
			"subject": []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}})
		raw, err := signEnvelope(st, payloadType, key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	other, _ := SignBundle("sha256:"+strings.Repeat("cd", 32), key)
	var otherBundle map[string]any
	_ = json.Unmarshal(other, &otherBundle)
	for name, raw := range map[string][]byte{
		"media type": forge(func(c map[string]any) { c["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.2+json" }),
		"payload swapped": forge(func(c map[string]any) {
			c["dsseEnvelope"].(map[string]any)["payload"] = otherBundle["dsseEnvelope"].(map[string]any)["payload"]
		}),
		"no signature":   forge(func(c map[string]any) { c["dsseEnvelope"].(map[string]any)["signatures"] = []any{} }),
		"message bundle": forge(func(c map[string]any) { delete(c, "dsseEnvelope"); c["messageSignature"] = map[string]any{} }),
		"predicate":      statement("https://slsa.dev/provenance/v1", inTotoPayloadType),
		"payload type":   statement(CosignSignPredicate, "text/plain"),
		"not json":       []byte("signature"),
	} {
		if _, err := VerifyBundle(raw, digest, trusted); !errors.Is(err, ErrSignature) {
			t.Fatal("forged bundle accepted:", name, err)
		}
	}

	// Keys: one public key PEM block of a supported type and size.
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKIXPublicKey(small.Public())
	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(key.Public())
	one := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	for name, raw := range map[string][]byte{
		"rsa 1024":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		"private key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}),
		"two keys":    append(append([]byte{}, one...), one...),
		"not pem":     []byte("ssh-ed25519 AAAA"),
	} {
		if _, err := ParsePublisherKey(raw); err == nil {
			t.Fatal("publisher key accepted:", name)
		}
	}
}

func TestSignedImportsNeedATrustedPublisher(t *testing.T) {
	for _, referrersAPI := range []bool{true, false} {
		reg := registrytest.New()
		reg.NoReferrers = !referrersAPI
		rule := localRule(reg, "acme/")
		signed, err := Push(t.Context(), rule, "acme/echo", "1.0.0", buildPackage(t, manifestFor("echo", "1.0.0")))
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := Push(t.Context(), rule, "acme/echo", "2.0.0", buildPackage(t, manifestFor("echo", "2.0.0")))
		if err != nil {
			t.Fatal(err)
		}
		publisherKey, stranger := ecdsaKey(t, elliptic.P256()), ecdsaKey(t, elliptic.P256())
		// A stranger's signature first, then the publisher's: both are attached.
		for _, k := range []crypto.Signer{stranger, publisherKey} {
			if _, err = Sign(t.Context(), rule, signed, k); err != nil {
				t.Fatal("sign", referrersAPI, err)
			}
		}
		trusting := rule
		trusting.Keys = []PublisherKey{publisher(t, publisherKey)}
		f, err := NewFetcher(Policy{Rules: []Rule{trusting}, RequireSignatures: true}, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := f.Fetch(t.Context(), signed, t.TempDir())
		if err != nil || pkg.Signer != trusting.Keys[0].ID {
			t.Fatal("signed package refused", referrersAPI, err, pkg.Signer)
		}
		// Unsigned, or signed only by someone else: refused before the image
		// is downloaded.
		pulls := reg.BlobPulls.Load()
		if _, err = f.Fetch(t.Context(), unsigned, t.TempDir()); !errors.Is(err, ErrSignature) {
			t.Fatal("unsigned package accepted", referrersAPI, err)
		}
		if _, err = Sign(t.Context(), rule, unsigned, stranger); err != nil {
			t.Fatal(err)
		}
		if _, err = f.Fetch(t.Context(), unsigned, t.TempDir()); !errors.Is(err, ErrSignature) {
			t.Fatal("package signed by an untrusted key accepted", referrersAPI, err)
		}
		if n := reg.BlobPulls.Load() - pulls; n > 2 {
			t.Fatal("the unsigned package was downloaded before the signature check", n)
		}
		reg.Close()
	}

	// A referrer whose subject is another package does not count, even if a
	// registry lists it for this one.
	reg := registrytest.New()
	defer reg.Close()
	reg.NoReferrers = true
	rule := localRule(reg, "acme/")
	a, _ := Push(t.Context(), rule, "acme/echo", "1.0.0", buildPackage(t, manifestFor("echo", "1.0.0")))
	b, _ := Push(t.Context(), rule, "acme/echo", "2.0.0", buildPackage(t, manifestFor("echo", "2.0.0")))
	key := ecdsaKey(t, elliptic.P256())
	if _, err := Sign(t.Context(), rule, a, key); err != nil {
		t.Fatal(err)
	}
	index := fetchTag(t, reg, "acme/echo", strings.Replace(a.Digest, ":", "-", 1))
	reg.PutManifestAs("acme/echo", strings.Replace(b.Digest, ":", "-", 1), index, ociIndexType)
	trusting := rule
	trusting.Keys = []PublisherKey{publisher(t, key)}
	f, _ := NewFetcher(Policy{Rules: []Rule{trusting}}, 64<<20)
	if _, err := f.Fetch(t.Context(), b, t.TempDir()); !errors.Is(err, ErrSignature) {
		t.Fatal("another package's signature was accepted", err)
	}
	// Strict mode refuses a rule that trusts no key.
	if (Policy{Rules: []Rule{rule}, RequireSignatures: true}).Validate() == nil {
		t.Fatal("strict mode accepted a rule without publisher keys")
	}
}

func fetchTag(t *testing.T, reg *registrytest.Registry, repo, tag string) []byte {
	t.Helper()
	c := newClient(Rule{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true}, 0)
	raw, _, err := c.getManifest(t.Context(), repo, "repository:"+repo+":pull", tag, ociIndexType)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testdata/sigstore-go-bundle.json was made by sigstore-go v1.3.0 (the library
// cosign v3 builds "cosign sign --key" bundles with) over a cosign statement
// for interopDigest, with the key in testdata/sigstore-go-key.pub. Our verifier
// must accept it, and the hint must match the key ID we derive.
const interopDigest = "sha256:7afe914e7dc584688eedc7bae8dcf97152e86d8bec70971bcbb0441a30ab4597"

func TestBundlesFromTheReferenceImplementationVerify(t *testing.T) {
	raw, err := os.ReadFile("testdata/sigstore-go-bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := os.ReadFile("testdata/sigstore-go-key.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePublisherKey(pemKey)
	if err != nil {
		t.Fatal(err)
	}
	if signer, err := VerifyBundle(raw, interopDigest, []PublisherKey{key}); err != nil || signer != key.ID {
		t.Fatal("a sigstore-go bundle was refused", err)
	}
	var b struct {
		VerificationMaterial struct {
			PublicKey struct {
				Hint string `json:"hint"`
			} `json:"publicKey"`
		} `json:"verificationMaterial"`
	}
	if json.Unmarshal(raw, &b) != nil {
		t.Fatal("bundle")
	}
	hint, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.PublicKey.Hint)
	if "sha256:"+hex.EncodeToString(hint) != key.ID {
		t.Fatal("key ID and bundle hint disagree", key.ID)
	}
	if _, err = VerifyBundle(raw, "sha256:"+strings.Repeat("0", 64), []PublisherKey{key}); !errors.Is(err, ErrSignature) {
		t.Fatal("the reference bundle verified for another digest", err)
	}
}
