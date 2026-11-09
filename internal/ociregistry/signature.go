package ociregistry

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Signatures follow the format of cosign v3 ("cosign sign --key"): an in-toto
// statement whose subject is the package manifest digest, in a DSSE envelope,
// packaged as a Sigstore bundle (v0.3) and attached to the package as an OCI
// referrer (or through the referrers tag schema on registries without the
// referrers API). Only the publisher keys configured by the operator are
// trusted: certificates and transparency log entries in a bundle are ignored.
const (
	BundleMediaType       = "application/vnd.dev.sigstore.bundle.v0.3+json"
	CosignSignPredicate   = "https://sigstore.dev/cosign/sign/v1"
	inTotoPayloadType     = "application/vnd.in-toto+json"
	inTotoStatementV1     = "https://in-toto.io/Statement/v1"
	ociIndexType          = "application/vnd.oci.image.index.v1+json"
	maxBundle             = 128 << 10
	maxReferrers          = 32
	bundlePredicateHeader = "dev.sigstore.bundle.predicateType"
)

// PublisherKey is a trusted signing key: ECDSA P-256, P-384 or P-521, Ed25519,
// or RSA of 2048 bits or more.
type PublisherKey struct {
	// ID is "sha256:" and the hex SHA-256 of the DER-encoded public key.
	ID  string
	key crypto.PublicKey
}

// ParsePublisherKey reads one PEM "PUBLIC KEY" block (cosign.pub, or
// openssl pkey -pubout).
func ParsePublisherKey(raw []byte) (PublisherKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return PublisherKey{}, errors.New("publisher key must be one PEM PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return PublisherKey{}, errors.New("publisher key does not parse")
	}
	if !supportedKey(pub) {
		return PublisherKey{}, errors.New("unsupported publisher key type or size")
	}
	sum := sha256.Sum256(block.Bytes)
	return PublisherKey{ID: "sha256:" + hex.EncodeToString(sum[:]), key: pub}, nil
}

func supportedKey(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	}
	return false
}

// hashFor is the digest each key type signs, as cosign and sigstore-go do;
// zero for pure Ed25519, which signs the message itself.
func hashFor(pub crypto.PublicKey) crypto.Hash {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
		return crypto.SHA256
	case *rsa.PublicKey:
		return crypto.SHA256
	}
	return 0
}

// pae is the DSSE v1 pre-authentication encoding of a payload.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func verifySignature(pub crypto.PublicKey, message, sig []byte) bool {
	h := hashFor(pub)
	digest := message
	if h != 0 {
		d := h.New()
		d.Write(message)
		digest = d.Sum(nil)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, message, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, digest, sig) == nil
	}
	return false
}

type dsseEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		Sig   string `json:"sig"`
		KeyID string `json:"keyid,omitempty"`
	} `json:"signatures"`
}

type sigstoreBundle struct {
	MediaType            string          `json:"mediaType"`
	VerificationMaterial json.RawMessage `json:"verificationMaterial,omitempty"`
	DSSE                 *dsseEnvelope   `json:"dsseEnvelope"`
}

type inTotoStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// decodeBytes reads protobuf JSON bytes: standard base64, padded or not.
func decodeBytes(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// VerifyBundle checks that a Sigstore bundle carries a cosign signature of the
// manifest digest by one of the keys, and returns that key's ID.
func VerifyBundle(raw []byte, manifestDigest string, keys []PublisherKey) (string, error) {
	var b sigstoreBundle
	if len(raw) > maxBundle || json.Unmarshal(raw, &b) != nil || b.MediaType != BundleMediaType || b.DSSE == nil {
		return "", fmt.Errorf("%w: not a Sigstore v0.3 DSSE bundle", ErrSignature)
	}
	if b.DSSE.PayloadType != inTotoPayloadType || len(b.DSSE.Signatures) == 0 || len(b.DSSE.Signatures) > 8 {
		return "", fmt.Errorf("%w: unexpected envelope", ErrSignature)
	}
	payload, err := decodeBytes(b.DSSE.Payload)
	if err != nil {
		return "", fmt.Errorf("%w: envelope payload", ErrSignature)
	}
	message := pae(b.DSSE.PayloadType, payload)
	signer := ""
	for _, s := range b.DSSE.Signatures {
		sig, err := decodeBytes(s.Sig)
		if err != nil {
			continue
		}
		for _, k := range keys {
			if verifySignature(k.key, message, sig) {
				signer = k.ID
				break
			}
		}
		if signer != "" {
			break
		}
	}
	if signer == "" {
		return "", fmt.Errorf("%w: not signed by a trusted publisher key", ErrSignature)
	}
	// Only now is the payload authentic: check what was signed.
	var st inTotoStatement
	if json.Unmarshal(payload, &st) != nil || st.Type != inTotoStatementV1 || st.PredicateType != CosignSignPredicate {
		return "", fmt.Errorf("%w: not a cosign signature statement", ErrSignature)
	}
	want := strings.TrimPrefix(manifestDigest, "sha256:")
	for _, s := range st.Subject {
		if s.Digest["sha256"] == want {
			return signer, nil
		}
	}
	return "", fmt.Errorf("%w: the signature covers another package", ErrSignature)
}

// SignBundle signs a cosign statement for manifestDigest with key and returns
// the Sigstore bundle, as "cosign sign --key" would attach it.
func SignBundle(manifestDigest string, key crypto.Signer) ([]byte, error) {
	if !validDigest(manifestDigest) || !supportedKey(key.Public()) {
		return nil, errors.New("invalid digest or unsupported key")
	}
	statement, err := json.Marshal(map[string]any{
		"_type":         inTotoStatementV1,
		"subject":       []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(manifestDigest, "sha256:")}}},
		"predicateType": CosignSignPredicate,
		"predicate":     map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	return signEnvelope(statement, inTotoPayloadType, key)
}

// signEnvelope signs payload in a DSSE envelope and wraps it in a bundle.
func signEnvelope(statement []byte, payloadType string, key crypto.Signer) ([]byte, error) {
	message := pae(payloadType, statement)
	h := hashFor(key.Public())
	toSign := message
	if h != 0 {
		d := h.New()
		d.Write(message)
		toSign = d.Sum(nil)
	}
	sig, err := key.Sign(rand.Reader, toSign, h)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	hint := sha256.Sum256(der)
	return json.Marshal(map[string]any{
		"mediaType": BundleMediaType,
		"verificationMaterial": map[string]any{
			"publicKey": map[string]string{"hint": base64.StdEncoding.EncodeToString(hint[:])},
		},
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(statement),
			"payloadType": payloadType,
			"signatures":  []any{map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)}},
		},
	})
}
