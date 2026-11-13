package authoritylog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Secrets leave the primary only wrapped to the operator's unlock key, with
// HPKE (RFC 9180) in base mode from the standard library: DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. The primary holds only the
// public part, the recipient. The operator keeps the unlock key off both hosts
// and gives it at promotion. Each wrapped secret is bound to its context (the
// authority, the agent and the volume), so a copy cannot be moved to another
// volume.

// ErrWrap marks an unlock key, a recipient or a wrapped secret that is
// malformed, or that does not open.
var ErrWrap = errors.New("wrapped secret does not open with this unlock key")

const (
	unlockPrefix    = "agentcapsule-unlock-key-v1:"
	recipientPrefix = "agentcapsule-unlock-recipient-v1:"
)

func kem() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

// Recipient is the public part of the unlock key.
type Recipient [32]byte

// UnlockKey is the private part. It never stays on the primary.
type UnlockKey struct {
	private hpke.PrivateKey
}

// GenerateUnlockKey returns a new unlock key, as the text the operator keeps,
// and its recipient.
func GenerateUnlockKey() ([]byte, Recipient, error) {
	var r Recipient
	k, err := kem().GenerateKey()
	if err != nil {
		return nil, r, err
	}
	private, err := k.Bytes()
	if err != nil {
		return nil, r, err
	}
	defer clear(private)
	copy(r[:], k.PublicKey().Bytes())
	text := make([]byte, 0, len(unlockPrefix)+44)
	text = append(text, unlockPrefix...)
	text = base64.RawURLEncoding.AppendEncode(text, private)
	return append(text, '\n'), r, nil
}

// ParseUnlockKey reads the text of an unlock key.
func ParseUnlockKey(text []byte) (*UnlockKey, error) {
	line := bytes.TrimSpace(text)
	if !bytes.HasPrefix(line, []byte(unlockPrefix)) {
		return nil, ErrWrap
	}
	raw, err := base64.RawURLEncoding.AppendDecode(nil, line[len(unlockPrefix):])
	defer clear(raw)
	if err != nil || len(raw) != 32 {
		return nil, ErrWrap
	}
	k, err := kem().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrWrap
	}
	return &UnlockKey{private: k}, nil
}

// Recipient returns the public part of the unlock key.
func (k *UnlockKey) Recipient() Recipient {
	var r Recipient
	copy(r[:], k.private.PublicKey().Bytes())
	return r
}

// String is the text form of a recipient, safe to print and to configure.
func (r Recipient) String() string {
	return recipientPrefix + base64.RawURLEncoding.EncodeToString(r[:])
}

// ParseRecipient reads the text form of a recipient.
func ParseRecipient(text string) (Recipient, error) {
	var r Recipient
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, recipientPrefix) {
		return r, ErrWrap
	}
	raw, err := base64.RawURLEncoding.DecodeString(text[len(recipientPrefix):])
	if err != nil || len(raw) != 32 {
		return r, ErrWrap
	}
	if _, err = kem().NewPublicKey(raw); err != nil {
		return r, ErrWrap
	}
	copy(r[:], raw)
	return r, nil
}

// KeyContext binds a wrapped volume key to its authority, agent and volume.
func KeyContext(keyAuthority, agent, volume string) string {
	return "agentcapsule-authority-volume-key-v1\x00" + keyAuthority + "\x00" + agent + "\x00" + volume
}

// SecretContext binds the restore authority's signing secret to its identity.
func SecretContext(restoreAuthority string) string {
	return "agentcapsule-authority-signing-secret-v1\x00" + restoreAuthority
}

// Seal wraps secret to the recipient, bound to context.
func Seal(r Recipient, context string, secret []byte) ([]byte, error) {
	pk, err := kem().NewPublicKey(r[:])
	if err != nil {
		return nil, ErrWrap
	}
	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(context), secret)
}

// Open unwraps a secret wrapped to this key's recipient for context.
func (k *UnlockKey) Open(context string, wrapped []byte) ([]byte, error) {
	secret, err := hpke.Open(k.private, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(context), wrapped)
	if err != nil {
		return nil, ErrWrap
	}
	return secret, nil
}

// KeyCommitment lets the replica tell two volume keys apart without holding
// either: SHA-256 over a 32-byte random key reveals nothing of it.
func KeyCommitment(keyAuthority, agent, volume string, key []byte) []byte {
	h := sha256.New()
	h.Write([]byte("agentcapsule-volume-key-commitment-v1\x00" + keyAuthority + "\x00" + agent + "\x00" + volume + "\x00"))
	h.Write(key)
	return h.Sum(nil)
}
