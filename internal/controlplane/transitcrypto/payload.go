// Package transitcrypto authenticates stored message bodies and their immutable recipients.
package transitcrypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

var ErrPayload = errors.New("transit payload authentication failed")

// Party identifies the agent and owner whose identities are bound to a body.
type Party struct{ Agent, Owner string }

// Binding is the versioned JSON format used as AEAD associated data.
// Its field names, order, and encoding are part of the stored ciphertext format.
type Binding struct {
	Version                    int
	ID, Kind, Reference, KeyID string
	Hash                       []byte
	Parties                    []Party
}

// Seal sets the content hash and prefixes the encrypted body with a fresh nonce.
func (binding Binding) Seal(key cipher.AEAD, body []byte) (Binding, []byte, error) {
	hash := sha256.Sum256(body)
	binding.Hash = hash[:]
	aad, err := json.Marshal(binding)
	if err != nil {
		return binding, nil, err
	}
	nonce := make([]byte, key.NonceSize())
	_, _ = rand.Read(nonce)
	return binding, key.Seal(nonce, nonce, body, aad), nil
}

// Open authenticates the binding and the content hash before returning the plaintext.
func (binding Binding) Open(key cipher.AEAD, encrypted []byte) ([]byte, error) {
	if len(encrypted) < key.NonceSize()+key.Overhead() {
		return nil, ErrPayload
	}
	aad, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	body, err := key.Open(nil, encrypted[:key.NonceSize()], encrypted[key.NonceSize():], aad)
	if err != nil {
		return nil, ErrPayload
	}
	hash := sha256.Sum256(body)
	if !bytes.Equal(hash[:], binding.Hash) {
		clear(body)
		return nil, ErrPayload
	}
	return body, nil
}
