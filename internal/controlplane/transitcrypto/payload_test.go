package transitcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

// Version one authenticates the exact JSON representation recorded in the
// database. A package move or field reordering must keep old rows readable.
func TestVersionOneOpensStoredPayloads(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("the stored body")
	sum := sha256.Sum256(body)
	digest := base64.StdEncoding.EncodeToString(sum[:])
	binding := Binding{Version: 1, ID: "pay_x", Kind: "instruction", Reference: "op_x", KeyID: "current", Hash: sum[:], Parties: []Party{{"agt_x", "user_x"}}}
	aad := []byte(`{"Version":1,"ID":"pay_x","Kind":"instruction","Reference":"op_x","KeyID":"current","Hash":"` + digest + `","Parties":[{"Agent":"agt_x","Owner":"user_x"}]}`)
	nonce := make([]byte, key.NonceSize())
	stored := key.Seal(nonce, nonce, body, aad)
	got, err := binding.Open(key, stored)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("open stored ciphertext", err)
	}
	sealed, ciphertext, err := binding.Seal(key, body)
	if err != nil {
		t.Fatal(err)
	}
	got, err = key.Open(nil, ciphertext[:key.NonceSize()], ciphertext[key.NonceSize():], aad)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("open new ciphertext with version-one binding", err)
	}
	sealed.Reference = "different"
	if _, err = sealed.Open(key, ciphertext); !errors.Is(err, ErrPayload) {
		t.Fatal("modified reference", err)
	}
}
