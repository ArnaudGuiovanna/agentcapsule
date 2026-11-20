package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/individualidentity"
	"github.com/golang-jwt/jwt/v5"
)

func identityKey(path string) (ed25519.PrivateKey, error) {
	data, err := readFile(path, true)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("invalid private identity file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid PKCS8 key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected an Ed25519 identity key")
	}
	return key, nil
}
func (cli console) identity(pos []string, o options) error {
	if len(pos) != 2 || pos[1] != "create" && pos[1] != "show" {
		return errors.New("use identity create|show --key-file PATH --display-name NAME")
	}
	path, label := o.take("key-file"), o.take("display-name")
	if path == "" || label == "" {
		return errors.New("both --key-file and --display-name are required")
	}
	if err := o.done(); err != nil {
		return err
	}
	var key ed25519.PrivateKey
	if pos[1] == "create" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		f, err := createPrivateFile(path)
		if err != nil {
			return err
		}
		err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		key = priv
	} else {
		var err error
		key, err = identityKey(path)
		if err != nil {
			return err
		}
	}
	pub := key.Public().(ed25519.PublicKey)
	return cli.print(map[string]string{"issuer": individualidentity.Issuer(pub), "subject": individualidentity.Subject(pub), "display_name": label}, "")
}
func signPersonal(path, org string) (string, error) {
	key, err := identityKey(path)
	if err != nil {
		return "", err
	}
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": individualidentity.Issuer(pub), "sub": individualidentity.Subject(pub), "aud": org, "jti": randomKey(), "iat": now.Unix(), "exp": now.Add(individualidentity.Lifetime).Unix(), "trust_generation": 1, "scope": strings.Join(individualidentity.Scopes(), " ")})
	t.Header["kid"] = individualidentity.KeyID
	return t.SignedString(key)
}
