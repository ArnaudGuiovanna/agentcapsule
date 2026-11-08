//go:build linux

package operatorconfig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

var ErrDelegationConfig = errors.New("invalid local delegated identity configuration")

type delegationFile struct {
	Version       int `json:"version"`
	MaxTokenBytes int `json:"max_token_bytes"`
	Trusts        []struct {
		TenantID      string   `json:"tenant_id"`
		Issuer        string   `json:"issuer"`
		Audience      string   `json:"audience"`
		AllowedScopes []string `json:"allowed_scopes"`
		MaxTTLSeconds int64    `json:"max_ttl_seconds"`
		Keys          []struct {
			ID        string `json:"kid"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	} `json:"trusts"`
}

// ReadDelegationConfig reads public keys, not signing secrets. The regular file
// must be owned by this user/root and not writable by group/others. No symlink,
// URL/key fetch, duplicate JSON field, unknown field or trailing JSON is allowed.
func ReadDelegationConfig(path string) (delegatedidentity.Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > 1<<20 {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	uid := st.Sys().(*syscall.Stat_t).Uid
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || !utf8.Valid(data) {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	return parseDelegationConfig(data)
}

func parseDelegationConfig(data []byte) (delegatedidentity.Config, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueJSON(d, 0); err != nil {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	if _, err := d.Token(); err != io.EOF {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var input delegationFile
	if err := d.Decode(&input); err != nil || input.Version != 1 {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	cfg := delegatedidentity.Config{MaxTokenBytes: input.MaxTokenBytes}
	for _, item := range input.Trusts {
		if item.MaxTTLSeconds < 1 || item.MaxTTLSeconds > int64((1<<63-1)/int64(time.Second)) {
			return delegatedidentity.Config{}, ErrDelegationConfig
		}
		trust := delegatedidentity.Trust{TenantID: item.TenantID, Issuer: item.Issuer, Audience: item.Audience, AllowedScopes: item.AllowedScopes, MaxTTL: time.Duration(item.MaxTTLSeconds) * time.Second, Keys: map[string]ed25519.PublicKey{}}
		for _, key := range item.Keys {
			if _, exists := trust.Keys[key.ID]; exists {
				return delegatedidentity.Config{}, ErrDelegationConfig
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
			if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != key.PublicKey {
				return delegatedidentity.Config{}, ErrDelegationConfig
			}
			trust.Keys[key.ID] = ed25519.PublicKey(decoded)
		}
		cfg.Trusts = append(cfg.Trusts, trust)
	}
	if _, err := delegatedidentity.NewVerifier(cfg); err != nil {
		return delegatedidentity.Config{}, ErrDelegationConfig
	}
	return cfg, nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrDelegationConfig
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || !canonicalDelegationField(name) || keys[name] {
				return ErrDelegationConfig
			}
			keys[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrDelegationConfig
	}
	_, err = d.Token()
	return err
}

// encoding/json matches struct fields case-insensitively, even with
// DisallowUnknownFields. Reject every alias before that decode, including
// Unicode case folds. The typed decode then enforces each field's nesting.
func canonicalDelegationField(name string) bool {
	switch name {
	case "version", "max_token_bytes", "trusts", "tenant_id", "issuer", "audience",
		"allowed_scopes", "max_ttl_seconds", "keys", "kid", "public_key":
		return true
	default:
		return false
	}
}
