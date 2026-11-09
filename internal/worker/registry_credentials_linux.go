//go:build linux

package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// ErrRegistryCredentials: a registry credentials file is missing, not
// private, or malformed. The message never contains the file's content.
var ErrRegistryCredentials = errors.New("registry credentials file must be private JSON with a username and a password")

// readRegistryCredentials reads {"username": ..., "password": ...} from an
// absolute path to a regular file (no symlink) owned by root or this user,
// with no group or other access, of at most 4 KiB. Unknown fields, duplicate
// documents and empty values are refused. For GHCR the password is a token
// with the read:packages scope.
func readRegistryCredentials(path string) (string, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", ErrRegistryCredentials
	}
	raw, err := operatorconfig.ReadPrivateUpTo(path, 4096)
	if err != nil {
		return "", "", ErrRegistryCredentials
	}
	defer clear(raw)
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&v); err != nil {
		return "", "", ErrRegistryCredentials
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) || v.Username == "" || v.Password == "" {
		return "", "", ErrRegistryCredentials
	}
	return v.Username, v.Password, nil
}
