package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Config is trusted operator input, a root-owned file like the worker's.
//
//   - Node: the SLIM node's data-plane endpoint (https://host:port).
//   - CA, Cert, Key: the SLIM authority and the bridge's client certificate;
//     the key and the secret are private to the bridge's user.
//   - SecretFile: the shared secret that SLIM uses for application identity.
//     Only the bridge holds it.
//   - Name: the bridge's own SLIM name, agentcapsule/platform/<host>.
//   - Socket: where the bridge listens for its worker, which runs as WorkerUID.
//   - WorkerSocket: where the worker listens for the bridge's calls back.
type Config struct {
	Version      int    `json:"version"`
	Node         string `json:"node"`
	CA           string `json:"ca"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	SecretFile   string `json:"secret_file"`
	Name         string `json:"name"`
	Socket       string `json:"socket"`
	WorkerSocket string `json:"worker_socket"`
	WorkerUID    int    `json:"worker_uid"`
	// IdleSeconds: a name nobody delivered to for this long stops being
	// served (default 600). ProbeSeconds: how often the bridge sends itself a
	// message through the node (default 5); three failures in a row end the
	// process, since SLIM clients do not reconnect. CallSeconds bounds one
	// delivery across SLIM (default 300).
	IdleSeconds  int `json:"idle_seconds,omitempty"`
	ProbeSeconds int `json:"probe_seconds,omitempty"`
	CallSeconds  int `json:"call_seconds,omitempty"`
}

var errConfig = errors.New("bridge configuration: version 1, an https node, absolute ca/cert/key/secret_file, a private key and secret of 32+ bytes, a platform name, two distinct absolute sockets, worker_uid >= 0, idle 60-86400, probe 1-60, call 1-3600 seconds")

func (c Config) Idle() time.Duration  { return time.Duration(c.IdleSeconds) * time.Second }
func (c Config) Probe() time.Duration { return time.Duration(c.ProbeSeconds) * time.Second }
func (c Config) Call() time.Duration  { return time.Duration(c.CallSeconds) * time.Second }

func absolute(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// private reads a file only its owner can read.
func private(path string, max int64) ([]byte, error) {
	if !absolute(path) {
		return nil, errConfig
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Size() > max {
		return nil, errConfig
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// LoadConfig reads and checks the configuration and returns the secret.
func LoadConfig(path string) (Config, string, error) {
	var c Config
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return c, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 16<<10 {
		return c, "", errors.New("bridge configuration must be a bounded regular file without group/other write access")
	}
	d := json.NewDecoder(io.LimitReader(f, 16<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, "", err
	}
	if c.IdleSeconds == 0 {
		c.IdleSeconds = 600
	}
	if c.ProbeSeconds == 0 {
		c.ProbeSeconds = 5
	}
	if c.CallSeconds == 0 {
		c.CallSeconds = 300
	}
	u, err := url.Parse(c.Node)
	if err != nil || c.Version != 1 || u.Scheme != "https" || u.Host == "" || u.Path != "" ||
		!absolute(c.CA) || !absolute(c.Cert) || !absolute(c.Key) ||
		!strings.HasPrefix(c.Name, platformNamespace) || !validName(c.Name) || !validName(c.Name+".probe") ||
		!absolute(c.Socket) || !absolute(c.WorkerSocket) || len(c.Socket) > 100 || len(c.WorkerSocket) > 100 || c.Socket == c.WorkerSocket ||
		c.WorkerUID < 0 || c.IdleSeconds < 60 || c.IdleSeconds > 86400 || c.ProbeSeconds < 1 || c.ProbeSeconds > 60 || c.CallSeconds < 1 || c.CallSeconds > 3600 {
		return c, "", errConfig
	}
	if _, err = private(c.Key, 16<<10); err != nil {
		return c, "", errConfig
	}
	secret, err := private(c.SecretFile, 4096)
	if err != nil {
		return c, "", errConfig
	}
	s := strings.TrimSpace(string(secret))
	clear(secret)
	if len(s) < 32 {
		return c, "", errConfig
	}
	return c, s, nil
}
