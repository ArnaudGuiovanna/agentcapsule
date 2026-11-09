//go:build linux

package worker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// ServiceDirectory connects the worker to the private Directory (INT-02,
// deploy/interop): the worker publishes the records of the organizations'
// agents and answers their searches. Address is the mutual-TLS edge
// (host:port); CA, Cert and Key are absolute paths to the Directory authority
// and the control plane's client certificate, the key private to the worker.
type ServiceDirectory struct {
	Address         string `json:"address"`
	CA              string `json:"ca"`
	Cert            string `json:"cert"`
	Key             string `json:"key"`
	PublishInterval string `json:"publish_interval,omitempty"` // default 5s
}

// ErrDirectoryConfig: the directory section is incomplete, a path is not
// absolute or not readable, the key is not private, or the interval is out of
// range. The message never contains file contents.
var ErrDirectoryConfig = errors.New("directory needs an edge address, absolute ca/cert/key paths with a private key, and an interval of 1s to 10m")

func readPublic(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrDirectoryConfig
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return nil, ErrDirectoryConfig
	}
	return os.ReadFile(path)
}

// OpenDirectory returns nil when the host has no Directory.
func (c ServiceConfig) OpenDirectory() (*directory.Client, time.Duration, error) {
	d := c.Directory
	if d == nil {
		return nil, 0, nil
	}
	interval := 5 * time.Second
	if d.PublishInterval != "" {
		var err error
		if interval, err = time.ParseDuration(d.PublishInterval); err != nil || interval < time.Second || interval > 10*time.Minute {
			return nil, 0, ErrDirectoryConfig
		}
	}
	if host, port, err := net.SplitHostPort(d.Address); err != nil || host == "" || port == "" {
		return nil, 0, ErrDirectoryConfig
	}
	ca, err := readPublic(d.CA, 64<<10)
	if err != nil {
		return nil, 0, ErrDirectoryConfig
	}
	cert, err := readPublic(d.Cert, 64<<10)
	if err != nil {
		return nil, 0, ErrDirectoryConfig
	}
	if !filepath.IsAbs(d.Key) || filepath.Clean(d.Key) != d.Key {
		return nil, 0, ErrDirectoryConfig
	}
	key, err := operatorconfig.ReadPrivateUpTo(d.Key, 16<<10)
	if err != nil {
		return nil, 0, ErrDirectoryConfig
	}
	defer clear(key)
	client, err := directory.Dial(d.Address, directory.Credentials{CA: ca, Cert: cert, Key: key})
	if err != nil {
		return nil, 0, ErrDirectoryConfig
	}
	return client, interval, nil
}

// EnableDirectory attaches the Directory once, like EnableLLM.
func (w *Placements) EnableDirectory(c *directory.Client) error {
	if c == nil || !w.directory.CompareAndSwap(nil, c) {
		return controlplane.ErrConflict
	}
	return nil
}

// FindAgents answers a running agent's search: the Directory narrows the
// candidates to its organization and skills, then PostgreSQL keeps only those
// the agent may see now. The Directory call holds no host or database lock.
func (a platformAPI) FindAgents(ctx context.Context, q capsuleprotocol.DirectoryQuery) ([]capsuleprotocol.DirectoryAgent, error) {
	if a.directory == nil || a.directory() == nil {
		return nil, &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	var tenant string
	err := a.withApplication(ctx, func(ctx context.Context) error {
		var err error
		tenant, err = a.store.DirectoryScopeFromVM(ctx, a.caller)
		return err
	})
	if err != nil {
		return nil, platformError(err)
	}
	search, cancel := context.WithTimeout(ctx, 10*time.Second)
	cids, err := a.directory().Search(search, tenant, q.Skills, 100)
	cancel()
	if err != nil {
		return nil, &capsuleprotocol.PlatformError{Code: "unavailable"}
	}
	var found []controlplane.DirectoryAgent
	err = a.withApplication(ctx, func(ctx context.Context) error {
		var err error
		found, err = a.store.FindDirectoryAgentsFromVM(ctx, a.caller, cids, q.Skills)
		return err
	})
	if err != nil {
		return nil, platformError(err)
	}
	out := make([]capsuleprotocol.DirectoryAgent, len(found))
	for i, f := range found {
		out[i] = capsuleprotocol.DirectoryAgent{AgentID: f.AgentID, Description: f.Description, Skills: f.Skills, Domains: f.Domains}
	}
	return out, nil
}
