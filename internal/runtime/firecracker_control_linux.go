//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

var ErrNoVM = errors.New("no confirmed VM for this agent")
var ErrNoControl = errors.New("authenticated capsule control is not configured")
var ErrCredentialsDue = errors.New("boot credentials require generation replacement")

// Longer than a bounded control RPC or normal boot. This is an availability
// margin, not permission to accept expired certificates or infer VMM absence.
const CredentialRenewalMargin = 5 * time.Minute

func (h *FirecrackerHost) credentialPath(run *VMRun) string {
	return filepath.Join(h.root, "credentials", run.ID+".json")
}
func identity(a *HostAgent) capsuleprotocol.Identity {
	return capsuleprotocol.Identity{Incarnation: a.Run.Incarnation, AgentID: a.ID, Generation: a.Run.Generation, VMID: a.Run.ID, FenceOnly: a.Run.FenceOnly}
}

func (h *FirecrackerHost) prepareControl(a *HostAgent) (capsuleprotocol.Credentials, error) {
	if !h.opts.AuthenticatedControl {
		return capsuleprotocol.Credentials{}, nil
	}
	host, guest, err := capsuleprotocol.NewBootCredentials(identity(a), 24*time.Hour, h.opts.PlatformHandler != nil)
	if err != nil {
		return guest, err
	}
	b, err := json.Marshal(host)
	if err != nil {
		return guest, err
	}
	f, err := os.OpenFile(h.credentialPath(a.Run), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return guest, err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return guest, err
	}
	if err = f.Sync(); err != nil {
		return guest, err
	}
	if err = f.Close(); err != nil {
		return guest, err
	}
	return guest, syncDir(filepath.Dir(h.credentialPath(a.Run)))
}

func appendControlConfig(f *os.File, guest capsuleprotocol.Credentials, harness *HarnessImage) error {
	if harness == nil {
		return capsuleprotocol.AppendBootConfig(f, guest, nil)
	}
	return capsuleprotocol.AppendBootConfig(f, guest, &capsuleprotocol.HarnessLaunch{Entrypoint: harness.Entrypoint})
}

func (h *FirecrackerHost) controlCredentials(a *HostAgent) (capsuleprotocol.Credentials, error) {
	if !h.opts.AuthenticatedControl {
		return capsuleprotocol.Credentials{}, ErrNoControl
	}
	b, err := os.ReadFile(h.credentialPath(a.Run))
	if err != nil {
		return capsuleprotocol.Credentials{}, err
	}
	var credentials capsuleprotocol.Credentials
	if err = json.Unmarshal(b, &credentials); err != nil {
		return credentials, errors.New("invalid control credential record")
	}
	if credentials.Identity != identity(a) {
		return credentials, capsuleprotocol.ErrIdentity
	}
	return credentials, nil
}

func credentialsDue(c capsuleprotocol.Credentials, now time.Time) (bool, error) {
	before, after, err := c.Validity()
	return now.Before(before) || !now.Add(CredentialRenewalMargin).Before(after), err
}

func (h *FirecrackerHost) controlClient(a *HostAgent) (*capsuleprotocol.Client, error) {
	credentials, err := h.controlCredentials(a)
	if err != nil {
		return nil, err
	}
	if due, err := credentialsDue(credentials, time.Now()); err != nil {
		return nil, err
	} else if due {
		return nil, ErrCredentialsDue
	}
	socket := a.Run.Socket
	return capsuleprotocol.NewClient(credentials, func(ctx context.Context) (net.Conn, error) { return capsuleprotocol.DialControl(ctx, socket) })
}

// CredentialRotations observes verified running boots. now is the trusted host
// clock, never a client timestamp. Callers must recheck under exclusive admission
// and retire the exact generation before replacing its credentials.
func (h *FirecrackerHost) CredentialRotations(ctx context.Context, now time.Time) (map[string]VMRun, error) {
	due := make(map[string]VMRun)
	if !h.opts.AuthenticatedControl {
		return due, nil
	}
	err := h.locked(ctx, func(r *hostRegistry) error {
		if err := h.recover(ctx, r); err != nil {
			return err
		}
		for id, a := range r.Agents {
			if a.Run == nil {
				continue
			}
			credentials, err := h.controlCredentials(a)
			if err != nil {
				return err
			}
			needs, err := credentialsDue(credentials, now)
			if err != nil {
				return err
			}
			if needs {
				due[id] = *a.Run
			}
		}
		return nil
	})
	return due, err
}

func (h *FirecrackerHost) controlReady(ctx context.Context, a *HostAgent) error {
	c, err := h.controlClient(a)
	if err != nil {
		return err
	}
	return waitControlReady(ctx, c)
}

// A negotiated contract is a separate application gate, not evidence that a
// VMM is absent/present. Physical recovery and credential census never call it.
func checkControlContract(ctx context.Context, c *capsuleprotocol.Client) error {
	if err := c.Health(ctx); err != nil {
		return err
	}
	return c.RequireControlContract(ctx)
}

func waitControlReady(ctx context.Context, c *capsuleprotocol.Client) error {
	for {
		err := checkControlContract(ctx, c)
		if err == nil {
			return nil
		}
		if !errors.Is(err, capsuleprotocol.ErrTransport) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Control derives the peer from the verified host registry and current durable
// placement, never a payload endpoint or identity. Call it for EVERY RPC. A
// returned session stays bound to its original boot, even after replacement.
// Inventory recovery can retain an incompatible or unreachable live VMM for
// maintenance; Control never returns an application session for that boot.
func (h *FirecrackerHost) Control(ctx context.Context, id string) (*capsuleprotocol.Client, error) {
	client, run, err := h.controlSession(ctx, id)
	if err == nil {
		err = checkControlContract(ctx, client)
	}
	if run.ID != "" {
		err = h.observeControlResult(ctx, id, run, err)
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

// RetirementControl deliberately exposes no event or invocation operation.
type RetirementControl interface {
	Identity() capsuleprotocol.Identity
	Quiesce(context.Context) error
}

// ControlForRetirement captures the authenticated boot session without an
// application health/capabilities probe. Commit STOPPING before Quiesce, then
// verify physical retirement independently of the guest acknowledgement.
func (h *FirecrackerHost) ControlForRetirement(ctx context.Context, id string) (RetirementControl, error) {
	client, _, err := h.controlSession(ctx, id)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (h *FirecrackerHost) controlSession(ctx context.Context, id string) (*capsuleprotocol.Client, VMRun, error) {
	var client *capsuleprotocol.Client
	var run VMRun
	err := h.locked(ctx, func(r *hostRegistry) error {
		if err := h.recover(ctx, r); err != nil {
			return err
		}
		a := r.Agents[id]
		if a == nil || a.Run == nil {
			return ErrNoVM
		}
		run = *a.Run
		var err error
		client, err = h.controlClient(a)
		return err
	})
	return client, run, err
}

func (h *FirecrackerHost) observeControlResult(ctx context.Context, id string, run VMRun, probeErr error) error {
	if h.opts.ObserveControl == nil {
		return probeErr
	}
	if probeErr != nil {
		// A timed-out probe must still invalidate its own prior observation.
		// Keep this bounded; failure is returned and never means physical absence.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		return errors.Join(probeErr, h.opts.ObserveControl(cleanup, id, run, false))
	}
	return h.opts.ObserveControl(ctx, id, run, true)
}
