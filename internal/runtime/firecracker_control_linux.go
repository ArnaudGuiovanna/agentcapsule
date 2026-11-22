//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// appendControlConfig writes the files a boot appends to its initrd:
// credentials, the launch of a registry harness, and corpora.json when the
// VM has corpora or build drives.
func appendControlConfig(f io.WriteSeeker, guest capsuleprotocol.Credentials, harness *HarnessImage, corpora *capsuleprotocol.GuestCorpora) error {
	if harness == nil {
		return capsuleprotocol.AppendBootConfig(f, guest, nil, corpora)
	}
	return capsuleprotocol.AppendBootConfig(f, guest, &capsuleprotocol.HarnessLaunch{Entrypoint: harness.Entrypoint}, corpora)
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

// controlClient returns the boot's control client. One client per boot is
// kept while the boot lasts, so that its connections, each authenticated at
// its own mTLS handshake, serve the next calls (P-09); cleanup closes them.
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
	vmID := a.Run.ID
	h.platformMu.Lock()
	c := h.clients[vmID]
	h.platformMu.Unlock()
	if c != nil && c.Identity() == credentials.Identity {
		return c, nil
	}
	// Each connection reaches the VMM's socket, which belongs to its UID,
	// through root (ADR 024).
	boot := a.clone()
	c, err = capsuleprotocol.NewClient(credentials, func(ctx context.Context) (net.Conn, error) { return h.privileged().Dial(ctx, boot) })
	if err != nil {
		return nil, err
	}
	h.platformMu.Lock()
	defer h.platformMu.Unlock()
	if h.platformClosed {
		return c, nil
	}
	if h.clients == nil {
		h.clients = map[string]*capsuleprotocol.Client{}
	}
	if old := h.clients[vmID]; old != nil && old.Identity() == credentials.Identity {
		return old, nil
	}
	h.clients[vmID] = c
	return c, nil
}

// dropClient closes the kept connections of a boot that ends.
func (h *FirecrackerHost) dropClient(vmID string) {
	h.platformMu.Lock()
	c := h.clients[vmID]
	delete(h.clients, vmID)
	h.platformMu.Unlock()
	if c != nil {
		c.CloseIdleConnections()
	}
}

// CredentialRotations observes verified running boots. now is the trusted host
// clock, never a client timestamp. Callers must recheck under exclusive admission
// and retire the exact generation before replacing its credentials.
func (h *FirecrackerHost) CredentialRotations(ctx context.Context, now time.Time) (map[string]VMRun, error) {
	due := make(map[string]VMRun)
	if !h.opts.AuthenticatedControl {
		return due, nil
	}
	if err := h.recover(ctx); err != nil {
		return due, err
	}
	r, err := h.view()
	if err != nil {
		return due, err
	}
	for id, a := range r.Agents {
		needs, err := h.credentialDue(a, now)
		if err != nil {
			return due, err
		}
		if needs {
			due[id] = *a.Run
		}
	}
	return due, nil
}

// CredentialRotation is CredentialRotations for one agent: its VM alone is
// recovered, then checked.
func (h *FirecrackerHost) CredentialRotation(ctx context.Context, id string, now time.Time) (VMRun, bool, error) {
	var run VMRun
	if !h.opts.AuthenticatedControl {
		return run, false, nil
	}
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return run, false, err
	}
	defer unlock()
	if err = h.recoverOne(ctx, id); err != nil {
		return run, false, err
	}
	a, err := h.agent(ctx, id)
	if err != nil || a == nil {
		return run, false, err
	}
	due, err := h.credentialDue(a, now)
	if due {
		run = *a.Run
	}
	return run, due, err
}

// credentialDue tells whether a's VM, if it runs, needs new credentials by now.
// A boot still starting, which another caller holds, got its credentials
// just now.
func (h *FirecrackerHost) credentialDue(a *HostAgent, now time.Time) (bool, error) {
	if a.Run == nil || a.Run.Phase != "RUNNING" {
		return false, nil
	}
	credentials, err := h.controlCredentials(a)
	if err != nil {
		return false, err
	}
	return credentialsDue(credentials, now)
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
// placement, never a payload endpoint or identity. Call it for EVERY RPC: it
// adopts the agent's VM again first (recoverOne). A returned session stays
// bound to its original boot, even after replacement.
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

// controlSession adopts the agent's VM under the agent's lock, never under
// host.lock, then returns its boot's client.
func (h *FirecrackerHost) controlSession(ctx context.Context, id string) (*capsuleprotocol.Client, VMRun, error) {
	var run VMRun
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return nil, run, err
	}
	defer unlock()
	if err = h.recoverOne(ctx, id); err != nil {
		return nil, run, err
	}
	a, err := h.agent(ctx, id)
	if err != nil {
		return nil, run, err
	}
	if a == nil || a.Run == nil {
		return nil, run, ErrNoVM
	}
	run = *a.Run
	client, err := h.controlClient(a)
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
