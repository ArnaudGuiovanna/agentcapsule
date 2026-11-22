//go:build linux

package workerhelper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// maxIdle bounds the connections a client keeps between requests.
const maxIdle = 8

// Client is the worker's side of the protocol. It is safe for concurrent
// use: each request takes a connection of its own.
type Client struct {
	path string
	// serverUID is the account the helper must run as: root.
	serverUID uint32
	mu        sync.Mutex
	idle      []*net.UnixConn
	closed    bool
}

// NewClient is the client of the helper at the socket path, which must be
// root's process.
func NewClient(path string) *Client { return &Client{path: path} }

// Close drops the kept connections.
func (c *Client) Close() {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()
	for _, conn := range idle {
		conn.Close()
	}
}

func (c *Client) take(ctx context.Context) (*net.UnixConn, error) {
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		conn := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "unixpacket", c.path)
	if err != nil {
		return nil, err
	}
	conn := raw.(*net.UnixConn)
	if uid, err := peerUID(conn); err != nil || uid != c.serverUID {
		conn.Close()
		return nil, errors.Join(errors.New("the worker helper's socket is not root's process"), err)
	}
	return conn, nil
}

func (c *Client) put(conn *net.UnixConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.idle) >= maxIdle {
		conn.Close()
		return
	}
	c.idle = append(c.idle, conn)
}

// Call sends one request with files, and returns the answer and its
// descriptors, which the caller closes. A refusal or a failure is an
// *Error; no answer is ErrHelperUnavailable.
func (c *Client) Call(ctx context.Context, req Request, files ...*os.File) (Response, []*os.File, error) {
	req.V = Version
	var resp Response
	conn, err := c.take(ctx)
	if err != nil {
		return resp, nil, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return resp, nil, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	err = send(conn, req, files)
	var out []*os.File
	if err == nil {
		out, err = receive(conn, &resp)
	}
	if !stop() || err != nil {
		conn.Close()
		closeFiles(out)
		if err == nil || ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
		return Response{}, nil, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	c.put(conn)
	if !resp.OK {
		closeFiles(out)
		return resp, nil, &Error{Code: resp.Code, Message: resp.Error}
	}
	return resp, out, nil
}

// one is Call for an operation that answers one descriptor.
func (c *Client) one(ctx context.Context, req Request, files ...*os.File) (*os.File, error) {
	_, out, err := c.Call(ctx, req, files...)
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		closeFiles(out)
		return nil, fmt.Errorf("%w: no descriptor in the answer", ErrHelperUnavailable)
	}
	return out[0], nil
}

// none is Call for an operation that answers no descriptor.
func (c *Client) none(ctx context.Context, req Request, files ...*os.File) (Response, error) {
	resp, out, err := c.Call(ctx, req, files...)
	closeFiles(out)
	return resp, err
}

// Hello returns the helper's layout: its jails and the VMs' cgroup.
func (c *Client) Hello(ctx context.Context) (Response, error) {
	resp, err := c.none(ctx, Request{Op: OpHello})
	if err == nil && resp.Version != Version {
		err = ErrUnsupported
	}
	return resp, err
}

// GiveVolume gives the provisioned volume f, at path, to agent's UID.
func (c *Client) GiveVolume(ctx context.Context, f *os.File, path, agent string, uid uint32) error {
	_, err := c.none(ctx, Request{Op: OpGiveVolume, Path: path, Agent: agent, UID: uid}, f)
	return err
}

// OpenVolume opens a registered agent's volume.
func (c *Client) OpenVolume(ctx context.Context, path string, write bool) (*os.File, error) {
	return c.one(ctx, Request{Op: OpOpenVolume, Path: path, Write: write})
}

// GiveDrives gives a stopped builder its drives.
func (c *Client) GiveDrives(ctx context.Context, agent string, drives []Drive) error {
	_, err := c.none(ctx, Request{Op: OpGiveDrives, Agent: agent, Drives: drives})
	return err
}

// ReclaimDrives gives a stopped builder's recorded drives back to the worker.
func (c *Client) ReclaimDrives(ctx context.Context, agent string) error {
	_, err := c.none(ctx, Request{Op: OpReclaimDrives, Agent: agent})
	return err
}

// CheckLinkable tells whether each file can be hard linked into the jails.
func (c *Client) CheckLinkable(ctx context.Context, paths ...string) error {
	_, err := c.none(ctx, Request{Op: OpCheckLinkable, Paths: paths})
	return err
}

// Prepare builds a starting run's jail and cgroup; appendix, when set, holds
// the files the boot appends to its initrd.
func (c *Client) Prepare(ctx context.Context, agent, run string, config []byte, appendix *os.File) error {
	var files []*os.File
	if appendix != nil {
		files = append(files, appendix)
	}
	_, err := c.none(ctx, Request{Op: OpPrepare, Agent: agent, Run: run, Config: config}, files...)
	return err
}

// Start starts a prepared run's jailer, its output to log.
func (c *Client) Start(ctx context.Context, agent, run string, log *os.File) error {
	_, err := c.none(ctx, Request{Op: OpStart, Agent: agent, Run: run}, log)
	return err
}

// Observe identifies a run's VMM and, with lock, its lock on the volume.
func (c *Client) Observe(ctx context.Context, agent, run string, lock bool) (Observation, error) {
	resp, err := c.none(ctx, Request{Op: OpObserve, Agent: agent, Run: run, Lock: lock})
	if err != nil {
		return Observation{}, err
	}
	if resp.Observation == nil {
		return Observation{}, fmt.Errorf("%w: no observation in the answer", ErrHelperUnavailable)
	}
	return *resp.Observation, nil
}

// Populated tells whether a run's cgroup holds a process.
func (c *Client) Populated(ctx context.Context, agent, run string) (bool, error) {
	resp, err := c.none(ctx, Request{Op: OpPopulated, Agent: agent, Run: run})
	return resp.Populated, err
}

// Cleanup kills a run's cgroup and removes it and the run's jail.
func (c *Client) Cleanup(ctx context.Context, agent, run string) error {
	_, err := c.none(ctx, Request{Op: OpCleanup, Agent: agent, Run: run})
	return err
}

// Dial returns a connection to a run's VMM's control socket.
func (c *Client) Dial(ctx context.Context, agent, run string) (*os.File, error) {
	return c.one(ctx, Request{Op: OpDial, Agent: agent, Run: run})
}

// Listen returns a listener on a run's platform socket.
func (c *Client) Listen(ctx context.Context, agent, run string) (*os.File, error) {
	return c.one(ctx, Request{Op: OpListen, Agent: agent, Run: run})
}

// FetchArchive fetches one archive from one store into the archive root.
func (c *Client) FetchArchive(ctx context.Context, root, store, archive string) error {
	_, err := c.none(ctx, Request{Op: OpFetchArchive, Path: root, Store: store, Archive: archive})
	return err
}

// RunConfined runs a confined program as the helper's inspection UID: the
// client is the sandbox's Delegate for a worker that is not root.
func (c *Client) RunConfined(ctx context.Context, d sandbox.Delegated) ([]byte, error) {
	req := Request{Op: OpSandbox, Path: d.ImagePath, Sandbox: &SandboxRequest{Program: d.Program, Self: d.Self, Args: d.Args, Input: d.Input,
		TimeoutMS: d.Timeout.Milliseconds(), CPUMS: d.CPU.Milliseconds()}}
	var files []*os.File
	if d.Image != nil {
		files = append(files, d.Image)
	}
	resp, err := c.none(ctx, req, files...)
	return resp.Output, err
}
