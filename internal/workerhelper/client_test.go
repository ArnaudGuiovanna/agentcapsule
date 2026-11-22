//go:build linux

package workerhelper

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// serve runs the lab's server on a socket and returns a client of it that
// accepts the test's own account as the helper's.
func (l *lab) serve(t *testing.T) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "wh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := Listen(path, uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.s.Serve(ctx, ln) }()
	c := NewClient(path)
	c.serverUID = uint32(os.Getuid())
	t.Cleanup(func() {
		c.Close()
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return c
}

// Requests and descriptors cross the socket; refusals come back as their
// codes, and the code's sentinel.
func TestTheClientAndTheServerSpeakVersionOne(t *testing.T) {
	l := newLab(t)
	c := l.serve(t)
	resp, err := c.Hello(t.Context())
	if err != nil || resp.Jails != l.c.Layout.Jails || resp.Cgroup != l.c.Layout.Cgroup {
		t.Fatal(resp, err)
	}
	path, st := l.volume("vol_x.luks")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = c.GiveVolume(t.Context(), f, path, "agt_x", agentUID); err != nil {
		t.Fatal(err)
	}
	if len(l.ops.ownedCalls()) != 1 || l.ops.ownedCalls()[0].ino != st.Ino || l.ops.ownedCalls()[0].uid != agentUID {
		t.Fatal("the descriptor did not cross", l.ops.ownedCalls())
	}
	a := l.agent("agt_a", agentUID+1, "RUNNING")
	if _, err = c.Observe(t.Context(), "agt_a", a.Run.ID, true); !errors.Is(err, ErrAbsent) {
		t.Fatal(err)
	}
	if err = os.MkdirAll(Jail(l.c.Layout.Jails, a.Run.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	o, err := c.Observe(t.Context(), "agt_a", a.Run.ID, true)
	if err != nil || o.PID != 7 || o.Ticks != "9" {
		t.Fatal(o, err)
	}
	conn, err := c.Dial(t.Context(), "agt_a", a.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err = c.Cleanup(t.Context(), "agt_none", a.Run.ID); !errors.Is(err, ErrUnknownAgent) {
		t.Fatal(err)
	}
	out, err := (sandbox.Options{Delegate: c}).Run(t.Context(), "", "/usr/sbin/debugfs", "-R", "stats")
	if err != nil || string(out) != "ok\n" {
		t.Fatal(string(out), err)
	}
	// The sandbox's delegate maps the helper's codes to the sandbox's errors.
	none := newLabWith(t, func(c *Config) { c.InspectionUID = 0 }).serve(t)
	if _, err = (sandbox.Options{Delegate: none}).Run(t.Context(), "", "/usr/sbin/debugfs"); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal(err)
	}
}

type batchInspection struct {
	Ops
	input, listing []byte
}

func (b batchInspection) Sandbox(_ context.Context, p SandboxPlan) ([]byte, error) {
	if !bytes.Equal(p.Input, b.input) || p.Image == nil || p.Program != "/usr/sbin/debugfs" {
		return nil, errors.New("incomplete batch inspection")
	}
	return b.listing, nil
}

func TestBatchInspectionCrossesTheHelperSocket(t *testing.T) {
	l := newLab(t)
	input := bytes.Repeat([]byte("# batch\nls -p <2>\n"), 512)
	listing := bytes.Repeat([]byte("directory entry\n"), sandbox.MaxOutput/16)
	l.s.ops = batchInspection{l.ops, input, listing}
	path, _ := l.volume("vol_x.luks")
	sb := sandbox.Options{Delegate: l.serve(t)}
	got, err := sb.RunInput(t.Context(), path, input, "/usr/sbin/debugfs", "-f", "-", sandbox.ImagePath)
	if err != nil || !bytes.Equal(got, listing) {
		t.Fatalf("got %d of %d bytes, error %v", len(got), len(listing), err)
	}
}

// The helper admits the worker's account alone; the worker talks only to a
// helper that is root (here: the test's account stands for root).
func TestBothEndsCheckTheirPeer(t *testing.T) {
	other := newLabWith(t, func(c *Config) { c.WorkerUID = uint32(os.Getuid()) + 1 })
	if _, err := other.serve(t).Hello(t.Context()); !errors.Is(err, ErrHelperUnavailable) {
		t.Fatal("another account was answered:", err)
	}
	c := newLab(t).serve(t)
	c.serverUID = uint32(os.Getuid()) + 1
	if _, err := c.Hello(t.Context()); !errors.Is(err, ErrHelperUnavailable) {
		t.Fatal("a helper of another account was trusted:", err)
	}
}

// A malformed message is answered invalid; a message with too many
// descriptors is refused with them closed.
func TestMalformedMessagesAreRefused(t *testing.T) {
	l := newLab(t)
	c := l.serve(t)
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: c.path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, raw := range [][]byte{[]byte("not json"), []byte(`{"v":1,"op":"hello","unknown":1}`), []byte(`{"v":1,"op":"hello"} {}`)} {
		if _, _, err = conn.WriteMsgUnix(raw, nil, nil); err != nil {
			t.Fatal(err)
		}
		var resp Response
		if _, err = receive(conn, &resp); err != nil || resp.OK || resp.Code != CodeInvalid {
			t.Fatal(string(raw), resp, err)
		}
	}
	null, _ := os.Open(os.DevNull)
	defer null.Close()
	many := []*os.File{null, null, null, null, null}
	fds := make([]int, len(many))
	for i, f := range many {
		fds[i] = int(f.Fd())
	}
	if err = sendRaw(conn, []byte(`{"v":1,"op":"hello"}`), fds); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if _, err = receive(conn, &resp); err != nil || resp.OK || resp.Code != CodeInvalid {
		t.Fatal(resp, err)
	}
	if len(l.ops.called()) != 0 {
		t.Fatal(l.ops.called())
	}
}
